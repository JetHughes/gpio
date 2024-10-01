#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/circ_buf.h>
#include "gpio.c"

#define MYDEV_NAME "asgn2"
#define CIRCULAR_BUFFER_SIZE 1024

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jet Hughes");
MODULE_DESCRIPTION("COSC440 asgn2");

/**
 * Circular buffer structure
 */
struct circ_buffer {
    char buffer[CIRCULAR_BUFFER_SIZE];
    int head;
    int tail;
    spinlock_t lock;
};
struct circ_buffer circ_buf;

/**
 * Page Node Structure
 */
struct page_node {
    struct page *page;
    size_t head_offset; // Read offset
    size_t tail_offset; // Write offset
    struct list_head list;
};

/**
 * Page queue structure (for multiple-page buffering)
 */
typedef struct page_queue_t {
    struct list_head pages; // Linked list head
    spinlock_t lock; // Lock for the queue
    int data_size;
} page_queue;
page_queue buffer_queue;

struct tasklet_struct my_tasklet;

dev_t dev_num;
struct cdev *asgn2_cdev;
struct class *asgn2_class;
struct device *asgn2_device;

spinlock_t queue_lock;
wait_queue_head_t read_queue;
atomic_t nprocs;

static bool session_complete = false;

/**
 * Initialize the circular buffer
 */
int init_circular_buffer(void) {
    circ_buf.head = 0;
    circ_buf.tail = 0;
    spin_lock_init(&circ_buf.lock);
    printk(KERN_INFO "asgn2: Circular buffer initialized\n");
    return 0;
}

/**
 * Initialize the page queue
 */
void init_page_queue(void) {
    buffer_queue.data_size = 0;
    INIT_LIST_HEAD(&buffer_queue.pages);
    spin_lock_init(&buffer_queue.lock);
    printk(KERN_INFO "asgn2: Page queue initialized\n");
}


/**
 * Write a byte to the circular buffer
 * Protected by spinlock
 */
int circ_buf_write(char data) {
    unsigned long flags;
    spin_lock_irqsave(&circ_buf.lock, flags);
    
    // If there is no space drop the byte
    if (CIRC_SPACE(circ_buf.head, circ_buf.tail, CIRCULAR_BUFFER_SIZE) == 0) {
        spin_unlock_irqrestore(&circ_buf.lock, flags);
        printk(KERN_ERR "asgn2: Circular buffer is full, dropping byte\n");
        return -1;  // Buffer is full
    }

    circ_buf.buffer[circ_buf.head] = data;
    circ_buf.head = (circ_buf.head + 1) % CIRCULAR_BUFFER_SIZE;
    printk(KERN_INFO "asgn2: Byte 0x%x written to circular buffer\n", data);
    spin_unlock_irqrestore(&circ_buf.lock, flags);
    return 0;
}

/**
 * Read a byte from the circular buffer
 * Protected by spinlock
 */
int circ_buf_read(char *data) {
    unsigned long flags;
    spin_lock_irqsave(&circ_buf.lock, flags);
    
    if (CIRC_CNT(circ_buf.head, circ_buf.tail, CIRCULAR_BUFFER_SIZE) == 0) {
        spin_unlock_irqrestore(&circ_buf.lock, flags);
        printk(KERN_INFO "asgn2: Circular buffer is empty\n");
        return -1;  // Buffer is empty
    }

    *data = circ_buf.buffer[circ_buf.tail];
    circ_buf.tail = (circ_buf.tail + 1) % CIRCULAR_BUFFER_SIZE;
    printk(KERN_INFO "asgn2: Byte 0x%x read from circular buffer\n", *data);
    spin_unlock_irqrestore(&circ_buf.lock, flags);
    return 0;
}

/**
 * Add a new page to the page queue. 
 */
struct page_node* alloc_new_page_node(void) {
    struct page_node *new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
    if (!new_node) {
        printk(KERN_ERR "Failed to allocate memory for page node\n");
        return NULL;
    }
    memset(new_node, 0, sizeof(struct page_node));

    new_node->page = alloc_page(GFP_KERNEL);
    if (!new_node->page) {
        printk(KERN_ERR "Failed to allocate new page\n");
        kfree(new_node);
        return NULL;
    }

    new_node->head_offset = 0;
    new_node->tail_offset = 0;
    INIT_LIST_HEAD(&new_node->list);

    list_add_tail(&new_node->list, &buffer_queue.pages);
    return new_node;
}


/**
 * Add a byte to the page queue (used by the tasklet). Allocates a new page 
 * if the current page is full or if the page queue is empty.
 * Protected by spinlock
 */
void add_to_page_queue(char byte) {
    unsigned long flags;
    struct page_node *tail_node;

    spin_lock_irqsave(&buffer_queue.lock, flags);

    // Allocate a new page if the list is empty or the current page is full
    if (list_empty(&buffer_queue.pages)) {
        tail_node = alloc_new_page_node();
        if (!tail_node) {
            spin_unlock_irqrestore(&buffer_queue.lock, flags);
            return;
        }
    } else {
        tail_node = list_last_entry(&buffer_queue.pages, struct page_node, list);
        
        // Allocate a new node if the current page is full
        if (tail_node->tail_offset >= PAGE_SIZE) {
            tail_node = alloc_new_page_node();
            if (!tail_node) {
                spin_unlock_irqrestore(&buffer_queue.lock, flags);
                return;
            }
        }
    }

    // Add byte to the page at the current offset
    void *page_addr = page_address(tail_node->page);
    ((char *)page_addr)[tail_node->tail_offset] = byte;
    tail_node->tail_offset++;
    buffer_queue.data_size++;

    printk(KERN_INFO "asgn2: Byte 0x%x added at page offset %d\n", byte, tail_node->tail_offset);

    spin_unlock_irqrestore(&buffer_queue.lock, flags);
}


/**
 * Tasklet function: Process the circular buffer and add to the page queue
 */
void bottom_half_tasklet_function(unsigned long data) {
    char byte;
    while (circ_buf_read(&byte) == 0) {
        add_to_page_queue(byte);
    }

    printk(KERN_INFO "asgn2: Tasklet processed circular buffer and added bytes to page queue\n");
    wake_up_interruptible(&read_queue);  // Wake up any readers waiting for data
}


/**
 * Interrupt handler: Handle half-bytes, assemble into full byte, and push to circular buffer
 */
irqreturn_t dummyport_interrupt(int irq, void *dev_id) {
    static bool is_msb = true;
    static u8 byte_buffer;

    // Read the half-byte from GPIO
    u8 half_byte = read_half_byte();
    printk(KERN_INFO "asgn2: Interrupt triggered, read half-byte 0x%x\n", half_byte);


    if (is_msb) {
        byte_buffer = half_byte << 4;  // Store MSB
        is_msb = false;
    } else {
        byte_buffer |= half_byte;  // Combine with LSB
        if (circ_buf_write(byte_buffer) < 0) {
            printk(KERN_ERR "Circular buffer is full, dropping byte\n");
        } else {
            printk(KERN_INFO "asgn2: Assembled byte 0x%x, scheduling tasklet\n", byte_buffer);
            tasklet_schedule(&my_tasklet);  // Schedule the tasklet to process the data
        }
        is_msb = true;  // Toggle back to MSB for the next byte
    }

    return IRQ_HANDLED;
}

/**
 * Read function: Consume data from the page queue.
 * Free pages that are fully read.
 */
ssize_t asgn2_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) {
    unsigned long flags;
    size_t bytes_read = 0;
    struct page_node *node, *tmp;

    if (session_complete) {
        printk(KERN_INFO "asgn2: Session already completed, blocking further reads\n");
        return 0;  // Block further reads until the device is closed
    }

    printk(KERN_INFO "asgn2: Read request for %zu bytes\n", count);
    printk(KERN_INFO "asgn2: I have %d bytes of data", buffer_queue.data_size);

    if (list_empty(&buffer_queue.pages)) {
        printk(KERN_INFO "asgn2: No data in page queue, waiting for data\n");
    }

    // Wait if no data is available
    wait_event_interruptible(read_queue, !list_empty(&buffer_queue.pages));

    printk(KERN_INFO "asgn2: Woken up from sleep. I have %d bytes of data", buffer_queue.data_size);

    spin_lock_irqsave(&buffer_queue.lock, flags);

    int page_number = 0;
    list_for_each_entry_safe(node, tmp, &buffer_queue.pages, list) {
        size_t available = node->tail_offset - node->head_offset;
        size_t to_read = min(available, count - bytes_read);
        void *page_addr = page_address(node->page);

        printk(KERN_INFO "Reading node %d, %zu bytes available, reading %zu bytes", page_number, available, to_read);

        // Check for NULL character before reading
        size_t i;
        for (i = 0; i < to_read; i++) {
            char byte = ((char *)page_addr)[node->head_offset + i];
            if (byte == '\0') {
                session_complete = true;  // Mark session as complete
                to_read = i;  // Stop reading before the NULL character
                printk(KERN_INFO "Found null after %zu bytes", i);
                break;
            }
        }
        
        ssize_t bytes_copied = to_read - copy_to_user(buf + bytes_read, page_addr + node->head_offset, to_read);
        bytes_read += bytes_copied;

        if (bytes_copied < to_read) {
            // Partial copy, some bytes could not be copied
            spin_unlock_irqrestore(&buffer_queue.lock, flags);
            printk(KERN_ERR "asgn2: Failed to copy all data to user space, %zu bytes copied\n", bytes_read);
            return bytes_read;  // Return the number of bytes successfully copied
        }

        buffer_queue.data_size -= session_complete ? to_read+1 : to_read;
        node->head_offset += session_complete ? to_read+1 : to_read;

        if (node->head_offset >= node->tail_offset) {
            // We've read all data from this page node
            printk(KERN_INFO "read all data, freeing page");
            list_del(&node->list);
            __free_page(node->page);
            kfree(node);
        }

        if (bytes_read >= count || session_complete) {
            break;
        }
        page_number++;
    }

    spin_unlock_irqrestore(&buffer_queue.lock, flags);

    printk(KERN_INFO "asgn2: Read completed, %zu bytes read\n", bytes_read);
    return bytes_read;
}


/**
 * Open function: Ensure only one reader is allowed
 */
int asgn2_open(struct inode *inode, struct file *filp) {
    if (atomic_inc_return(&nprocs) > 1) {
        atomic_dec(&nprocs);
        printk(KERN_ERR "asgn2: Device already in use by another process\n");
        return -EBUSY;  // Only one reader allowed
    }
    printk(KERN_INFO "asgn2: Device opened by process\n");
    return 0;
}

/**
 * Release function: Decrement the process count
 */
int asgn2_release(struct inode *inode, struct file *filp) {
    atomic_dec(&nprocs);
    session_complete = false;
    printk(KERN_INFO "asgn2: Device released by process\n");
    return 0;
}

static struct file_operations asgn2_fops = {
    .owner = THIS_MODULE,
    .read = asgn2_read,
    .open = asgn2_open,
    .release = asgn2_release,
};

/**
 * Module initialization function
 */
static int __init asgn2_init_module(void) {
    int result;

    // Initialize GPIO
    result = gpio_dummy_init();
    if (result) {
        printk(KERN_ERR "asgn2: GPIO initialization failed\n");
        return result;
    }
    printk(KERN_INFO "asgn2: GPIO initialized successfully\n");

    // Initialize circular buffer and page queue
    init_circular_buffer();
    init_page_queue();
    init_waitqueue_head(&read_queue);

    // Allocate device number
    result = alloc_chrdev_region(&dev_num, 0, 1, MYDEV_NAME);
    if (result < 0) {
        printk(KERN_ERR "asgn2: Failed to allocate device number\n");
        goto fail_chrdev;
    }
    printk(KERN_INFO "asgn2: Device number allocated\n");

    // Initialize cdev
    asgn2_cdev = cdev_alloc();
    cdev_init(asgn2_cdev, &asgn2_fops);
    asgn2_cdev->owner = THIS_MODULE;
    result = cdev_add(asgn2_cdev, dev_num, 1);
    if (result) {
        printk(KERN_ERR "asgn2: Failed to add cdev\n");
        goto fail_cdev;
    }

    // Create device class and device node
    asgn2_class = class_create(MYDEV_NAME);
    if (IS_ERR(asgn2_class)) {
        result = PTR_ERR(asgn2_class);
        printk(KERN_ERR "asgn2: Failed to create device class\n");
        goto fail_class;
    }

    asgn2_device = device_create(asgn2_class, NULL, dev_num, NULL, MYDEV_NAME);
    if (IS_ERR(asgn2_device)) {
        result = PTR_ERR(asgn2_device);
        printk(KERN_ERR "asgn2: Failed to create device node\n");
        goto fail_device;
    }

    // Initialize tasklet
    tasklet_init(&my_tasklet, bottom_half_tasklet_function, 0);
    printk(KERN_INFO "asgn2: Tasklet initialized\n");

    atomic_set(&nprocs, 0);

    printk(KERN_INFO "asgn2: Module loaded\n");
    return 0;

fail_device:
    class_destroy(asgn2_class);
fail_class:
    cdev_del(asgn2_cdev);
fail_cdev:
    unregister_chrdev_region(dev_num, 1);
fail_chrdev:
    gpio_dummy_exit();
    return result;
}

/**
 * Module cleanup function
 */
static void __exit asgn2_exit_module(void) {
    struct page_node *node, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&buffer_queue.lock, flags);

    // Free all pages in page queue
    list_for_each_entry_safe(node, tmp, &buffer_queue.pages, list) {
        list_del(&node->list);
        __free_page(node->page);
        kfree(node);
    }
    spin_unlock_irqrestore(&buffer_queue.lock, flags);

    tasklet_kill(&my_tasklet);
    device_destroy(asgn2_class, dev_num);
    class_destroy(asgn2_class);
    cdev_del(asgn2_cdev);
    unregister_chrdev_region(dev_num, 1);
    gpio_dummy_exit();
    printk(KERN_INFO "asgn2: Module unloaded\n");
}


module_init(asgn2_init_module);
module_exit(asgn2_exit_module);

