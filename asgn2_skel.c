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
#include "gpio.c"  // Include your GPIO-related code

#define MYDEV_NAME "asgn2"
#define PAGE_QUEUE_SIZE 16
#define CIRCULAR_BUFFER_SIZE 1024  // Size of the circular buffer

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
    spinlock_t lock;  // Spinlock to protect the circular buffer
};

struct circ_buffer circ_buf;

/**
 * Page queue structure (for multiple-page buffering)
 */
typedef struct page_queue_t {
    struct page *pages[PAGE_QUEUE_SIZE];  // Array of pages
    int head;   // Index to the next page to be read
    int tail;   // Index to the next page to be written
    int head_offset;
    int tail_offset;
} page_queue;

page_queue buffer_queue;  // Declare the buffer queue globally
struct tasklet_struct my_tasklet;  // Tasklet declaration

dev_t dev_num;  // Device number
struct cdev *asgn2_cdev;
struct class *asgn2_class;
struct device *asgn2_device;
spinlock_t queue_lock;  // Spinlock for page queue synchronization

wait_queue_head_t read_queue;  // Wait queue for blocking readers
static bool session_complete = false;   // Bool to ensure device is closed after each session is fully read
atomic_t nprocs;  // Number of processes currently accessing the device

/**
 * Initialize the circular buffer
 */
int init_circular_buffer(void) {
    circ_buf.head = 0;
    circ_buf.tail = 0;
    spin_lock_init(&circ_buf.lock);  // Initialize the spinlock
    printk(KERN_INFO "asgn2: Circular buffer initialized\n");
    return 0;
}

/**
 * Write a byte to the circular buffer
 */
int circ_buf_write(char data) {
    unsigned long flags;
    spin_lock_irqsave(&circ_buf.lock, flags);
    
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
 * Initialize the page queue
 */
void init_page_queue(void) {
    buffer_queue.head = 0;
    buffer_queue.tail = 0;
    buffer_queue.head_offset = 0;
    buffer_queue.tail_offset = 0;
    printk(KERN_INFO "asgn2: Page queue initialized\n");
}

/**
 * Add a byte to the page queue (used by the tasklet)
 */
void add_to_page_queue(char byte) {
    unsigned long flags;
    struct page *page;

    spin_lock_irqsave(&queue_lock, flags);

    // Check if the current page is full or if it's the first write
    if (!buffer_queue.pages[buffer_queue.tail] || buffer_queue.tail_offset >= PAGE_SIZE) {
        page = alloc_page(GFP_KERNEL);
        if (!page) {
            printk(KERN_ERR "Failed to allocate new page\n");
            spin_unlock_irqrestore(&queue_lock, flags);
            return;
        }

        buffer_queue.pages[buffer_queue.tail] = page;
        buffer_queue.tail_offset = 0;
        printk(KERN_INFO "asgn2: Allocated new page at tail %d\n", buffer_queue.tail);
    } else {
        page = buffer_queue.pages[buffer_queue.tail];
    }

    // Add byte to the page at the current offset
    void *page_addr = page_address(page);
    ((char *)page_addr)[buffer_queue.tail_offset] = byte;
    printk(KERN_INFO "asgn2: Byte 0x%x added at page offset %d\n", byte, buffer_queue.tail_offset);

    buffer_queue.tail_offset++;

    // Move to the next page slot if full
    if (buffer_queue.tail_offset >= PAGE_SIZE) {
        buffer_queue.tail = (buffer_queue.tail + 1) % PAGE_QUEUE_SIZE;
        buffer_queue.tail_offset = 0;  // Reset offset for the new page
        printk(KERN_INFO "asgn2: Page full, moving to next page tail %d\n", buffer_queue.tail);
    }

    spin_unlock_irqrestore(&queue_lock, flags);
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

bool page_queue_is_empty(void){
    return (buffer_queue.head == buffer_queue.tail && buffer_queue.head_offset == buffer_queue.tail_offset);
}

/**
 * Read function: Consume data from the page queue
 */
ssize_t asgn2_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos) {
    unsigned long flags;
    size_t bytes_read = 0;
    struct page *page;

    if (session_complete) {
        printk(KERN_INFO "asgn2: Session already completed, blocking further reads\n");
        return 0;  // Block further reads until the device is closed
    }

    printk(KERN_INFO "asgn2: Read request for %zu bytes\n", count);

    // Wait if no data is available
    if (page_queue_is_empty()) {
        printk(KERN_INFO "asgn2: No data in page queue, waiting for data\n");
    }
    wait_event_interruptible(read_queue, !page_queue_is_empty());

    printk(KERN_INFO "asgn2: Woken up from sleep, head = %d + %d, tail = %d + %d\n", buffer_queue.head, buffer_queue.head_offset, buffer_queue.tail, buffer_queue.tail_offset);

    spin_lock_irqsave(&queue_lock, flags);

    while (bytes_read < count && !page_queue_is_empty()) {
        page = buffer_queue.pages[buffer_queue.head];
        
        size_t available_in_page;

        if (buffer_queue.head == buffer_queue.tail) {
            // If head equals tail, we can only read up to tail_offset
            available_in_page = buffer_queue.tail_offset - buffer_queue.head_offset;
        } else {
            // Otherwise, we can read the remainder of the page
            available_in_page = PAGE_SIZE - buffer_queue.head_offset;
        }

        printk(KERN_INFO "%zu bytes available", available_in_page);

        size_t to_read = min(available_in_page, count - bytes_read);
        void *page_addr = page_address(page);

        // Check for NULL character before reading
        for (size_t i = 0; i < to_read; i++) {
            char byte = ((char *)page_addr)[buffer_queue.head_offset + i];
            if (byte == '\0') {
                session_complete = true;  // Mark session as complete
                printk(KERN_INFO "asgn2: NULL character encountered, session complete\n");
                to_read = i;  // Stop reading before the NULL character
                break;
            }
        }

        printk(KERN_INFO "asgn2: Reading from page %d, offset %d, reading %zu bytes\n",
               buffer_queue.head, buffer_queue.head_offset, to_read);

        if (copy_to_user(buf + bytes_read, page_addr + buffer_queue.head_offset, to_read)) {
            spin_unlock_irqrestore(&queue_lock, flags);
            printk(KERN_ERR "asgn2: Failed to copy data to user space\n");
            return -EFAULT;
        }

        buffer_queue.head_offset += to_read;
        bytes_read += to_read;

        if (buffer_queue.head_offset >= PAGE_SIZE) {
            printk(KERN_INFO "asgn2: Page %d fully read, freeing page\n", buffer_queue.head);
            __free_page(buffer_queue.pages[buffer_queue.head]);
            buffer_queue.pages[buffer_queue.head] = NULL;
            buffer_queue.head = (buffer_queue.head + 1) % PAGE_QUEUE_SIZE;
            buffer_queue.head_offset = 0;
            printk(KERN_INFO "asgn2: Moved to next page, head = %d, head_offset reset to 0\n", buffer_queue.head);
        }

        if (session_complete) {
            break;
        }

        printk(KERN_INFO "asgn2: %zu bytes read so far\n", bytes_read);
    }

    spin_unlock_irqrestore(&queue_lock, flags);

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
        return result;
    }
    printk(KERN_INFO "asgn2: Device number allocated\n");

    // Initialize cdev
    asgn2_cdev = cdev_alloc();
    cdev_init(asgn2_cdev, &asgn2_fops);
    asgn2_cdev->owner = THIS_MODULE;
    result = cdev_add(asgn2_cdev, dev_num, 1);
    if (result) {
        printk(KERN_ERR "asgn2: Failed to add cdev\n");
        goto fail_chrdev;
    }

    // Create device class and device node
    asgn2_class = class_create(MYDEV_NAME);
    if (IS_ERR(asgn2_class)) {
        result = PTR_ERR(asgn2_class);
        printk(KERN_ERR "asgn2: Failed to create device class\n");
        goto fail_cdev;
    }

    asgn2_device = device_create(asgn2_class, NULL, dev_num, NULL, MYDEV_NAME);
    if (IS_ERR(asgn2_device)) {
        result = PTR_ERR(asgn2_device);
        printk(KERN_ERR "asgn2: Failed to create device node\n");
        goto fail_class;
    }

    // Initialize tasklet
    tasklet_init(&my_tasklet, bottom_half_tasklet_function, 0);
    printk(KERN_INFO "asgn2: Tasklet initialized\n");

    // // Request IRQ for GPIO
    // result = request_irq(dummy_irq, dummyport_interrupt, IRQF_TRIGGER_RISING | IRQF_ONESHOT, "gpio27", NULL);
    // if (result) {
    //     printk(KERN_ERR "asgn2: Failed to request IRQ\n");
    //     goto fail_device;
    // }
    // printk(KERN_INFO "asgn2: IRQ requested successfully\n");

    atomic_set(&nprocs, 0);  // Initialize process count

    printk(KERN_INFO "asgn2: Module loaded\n");
    return 0;

// fail_device:
//     device_destroy(asgn2_class, dev_num);
fail_class:
    class_destroy(asgn2_class);
fail_cdev:
    cdev_del(asgn2_cdev);
fail_chrdev:
    unregister_chrdev_region(dev_num, 1);
    return result;
}

/**
 * Module cleanup function
 */
static void __exit asgn2_exit_module(void) {
    free_irq(dummy_irq, NULL);
    tasklet_kill(&my_tasklet);
    device_destroy(asgn2_class, dev_num);
    class_destroy(asgn2_class);
    cdev_del(asgn2_cdev);
    unregister_chrdev_region(dev_num, 1);
    gpio_dummy_exit();
}

module_init(asgn2_init_module);
module_exit(asgn2_exit_module);

