
/**
 * File: asgn1.c
 * Date: 13/03/2011
 * Author: Your Name 
 * Version: 0.1
 *
 * This is a module which serves as a virtual ramdisk which disk size is
 * limited by the amount of memory available and serves as the requirement for
 * COSC440 assignment 1. This template is provided to students for their 
 * convenience and served as hints/tips, but not necessarily as a standard
 * answer for the assignment. So students are free to change any part of
 * the template to fit their design, not the other way around. 
 *
 * Note: multiple devices and concurrent modules are not supported in this
 *       version. The template is 
 */
 
/* This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/device.h>
#include <linux/sched.h>

#define MYDEV_NAME "asgn1"
#define MYIOC_TYPE 'k'

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jet Hughes");
MODULE_DESCRIPTION("COSC440 asgn1");


/**
 * The node structure for the memory page linked list.
 */ 
typedef struct page_node_rec {
  struct list_head list;
  struct page *page;
} page_node;

/*
 * Main device structure.
 */
typedef struct asgn1_dev_t {
    dev_t dev;               /* Device number */
    struct cdev *cdev;       /* Character device structure */
    struct list_head mem_list; /* List of memory pages */
    int num_pages;           /* Number of memory pages held by the module */
    size_t data_size;        /* Total data size in the module */
    atomic_t nprocs;         /* Number of processes accessing this device */
    atomic_t max_nprocs;     /* Max number of processes allowed to access this device */
    struct kmem_cache *cache; /* Cache memory */
    struct class *class;     /* Udev class */
    struct device *device;   /* Udev device node */
} asgn1_dev;

asgn1_dev asgn1_device;


int asgn1_major = 0;         /* Major number of the module */
int asgn1_minor = 0;         /* Minor number of the module */
int asgn1_dev_count = 1;     /* Number of devices */


/**
 * This function frees all memory pages held by the module.
 */
void free_memory_pages(void) {
    page_node *curr, *tmp;

    /* Traverse the memory list and free each page */
    list_for_each_entry_safe(curr, tmp, &asgn1_device.mem_list, list) {
        if (curr->page) {
            __free_page(curr->page);
        }
        list_del(&curr->list);
        printk(KERN_INFO "Removed page\n");
        kfree(curr);
    }

    /* Reset device data */
    asgn1_device.data_size = 0;
    asgn1_device.num_pages = 0;
    INIT_LIST_HEAD(&asgn1_device.mem_list);

    printk(KERN_INFO "Removed all pages in %s\n", MYDEV_NAME);
}

/**
 * This function opens the virtual disk, if it is opened in the write-only
 * mode, all memory pages will be freed.
 */
int asgn1_open(struct inode *inode, struct file *filp) {
  /* Increment the process counter and check against the maximum allowed */
  if(atomic_inc_return(&asgn1_device.nprocs) > atomic_read(&asgn1_device.max_nprocs)){
    atomic_dec(&asgn1_device.nprocs);
    printk(KERN_INFO "Failed to open %s. Too many processes have this device open already\n", MYDEV_NAME);
    return -EBUSY;
  }

  /* If opened in write-only mode, free all memory pages */
  if ((filp->f_flags & O_ACCMODE) == O_WRONLY){
    printk(KERN_INFO "Opening %s device in write only mode\n", MYDEV_NAME);
    free_memory_pages();
  }

  printk(KERN_INFO "Opened %s device\n", MYDEV_NAME);
  return 0; /* success */
}


/**
 * This function releases the virtual disk, but nothing needs to be done
 * in this case. 
 */
int asgn1_release (struct inode *inode, struct file *filp) {
  atomic_dec(&asgn1_device.nprocs);
  return 0;
}

/**
 * This function reads contents of the virtual disk and writes to the user 
 */
ssize_t asgn1_read(struct file *filp, char __user *buf, size_t count,
  loff_t *f_pos) {

  printk(KERN_INFO "Start read %d bytes\n", count);

  size_t size_read = 0;     /* Size read from virtual disk in this function */
  size_t begin_offset = *f_pos % PAGE_SIZE;;      /* Offset from the beginning of a page to start reading */
  int begin_page_no = *f_pos / PAGE_SIZE; /* The first page containing the requested data */
  int curr_page_no = 0;     /* Current page number */
  size_t size_to_be_read;   /* Size to be read in the current round in the loop */
  page_node *curr;

  /* Check if the read position is beyond the data size */
  if (*f_pos >= asgn1_device.data_size){
    printk(KERN_INFO "End of data area reached\n");
    return 0;
  }

  list_for_each_entry(curr, &asgn1_device.mem_list, list){
    if (curr_page_no < begin_page_no){
      curr_page_no++;
      continue;
    }

    size_to_be_read = min(count - size_read, PAGE_SIZE - begin_offset);
    void *page_addr = page_address(curr->page);

    if (*f_pos + size_to_be_read > asgn1_device.data_size){
      size_to_be_read = asgn1_device.data_size - *f_pos;
    }

    /* Copy data to user space */
    printk(KERN_INFO "Attempting to read %d bytes from page %d at location %p with offset %d\n", 
      size_to_be_read, curr_page_no, page_addr, begin_offset);
    if (copy_to_user(buf + size_read, page_addr + begin_offset, size_to_be_read)){
      printk(KERN_INFO "Failed to read bytes\n");
      return -EFAULT;
    }
    
    size_read += size_to_be_read;
    *f_pos += size_to_be_read;
    begin_offset = 0; /* Only offset the first page */
    curr_page_no++;

    if (size_read >= count){
      printk(KERN_INFO "Read all bytes\n");
      break;
    }

    if (*f_pos >= asgn1_device.data_size){
      printk(KERN_INFO "End of data area reached\n");
      break;
    }
  }

  printk(KERN_INFO "Finish read. Read %d bytes\n", size_read);

  return size_read;
}

static loff_t asgn1_lseek (struct file *file, loff_t offset, int cmd)
{
    loff_t testpos;
    size_t buffer_size = asgn1_device.num_pages * PAGE_SIZE;

    switch (cmd) {
      case SEEK_SET:
        testpos = offset;
        break;
      case SEEK_CUR:
        testpos = file->f_pos + offset;
        break;
      case SEEK_END:
        testpos = buffer_size + offset;
        break;
    
      default:
        return -EINVAL;
    }

    printk (KERN_INFO "Attempting seek to pos=%lld. Buffer size is %zu\n", offset, buffer_size);

    /* Ensure the seek position is within bounds */
    if (testpos < 0){
      printk (KERN_INFO "Attempted seek to negative position %lld, seeking to 0\n", testpos);
      testpos = 0;
    }

    if (testpos > buffer_size) {
      printk (KERN_INFO "Attempted seek past end of device (%lld), seeking to end of device (%zu)\n", testpos, buffer_size);
      testpos = buffer_size;    
    }
      
    file->f_pos = testpos;
    printk (KERN_INFO "Seeked to pos=%lld\n", file->f_pos);
    return testpos;
}


/**
 * This function writes from the user buffer to the virtual disk of this
 * module
 */
ssize_t asgn1_write(struct file *filp, const char __user *buf, size_t count,
		  loff_t *f_pos) {
  
  printk(KERN_INFO "Start write %zu bytes\n", count);

  size_t orig_f_pos = *f_pos; /* Original file position */
  size_t size_written = 0;    /* Size written to virtual disk in this function */
  size_t begin_offset;        /* Offset from the beginning of a page to start writing */
  int begin_page_no = *f_pos / PAGE_SIZE; /* First page to start writing to */
  int curr_page_no = 0;       /* Current page number */
  size_t size_to_be_written;  /* Size to be written in the current round in the loop */
  page_node *curr;
  int num_created_pages = 0;
  int num_pages_used = 0;

  begin_offset = *f_pos % PAGE_SIZE;
  list_for_each_entry(curr, &asgn1_device.mem_list, list){
    if (curr_page_no < begin_page_no) {
      curr_page_no++;
      continue;
    }
    
    /* Calculate the size to write for the current page */
    size_to_be_written = min(count - size_written, PAGE_SIZE - begin_offset);
    void* page_addr = page_address(curr->page);

    /* Copy data from user space */
    if (copy_from_user(page_addr + begin_offset, buf + size_written, size_to_be_written)) {
      printk(KERN_INFO "Failed to write to page %d\n", curr_page_no);
      return -EINVAL;
    } 
    
    printk(KERN_INFO "Wrote %d bytes to existing page %d at location %p with offset %d\n", size_to_be_written, curr_page_no, page_addr, begin_offset);
    
    size_written += size_to_be_written;
    *f_pos += size_to_be_written;
    begin_offset = 0; /* Only offset the first page */
    curr_page_no ++;
    num_pages_used ++;

    if (size_written >= count)
    {
      goto finish_write;
    }
  }

  // Add new pages if necessary
  printk(KERN_INFO "Need to add more pages\n");
  while (size_written < count) {
    /* Alooc spage for new page node*/
    curr = kmalloc(sizeof(page_node), GFP_KERNEL);
    if (!curr) {
      printk(KERN_INFO "Failed to allocate mamory for new page node\n");
      return size_written;
    }
    memset(curr, 0, sizeof(page_node));

    /* Alloc space for page in new page node*/
    curr->page = alloc_page(GFP_KERNEL);
    if (!curr->page){
	    printk(KERN_INFO "Not enough memory left\n");
      kfree(curr);
	    return size_written;
    }

    list_add_tail(&(curr->list), &asgn1_device.mem_list);
    asgn1_device.num_pages ++;
    num_created_pages ++;   

    size_to_be_written = min(count - size_written, PAGE_SIZE - begin_offset);
    void* page_addr = page_address(curr->page);

    /* Copy data from user space */
    if (copy_from_user(page_addr + begin_offset, buf + size_written, size_to_be_written))
    {
      printk(KERN_INFO "Failed to copy data from user space\n");
      __free_page(curr->page);
      list_del(&curr->list);
      kfree(curr);
      return -EINVAL;
    }
    
    size_written += size_to_be_written;
    *f_pos += size_to_be_written;
    begin_offset = 0; // only offset first page
    curr_page_no ++;
    num_pages_used ++;
    
    printk(KERN_INFO "Wrote %d bytes to new page %d at location %p with offset %d\n", size_to_be_written, curr_page_no, page_addr, begin_offset);
  }

finish_write:
  /* Update data size*/
  asgn1_device.data_size = max(asgn1_device.data_size, orig_f_pos + size_written);
  printk(KERN_INFO "Finish write. Wrote %d bytes. Created %d pages. Used %d pages in total", size_written, num_created_pages, num_pages_used);

  return size_written;
}

#define SET_NPROC_OP 1
#define TEM_SET_NPROC _IOW(MYIOC_TYPE, SET_NPROC_OP, int) 

/**
 * IOCTL operations.
 */
long asgn1_ioctl (struct file *filp, unsigned cmd, unsigned long arg) {
  int nr;
  int new_nprocs;

  /* Check that the IOCTL command type matches */
  if (_IOC_TYPE(cmd) != MYIOC_TYPE) {
    return -EINVAL;
  }

  nr = _IOC_NR(cmd);

  /* Handle the specific IOCTL operation */
  if (nr == SET_NPROC_OP) {
    /* Copy the number of processes from user space */
    if (copy_from_user(&new_nprocs, (int *)arg, sizeof(int))) {
      return -EFAULT;
    }

    /* Validate the new number of processes */
    if (new_nprocs < 1) {
      return -EINVAL;
    }

    /* Set the maximum number of processes */
    atomic_set(&asgn1_device.max_nprocs, new_nprocs);
    printk(KERN_INFO "Set max_nprocs to %d\n", new_nprocs);
    return 0;
  }

   return -ENOTTY;
}

/**
 * Memory mapping operation.
 */
static int asgn1_mmap (struct file *filp, struct vm_area_struct *vma)
{
  unsigned long pfn;
  unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
  unsigned long len = vma->vm_end - vma->vm_start;
  unsigned long ramdisk_size = asgn1_device.num_pages * PAGE_SIZE;
  page_node *curr;
  unsigned long index = 0;

  /* Ensure the requested mapping does not exceed the device size */
  if (offset + len > ramdisk_size) {
    printk(KERN_INFO "Attempted to mmap beyond the end of the device\n");
    return -EINVAL;
  }

  /* Iterate through the list of pages to map */
  list_for_each_entry(curr, &asgn1_device.mem_list, list){
    /* Skip pages until the desired offset is reached */
    if (index * PAGE_SIZE < offset)
    {
      index ++;
      continue;
    }

    /* Get the page frame number and map it to the user space */
    pfn = page_to_pfn(curr->page);
    if (remap_pfn_range(vma, vma->vm_start + index * PAGE_SIZE, pfn, PAGE_SIZE, vma->vm_page_prot)) {
      printk(KERN_INFO "Failed to remap page %ld\n", index);
      return -EAGAIN;
    }
    index ++;

    printk(KERN_INFO "Remapped page %ld\n", index);

    /* Stop mapping once the requested length is covered */
    if (index * PAGE_SIZE >= offset + len)
    {
      break;
    }
  }

  return 0;
}

/**
 * File operations structure.
 */
struct file_operations asgn1_fops = {
  .owner = THIS_MODULE,
  .read = asgn1_read,
  .write = asgn1_write,
  .unlocked_ioctl = asgn1_ioctl,
  .open = asgn1_open,
  .mmap = asgn1_mmap,
  .release = asgn1_release,
  .llseek = asgn1_lseek
};


static void *my_seq_start(struct seq_file *s, loff_t *pos)
{
  if(*pos >= 1) return NULL;
  else return &asgn1_dev_count + *pos;
}
static void *my_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
  (*pos)++;
  if(*pos >= 1) return NULL;
  else return &asgn1_dev_count + *pos;
}
static void my_seq_stop(struct seq_file *s, void *v)
{
  /* There's nothing to do here! */
}

int my_seq_show(struct seq_file *s, void *v) {
  seq_printf(s, "Number of pages: %d\n", asgn1_device.num_pages);
  seq_printf(s, "Data size: %zu bytes\n", asgn1_device.data_size);
  seq_printf(s, "Max processes: %d\n", atomic_read(&asgn1_device.max_nprocs));
  seq_printf(s, "Current processes: %d\n", atomic_read(&asgn1_device.nprocs));
  return 0;
}

static struct seq_operations my_seq_ops = {
  .start = my_seq_start,
  .next = my_seq_next,
  .stop = my_seq_stop,
  .show = my_seq_show
};

static int my_proc_open(struct inode *inode, struct file *filp)
{
  return seq_open(filp, &my_seq_ops);
}

static struct proc_ops asgn1_proc_ops = {
  .proc_open = my_proc_open,
  .proc_lseek = seq_lseek,
  .proc_read = seq_read,
  .proc_release = seq_release,
};



/**
 * Initialise the module and create the master device
 */
int __init asgn1_init_module(void){
  int result; 

  // n and max nprocs
  atomic_set(&asgn1_device.nprocs, 0);
  atomic_set(&asgn1_device.max_nprocs, 1);
	
  /* Allocate a major number dynamically */
  result = alloc_chrdev_region(&asgn1_device.dev, asgn1_minor, asgn1_dev_count, MYDEV_NAME);
  if (result < 0) {
	  printk(KERN_INFO "Can't allocate major number \n");
	  return result;
  }
  asgn1_major = MAJOR(asgn1_device.dev);

  /* Allocate and initialize cdev structure */
  asgn1_device.cdev = cdev_alloc();
  if(!asgn1_device.dev) {
	  printk(KERN_INFO "Can't allocate cdev\n");
	  result = -ENOMEM;
	  goto fail_cdev;
  } 

  cdev_init(asgn1_device.cdev, &asgn1_fops);
  asgn1_device.cdev->owner = THIS_MODULE;

  /* Add the cdev structure to the system */
  result = cdev_add(asgn1_device.cdev, asgn1_device.dev, asgn1_dev_count);
  if (result){
	  printk(KERN_INFO "Error %d adding cdev\n", result);
	  goto fail_cdev;
  }

  /* Initialize the list head */
  INIT_LIST_HEAD(&asgn1_device.mem_list);

  /* Create proc entry */
  proc_create(MYDEV_NAME, 0, NULL, &asgn1_proc_ops);

  /* Create device class */
  asgn1_device.class = class_create(MYDEV_NAME);
  if (IS_ERR(asgn1_device.class)) {
    result = PTR_ERR(asgn1_device.class);
    goto fail_class;
  }

  /* Create the device node in /dev */
  asgn1_device.device = device_create(asgn1_device.class, NULL, 
                                      asgn1_device.dev, "%s", MYDEV_NAME);
  if (IS_ERR(asgn1_device.device)) {
    printk(KERN_INFO "%s: can't create udev device\n", MYDEV_NAME);
    result = -ENOMEM;
    goto fail_device;
  }
  
  printk(KERN_INFO "set up udev entry\n");
  printk(KERN_INFO "Hello world from %s\n", MYDEV_NAME);
  return 0;

  /* Cleanup code in case of failure */
fail_device:
   class_destroy(asgn1_device.class);
fail_class:
  cdev_del(asgn1_device.cdev);
fail_cdev:
  unregister_chrdev_region(asgn1_device.dev, asgn1_dev_count);

  return result;
}


/**
 * Finalise the module
 */
void __exit asgn1_exit_module(void){
  device_destroy(asgn1_device.class, asgn1_device.dev);
  class_destroy(asgn1_device.class);
  printk(KERN_INFO "cleaned up udev entry\n");

  remove_proc_entry(MYDEV_NAME, NULL);
  free_memory_pages();
  cdev_del(asgn1_device.cdev);
  unregister_chrdev_region(asgn1_device.dev, asgn1_dev_count);
  printk(KERN_INFO "Good bye from %s\n", MYDEV_NAME);
}


module_init(asgn1_init_module);
module_exit(asgn1_exit_module);


