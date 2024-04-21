#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/major.h>
#include "flag.h"

static int flag_open(struct inode* node, struct file* fpointer);
static int flag_release(struct inode* node, struct file* fpointer);
loff_t flag_llseek(struct file *, loff_t, int);
static ssize_t flag_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t flag_write(struct file *, const char __user *, size_t, loff_t *);

struct file_operations shiftops = {
    .owner = THIS_MODULE,
    .open = flag_open,
    .release = flag_release,
    .llseek = flag_llseek,
    .read = flag_read,
    .write = flag_write,
};

/* Note: You can modify this structure as needed */
struct flag_device {
    struct cdev cdev;
    char buff[DEFAULT_BUFF_SIZE];
}; 

struct flag_device dev;

/**
 * @brief Start the character device
 * Register the character device (major, minor, and name)
 * Initialize the cdev value inside of the flag_device struct (cdev_init)
 * Add the cdev to the kernel (cdev_add)
 * 
 * @return int
*/
static int __init flag_start(void)
{

fail:
    return 0;
}

/**
 * @brief Cleaning up character device
 * Remove the character device from the kernel
 * Unregister the character device region
 * 
 */
static void __exit flag_stop(void)
{

    return;
}


/**
 * @brief We are going to add the flag in every time we open the device. 
 * 
 * Utilize container_of on the node to get the character device
 * Open /flag utilizing a certain kernel function. Return any errors if there is an issue.
 * Read the flag into the device's buffer.
 * Close the flag file. This will be the only time we read from /flag
 * Save the character device for later use inside of fpointer->private_data
 * 
 * @param node 
 * @param fpointer 
 * @return int 
 */
static int flag_open(struct inode *node, struct file *fpointer)
{

    
    return 0;   
}

/**
 * @brief We are going to wipe the buffer every time we release. 
 * (Hint: memset has a definition in the kernel)
 * 
 * @param node 
 * @param fpointer 
 * @return int 
 */
static int flag_release (struct inode *node, struct file *fpointer)
{

    return 0;
}

/**
 * @brief For this we are going to seek to proper offset in the device's buffer. 
 * We need to set the following
 * SEEK_SET - This is the beginning of the file
 * SEEK_CUR - This is the current position of the file
 * SEEK_END - This is the end of the file
 * 
 * Once we set the new offset, we need to update it in fpointer. 
 * 
 * @param fpointer 
 * @param offset 
 * @param whence 
 * @return loff_t 
 */
loff_t flag_llseek(struct file *fpointer, loff_t offset, int whence)
{
    loff_t newoff = 0;

    return newoff;
}

/**
 * @brief Send the contents of the device's buffer back to the user. 
 * This is going to be whatever is in dev->buff at the time and sending it back to the user. The user will trigger this in userspace by making a read system call on the character device.  
 * Ensure that we are reading the minimum of the size we pass in or the number of bytes before the end of the buffer. 
 * 
 * This is when the user invokes the read system call on the character device.  
 * 
 * @param fpointer 
 * @param buf 
 * @param size 
 * @param offset 
 * @return ssize_t 
 */
static ssize_t flag_read(struct file *fpointer, char __user *buf, size_t size , loff_t *offset)
{
    ssize_t result = 0;

    return result; 
}

/**
 * @brief Write to the kernel buffer (dev->buff). This has the potential of overwriting the flag we just wrote depending on the offset we are writing to. This is set via the flag_llseek (lseek system call) 
 * Similar constraints as flag_read. 
 * 
 * This is when the user invokes the write systme call onto the character device. 
 * 
 * @param fpointer 
 * @param buf 
 * @param size 
 * @param offset 
 * @return ssize_t 
 */
static ssize_t flag_write(struct file *fpointer, const char __user *buf, size_t size, loff_t *offset)
{
    ssize_t result = 0; 

    return result; 
    
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michael Wittner");
MODULE_DESCRIPTION("Shift Character Device");
module_init(flag_start);
module_exit(flag_stop);
