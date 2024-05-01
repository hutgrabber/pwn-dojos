/* -------------------------------------------------------------------------
 * Character Devices - ENPM809V - UID 119362914 - Sparsh Mehta / hutgrabber
 * -------------------------------------------------------------------------
 * For thius homework we are supposed to create a character device that calls
 * a few functions which will essentially handle the flag in memory & then print
 * it out in the kernel logs. In order to make this work, we will first define
 * the functions flag_start(), flag_stop(), flag_open(), flag_release(),
 * flag_llseek(), flag_read(), flag_write().
 *
 * # flag_start():
 * * First we need to register a region using the register_chrdev_region
 * function which takes in the parameters -- device number, 1, and some string.
 * * Next we need to initialize the cdev device using the cdev_init() function
 *    which is called on the dev.cdev and &shiftops address.
 * * Finally we use the cdev_add() function on dev.cdev, dev_number and 1
 *    and we make sure that we handle all the erros.
 *
 * # flag_stop():
 * * We start by using the cdev_del which takes in similar params to
 * flag_start().
 * * Next we unregister the region in memory so that we can free it.
 *
 * # flag_open():
 * * Here we start by using the container_of() function on the dev (flag device)
 *    and we can then call the pointer to this flag device - flagdev.
 * * Next we can create a struct file pointer and use it to open a file (/flag)
 *    using the filp_open function. We can also use something else instead of
 *    filp_open. After this we make sure that the errors are handled well.
 * * Finally, we read the flag device into a buffer using the filepointer we
 * created earlier. We also need to error handle this part in case we do not
 * find the flag. Also we need to close the file pointer to prevent it from
 * being re-used.
 *
 * # flag_release():
 * * We repeat the steps from flag_open() to create a flag device.
 * * Finally we need to create a pointer to flag_dev fpointer->private_data.
 *
 * # flag_llseek():
 * * I used to perform some cleanup after performing all the operations. We need
 * to remember to use the fpointer->f_pos pointer update the poisition of the
 * pointer.
 *
 * # flag_read():
 * * We need to define the flag_dev as fpointer->private_data just like we did
 *    we used the flag device structure before.
 * * We also need to use the copy_to_user from buf to flagdev->buff + pointer to
 * offset Once we finish, we also need to handle the errors.
 *
 * # flag_write():
 * * First we begin by defining the flag_device as fpointer->private_data just
 * like we did with the flag_device structure before.
 * * We also have to define an offset pointer using the argument from the
 * function and match all the data types as needed as shown in the flag_write()
 * function below.
 * * Finally, we can copy_to_user from buf to flagdev->buff + ptr to offset and
 * then handle all the erors as shown.
 */

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/module.h>
#include <linux/uaccess.h>
// #include <sys/types.h>

#ifndef __FLAG_H
#define __FLAG_H

#define DEFAULT_BUFF_SIZE 256
#define DEFAULT_XOR_ENCRYPTION 0x41
#define DEFAULT_SHIFT_ENCRYPTION 3

#define MAJOR 256
#define MINOR 135

#define XOR_KEY_CMD 0x1
#define SHIFT_KEY_CMD 0x2

#ifdef __KERNEL__
#define print(fmt, args...) printk(KERN_ALERT fmt, ##args)
#else
#define print(fmt, args...) printf(fmt, ##args)
#endif

#define GOTO_FAIL_IF(v)                                                        \
  if (v)                                                                       \
  goto fail

#define GOTO_FAIL_WITH_RESULT_IF(v, rv)                                        \
  ({                                                                           \
    if (v) {                                                                   \
      result = rv;                                                             \
      goto fail;                                                               \
    }                                                                          \
  })

#define LOG_GOTO_FAIL_IF(v, log, ...)                                          \
  ({                                                                           \
    if (v) {                                                                   \
      print(log, ##__VA_ARGS__);                                               \
      goto fail;                                                               \
    }                                                                          \
  })

#define LOG_GOTO_FAIL_WITH_RESULT_IF(v, rv, log, ...)                          \
  ({                                                                           \
    if (v) {                                                                   \
      result = rv;                                                             \
      print(log, ##__VA_ARGS__);                                               \
      goto fail;                                                               \
    }                                                                          \
  })

#endif

static int flag_open(struct inode *node, struct file *fpointer);
static int flag_release(struct inode *node, struct file *fpointer);
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
static int __init flag_start(void) {
  dev_t dev_number = MKDEV(MAJOR, MINOR);
  if (register_chrdev_region(dev_number, 1, "flag_device") < 0) {
    printk(KERN_ALERT "Cannot register device\n");
    goto fail;
  }
  printk(KERN_INFO "Registered device\n");

  cdev_init(&dev.cdev, &shiftops);

  if (cdev_add(&dev.cdev, dev_number, 1) < 0) {
    printk(KERN_ALERT "cannot add the device to the system\n");
    goto fail;
  }
  printk(KERN_INFO "Added device\n");
fail:
  return 0;
}

/**
 * @brief Cleaning up character device
 * Remove the character device from the kernel
 * Unregister the character device region
 *
 */
static void __exit flag_stop(void) {
  dev_t dev_number = MKDEV(MAJOR, MINOR);
  cdev_del(&dev.cdev);
  unregister_chrdev_region(dev_number, 1);
  printk(KERN_INFO "Module ended\n");
  return;
}

/**
 * @brief We are going to add the flag in every time we open the device.
 *
 * Utilize container_of on the node to get the character device
 * Open /flag utilizing a certain kernel function. Return any errors if there is
 * an issue. Read the flag into the device's buffer. Close the flag file. This
 * will be the only time we read from /flag Save the character device for later
 * use inside of fpointer->private_data
 *
 * @param node
 * @param fpointer
 * @return int
 */
static int flag_open(struct inode *node, struct file *fpointer) {
  struct flag_device *flagdev =
      container_of(node->i_cdev, struct flag_device, cdev);
  struct file *flag = filp_open("/flag", O_RDONLY, 0);
  if (IS_ERR(flag)) {
    printk(KERN_ALERT "Could not open /flag\n");
    return -ENOENT;
  }

  ssize_t bytes_from_flag =
      kernel_read(flag, flagdev->buff, DEFAULT_BUFF_SIZE, &flag->f_pos);
  if (bytes_from_flag < 0) {
    printk(KERN_ALERT "Could not read /flag\n");
    filp_close(flag, NULL);
    return -EIO;
  }

  filp_close(flag, NULL);
  fpointer->private_data = flagdev;
  printk(KERN_INFO "flag_open finished successfully\n");

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
static int flag_release(struct inode *node, struct file *fpointer) {
  struct flag_device *flagdev = fpointer->private_data;
  memset(flagdev->buff, 0, DEFAULT_BUFF_SIZE);
  printk(KERN_INFO "flag_release finished successfully\n");
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
loff_t flag_llseek(struct file *fpointer, loff_t offset, int whence) {
  loff_t newoff = 0;
  switch (whence) {
  case 0:
    newoff = offset;
    break;
  case 1:
    newoff = fpointer->f_pos + offset;
    break;
  case 2:
    newoff = DEFAULT_BUFF_SIZE + offset;
    break;
  default:
    return -EINVAL;
  }

  if (newoff < 0 || newoff > DEFAULT_BUFF_SIZE)
    return -EINVAL;
  fpointer->f_pos = newoff;
  return newoff;
}

/**
 * @brief Send the contents of the device's buffer back to the user.
 * This is going to be whatever is in dev->buff at the time and sending it back
 * to the user. The user will trigger this in userspace by making a read system
 * call on the character device. Ensure that we are reading the minimum of the
 * size we pass in or the number of bytes before the end of the buffer.
 *
 * This is when the user invokes the read system call on the character device.
 *
 * @param fpointer
 * @param buf
 * @param size
 * @param offset
 * @return ssize_t
 */
static ssize_t flag_read(struct file *fpointer, char __user *buf, size_t size,
                         loff_t *offset) {
  ssize_t result = 0;
  struct flag_device *flagdev = fpointer->private_data;
  unsigned long size_n = min(size, sizeof(flagdev->buff));
  if (copy_to_user(buf, flagdev->buff, size_n)) {
    printk(KERN_ALERT "Could not copy to userspace\n");
    return -1;
  }
  printk(KERN_INFO "flag_read successfull\n");
  return result;
}

/**
 * @brief Write to the kernel buffer (dev->buff). This has the potential of
 * overwriting the flag we just wrote depending on the offset we are writing to.
 * This is set via the flag_llseek (lseek system call) Similar constraints as
 * flag_read.
 *
 * This is when the user invokes the write systme call onto the character
 * device.
 *
 * @param fpointer
 * @param buf
 * @param size
 * @param offset
 * @return ssize_t
 */
static ssize_t flag_write(struct file *fpointer, const char __user *buf,
                          size_t size, loff_t *offset) {
  ssize_t result = 0;
  struct flag_device *flagdev = fpointer->private_data;
  loff_t offset_n = *offset;
  if (copy_from_user(flagdev->buff + offset_n, buf, size)) {
    printk(KERN_ALERT "Could not copy from userspace\n");
    return -1;
  }
  printk(KERN_INFO "flag_write successfull\n");

  return result;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sparsh Mehta / hutgrabber");
MODULE_DESCRIPTION("Shift Character Device");
module_init(flag_start);
module_exit(flag_stop);
