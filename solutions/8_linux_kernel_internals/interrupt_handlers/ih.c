/*  -------------------------------------------------------------------------------------
 *  Interrupt Handlers ENPM809V - UID 1193629134 - Sparsh Mehta / hutgrabber
 *  -------------------------------------------------------------------------------------
 *  In this homework we are supposed to create our own interrupt handler using
 *  kernel modules. This task is achieved by creating and loading our own kernel
 *  module. The following sequence of steps need to be followed in order to make
 *  our interrupt handler successfully & print each time the int_handler is called:
 *
 *  1. We first begin by initialzing some important variables like spinlock, count
 *      and create a pointer for the struct workqueue.
 *  2. Next we request the interrupt using the request_irq function which takes in
 *      the name of the request, the handler which we have to create, the IRQF_SHARED
 *      a string of some sort and the (void *)&count pointer.
 *  3. Next we need to create a workqueue. We need to also define a situation wherein
 *      if this workqueue errors out, we can handle that using the free_irq function
 *      which takes in parameters like the name of the interrupt request (ENPM809V_IRQ),
 *      and the (void *)&count pointer.
 *  4. All up till here was a part of the _init intialize() part of the process where
 *      variables are defined, structures are created & API functions are called. What we 
 *      will do next, is going to be a part of the _exit finalize() function.
 *  5. First we need to free the irq using the free_irq function like before. We also need 
 *      to destroy & flush the existing workqueue. We won't remove the KERN_ALERT printk()
 *      statements just yet.
 *  6. Next we work with the handler(). Here we use the initialized spinlock and lock on &lock.
 *      Then we increment the count and unlock the spinlock. If the workqueue exists, we call
 *      queue_work on our workqueue and use &print_work to print to the kernel log (dmseg).
 *  7. The final part of handler() will return the IRQ_HANDLED param.
 *  8. Next we will work with the printTaskHandler() function. We define a timespec and 
 *      get the time using the ktime_get_real_ts64 parameter. This may change depending on
 *      the version of the kernel.
 *  9. Finally we print the count and the time using the printk() statement and unlock the
 *      spinlock.
 */
#include <asm/io.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/workqueue.h>

// #define ENPM809V_IRQ 10 - //Use this if working on pwn.college
#define ENPM809V_IRQ 10

// This can be any value, but you need to ensure that you can trigger it
// somehow. For IRQ of 1, you may need to free it prior to initalizing it.
// Defining a software interrupt that is unregistered would mean that you
// need to call it via the `int <val>` instruction.

static volatile int count;
static spinlock_t lock;
static struct workqueue_struct *wq;

irqreturn_t handler(int irq_nr, void *dev_id);
void printTaskHandler(struct work_struct *work);
static int __init initialize(void);
static void __exit finalize(void);

DECLARE_WORK(print_work, printTaskHandler);

/* Choose the one that you'd like to do. */
// struct tasklet_struct printTask;
// DECLARE_WORK(print_work, print_work_handler);

/**
 * @brief Initialize the module
 * We are going to request the IRQ (via request_irq make sure to set the
 * IRQF_SHARED) and initialize the tasklet or waitqueue The waitqueue/tasklet is
 * for the deferred work to be done for the interrupt. We will also want to
 * intialize the spin lock
 */
static int __init initialize(void) {
  int ret;
  spin_lock_init(&lock);
  ret = request_irq(ENPM809V_IRQ, handler, IRQF_SHARED, "enpm809v_device",
                    (void *)&count);
  if (ret) {
    printk(KERN_ALERT "Unable to register IRQ handler\n");
  }

  wq = create_workqueue("enpm809v_wq");
  if (!wq) {
    printk(KERN_ALERT "Unable to create workqueue\n");
    free_irq(ENPM809V_IRQ, (void *)&count);
    return -ENOMEM;
  }
  printk(KERN_INFO "Module finished initializing successfully\n");
  return 0;
}

/**
 * @brief Free the IRQ and kill the tasklet/cancel work sync.
 */
static void __exit finalize(void) {
  free_irq(ENPM809V_IRQ, (void *)&count);
  if (wq)
    destroy_workqueue(wq);
  // if tasklet is running will wait for completion
  // tasklet_kill(&printTask);
  // cancel_work_sync(&print_work);

  printk(KERN_ALERT "Handler invoked %d times\n", count);
  printk(KERN_ALERT "Module Exiting\n");
  return;
}

/**
 * @brief The interrupt handler is going to increase the counter by 1.
 * We will need to set a spinlock around it because this is a global variable.
 *
 * The non-deferred work is increasing the counter
 * The deferred work is printing the counter.
 *
 * @param irq_nr The IRQ number that was triggered.
 * @param dev_id The device ID that was passed in
 *
 * @return IRQ_HANDLED - We are going to say the IRQ is handled after we call
 * the handler.
 *
 */
irqreturn_t handler(int irq_nr, void *dev_id) {
  unsigned long flags;
  printk(KERN_INFO "This handler started\n");
  spin_lock_irqsave(&lock, flags);
  count++;
  spin_unlock_irqrestore(&lock, flags);

  if (wq) {
    queue_work(wq, &print_work);
  }

  return IRQ_HANDLED;
}

/**
 * @brief This is a function for the deferred work. We are going to get the
 * current value of the counter and time and then print it. Make sure to lock
 * during the retrival of the counter and time.
 *
 * @param data
 */
void printTaskHandler(
    struct work_struct *work) { // If you are choosing this to be work, must
                                // replace param with struct work_struct *work
  struct timespec64 ts;
  unsigned long flags;
  ktime_get_real_ts64(&ts);
  spin_lock_irqsave(&lock, flags);
  printk(KERN_ALERT "Count: %d, Time: %11lld.%09ld\n", count, ts.tv_sec,
         ts.tv_nsec);
  spin_unlock_irqrestore(&lock, flags);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sparsh Mehta / hutgrabber / 1193629134");
MODULE_DESCRIPTION("Interrupt Handler Demo");
module_init(initialize);
module_exit(finalize);
