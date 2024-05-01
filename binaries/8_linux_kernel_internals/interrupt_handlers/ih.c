#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <asm/io.h>
#include <linux/time.h>

// #define ENPM809V_IRQ 10 - //Use this if working on pwn.college
#define ENPM809V_IRQ  1 //This can be any value, but you need to ensure that you can trigger it somehow. For IRQ of 1, you may need to free it prior to initalizing it. Defining a software interrupt that is unregistered would mean that you need to call it via the `int <val>` instruction. 

DECLARE_WORK(print_work, printTaskHandler);

static volatile int count;
static spinlock_t lock;
static struct workqueue_struct *wq;

irqreturn_t handler(int irq_nr, void* dev_id);
void printTask(unsigned long data);
static int __init initialize(void);
static void __exit finalize(void);

/* Choose the one that you'd like to do. */
// struct tasklet_struct printTask;
// DECLARE_WORK(print_work, print_work_handler);

/**
 * @brief Initialize the module
 * We are going to request the IRQ (via request_irq make sure to set the IRQF_SHARED) and initialize the tasklet or waitqueue
 * The waitqueue/tasklet is for the deferred work to be done for the interrupt.
 * We will also want to intialize the spin lock  
*/
static int __init initialize(void) {
  int ret;
  spin_lock_init(&lock);
  ret = request_irq(ENPM809V_IRQ, Handler, IRQF_SHARED, "enpm809v_device", (void *)&count);
  if (ret) {
    printk(KERN_ALERT "Unable to register IRQ handler\n");
    return ret;
  }

  wq = create_workqueue("enpm809v_wq");
  if (!wq) {
    printk(KERN_ALERT "Unable to create workqueue\n");
    free_irq(ENPM809V_IRQ, (void *)&count);
    return -ENOMEM;
  }
	return 0;
}

/**
 * @brief Free the IRQ and kill the tasklet/cancel work sync. 
*/
static void __exit finalize(void) {
  free_irq(ENPM809V_IRQ, (void*)&count);
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
 * @return IRQ_HANDLED - We are going to say the IRQ is handled after we call the handler. 
 * 
*/
irqreturn_t handler(int irq_nr, void* dev_id) {
  unsigned long flags;
  spin_lock_irqsave(&lock, flags);
  count++;
  spin_unlock_irqrestore(&lock, flags);

  if (wq) {
    queue_work(wq, &print_work);
  }

  return IRQ_HANDLED;
}

/**
 * @brief This is a function for the deferred work. We are going to get the current value of the counter and time and then print it. Make sure to lock during the retrival of the counter and time.  
 * 
 * @param data 
*/
void printTaskHandler(struct work_struct *work) { //If you are choosing this to be work, must replace param with struct work_struct *work
  struct timespec64 ts;
  ktime_get_real_ts64(&ts);

  unsigned long flags;
  spin_lock_irqsave(&lock, flags);
  printk(KERN_ALERT "Count: %d, Time: %11lld.%09ld\n", count, ts.tv_sec, ts.tv_nsec);
  spin_unlock_irqrestore(&lock, flags);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sparsh Mehta / hutgrabber");
MODULE_DESCRIPTION("Interrupt Handler Demo");
module_init(initialize);
module_exit(finalize);
