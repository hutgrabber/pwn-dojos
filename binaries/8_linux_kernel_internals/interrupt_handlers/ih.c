#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <asm/io.h>
#include <linux/time.h>

// #define ENPM809V_IRQ 10 - //Use this if working on pwn.college
#define ENPM809V_IRQ  1 //This can be any value, but you need to ensure that you can trigger it somehow. For IRQ of 1, you may need to free it prior to initalizing it. Defining a software interrupt that is unregistered would mean that you need to call it via the `int <val>` instruction. 


static volatile int count;
static spinlock_t lock;

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

	return 0;
}

/**
 * @brief Free the IRQ and kill the tasklet/cancel work sync. 
*/
static void __exit finalize(void) {
    free_irq(ENPM809V_IRQ, (void*)&count);

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

    return IRQ_HANDLED;
}

/**
 * @brief This is a function for the deferred work. We are going to get the current value of the counter and time and then print it. Make sure to lock during the retrival of the counter and time.  
 * 
 * @param data 
*/
void printTaskHandler(unsigned long data) { //If you are choosing this to be work, must replace param with struct work_struct *work

}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michael Wittner");
MODULE_DESCRIPTION("Interrupt Handler Demo");
module_init(initialize);
module_exit(finalize);
