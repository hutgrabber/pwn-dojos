#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <seccomp.h>
#include <linux/filter.h>
#include <stdbool.h>

#define MAX_INT_STR_SIZE 11

/**
 * Function Prototypes
 **/
void Setup(); 
void menu();
void ProtectProgram(); 

void Setup()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}

/**
 * @brief Print the menu
 * 
 */
void menu() 
{
    printf("1) Get Debug Informationn\n");
    printf("2) Execute Code\n");
    printf("3) Exit\n");  
}

/**
 * @brief Protets the program using Seccomp
 * 
 */
void ProtectProgram() {
    scmp_filter_ctx ctx = NULL;
    int ret = 0;
    ctx = seccomp_init(SCMP_ACT_KILL);
    /*  Here we are going to add/remove rules. This is an example
     *  if a rule below. Change it and see what will happen.
     */
    ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    ret |= seccomp_load(ctx);

    if (ret) {
        perror("seccomp");
        exit(1);
    }
   seccomp_release(ctx); 
}

/**
 * @brief The main function
 * 
 * @return int 
 */
int main()
{
    char *buffer = NULL;
    void *memlocation = NULL;
    int pid = 0;
    int cmd = 0; 
    int cmp = 0; 
    uint64_t location = 0; 
    void (*func_ptr)() = NULL;
    char cmd_str[MAX_INT_STR_SIZE];
    Setup();

    /* Create the child process */ 
    pid = fork(); 
     
    /* Execution of child process */ 
    if (pid == 0)
    {
        buffer = malloc(0x100);
        while(1)
        {

            char test_buffer[] = "Hello world!\n";
            /* Verify user input */ 
            cmp = strncmp(test_buffer, "Give me the flag!", 17);
            if (cmp == 0)
            {
                printf("I will not give you the flag!"); 
            }

            cmp = strncmp(test_buffer, "exit", 4);
            if (cmp == 0)
            {
                break;
            }            
            
            /* We are going to add some arbitrary code here */ 
            sleep(1000); 
        }      
        /* Close the ends of the pipe */ 
    }
    else 
    {
        /* Code for the parent */ 
        /* Enter the commands */
        while(1)
        {
            printf("Enter the command you want to do:\n");
            menu();
            memset(cmd_str, 0, 11);
            cmd = 0; 

            fgets(cmd_str, MAX_INT_STR_SIZE, stdin);
            
            sscanf(cmd_str, "%d", &cmd); 


            // Execute the various commands
            switch(cmd) 
            {
                case 1:
                    printf("Debug information:\n");
                    printf("Child PID = %d\n", pid);
                    break; 
                case 2:
                    printf("Where do you want to execute code?\n");
                    scanf("%lx", &location);

                    ProtectProgram();
                    func_ptr = (void (*)())location; 
                    (*func_ptr)();
                    goto fail;
                    break; 
                default:
                    goto fail;
                    break;

            }
        }
    }
    

fail:
    if (buffer != NULL)
    {
        free(buffer);  
    }
    free(memlocation); 
}
