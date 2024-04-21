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

#define GOTO_FAIL_IF(v) \
    if (v) \
        goto fail

#define GOTO_FAIL_WITH_RESULT_IF(v, rv) \
    ({ \
        if (v) { \
            result = rv; \
            goto fail; \
        } \
    })

#define LOG_GOTO_FAIL_IF(v, log, ...) \
    ({ \
        if (v) { \
            print(log, ##__VA_ARGS__); \
            goto fail; \
        } \
    })

#define LOG_GOTO_FAIL_WITH_RESULT_IF(v, rv, log, ...) \
    ({ \
        if (v) { \
            result = rv; \
            print(log, ##__VA_ARGS__); \
            goto fail; \
        } \
    })

#endif