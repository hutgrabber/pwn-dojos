/*
 * This file contains code for hooking the encrypted_send routine of server.c.
 *
 * load first initializes the capstone library. We use the udis library to get the length
 * of instructions at the start of encrypted_send. Next, we call entry_stub_create to create
 * our trampoline. Finally, we call entry_stub_hook to overwrite the first bytes of encrypted_send
 * with a jump to our wrapper function.
 *
 * Our wrapper function is myEncryptedPrint. myEncryptedPrint uses the trampoline created in
 * entry_stub_create to call the original encrypted_send routine.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <elf.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <dlfcn.h>
#include <capstone/capstone.h>
#include <fcntl.h>


#define BUF_SIZE			0x1000
#define MAX_ADDR_FMT_LEN	16
#define DUMP_COLS			16
#define MAX_INSTRUCTION_SIZE 15
#define JMP_PATCH_SIZE		12

/* Entry Stub Trampoline structure */
typedef struct _entry_stub {
    void* original_entry;
    unsigned long entry_size;
    void* trampoline;
} entry_stub_t;

__attribute__((constructor)) void load(void);
__attribute__((destructor)) void unload(void);
int debug(char* param);
void hexdump(const unsigned char* buf, unsigned int len);
void patch_code(void* target, void* patch, unsigned long len);
void write_absolute_jump(void* jump_from, void* jump_to);
ssize_t myEncryptedPrint(char* msg);


/* entry stub helpers */
uint16_t get_instruction_length(void *addr);
int entry_stub_create(entry_stub_t* stub, void* original);
int entry_stub_hook(entry_stub_t* stub, void* wrapper_func);

entry_stub_t stub;
csh handle;

int debug(char* param) {
	printf("Pfffttt... I ain't the real debuglib\n");
	return 0;
}

void load(void) {
	void* encryptedPrintAddr;
	printf("Injected lib running...\n");

    encryptedPrintAddr = dlsym(NULL, "encryptedPrint");
	printf("Address of encrypted_send is %p\n", encryptedPrintAddr);

	cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	if (err) 
	{
		printf("CS_ERR is %d\n", err);
		return; 
	}

	/* Add in the functions to create the trampoline*/

	return;
}

void unload(void) {
	printf("Unloading\n");
	cs_close(&handle);
	return;
}

ssize_t myEncryptedPrint(char* msg) {
	ssize_t ret;
	int fd;
	char buffer[128];
	ssize_t (*original)(char* msg);
	
	printf("I'm in your codez, stealin ur stuff\n");
    printf("Encrypted message is = %s\n", msg); 
	printf("Calling original...\n");
	original = stub.trampoline;
	ret = original(msg);
	return ret;
}

/** 
 * Will partch [target] with the value of [patch]
*/
void patch_code(void* target, void* patch, unsigned long len) {
	void* target_page = (void*)((size_t)target & 0xfffffffffffff000);
	unsigned long protlen = len + (target - target_page);
	if (mprotect(target_page, protlen, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
		fprintf(stderr, "Failed to change permissions of memory before patch:\n%s\n", strerror(errno));
	}
	memcpy(target, patch, len);
	if (mprotect(target_page, protlen, PROT_READ | PROT_EXEC) == -1) {
		fprintf(stderr, "Failed to change permissions of memory back to original:\n%s\n", strerror(errno));
	}
	return;
}

/**
 * This will patch the location at jump_from with a movabs+jump. 
*/
void write_absolute_jump(void* jump_from, void* jump_to) {
	/*	currently:
	 *		movabs rax, 0x0000000000000000
	 *		jmp rax */
	unsigned char jmp_template[] = {0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xe0};
	*((uint64_t*)(jmp_template + 2)) = (uint64_t)(jump_to);
	patch_code(jump_from, jmp_template, 12); /* patch is 12 bytes */
	return;
}

uint16_t get_instruction_length(void* addr) {
    unsigned int len = 0;
	uint16_t insn_len = 0;
	cs_insn *insn = NULL;
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON); 
	len = cs_disasm(handle, (uint8_t *) addr, MAX_INSTRUCTION_SIZE + JMP_PATCH_SIZE, (uint64_t) addr, 1, &insn);
	if (len == 0)
	{
		return 0; 
	}

	insn_len = insn->size;
	cs_free(insn, 1); 
    return insn_len;
}

/**
 * We are going to be creating the entry stub trampoline. For this we need to do the following:
 * 
 * - Determine the number of bytes we need to save for the trampoline - this is the number 
 * of instructions that get overwritten from patching in our jump
 * - Allocate executable memory for the trampoline
 * - Back up the original bytes to the trampoline
 * - Write an absolute jump back to the over to the original function (offset by number of bytes overwritten)
 * - Populate the entry stub structure. 
*/
int entry_stub_create(entry_stub_t* stub, void* original) {
 

    return 0;
}

/**
 * write a hook from the original function to myEncryptedPrint
 */
int entry_stub_hook(entry_stub_t* stub, void* wrapper_func) {
    return 0;
}
