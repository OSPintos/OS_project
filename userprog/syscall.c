#include <stdio.h>
#include <syscall-nr.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/file.h"

static void syscall_handler(struct intr_frame *);
void syscall_init(void) {
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}
static void syscall_handler(struct intr_frame *f) {
	int *p = f->esp;
	int syscall_num = *p; //get the syscall_num from the stack
	if (syscall_num == SYS_WRITE) {
		//printf("Write\n");
		f->eax = syscall_write(*(p+5),*(p+6),*(p+7));
	}
	else if (syscall_num == SYS_HALT)
		syscall_halt();
	else if (syscall_num == SYS_EXIT) {
		syscall_exit(*(p+1));
	}
	return;
}

/* Reads a byte at user virtual address UADDR.
 UADDR must be below PHYS_BASE.
 Returns the byte value if successful, -1 if a segfault
 occurred. */
static int get_user(const int *uaddr) {
	if ((void *) uaddr >= PHYS_BASE) {
		printf("EXIT");
		syscall_exit(-1);
	}
	int result;
	asm ("movl $1f, %0; movzbl %1, %0; 1:"
			: "=&a" (result) : "m" (*uaddr));
	return result;
}
int syscall_write(int fd, void *buffer, unsigned size) {
	//printf("fd:%d size:%d\n", fd, size);
	if (fd == 1) {
		putbuf((char *)buffer, size);
		return size;
	}

	return -1;
}
void syscall_halt(void) {
	shutdown_power_off();
}
void syscall_exit(int status) {
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
}
