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
#include "filesys/filesys.h"

typedef int pid_t;
static struct lock file_lock;
struct lock mylock;

static void syscall_handler(struct intr_frame *);
void syscall_init(void) {
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init (&file_lock);
	lock_init(&mylock);
}



static void syscall_handler(struct intr_frame *f) {
	int *p = f->esp;
	get_user(p);
	int syscall_num = *p; //get the syscall_num from the stack
	if (syscall_num == SYS_WRITE) {
		//printf("Write\n");
		get_user(p+3);
		get_user(*(p+2));
		f->eax = syscall_write(*(p + 1), *(p + 2), *(p + 3));
	}
	else if (syscall_num == SYS_HALT)
		syscall_halt();
	else if (syscall_num == SYS_EXIT) {
		get_user(p+1);
		syscall_exit(*(p + 1));
	}
	else if(syscall_num == SYS_WAIT){
		get_user(p+1);
		f->eax = process_wait(*(p+1));
	}
	else if(syscall_num == SYS_EXEC){
		get_user(p+1);
		get_user(*(p+1));
        f->eax = exec(*(p+1));
    }

	else if(syscall_num == SYS_CREATE){
		get_user(p+2);
		get_user(*(p+1));
		lock_acquire(&mylock);
		bool res = filesys_create(*(p + 1), *(p + 2));
		lock_release(&mylock);
		f -> eax = res;
	}
	else if(syscall_num == SYS_REMOVE){
		get_user(p+1);
		get_user(*(p+1));
        f->eax = syscall_remove(*(p+1));
	}
	else if(syscall_num == SYS_OPEN){
		get_user(p+1);
		get_user(*(p+1));
		f -> eax = syscall_open(*(p+1));
	}
	else if(syscall_num == SYS_FILESIZE){
		get_user(p+1);
		get_user(*(p+1));
		f -> eax = syscall_filesize(*(p+1));
	}
	return;
}

/* Reads a byte at user virtual address UADDR.
 UADDR must be below PHYS_BASE.
 Returns the byte value if successful, -1 if a segfault
 occurred. */
static int get_user(const int *uaddr) {
	if (!is_user_vaddr(uaddr)) {
		syscall_exit(-1);
		return -1;
	}
	int result;
	asm ("movl $1f, %0; movzbl %1, %0; 1:"
			: "=&a" (result) : "m" (*uaddr));
	if(result == -1)
		syscall_exit(-1);
	return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
    if ((void *) udst >= PHYS_BASE) {
		syscall_exit(-1);
	}
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

int syscall_write(int fd, void *buffer, unsigned size) {
	//printf("fd:%d size:%d\n", fd, size);
	if (fd == 1) {
		putbuf((char *) buffer, size);
		return size;
	}
	return -1;
}
void syscall_halt(void) {
	shutdown_power_off();
}
void syscall_exit(int status) {
	struct list_elem *e;

    if (lock_held_by_current_thread (&file_lock) )
        lock_release (&file_lock);

	for (e = list_begin(&thread_current()->parent->child_proc);
			e != list_end(&thread_current()->parent->child_proc);
			e = list_next(e)) {
		struct child *f = list_entry (e, struct child, elem);
		if (f->tid == thread_current()->tid) {
			f->used = true;
			f->exit_error = status;
		}
	}

	thread_current()->exit_error = status;

	if (thread_current()->parent->waitingon == thread_current()->tid)
		sema_up(&thread_current()->parent->child_lock);

	thread_exit();
}
pid_t exec (const char *cmd_line)
{
    lock_acquire(&file_lock);
    pid_t pid = process_execute(cmd_line);
    lock_release(&file_lock);
    return pid;
}

bool syscall_remove (const char *file)
{
  lock_acquire(&file_lock);
  bool success = filesys_remove(file);
  lock_release(&file_lock);
  return success;
}



int syscall_open(const char *file){
	lock_acquire(&mylock);
	if(file == NULL){
		lock_release(&mylock);
		return -1;
	}
	// printf("[MY_DEBUG] HERE_OPEN_SYSCALL\n");

	if(thread_current() -> open_files_list == NULL){
		// printf("[MY_DEBUG] INITIALIZING OPEN_FILES_LIST\n");
		thread_current() -> open_files_list = (struct file **)malloc(sizeof(struct file *) * 101);
		thread_current() -> open_files_list[0] = NULL; // empty list
	}


	struct file *myfile = filesys_open(file);
	if(!myfile)
		return -1;

	int i = 0;
	while(thread_current() -> open_files_list[i] != NULL && i < 99){
		i++;
	}

	if(i >= 99)
		return -1;
	thread_current() -> open_files_list[i] = myfile;
	thread_current() -> open_files_list[i + 1] = NULL;
	lock_release(&mylock);

	return i + 2;
}

int syscall_filesize(int fd){
    int size = -1;
    if(thread_current() -> open_files_list[fd-2] != NULL){
        lock_acquire(&file_lock);
        size = file_length(thread_current() -> open_files_list[fd-2]);
        lock_release(&file_lock);
    }
    return size;
}
