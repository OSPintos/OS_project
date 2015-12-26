#include <stdbool.h>
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
typedef int pid_t;

static int get_user(const int *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
void syscall_init (void);
void syscall_halt(void);
void syscall_exit(int status);
pid_t syscall_exec(const char *file);
int syscall_wait(pid_t pid);
bool syscall_create(const char *file, unsigned initial_size);
bool syscall_remove(const char *file);
int syscall_open(const char *file);
int syscall_filesize(int fd);
int syscall_read(int fd, void *buffer, unsigned length);
int syscall_write(int fd, void *buffer, unsigned length);
void syscall_seek(int fd, unsigned position);
unsigned syscall_tell(int fd);
void syscall_close(int fd);

#define ERROR -1

#define NOT_LOADED 0
#define LOAD_SUCCESS 1
#define LOAD_FAIL 2
#endif /* userprog/syscall.h */
