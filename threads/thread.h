#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"

/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING, /* Running thread. */
	THREAD_READY, /* Not running but ready to run. */
	THREAD_BLOCKED, /* Waiting for an event to trigger. */
	THREAD_DYING /* About to be destroyed. */
};

/* Thread identifier type.
 You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */
#define NICE_MIN -20                    /* Lowest nice */
#define NICE_MAX 20                     /* Highest nice */
#define NICE_DEFAULT 0                  /* Default nice */
#define LOAD_AVG_DEFAULT 0              /* Default load_avg */
#define RECENT_CPU_DEFAULT 0            /* Default cpu reset */
#define fixed_point_p 17                /* p for fixed point operations */
#define fixed_point_q 14                /* q for fixed point operations */
#define fixed_point_f (1<<fixed_point_q)  /* f for fixed point operations */
#define int_to_fixed_point(N) N*fixed_point_f
#define fp_to_int_round_zero(X) X/fixed_point_f
#define fp_to_int_round_nearest(X) (X >= 0) ? ((X + (fixed_point_f / 2)) / fixed_point_f): ((X - (fixed_point_f / 2)) / fixed_point_f)
#define add_fixed_point(X,Y) X+Y
#define sub_y_from_x(X,Y) X-Y
#define add_x_and_n(X,N) X+(N*fixed_point_f)
#define sub_n_from_x(X,N) X-(N*fixed_point_f)
#define fixed_point_multiply(X,Y) ((int64_t) X) * X / fixed_point_f
#define mul_x_n(X,N) X*N
#define fixed_point_div(X,Y) ((int64_t) X)*fixed_point_f/Y
#define div_x_n(X,N) X/N

/* A kernel thread or user process.
   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:
        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+
   The upshot of this is twofold:
      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.
      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.
   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */

/* The `elem' member has a dual purpose.  It can be an element in
 the run queue (thread.c), or it can be an element in a
 semaphore wait list (synch.c).  It can be used these two ways
 only because they are mutually exclusive: only a thread in the
 ready state is on the run queue, whereas only a thread in the
 blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid; /* Thread identifier. */
	enum thread_status status; /* Thread state. */
	char name[16]; /* Name (for debugging purposes). */
	uint8_t *stack; /* Saved stack pointer. */
	int priority; /* Priority. */
	int initial_priority;
	struct thread *lock_holder;
	int donate[100];
	int i;
	struct list_elem allelem; /* List element for all threads list. */
	int nice;                   /* nice value */
	int recent_cpu;             /* recent cpu value */

	/* Shared between thread.c and synch.c. */
	struct list_elem elem; /* List element. */

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint32_t *pagedir; /* Page directory. */
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */


	struct list_elem sleep_elem;
	struct list_elem ready_elem;
	int64_t time_put_to_sleep;
	int64_t ticks_to_remain_sleep;
  };


/* If false (default), use round-robin scheduler.
 If true, use multi-level feedback queue scheduler.
 Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func(struct thread *t, void *aux);
void thread_foreach(thread_action_func *, void *);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);
void thread_calculate_priority(struct thread *t);
void thread_calculate_recent_cpu(struct thread *t);
void calculate_load_avg(void);
void thread_recalculate_priority(void);
void thread_recalculate_recent_cpu(void);

bool less(const struct list_elem *a, const struct list_elem *b, void *aux);
bool more(const struct list_elem *a, const struct list_elem *b, void *aux);
void thread_reset_priority(struct thread *t, int lock_id);
void thread_donate_priority(struct thread *donor,struct thread *t, int lock_id);
int max_donation(struct thread *t);
#endif /* threads/thread.h */
