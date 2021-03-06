#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct child_thread {
    tid_t tid;
    int exit_status;
    struct semaphore exit_lock;
    struct list_elem elem;
};

struct child_thread* add_child(struct thread *t, tid_t child_tid);
struct child_thread* get_child_thread(struct thread *parent, tid_t child_tid);

#endif /* userprog/process.h */
