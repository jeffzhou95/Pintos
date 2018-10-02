#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);
void BadExit(int status);
void *BadAddr(const void *Addr);
int myExec(char *file_name); 

extern bool running;

struct proc_file {
  struct file *ptr;
  int fd;
  struct list_elem elem;
};

void
syscall_init (void)
{
  // printf("syscall_init!\n");
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  // printf("system cal!\n");


  int *ptr = f->esp;
  BadAddr(ptr);

  // if (!is_user_vaddr(*ptr) || !pagedir_get_page(thread_current()->pagedir, ptr))
  // {
  //   exit(-1);
  // } 
  
  int system_call = *ptr;

  //if(!is_user_vaddr(*ptr)) BadExit(-1);

  switch (system_call)
  {
  	case SYS_WRITE:
  	if (*(ptr+5) == 1) putbuf(*(ptr+6), *(ptr+7));
  	break;

  	case SYS_HALT:
  	shutdown_power_off();
  	break;

    case SYS_EXIT:
    BadExit(*(ptr + 1));
    break;

    case SYS_EXEC:
    BadAddr(ptr + 1);
    BadAddr(*(ptr + 1));
    f->eax = myExec(*(ptr + 1));
    break;

    case SYS_WAIT:
    BadAddr(ptr + 1);
    f->eax = process_wait(*(ptr + 1));
    break;


    case SYS_CREATE:
    BadAddr(ptr + 5);
    BadAddr(*(ptr + 4));
    acquire_filesys_lock();
    f->eax = filesys_create(*(ptr + 4), *(ptr + 5));
    release_filesys_lock();
    break;

    case SYS_REMOVE:
    BadAddr(ptr + 1);
    BadAddr(*(ptr + 1));
    acquire_filesys_lock();
    if(filesys_remove(*(ptr + 1))==NULL) f->eax = false;
    else f->eax = true;
    release_filesys_lock();
    break;

    case SYS_OPEN:
    BadAddr(ptr + 1);
    BadAddr(*(ptr + 1));
    acquire_filesys_lock();
    struct file *file_ptr = filesys_open (*(ptr + 1));
    release_filesys_lock();
    if(file_ptr==NULL)
      f->eax = -1;
    else {
      struct proc_file *pfile = malloc(sizeof(*pfile));
      pfile->ptr = file_ptr;
      pfile->fd = thread_current()->fd_count;
      thread_current()->fd_count++;
      list_push_back(&thread_current()->files, &pfile->elem);
      f->eax = pfile->fd;
    }
    break;


    // case SYS_SEEK:
    // BadAddr(ptr + 5);
    // acquire_filesys_lock();
    // file_seek(list_search(&thread_current()->files, *(ptr + 4))->ptr,*(ptr + 5));
    // release_filesys_lock();
    // break;

    // case SYS_TELL:
    // BadAddr(ptr + 1);
    // acquire_filesys_lock();
    // f->eax = file_tell(list_search(&thread_current()->files, *(ptr + 1))->ptr);
    // release_filesys_lock();
    // break;

  	default:
  	printf("No match\n");
  }
}

int myExec(char *file_name) {
  acquire_filesys_lock();
  char * file_name_copy = malloc (strlen(file_name) + 1);
  strlcpy(file_name_copy, file_name, strlen(file_name) + 1);
  char * saveptr;
  file_name_copy = strtok_r(file_name_copy," ",&saveptr);
  struct file* f = filesys_open (file_name_copy);  

  if(f == NULL) {
    release_filesys_lock();
    return -1;
  }else {
    file_close(f);
    release_filesys_lock();
    return process_execute(file_name);
  }
}

void *BadAddr(const void *Addr) {
  if(!is_user_vaddr(Addr)) {
      BadExit(-1);
      return 0;
  }  
  if(!pagedir_get_page(thread_current()->pagedir, Addr)) {
      BadExit(-1);
      return 0;    
  }
  return pagedir_get_page(thread_current()->pagedir, Addr);

}

void
exit (int status)
{
  struct thread *cur = thread_current();
  cur->parent->exit = true;
  if(status < 0) status = -1;
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}

void BadExit(int status) {
  struct thread *cur = thread_current();
  cur->parent->exit = true;
  if(status < 0) status = -1;
  printf("%s: exit(%d)\n", cur->name, status);
  cur->ret = status;
  thread_exit();
}
