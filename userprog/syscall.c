#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "process.h"
#include <string.h>
#include <stdlib.h>
#include "filesys/file.h"
#include "filesys/inode.h"

static void syscall_handler (struct intr_frame *);

void BadExit(int status);
void *BadAddr(const void *Addr);
int myExec(char *file_name); 
void parse_argus(int *ptr, int *argu, int size);
int write (int fd, const void *buffer, unsigned size);
int read (int fd, const void *buffer, unsigned size);
struct file* process_get_file (int fd);

#ifdef FILESYS
bool sys_chdir(const char *filename);
bool sys_mkdir(const char *filename);
#endif

struct lock filesys_lock;

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void

syscall_handler (struct intr_frame *f UNUSED){
  int *ptr = f->esp;
  BadAddr(ptr); 
  int system_call = *ptr;
  int argu[3];

  switch (system_call)
  {

    case SYS_READ:
    parse_argus(ptr,argu,3);
    f->eax = read(argu[0],(void *)argu[1],argu[2]);
    break;
      
  	case SYS_WRITE:   
    parse_argus(ptr,argu,3);
    f->eax = write(argu[0],(void *)argu[1],argu[2]);
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
    f->eax = filesys_create(*(ptr + 4), *(ptr + 5), false);
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
    struct file *file_ptr = filesys_open(*(ptr + 1));
    release_filesys_lock();
    if(file_ptr == NULL) f->eax = -1;
    else {
      struct proc_file *pfile = malloc(sizeof(*pfile));
      pfile->ptr = file_ptr;
      pfile->fd = thread_current()->fd_count;
      thread_current()->fd_count++;
      list_push_back(&thread_current()->files, &pfile->elem);
      f->eax = pfile->fd;
    }
    break;

    case SYS_CLOSE:
    BadAddr(ptr + 1);
    acquire_filesys_lock();
    struct list_elem *e_close;
    for(e_close = list_begin(&thread_current()->files); e_close != list_end(&thread_current()->files); e_close = list_next(e_close)) {
      struct proc_file *f = list_entry (e_close, struct proc_file, elem);
      if(f->fd == *(ptr + 1)) {
        file_close(f->ptr);
        list_remove(e_close);
        break;
      }
    }
    release_filesys_lock();
    break;

    case SYS_SEEK:
    BadAddr(ptr + 5);
    struct list_elem *e_seek;
    struct proc_file *file_ptr_seek = malloc(sizeof(*file_ptr_seek));
    for(e_seek = list_begin(&thread_current()->files); e_seek != list_end(&thread_current()->files); e_seek = list_next(e_seek)) {
      struct proc_file *f = list_entry(e_seek, struct proc_file, elem);
      if(f->fd == *(ptr + 4)) {
        file_ptr_seek = f;
        break;
      }
    }
    acquire_filesys_lock();
    file_seek(file_ptr_seek->ptr, *(ptr + 5));
    release_filesys_lock();
    break;

    case SYS_TELL:
    BadAddr(ptr + 1);
    struct list_elem *e_tell;
    struct proc_file *file_ptr_tell = malloc(sizeof(*file_ptr_tell));
    for(e_tell = list_begin(&thread_current()->files); e_tell != list_end(&thread_current()->files); e_tell = list_next(e_tell)) {
      struct proc_file *f = list_entry (e_tell, struct proc_file, elem);
      if(f->fd == *(ptr + 4)) {
        file_ptr_tell = f;
        break;
      }
    }
    acquire_filesys_lock();
    f->eax = file_tell(file_ptr_tell->ptr);
    release_filesys_lock();
    break;

    case SYS_FILESIZE:
    BadAddr(ptr + 1);
    acquire_filesys_lock();
    struct list_elem *e_fs;
    struct proc_file *file_ptr_fs = malloc(sizeof(*file_ptr_fs));
    for(e_fs = list_begin(&thread_current()->files); e_fs != list_end(&thread_current()->files); e_fs = list_next(e_fs)) {
      struct proc_file *f = list_entry (e_fs, struct proc_file, elem);
      if(f->fd == *(ptr + 1)) {
        file_ptr_fs = f;
        break;
      } 
    }
    f->eax = file_length(file_ptr_fs->ptr);
    release_filesys_lock();
    break;

#ifdef FILESYS
  case SYS_CHDIR: // 15
    {
      const char* filename;
      int return_code;
      parse_argus(ptr,argu,1);
      filename = (char*)argu[0];
      return_code = sys_chdir(filename);
      f->eax = return_code;
      break;
    }
  case SYS_MKDIR: // 16
    {
      const char* filename;
      int return_code;
      parse_argus(ptr,argu,1);
      filename = (char*)argu[0];
      return_code = sys_mkdir(filename);
      f->eax = return_code;
      break;
    }
  case SYS_READDIR: // 17
    {
    }
  case SYS_ISDIR: // 18
    {
    }
  case SYS_INUMBER: // 19
    {
    }
#endif



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

void BadExit(int status) {
  struct thread *cur = thread_current();
  sema_up(&cur->ch->exit_lock);
  cur->ch->exit_status = status;
  if(status < 0) status = -1;
  printf("%s: exit(%d)\n", cur->name, status);
  cur->ret = status;
  thread_exit();
}

void parse_argus(int *ptr, int *argu, int size){
  for(int i=0;i<size;i++){
    BadAddr(ptr+1+i);
    argu[i] = *(ptr+1+i);
  }
}

int write (int fd, const void *buffer, unsigned size){
  BadAddr(buffer);
  if (fd == STDOUT_FILENO)
    {
      putbuf(buffer, size);
      return size;
    }
  acquire_filesys_lock();
  struct file *f = process_get_file(fd);
  if (!f)
    {
      release_filesys_lock();
      return -1;
    }
  int bytes = file_write(f, buffer, size);
  release_filesys_lock();
  return bytes;
}


int read (int fd, const void *buffer, unsigned size)
{
  BadAddr(buffer);
  if (fd == STDIN_FILENO){
      unsigned i;
      uint8_t* local_buffer = (uint8_t *) buffer;
      for (i = 0; i < size; i++){
        local_buffer[i] = input_getc();
      }
      return size;
  }
  acquire_filesys_lock();
  struct file *f = process_get_file(fd);
  if (!f)
    {
      release_filesys_lock();
      return -1;
    }
  int bytes = file_read(f, buffer, size);
  release_filesys_lock();
  return bytes;
}


struct file* process_get_file (int fd){
  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->files); e != list_end (&t->files); e = list_next (e)){
          struct proc_file *pf = list_entry (e, struct proc_file, elem);
          if (fd == pf->fd){
        return pf->ptr;
      }
  }
  return NULL;
}

#ifdef FILESYS
bool sys_chdir(const char *filename)
{
  bool return_code;
  BadAddr(filename);
  lock_acquire (&filesys_lock);
  return_code = filesys_chdir(filename);
  lock_release (&filesys_lock);
  return return_code;
}
bool sys_mkdir(const char *filename)
{
  bool return_code;
  BadAddr(filename);
  lock_acquire (&filesys_lock);
  return_code = filesys_create(filename, 0, true);
  lock_release (&filesys_lock);
  return return_code;
}
#endif

