#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);

extern bool running;

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{

  int *ptr = f->esp;
  int system_call = *ptr;
  switch (system_call)
  {
  	case SYS_HALT:
  	shutdown_power_off();
  	break;

    case SYS_EXIT:
    thread_current()->exit = true;
    //thread_current()->exit_error = *(p+1);
    thread_exit();
    break;

	default:
	printf("No match\n");
  }
}
