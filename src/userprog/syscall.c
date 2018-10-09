#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

/* David driving */
static void syscall_handler (struct intr_frame *);
static void halt_handler (struct intr_frame *f);
static void exit_handler (struct intr_frame *f);
static void exec_handler (struct intr_frame *f);
static void wait_handler (struct intr_frame *f);
static void create_handler (struct intr_frame *f);
static void remove_handler (struct intr_frame *f);
static void open_handler (struct intr_frame *f);
static void filesize_handler (struct intr_frame *f);
static void read_handler (struct intr_frame *f);
static void write_handler (struct intr_frame *f);
static void seek_handler (struct intr_frame *f);
static void tell_handler (struct intr_frame *f);
static void close_handler (struct intr_frame *f);
bool is_valid_ptr (void *ptr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Makes sure a pointer points to valid user memory */
bool 
is_valid_ptr (void *ptr)
{
  /* Stephen drove here */
  struct thread *cur = thread_current ();
  return is_user_vaddr (ptr) && lookup_page (cur->pagedir, ptr, false) != NULL;
}

static void
syscall_handler (struct intr_frame *f) 
{
  /* Stephen driving */
  void *esp = f->esp;
  int syscall_no;
  if(!is_valid_ptr(esp))
    thread_exit ();
  int *syscall_ptr = (int *)esp;
  syscall_no = *syscall_ptr;
  switch (syscall_no)
  {
    /* David driving */
    case 0: halt_handler (f); break;
    case 1: exit_handler (f); break;
    case 2: exec_handler (f); break;
    case 3: wait_handler (f); break;
    case 4: create_handler (f); break;
    case 5: remove_handler (f); break;
    case 6: open_handler (f); break;
    case 7: filesize_handler (f); break;
    case 8: read_handler (f); break;
    case 9: write_handler (f); break;
    case 10: seek_handler (f); break;
    case 11: tell_handler (f); break;
    case 12: close_handler (f); break;
    default: 
    printf("System call SYSCALLNO: %d not implemented", syscall_no);
    thread_exit ();
    break;
  }

  
  thread_exit ();
}

/* halt system call handler */
static void
halt_handler (struct intr_frame *f UNUSED)
{
  /* Stephen driving */
  printf ("halt called!\n");
  thread_exit ();
}

/* exit system call handler */
static void
exit_handler (struct intr_frame *f UNUSED)
{
  /* David driving */
  printf ("exit call!\n");
  thread_exit ();
}

/* exec system call handler */
static void
exec_handler (struct intr_frame *f UNUSED)
{
  /* Stephen driving */
  printf ("exec called!\n");
  thread_exit ();
}

/* wait system call handler */
static void
wait_handler (struct intr_frame *f UNUSED)
{
  /* Stephen driving */
  printf ("wait called!\n");
  thread_exit ();
}

/* create file system call handler */
static void
create_handler (struct intr_frame *f UNUSED)
{
  /* Stephen driving */
  printf ("create called!\n");
  thread_exit ();
}

/* remove file system call handler */
static void
remove_handler (struct intr_frame *f UNUSED)
{
  /* Stephen driving */
  printf ("remove called!\n");
  thread_exit ();
}

/* open file system call handler */
static void
open_handler (struct intr_frame *f UNUSED)
{
  /* Stephen driving */
  printf ("open called!\n");
  thread_exit ();
}

/* filesize system call handler */
static void
filesize_handler (struct intr_frame *f UNUSED)
{
  /* Stephen driving */
  printf ("filesize called!\n");
  thread_exit ();
}

/* read system call handler */
static void
read_handler (struct intr_frame *f UNUSED)
{
  /* Stephen driving */
  printf ("read called!\n");
  thread_exit ();
}

/* write system call handler */
static void
write_handler (struct intr_frame *f UNUSED)
{
  /* Stephen driving */
  printf ("write called!\n");
  void *buf = (f->esp + 8);
  printf("buffer %Z\n", buf);
  thread_exit ();
}

/* seek system call handler */
static void
seek_handler (struct intr_frame *f UNUSED)
{
  /* Stephen driving */
  printf ("seek called!\n");
  thread_exit ();
}

/* tell system call handler */
static void
tell_handler (struct intr_frame *f UNUSED)
{
  /* Stephen driving */
  printf ("tell called!\n");
  thread_exit ();
}

/* close file system handler */
static void
close_handler (struct intr_frame *f UNUSED)
{
  /* Stephen driving */
  printf ("close called!\n");
  thread_exit ();
}

