#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "lib/kernel/console.h"
#include "filesys/filesys.h"

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

  
  // thread_exit ();
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
  if (!is_valid_ptr (f->esp + 4))
    {
      printf("BAD stack ptr!!!\n");
      thread_exit ();
    }
  int exit_status = *(int *)(f->esp + 4);
  printf ("exit call with status %d!\n", exit_status);
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
  /* David driving */
  void *size_ptr = f->esp + 8;
  char *buf = *((char **) f->esp + 1);
  if (!is_valid_ptr (size_ptr) || !is_valid_ptr (buf))
    {
      printf ("invalid memory access from create syscall");
      thread_exit ();
    }
  printf ("create called!\n");
  bool success = filesys_create (buf, *(int *)size_ptr);
  f->eax = success;
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
  /* David driving */
  void *file_ptr = f->esp + 4;
  char *buf = *((char **) f->esp + 1);
  struct file *file;
  int fd;
  printf ("open called!\n");
  if (!is_valid_ptr (file_ptr) || !is_valid_ptr (buf))
    {
      printf ("invalid memory from open syscall");
      thread_exit ();
    }
  struct thread *cur = thread_current ();
  if ((file = filesys_open (buf)) != NULL)
    {
      for (fd = 2; fd < MAX_OPEN_FILES; fd++)
        {
          if (cur->open_files[fd] == NULL)
            {
              cur->open_files[fd] = file;
              f->eax = fd;
              return;
            }
        }
    }
  f->eax = -1;
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
  /* Matthew driving */
  void *count_ptr = f->esp + 12;
  char *buf = *((char **) f->esp + 2);
  if (!is_valid_ptr (count_ptr) || !is_valid_ptr (buf))
    {
      printf ("invalid memory access from write syscall");
      thread_exit ();
    }
  
  
  putbuf (buf, *((int *) count_ptr));
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

