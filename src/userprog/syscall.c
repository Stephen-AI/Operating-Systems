#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/kernel/console.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

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
struct semaphore filesys_sema;

void
syscall_init (void) 
{
  /* Matthew driving */
  sema_init (&filesys_sema, 1);
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
  /*TODO stop dereferencing stack pointer before checking validity */
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
  void *file_name_ptr = f->esp + 4;
  char **file_name = (char **)file_name_ptr;
  if (!is_valid_ptr (file_name_ptr) || !is_valid_ptr (*file_name))
    {
      printf ("invalid memory access from remove syscall");
      thread_exit ();
    }
  
  f->eax = filesys_remove (*file_name);
}

/* open file system call handler */
static void
open_handler (struct intr_frame *f UNUSED)
{
  /* David driving */
  void *file_ptr = f->esp + 4;
  /*TODO stop dereferencing stack pointer before checking validity */  
  char *buf = *((char **) f->esp + 1);
  struct file *file;
  int fd;
  printf ("open called!\n");
  if (!is_valid_ptr (file_ptr) || !is_valid_ptr (buf))
    {
      printf ("invalid memory access from open syscall");
      thread_exit ();
    }
  struct thread *cur = thread_current ();
  /* check if the file is in the file system
     if it is in the file system, look for a fd number for the file*/
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
  /* Matthew driving */
  int *fd_ptr = (int *)(f->esp + 4), file_size; 
  printf ("filesize called!\n");
  if (!is_valid_ptr (fd_ptr))
    {
      printf ("invalid memory access from filesize syscall");
      thread_exit ();
    }

  int fd = *fd_ptr;

  if (fd <= 1 || fd >= MAX_OPEN_FILES)
    {
      f->eax = -1;
      return;
    }
  else
    {
      struct file *file = thread_current ()->open_files[fd];
      if (file == NULL)
        {
          f->eax = -1;
          return;
        }
      else
        {
          file_size = file_length (file);
          f->eax = file_size;
        }
    }
}

/* read system call handler */
static void
read_handler (struct intr_frame *f UNUSED)
{
  /* YunFan driving */
  void *size_ptr = f->esp + 12;
  /*TODO stop dereferencing stack pointer before checking validity */  
  char *buf = *((char **) (f->esp + 8));

  if (!is_valid_ptr (size_ptr) || !is_valid_ptr (buf))
    {
      printf ("invalid memory access from read syscall");
      thread_exit ();
    }
  printf ("read called!\n");

  int fd = *(int *)(f->esp + 4), byte_read; 
  
  if (fd == 0)
    {
      /* Maybe synchronize keyboard input with filesys?? */
      input_getc (); /* read stdio and complete */
    }
  else if (fd <= 1 || fd >= MAX_OPEN_FILES)
    {
      f->eax = -1;
      return;
    }
  else
    {
      struct file *file = thread_current ()->open_files[fd];
      if (file == NULL)
        {
          f->eax = -1;
          return;
        }
      else
        {
          /* Matthew driving */
          /* synchronize reading/writing */
          sema_down (&filesys_sema);
          byte_read = file_read (file, buf, *(int *)size_ptr);
          sema_up (&filesys_sema);
          f->eax = byte_read;
        }
    }
}

/* write system call handler */
static void
write_handler (struct intr_frame *f UNUSED)
{
  /* Matthew driving */
  int *count_ptr = (int *)(f->esp + 12);
  /*TODO stop dereferencing stack pointer before checking validity */ 
  int fd, bytes, buf_len, count;
  struct file *file;
  if (!is_valid_ptr (count_ptr))
    {
      printf ("invalid memory access from write syscall");
      thread_exit ();
    }
  char *buf = *((char **) (f->esp + 8));
  if (!is_valid_ptr (buf))
    {
      printf ("invalid memory access from write syscall");
      thread_exit ();
    }
  fd = *(int *)(f->esp + 4);
  buf_len = strlen (buf);
  count = *((int *) count_ptr);
  if (fd == 1)
    {
      if (count > buf_len)
        count = buf_len;
      /* Matthew driving */
      /* synchronize reading/writing */
      sema_down (&filesys_sema);
      putbuf (buf, count);
      sema_up (&filesys_sema);
      bytes = count;
    }
  else if (fd < 1 || fd >= MAX_OPEN_FILES)
    {
      bytes = 0;
    }
  else
    {
      file = thread_current ()->open_files[fd];
      if (file == NULL)
        {
          printf ("file not in open files\n");
          // TODO: THREAD EXIT???
          thread_exit ();
        }
      /* Matthew driving */
      /* synchronize reading/writing */
      sema_down (&filesys_sema);
      bytes = file_write (file, buf, count);
      sema_up (&filesys_sema);
    }
  f->eax = bytes;
}

/* seek system call handler */
static void
seek_handler (struct intr_frame *f UNUSED)
{
  /* David driving */
  int *pos_ptr = (int *)(f->esp + 8);
  /*TODO TEST SEEK */
  int *fd_ptr = (int *)(f->esp + 4);
  struct file *file;
  printf ("seek called!\n");
  if (!is_valid_ptr (pos_ptr))
    {
      printf ("invalid memory access from seek syscall\n");
      thread_exit ();
    }
  if (*fd_ptr <= 1 || *fd_ptr >= MAX_OPEN_FILES)
    {
      printf ("not a valid file to seek\n");
      thread_exit ();
    }
  file = thread_current ()->open_files[*fd_ptr];
  if (file == NULL)
    {
      printf ("file not in thread's fd\n");
      thread_exit ();
    }
  file_seek (file, *pos_ptr);
}

/* tell system call handler */
static void
tell_handler (struct intr_frame *f UNUSED)
{
  /* David driving */
  /*TODO TEST TELL */
  int *fd_ptr = (int *)(f->esp + 4);
  struct file *file;
  printf ("tell called!\n");
  if (!is_valid_ptr (fd_ptr))
    {
      printf ("invalid memory access from tell syscall");
      thread_exit ();
    }
  if (*fd_ptr <= 1 || *fd_ptr >= MAX_OPEN_FILES)
    {
      printf ("not a valid file to tell");
      thread_exit ();
    }
  file = thread_current ()->open_files[*fd_ptr];
  if (file == NULL)
    {
      printf ("file not in thread's fd");
      thread_exit ();
    }
  file_tell (file);
}

/* close file system handler */
static void
close_handler (struct intr_frame *f UNUSED)
{
  printf ("close called!\n");
  /* Matthew driving */
  int *fd_ptr = (int *)(f->esp + 4);
  struct file *file;
  if (!is_valid_ptr (fd_ptr))
    {
      printf ("invalid memory access from close syscall");
      thread_exit ();
    }
  if (*fd_ptr <= 1 || *fd_ptr >= MAX_OPEN_FILES)
    {
      printf ("not a valid file to close");
      thread_exit ();
    }
  file = thread_current ()->open_files[*fd_ptr];
  if (file == NULL)
    {
      printf ("file not in thread's fd");
      thread_exit ();
    }
  file_close (file);
}

