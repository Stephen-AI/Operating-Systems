#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/kernel/console.h"
#include "filesys/filesys.h"
#include "lib/user/syscall.h"
#include "devices/shutdown.h"
#include <string.h>
#include "userprog/process.h"
#include "filesys/file.h"
#include "devices/input.h"

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
static bool is_valid_str (char *str);
/* Stephen driving */
static void chdir_handler (struct intr_frame *f);
static void mkdir_handler (struct intr_frame *f);
static void readdir_handler (struct intr_frame *f);
static void isdir_handler (struct intr_frame *f);
static void inumber_handler (struct intr_frame *f);

/* check if a string is in valid memory*/
bool 
is_valid_str (char *str)
{
  /* YunFan is driving*/
  struct thread *cur = thread_current ();
  uint32_t *page = lookup_page (cur->pagedir, str, false);
  void *upper = pg_round_up (str);
  
  if (!is_user_vaddr (str) || page == NULL)
    return false;

  while (*str != '\0')
    {
      if (!is_user_vaddr (str))
        return false;
      else if (str <= upper)
        str++;  
    /* when the string exceeds a page boundary check if it's in the next page*/
      else
        {
          page = lookup_page (cur->pagedir, str, false);
          if (!is_user_vaddr (str) || page == NULL)
            return false;
          else 
            upper = pg_round_up (str);
        }
    }
  return true;
}

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
    case 15: chdir_handler (f); break;
    case 16: mkdir_handler (f); break;
    case 17: readdir_handler (f); break;
    case 18: isdir_handler (f); break;
    case 19: inumber_handler (f); break;
    default: 
    printf("System call SYSCALLNO: %d not implemented\n", syscall_no);
    thread_exit ();
    break;
  }
}

/* halt system call handler */
static void
halt_handler (struct intr_frame *f UNUSED)
{
  /* Matthew driving */
  shutdown_power_off ();
}

/* exit system call handler */
static void
exit_handler (struct intr_frame *f UNUSED)
{
  /* David driving */
  int exit_status;

  if (!is_valid_ptr (f->esp + 4))
    thread_exit ();
  
  exit_status = *(int *)(f->esp + 4);
  thread_current ()->exit = exit_status;
  thread_exit ();
}

/* exec system call handler */
static void
exec_handler (struct intr_frame *f UNUSED)
{
  /* David driving */
  void *file_ptr = f->esp + 4;
  char *buf, s[128];

  if (!is_valid_ptr (file_ptr))
    thread_exit ();

  buf = *((char **) f->esp + 1);
  if (!is_valid_str (buf))
    thread_exit ();
  
  /* copy the name of the file being exec'd into s from buf */
  strlcpy (s, buf, strlen (buf) + 1);
  f->eax = process_execute (s);
}

/* wait system call handler */
static void
wait_handler (struct intr_frame *f UNUSED)
{
  /* Matthew driving */
  if (!is_valid_ptr (f->esp + 4))
    thread_exit ();
  pid_t child_pid = *(pid_t *)(f->esp + 4);

  if (child_pid > 0)
    f->eax = process_wait (child_pid);
}

/* create file system call handler */
static void
create_handler (struct intr_frame *f UNUSED)
{
  /* David driving */
  void *size_ptr = f->esp + 8;
  char **buf = ((char **) f->esp + 1);
  if (!is_valid_ptr (size_ptr))
    thread_exit ();
  if (!is_valid_str (*buf))
    thread_exit ();

  sema_down (&filesys_sema);
  f->eax = filesys_create (*buf, *(int *)size_ptr, false);
  sema_up (&filesys_sema);
}

/* remove file system call handler */
static void
remove_handler (struct intr_frame *f UNUSED)
{
  /* Stephen driving */
  void *file_name_ptr = f->esp + 4;
  char **file_name = (char **)file_name_ptr;
  if (!is_valid_ptr (file_name_ptr))
    thread_exit ();
  
  if (!is_valid_str (*file_name))
    thread_exit ();
  sema_down (&filesys_sema);
  f->eax = filesys_remove (*file_name);
  sema_up (&filesys_sema);
}

/* open file system call handler */
static void
open_handler (struct intr_frame *f UNUSED)
{
  /* David driving */
  void *file_ptr = f->esp + 4;
  /*TODO stop dereferencing stack pointer before checking validity */  
  char **buf = ((char **) f->esp + 1);
  struct file *file;
  int fd;

  if (!is_valid_ptr (file_ptr))
    thread_exit ();
  if (!is_valid_str (*buf))
    thread_exit ();

  struct thread *cur = thread_current ();
  /* check if the file is in the file system
     if it is in the file system, look for a fd number for the file */
  sema_down (&filesys_sema);
  if ((file = filesys_open (*buf)) != NULL) 
    {
      for (fd = 2; fd < MAX_OPEN_FILES; fd++)
        {
          if (cur->open_files[fd] == NULL)
            {
              cur->open_files[fd] = file;
              f->eax = fd;
              sema_up (&filesys_sema);
              return;
            }
        }
    }
  sema_up (&filesys_sema);
  f->eax = -1;
}

/* filesize system call handler */
static void
filesize_handler (struct intr_frame *f UNUSED)
{
  /* Matthew driving */
  int *fd_ptr = (int *)(f->esp + 4); 
  if (!is_valid_ptr (fd_ptr))
    thread_exit ();

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
          sema_down (&filesys_sema);
          f->eax = file_length (file);
          sema_up (&filesys_sema);
        }
    }
}


/* read system call handler */
static void
read_handler (struct intr_frame *f UNUSED)
{
  /* YunFan driving */
  void *size_ptr = f->esp + 12;
  char **buf = ((char **) (f->esp + 8));
  int fd, byte_read;
  if (!is_valid_ptr (size_ptr))
    thread_exit ();
  if (!is_valid_str (*buf))
    thread_exit ();

  fd = *(int *)(f->esp + 4);
  
  if (fd == 0)
    {
      /* Maybe synchronize keyboard input with filesys?? */
      input_getc (); /* read stdio and complete */
    }
  else if (fd < 0 || fd >= MAX_OPEN_FILES)
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
          /* Stephen driving */
          /* synchronize reading/writing */
          sema_down (&filesys_sema);
          byte_read = file_read (file, *buf, *(int *)size_ptr);
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
  char **buf = ((char **) (f->esp + 8));
  if (!is_valid_ptr (count_ptr))
    thread_exit ();
  if (!is_valid_ptr (*buf))
    thread_exit ();
  fd = *(int *)(f->esp + 4);
  buf_len = strlen (*buf);
  count = *((int *) count_ptr);
  if (fd == 1)
    {
      if (count > buf_len)
        count = buf_len;
      putbuf (*buf, count);
      bytes = count;
    }
  else if (fd < 1 || fd >= MAX_OPEN_FILES)
    bytes = 0;
  else
    {
      file = thread_current ()->open_files[fd];
      if (file == NULL)
        bytes = -1;
      /* Matthew driving */
      /* synchronize reading/writing */
      else 
        {
          sema_down (&filesys_sema);
          bytes = file_write (file, *buf, count);
          sema_up (&filesys_sema);
        }
    }
  f->eax = bytes;
}

/* seek system call handler */
static void
seek_handler (struct intr_frame *f UNUSED)
{
  /* David driving */
  int *pos_ptr = (int *)(f->esp + 8);
  int *fd_ptr = (int *)(f->esp + 4);
  struct file *file;
  if (!is_valid_ptr (pos_ptr))
      thread_exit ();
  if (*fd_ptr <= 1 || *fd_ptr >= MAX_OPEN_FILES);
  else
    {
      file = thread_current ()->open_files[*fd_ptr];
      if (file != NULL)
        {
          sema_down (&filesys_sema);
          file_seek (file, *pos_ptr);
          sema_up (&filesys_sema);
        }
    }
}

/* tell system call handler */
static void
tell_handler (struct intr_frame *f UNUSED)
{
  /* David driving */
  int *fd_ptr = (int *)(f->esp + 4);
  struct file *file;
  if (!is_valid_ptr (fd_ptr))
    thread_exit ();
  if (*fd_ptr <= 1 || *fd_ptr >= MAX_OPEN_FILES)
    f->eax = -1;
  else
    {
      file = thread_current ()->open_files[*fd_ptr];
      if (file == NULL)
        f->eax = -1;
      else
        {
          sema_down (&filesys_sema);
          f->eax = file_tell (file);
          sema_up (&filesys_sema);
        }
    }
}

/* close file system handler */
static void
close_handler (struct intr_frame *f UNUSED)
{
  /* Matthew driving */
  int *fd_ptr = (int *)(f->esp + 4);
  struct file *file;
  if (!is_valid_ptr (fd_ptr))
    thread_exit ();
  if (*fd_ptr <= 1 || *fd_ptr >= MAX_OPEN_FILES);
  else
    {
      file = thread_current ()->open_files[*fd_ptr];
      /* remove file from list of open files */
      thread_current ()->open_files[*fd_ptr] = NULL;
      sema_down (&filesys_sema);
      file_close (file);
      sema_up (&filesys_sema);
    }
}

static void 
chdir_handler (struct intr_frame *f)
{
  /* Matthew driving */
  char **buf = ((char **) f->esp + 1);
  if (!is_valid_ptr (buf))
    thread_exit ();
  if (!is_valid_str (*buf))
    thread_exit ();

  sema_down (&filesys_sema);
  f->eax = change_working_directory (*buf);
  sema_up (&filesys_sema);
}

static void mkdir_handler (struct intr_frame *f)
{
  /* YunFan driving */
  char **buf = ((char **) f->esp + 1);
  if (!is_valid_ptr (buf))
    thread_exit ();
  if (!is_valid_str (*buf))
    thread_exit ();

  sema_down (&filesys_sema);
  f->eax = filesys_create (*buf, 0, true);
  sema_up (&filesys_sema);
}

static void readdir_handler (struct intr_frame *f)
{
  printf ("readdir called\n");
}

static void isdir_handler (struct intr_frame *f)
{
  /* Stephen driving */
  int *fd_ptr = (int *)(f->esp + 4);
  struct file *file;
  if (!is_valid_ptr (fd_ptr))
    thread_exit ();
  if (*fd_ptr <= 1 || *fd_ptr >= MAX_OPEN_FILES)
    f->eax = 0;
  else
    {
      file = thread_current ()->open_files[*fd_ptr];
      /* remove file from list of open files */
      f->eax = file_isdir (file);
    }
}

static void inumber_handler (struct intr_frame *f)
{
  printf ("inumber called\n");
}


