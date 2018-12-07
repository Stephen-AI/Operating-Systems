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
#include "threads/palloc.h"
#include "threads/pte.h"

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
static bool is_valid_buf (char *buf, size_t bytes_to_check);
static bool check_writable_page (uint32_t *pte);
/* Stephen driving */
static void chdir_handler (struct intr_frame *f);
static void mkdir_handler (struct intr_frame *f);
static void readdir_handler (struct intr_frame *f);
static void isdir_handler (struct intr_frame *f);
static void inumber_handler (struct intr_frame *f);

/* check if a string is in valid memory */
bool 
is_valid_str (char *str)
{
  /* YunFan driving */
  void *upper = pg_round_up (str);
  
  if (!is_valid_ptr (str))
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
          /* David driving */
          if (!is_valid_ptr (str))
            return false;
          else 
            upper = pg_round_up (str);
        }
    }
  return true;
}

/* check if a buffer is in valid user memory and is writable */
bool is_valid_buf (char *buf, size_t bytes_to_check)
{
  /* David driving */
  uint32_t *pte, *pagedir;
  size_t count = 0;
  pagedir = thread_current ()->pagedir;
  while (count < bytes_to_check)
    {
      /* use the pte because we need to check if page is writable */
      pte = lookup_page (pagedir, buf, false);
      if (!check_writable_page (pte))
        return false;
      count += ((size_t)pg_round_down (buf + (PGSIZE)) - (size_t)buf);
      buf = pg_round_down (buf + PGSIZE);
    }
  return true;
}

/* checks validity of a page table entry for writing purposes, checks if 
   page is present, a user page, and writable */
bool check_writable_page (uint32_t *pte)
{
  /* David driving */
  return !(pte == NULL || 
           !(*pte & PTE_P) || 
           !(*pte & PTE_U) || 
           !(*pte & PTE_W));
}

void
syscall_init (void) 
{
  /* Matthew driving */
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Makes sure a pointer points to valid user memory */
bool 
is_valid_ptr (void *ptr)
{
  /* Stephen drove here */
  struct thread *cur = thread_current ();
  /* David driving */
  return ptr != NULL && is_user_vaddr (ptr) && 
         pagedir_get_page (cur->pagedir, ptr) != NULL;
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
  char *buf, *s;

  if (!is_valid_ptr (file_ptr))
    thread_exit ();

  buf = *((char **) f->esp + 1);
  if (!is_valid_str (buf))
    thread_exit ();
  s = palloc_get_page (PAL_ZERO);
  /* copy the name of the file being exec'd into s from buf */
  strlcpy (s, buf, strlen (buf) + 1);
  f->eax = process_execute (s);
  palloc_free_page (s);
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
  f->eax = filesys_create (*buf, *(int *)size_ptr, false);
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
  
  f->eax = filesys_remove (*file_name);
}

/* open file system call handler */
static void
open_handler (struct intr_frame *f UNUSED)
{
  /* David driving */
  void *file_ptr = f->esp + 4;
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
  
  if ((file = filesys_open (*buf)) != NULL) 
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
          f->eax = file_length (file);
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
  if (!is_valid_buf (*buf, *(int *)size_ptr))
    thread_exit ();

  fd = *(int *)(f->esp + 4);
  
  if (fd == 0)
    {
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
          byte_read = file_read (file, *buf, *(int *)size_ptr);
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
      else 
        {
          if (!file_isdir (file))
            bytes = file_write (file, *buf, count);
          else
            bytes = -1;
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
          file_seek (file, *pos_ptr);
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
          f->eax = file_tell (file);
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
      
      file_close (file);
    }
}

/* changes process's current working directory */
static void 
chdir_handler (struct intr_frame *f)
{
  /* Matthew driving */
  char **buf = ((char **) f->esp + 1);
  if (!is_valid_ptr (buf))
    thread_exit ();
  if (!is_valid_str (*buf))
    thread_exit ();
  
  f->eax = change_working_directory (*buf);
}

/* create a directory */
static void mkdir_handler (struct intr_frame *f)
{
  /* YunFan driving */
  char **buf = ((char **) f->esp + 1);
  if (!is_valid_ptr (buf))
    thread_exit ();
  if (!is_valid_str (*buf))
    thread_exit ();
  
  /* calls filesys_create with a size of 0, because directories are initialized
     to an arbitrary initial starting size anyway */
  f->eax = filesys_create (*buf, 0, true);
}

/* reads entries in a directory and copies them to buf */
static void readdir_handler (struct intr_frame *f)
{
  /* Stephen driving */
  int *fd_ptr = (int *)(f->esp + 4);
  char **buf = ((char **) f->esp + 2);
  struct file *file;
  if (!is_valid_ptr (fd_ptr))
    thread_exit ();
  if (!is_valid_buf (*buf, READDIR_MAX_LEN + 1))
    thread_exit ();

  f->eax = false;
  file = thread_current ()->open_files[*fd_ptr];
  if (file != NULL)
    {
      /* make sure fd corresponds to a directory before trying to read it */
      if (file_isdir (file))
        {
          if (file != NULL)
            f->eax = dir_readdir ((struct dir *)file, *buf);
        }
    }
}

/* checks whether an fd corresponds to a directory */
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
      if (file == NULL)
        f->eax = 0;
      else
        f->eax = file_isdir (file);
    }
}

/* returns the inumber (sector number) of a file's inode */
static void inumber_handler (struct intr_frame *f)
{
  /* Matthew driving */
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
        f->eax = file_get_inumber (file);
    }
}


