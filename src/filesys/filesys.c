#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/palloc.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);
/* David driving */
static struct dir *get_start_dir (const char *name);
/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* returns the starting directory of a relative or absolute path.
   if the first character in the path is '/', or if the thread's cwd isn't set,
   then start from root, otherwise start from the thread's current working
   directory */
static struct dir *
get_start_dir (const char *name)
{
  /* David driving */
  if (name[0] == '/' || thread_current ()->cwd == NULL)
    return dir_open_root ();
  else
    return dir_reopen (thread_current ()->cwd);
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool isdir) 
{
  /* David driving */
  block_sector_t inode_sector = 0;
  struct dir *dir;
  bool success;
  char *path, **path_args;
  int path_length;
  struct inode *inode;
  /* ignore calls with empty names */
  if (strlen (name) == 0)
    return false;

  /* allocate pages for parsing the path, call tokenize path to parse path */
  path = palloc_get_page (PAL_ZERO);
  path_args = palloc_get_page (PAL_ZERO);
  if (path == NULL || path_args == NULL)
    {
      palloc_free_page (path);
      palloc_free_page (path_args);
      return false;
    }
  strlcpy (path, name, strlen (name) + 1);
  path_length = tokenize_path (path, path_args);

  /* if the first character in the path is '/', or if the thread's cwd isn't
     set, then start from root, otherwise start from  */
  dir = get_start_dir (name);
  /* traverse up to second to last argument */
  dir = path_lookup (dir, path_args, path_length - 1);

  /* make sure we found the directory, and were able to get a disk sector for
     the inode */
  success = (dir != NULL && free_map_allocate (1, &inode_sector));
  /* create the file or directory with the name of the last token in the
     path */
  if (success && isdir)
    success = dir_create (get_dir_sector (dir), inode_sector, DIR_INIT) &&
              dir_add (dir, path_args[path_length - 1], inode_sector);
  else if (success)
    success = inode_create (inode_sector, initial_size, false) &&
              dir_add (dir, path_args[path_length - 1], inode_sector);
  
  if (!success && inode_sector != 0)
    {
      /* if we failed to add the file or directory, then deallocate all of the
         sectors allocated to the inode */
      inode = inode_open (inode_sector);
      inode_remove (inode);
      inode_close (inode);
    }
  /* close the directory once we're done with it */
  dir_close (dir);
  palloc_free_page (path);
  palloc_free_page (path_args);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  /* Stephen driving */
  struct dir *dir;
  char *path, **path_args;
  int path_length;
  struct inode *inode = NULL;
  if (strlen (name) == 0)
    return NULL;
  /* if name is '/', it'll get chewed up by tokenize path */
  if (strlen (name) == 1 && name[0] == '/')
    return dir_open (inode_open (ROOT_DIR_SECTOR));
  
  path = palloc_get_page (PAL_ZERO);
  path_args = palloc_get_page (PAL_ZERO);

  if (path == NULL || path_args == NULL)
    {
      palloc_free_page (path);
      palloc_free_page (path_args);
      return NULL;
    }
  strlcpy (path, name, strlen (name) + 1);
  path_length = tokenize_path (path, path_args);
  dir = get_start_dir (name);
  /* traverse up to the second to last argument */
  dir = path_lookup (dir, path_args, path_length - 1);
  /* failed to traverse the path */
  if (dir == NULL)
    {
      palloc_free_page (path);
      palloc_free_page (path_args);
      return NULL;
    }

  /* look for the file */
  dir_lookup (dir, path_args[path_length - 1], &inode);
  palloc_free_page (path);
  palloc_free_page (path_args);
  dir_close (dir);
  /* perform a dir open if the file found is a directory */
  if (inode != NULL && inode_is_directory (inode))
    return (struct file *)dir_open (inode);
  return file_open (inode);
}

/* changes the current thread's working directory to the working directory
   specified by name */
bool
change_working_directory (const char *name)
{
  /* David driving */
  bool success = true;
  struct dir *dir;
  char *path, **path_args;
  int path_length;
  if (strlen (name) == 0)
    return false;
  path = palloc_get_page (PAL_ZERO);
  path_args = palloc_get_page (PAL_ZERO);

  if (path == NULL || path_args == NULL)
    {
      palloc_free_page (path);
      palloc_free_page (path_args);
      return false;
    }
  strlcpy (path, name, strlen (name) + 1);
  path_length = tokenize_path (path, path_args);
  dir = get_start_dir (name);

  /* traverses up to the last argument of path_args */
  dir = path_lookup (dir, path_args, path_length);
  if (dir == NULL)
    success = false;
  if (success)
    {
      /* close the thread's previous current working directory */
      dir_close (thread_current ()->cwd);
      thread_current ()->cwd = dir;
    }
  palloc_free_page (path);
  palloc_free_page (path_args);
  return success;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  /* Stephen driving */
  struct dir *dir;
  bool success;
  char *path, **path_args;
  int path_length;

  /* don't allow a process to remove root */
  if (strlen(name) == 1 && name[0] == '/')
    return false;
  path = palloc_get_page (PAL_ZERO);
  path_args = palloc_get_page (PAL_ZERO);

  if (path == NULL || path_args == NULL)
    {
      palloc_free_page (path);
      palloc_free_page (path_args);
      return false;
    }
  strlcpy (path, name, strlen (name) + 1);
  path_length = tokenize_path (path, path_args);

  dir = get_start_dir (name);

  /* traverse up to the second to last name in the path */
  dir = path_lookup (dir, path_args, path_length - 1);
  if (dir == NULL)
    return false;
  
  /* don't allow a process to remove '.' or ".." */
  if (strcmp (path_args[path_length - 1], ".") && 
      strcmp (path_args[path_length - 1], ".."))
    success = dir_remove (dir, path_args[path_length - 1]);
  else
    success = false;
  palloc_free_page (path);
  palloc_free_page (path_args);
  dir_close (dir);
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
