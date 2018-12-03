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

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool isdir) 
{
  block_sector_t inode_sector = 0;
  struct dir *dir;
  bool success;
  char *path, **path_args;
  int path_length;
  struct inode *inode;
  if (strlen (name) == 0)
    return false;

  path = palloc_get_page (PAL_ZERO);
  path_args = palloc_get_page (PAL_ZERO);
  ASSERT (path != NULL && path_args != NULL);
  strlcpy (path, name, strlen (name) + 1);
  path_length = tokenize_path (path, path_args);

  if (name[0] == '/' || thread_current ()->cwd == NULL)
    dir = dir_open_root ();
  else
    dir = dir_reopen (thread_current ()->cwd);
  dir = path_lookup (dir, path_args, path_length - 1);
  success = (dir != NULL && free_map_allocate (1, &inode_sector));
  if (success && isdir)
    success = dir_create (get_dir_sector (dir), inode_sector, DIR_INIT) &&
              dir_add (dir, path_args[path_length - 1], inode_sector);
  else if (success)
    success = inode_create (inode_sector, initial_size, false) &&
              dir_add (dir, path_args[path_length - 1], inode_sector);
  
  if (!success && inode_sector != 0)
    {
      inode = inode_open (inode_sector);
      inode_remove (inode);
      inode_close (inode);
    }
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
  struct dir *dir;
  char *path, **path_args;
  int path_length;
  struct inode *inode = NULL;
  if (strlen (name) == 0)
    return NULL;
  /* if name is '/' */
  if (strlen (name) == 1 && name[0] == '/')
    {
      return file_open (inode_open (ROOT_DIR_SECTOR));
    }
  
  path = palloc_get_page (PAL_ZERO);
  path_args = palloc_get_page (PAL_ZERO);

  ASSERT (path != NULL && path_args != NULL);
  strlcpy (path, name, strlen (name) + 1);
  path_length = tokenize_path (path, path_args);
  if (name[0] == '/' || thread_current ()->cwd == NULL)
    dir = dir_open_root ();
  else
    dir = dir_reopen (thread_current ()->cwd);
  dir = path_lookup (dir, path_args, path_length - 1);
  if (dir == NULL)
    {
      palloc_free_page (path);
      palloc_free_page (path_args);
      return NULL;
    }

  dir_lookup (dir, path_args[path_length - 1], &inode);
  palloc_free_page (path);
  palloc_free_page (path_args);
  dir_close (dir);
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

  ASSERT (path != NULL && path_args != NULL);
  strlcpy (path, name, strlen (name) + 1);
  path_length = tokenize_path (path, path_args);
  if (name[0] != '/')
    dir = dir_reopen (thread_current ()->cwd);
  else
    dir = dir_open_root ();
  // printf ("called dir_reopen on cwd from filesys_open: %p\n", dir);

  dir = path_lookup (dir, path_args, path_length);
  if (dir == NULL)
    success = false;
  if (success)
    {
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
  struct dir *dir;
  bool success;
  char *path, **path_args;
  int path_length;

  if (strlen(name) == 1 && name[0] == '/')
    return false;
  path = palloc_get_page (PAL_ZERO);
  path_args = palloc_get_page (PAL_ZERO);

  ASSERT (path != NULL && path_args != NULL);
  strlcpy (path, name, strlen (name) + 1);
  path_length = tokenize_path (path, path_args);

  if (name[0] == '/' || thread_current ()->cwd == NULL)
    dir = dir_open_root ();
  else
    dir = dir_reopen (thread_current ()->cwd);

  dir = path_lookup (dir, path_args, path_length - 1);
  if (dir == NULL)
    return false;
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
