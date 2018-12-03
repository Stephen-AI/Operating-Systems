#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "filesys/free-map.h"

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };
static struct lock *dir_get_lock (struct dir *dir);
static void dir_decr_file_cnt (struct dir *dir);
static void dir_incr_file_cnt (struct dir *dir);
static bool remove_dir (struct inode *inode);

/* Gets the directory lock for a struct dir */
static struct lock *
dir_get_lock (struct dir *dir)
{
  ASSERT (inode_is_directory (dir->inode));
  return &dir->inode->dir_lock;
}

static void 
dir_incr_file_cnt (struct dir *dir)
{
  dir->inode->data.num_files++;
}

static void 
dir_decr_file_cnt (struct dir *dir)
{
  dir->inode->data.num_files--;
}

block_sector_t
get_dir_sector (struct dir *dir)
{
  ASSERT (dir != NULL);
  return dir->inode->sector;
}

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t parent_sec, block_sector_t sector, size_t entry_cnt)
{
  struct dir *cur_dir;
  if (inode_create (sector, (2 + entry_cnt) * sizeof (struct dir_entry), true))
    {
      cur_dir = dir_open (inode_open (sector));
      dir_add (cur_dir, "..", parent_sec);
      dir_add (cur_dir, ".", sector);
      dir_close (cur_dir);
      return true;
    }
  else
    return false;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  ASSERT (inode->data.isdir);
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 2 * sizeof (struct dir_entry);
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  ASSERT (dir != NULL);
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  if (inode_is_removed (dir->inode))
    return false;
  if (!inode_is_directory (dir->inode))
    return false;
  
  struct lock *dir_lock = dir_get_lock (dir);
  lock_acquire (dir_lock);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  lock_release (dir_lock);
  return *inode != NULL;
}

int
tokenize_path (char *name, char **argv)
{
  int num_tokens = 0;
  char *save_ptr, *token;
  for (token = strtok_r (name, "/", &save_ptr); token != NULL;
       token = strtok_r (NULL, "/", &save_ptr))
    {
      argv[num_tokens++] = token;
    }
  argv[num_tokens] = NULL;
  return num_tokens;
}

struct dir *
path_lookup (struct dir *dir, char **path, int path_length)
{
  int i = 0;
  struct dir *cur_dir = dir;
  struct inode *inode;
  for (i = 0; i < path_length; i++)
    {
      if (!dir_lookup (cur_dir, path[i], &inode))
        {
          dir_close (cur_dir);
          return NULL;
        }
      dir_close (cur_dir);
      if (inode_is_directory (inode))
        {
          cur_dir = dir_open (inode);
        }
      else
        return NULL;
    }
  return cur_dir;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;
  struct lock *dir_lock = dir_get_lock (dir);
  if (inode_is_removed (dir->inode))
    return false;
  lock_acquire (dir_lock);

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
  if (success)
    dir_incr_file_cnt (dir);

 done:
  lock_release (dir_lock);
  return success;
}

/* mark the dirctory as removed by taking in the inode of the directory */
static bool
remove_dir (struct inode *inode)
{
  /* YunFan driving */
  bool success = false;
  lock_acquire (&inode->dir_lock);

  if (inode->data.num_files == 2)
    {
      inode_remove (inode);
      success = true;
    }
  
  lock_release (&inode->dir_lock);
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  if (inode_is_removed (dir->inode))
    return false;
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* YunFan driving */
  struct lock *dir_lock = dir_get_lock (dir);
  lock_acquire (dir_lock);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  if (inode_is_directory (inode))
    {
      if (!remove_dir (inode))
        goto done;
    }

  /* Erase directory entry. */
  e.in_use = false;
  dir_decr_file_cnt (dir);
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  lock_release (dir_lock);
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;
  struct lock *dir_lock = dir_get_lock (dir);

  if (inode_is_removed (dir->inode))
    return false;
  lock_acquire (dir_lock);
  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          lock_release (dir_lock);
          return true;
        } 
    }
  lock_release (dir_lock);
  return false;
}
