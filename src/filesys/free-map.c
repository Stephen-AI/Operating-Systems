#include "filesys/free-map.h"
#include <bitmap.h>
#include <debug.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/synch.h"

static struct file *free_map_file;   /* Free map file. */
/* David driving */
static struct lock free_map_lock;    /* Synchronizes access to free map file */
static struct bitmap *free_map;      /* Free map, one bit per sector. */

/* Initializes the free map. */
void
free_map_init (void) 
{
  free_map = bitmap_create (block_size (fs_device));
  if (free_map == NULL)
    PANIC ("bitmap creation failed--file system device is too large");
  bitmap_mark (free_map, FREE_MAP_SECTOR);
  bitmap_mark (free_map, ROOT_DIR_SECTOR);
  /* David driving */
  lock_init (&free_map_lock);
}

/* Allocates CNT non-contiguous sectors from the free map and stores
   them consecutively in *SECTORP.
   Returns true if successful, false if not enough consecutive
   sectors were available or if the free_map file could not be
   written. */
bool
free_map_allocate (size_t cnt, block_sector_t *sectorp)
{
  /* YunFan driving */
  bool success = true;
  block_sector_t sector;
  size_t i, j;
  lock_acquire (&free_map_lock);
  for (i = 0; i < cnt; i++)
    {
      sector = bitmap_scan_and_flip (free_map, 2, 1, false);
      ASSERT (sector > 1);
      if (sector == BITMAP_ERROR)
      {
        /* allocation failed, so unflip anything that we allocated previously */
        for (j = 0; j < i; j++)
          {
            ASSERT (bitmap_test (free_map, sectorp[j]));
            bitmap_flip (free_map, sectorp[j]);
          }
        lock_release (&free_map_lock); 
        return false;
      }
      sectorp[i] = sector; 
    }
  /* write allocations to the free map */
  if (free_map_file != NULL && !bitmap_write (free_map, free_map_file))
    {
      /* if failed to write changes, deallocate all sectors allocated */
      for (j = 0; j < i; j++)
        {
          ASSERT (bitmap_test (free_map, sectorp[j]));
          bitmap_flip (free_map, sectorp[j]);
        }
      success = false;
    }
  lock_release (&free_map_lock);
  return success;
}

/* Makes CNT sectors starting from sectorp available for use.
   Takes an array of sectors to free */
void
free_map_release (block_sector_t *sectorp, size_t cnt)
{
  /* YunFan driving */
  size_t i;
  for (i = 0; i < cnt; i++)
    {
      /* shouldn't be trying to release free map or root dir sectors,
         and sectors being released should be allocated */
      ASSERT (sectorp[i] > 1);
      ASSERT (bitmap_test (free_map, sectorp[i]));
      bitmap_flip (free_map, sectorp[i]);
    }
  bitmap_write (free_map, free_map_file);
}

/* Opens the free map file and reads it from disk. */
void
free_map_open (void) 
{
  free_map_file = file_open (inode_open (FREE_MAP_SECTOR));
  if (free_map_file == NULL)
    PANIC ("can't open free map");
  if (!bitmap_read (free_map, free_map_file))
    PANIC ("can't read free map");
}

/* Writes the free map to disk and closes the free map file. */
void
free_map_close (void) 
{
  file_close (free_map_file);
}

/* Creates a new free map file on disk and writes the free map to
   it. */
void
free_map_create (void) 
{
  /* Create inode. */
  if (!inode_create (FREE_MAP_SECTOR, bitmap_file_size (free_map), false))
    PANIC ("free map creation failed");

  /* Write bitmap to file. */
  free_map_file = file_open (inode_open (FREE_MAP_SECTOR));
  if (free_map_file == NULL)
    PANIC ("can't open free map");
  if (!bitmap_write (free_map, free_map_file))
    PANIC ("can't write free map");
}
