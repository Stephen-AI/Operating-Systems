#include "filesys/inode.h"
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_LIMIT 5120             /* upper limit for direct block access */
#define FIRST_LEVEL_LIMIT 70656       /* upper limit for first level block   */
#define SECOND_LEVEL_LIMIT 8459264    /* upper limit for second level block  */
/* number of bytes that fits in an indirect block */
#define FIRST_LEVEL_SIZE (BLOCK_SECTOR_SIZE * (BLOCK_SECTOR_SIZE / 4))
/* number of sectors per indirect block */
#define INDIRECT_SECTORS (BLOCK_SECTOR_SIZE / (sizeof BLOCK_SECTOR_SIZE))
/* number of sectors in an inode's direct block */
#define DIRECT_SECTORS 10
/* static array of zeroes used for zeroing out blocks */
static char zeros[BLOCK_SECTOR_SIZE];

/* enums for identifying index type of a byte query */
enum level_type
  {
    DIRECT_BLOCK,                       /* direct block access */
    FIRST_LEVEL,                        /* first level block access */
    SECOND_LEVEL,                       /* second level block access */
    ERR                                 /* access past file limit */
  };

/* struct for storing indices on calculated positions for a particular 
   file offset */
struct byte_query
  {
    enum level_type type;               /* indicates what indices to read */
    off_t direct_block_index;           /* direct block index */
    off_t second_level_index;           /* second indirection block index */
    off_t first_level_index;            /* first indirection block index */
  };

static void inode_free_sectors (off_t, struct inode_disk *);
static bool allocate_first_level (block_sector_t *, off_t , size_t);
static bool allocate_second_level (block_sector_t *, off_t, off_t, 
                                   size_t, struct inode_disk *);
static bool free_second_level (struct inode_disk *, off_t, off_t, size_t);
static bool free_first_level (struct inode_disk *, block_sector_t,
                              off_t, size_t);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* calculates how to index into the sectors in a disk inode given a certain
   offset, type field will identify whether an offset is in a direct, indirect
   or double indirect block */
static void 
calculate_sector_indices (struct byte_query *byte_query, off_t pos)
{
  /* Stephen driving */
  byte_query->direct_block_index = -1;
  byte_query->first_level_index = -1;
  byte_query->second_level_index = -1;
  if (pos < DIRECT_LIMIT)
    {
      byte_query->direct_block_index = pos / BLOCK_SECTOR_SIZE;
      byte_query->type = DIRECT_BLOCK;
    }
  else if (pos < FIRST_LEVEL_LIMIT)
    {
      byte_query->first_level_index = (pos - DIRECT_LIMIT) / BLOCK_SECTOR_SIZE;
      byte_query->type = FIRST_LEVEL;
    }
  else if (pos < SECOND_LEVEL_LIMIT)
    {
      byte_query->second_level_index = (pos - FIRST_LEVEL_LIMIT) / 
                                       FIRST_LEVEL_SIZE;
      byte_query->first_level_index = 
      (pos - FIRST_LEVEL_LIMIT - FIRST_LEVEL_SIZE * 
      byte_query->second_level_index) / BLOCK_SECTOR_SIZE;
      byte_query->type = SECOND_LEVEL;
    }
  else
      byte_query->type = ERR;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  /* David driving */
  block_sector_t *first_level, *second_level, retval;
  struct byte_query result;
  ASSERT (inode != NULL);
  struct inode_disk disk_data = inode->data;
  int first_ind, second_ind;
  first_level = NULL;
  second_level = NULL;
  /* calculate indices for position */
  calculate_sector_indices (&result, pos);
  if (result.type != ERR)
    {
      /* position in file is less than number of bytes contained in direct
         blocks, index directly into direct blocks */
      if (result.type == DIRECT_BLOCK)
        {
          return disk_data.direct_blocks[result.direct_block_index];
        }
      /* position is less than number of bytes contained in first level of
         indirection, calculate where to index into first level of indirection,
         and index directly into it after reading in the first level */
      else if (result.type == FIRST_LEVEL)
        {
          first_ind = result.first_level_index;
          ASSERT (disk_data.first_level != 0);
          first_level = palloc_get_page (PAL_ZERO);
          ASSERT (first_level != NULL);
          block_read (fs_device, disk_data.first_level, first_level);
          retval = first_level[first_ind];
          palloc_free_page (first_level);
          return retval;
        }
      /* position is in second level of indirection */
      else
        {
          /* calculate which first level block in the second level of 
             indirection contains pos */
          second_ind = result.second_level_index;
          first_ind = result.first_level_index;
          ASSERT (disk_data.second_level != 0);
          /* read in second level block */
          second_level = palloc_get_page (PAL_ZERO);
          ASSERT (second_level != NULL);
          block_read (fs_device, disk_data.second_level, second_level);
          ASSERT (second_level[second_ind] != 0);
          first_level = palloc_get_page (PAL_ZERO);
          ASSERT (first_level != NULL);
          /* read in the first level block that contains data */
          block_read (fs_device, second_level[second_ind], first_level);
          palloc_free_page (second_level);
          /* return sector number of file position in first level of 
             indirection */
          retval = first_level[first_ind];
          palloc_free_page (first_level);
          return retval;
        }
    }
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
/* Lock for synchronizing opening and closing of inode structs */
/* David driving */
static struct lock open_inodes_lock;
/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  /* David driving */
  lock_init (&open_inodes_lock);
}

/* extends an inode starting from a certain starting offset in bytes to be able 
   to accomodate writes up to a certain ending point. allocates sectors to 
   inode, but does not change the length. Caller must change length */
bool inode_extend (struct inode_disk *disk_inode, off_t start, off_t length)
{
  /* Stephen driving */
  struct byte_query index;
  off_t direct_idx = -1, second_idx = -1, first_idx = -1;
  off_t sec_alloc, sec_len;
  bool success = true;
  off_t i;
  block_sector_t *level1, *level2;
  /* calculate number of sectors to allocate */
  sec_len = bytes_to_sectors (length) - bytes_to_sectors (start);
  /* if starting point is at a block boundary, that block isn't allocated */
  if (start % BLOCK_SECTOR_SIZE != 0)
    start += BLOCK_SECTOR_SIZE;
  calculate_sector_indices (&index, start);
  if (index.type == ERR)
    return false;
  if (index.type == DIRECT_BLOCK && sec_len > 0)
    {
      direct_idx = index.direct_block_index;
      /* calculate the number of direct blocks to allocate */
      sec_alloc = DIRECT_SECTORS - direct_idx >= sec_len ? 
                  sec_len : DIRECT_SECTORS - direct_idx;
      if (free_map_allocate (sec_alloc, disk_inode->direct_blocks + direct_idx))
        {
          for (i = direct_idx; i < direct_idx + sec_alloc ; i++)
            {
              block_write (fs_device, disk_inode->direct_blocks[i], zeros);
            }
          sec_len -= sec_alloc;
          start += BLOCK_SECTOR_SIZE * sec_alloc;
        }
      else
        {
          success = false;
        }
      if (success)
        disk_inode->sectors_allocated += sec_alloc;
      /* recalculate sector indices for fall-through */
      calculate_sector_indices (&index, start);
    }
  
  /* Matthew driving */
  if (success && index.type == FIRST_LEVEL && sec_len > 0)
    {
      level1 = palloc_get_page (PAL_ZERO);
      if (level1 == NULL)
        return false;
      first_idx = index.first_level_index;
      sec_alloc = INDIRECT_SECTORS - first_idx >= sec_len ? 
                  sec_len : INDIRECT_SECTORS - first_idx;

      /* Partially filled first level */
      if (disk_inode->first_level != 0)
        block_read (fs_device, disk_inode->first_level, level1 + 1);
      else
        free_map_allocate (1, &disk_inode->first_level);

      /* allocate first level expects the sector of the indirect block in
         the 0th index */
      level1[0] = disk_inode->first_level;
      
      /* allocate starting from first_ind + 1 because the 0th index contains
         the indirection block sector */
      if (!allocate_first_level (level1, first_idx + 1, sec_alloc))
        {
          success = false;
        }
      else
        {
          sec_len -= sec_alloc;
          start += BLOCK_SECTOR_SIZE * sec_alloc;
        }
      if (success)
        disk_inode->sectors_allocated += sec_alloc;
      /* recalculate sector indices for fall-through behavior */
      calculate_sector_indices (&index, start);
      palloc_free_page (level1);
    }
  
  if (success && index.type == SECOND_LEVEL && sec_len > 0)
    {
      level2 = palloc_get_page (PAL_ZERO);
      if (level2 == NULL)
        return false;
      first_idx = index.first_level_index;
      second_idx = index.second_level_index;
      
      /* Partially filled second level, if not partially filled, then the
         second level needs to be allocated */
      if (disk_inode->second_level != 0)
        block_read (fs_device, disk_inode->second_level, level2 + 1);
      else
        if (!free_map_allocate (1, &disk_inode->second_level))
          {
            success = false;
          }
      /* allocate_second_level expects the second level block sector at the 0th
         index */
      level2[0] = disk_inode->second_level;
      
      if (!allocate_second_level (level2, first_idx, second_idx + 1, 
                                  sec_len, disk_inode))
        {
          success = false;
        }
      palloc_free_page (level2);
    }

  /* if we failed to extend, free all of the sectors starting from the current
     length of the disk inode */
  if (!success)
    inode_free_sectors (disk_inode->length, disk_inode);
  return success;
}

/* allocates disk sectors for inode by calling extend from 0 to length, 
   records whether inode is for a directory or a file */
bool
inode_create (block_sector_t sector, off_t length, bool dir)
{
  /* Stephen driving */
  struct inode_disk *disk_inode = NULL;
  bool success = true;
  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->magic = INODE_MAGIC;
      disk_inode->sectors_allocated = 0;
      /* extend the inode */
      success = inode_extend (disk_inode, 0, length);

      if (!success)
        {
          inode_free_sectors (0, disk_inode);
          free (disk_inode);
        }
      else
        {
          ASSERT (disk_inode->sectors_allocated == sectors);
          disk_inode->isdir = dir;
          disk_inode->length = length;
          block_write (fs_device, sector, disk_inode);
        }
    }
  return success;
}

/* allocates length sectors for a first level indirection block, expects 
   a non-NULL first_level page, and expects the 0th index in first level
   to contain the indirect block's sector */
static bool
allocate_first_level (block_sector_t *first_level, off_t start, size_t length)
{
  /* David driving */
  bool success = false;
  size_t i;

  ASSERT (first_level != NULL);

  /* allocate sectors_to_allocate sectors plus one additional sector for
     the first level of indirection. first level of indirection sector will be 
     the first value in *first_level */
  if (free_map_allocate (length, first_level + start))
    {
      for (i = start; i < start + length; i++)
        {
          /* zeros out any allocated sectors */
          block_write (fs_device, first_level[i], zeros);
        }
      /* writes the first level of indirection block to disk */
      ASSERT (first_level[0] > 1);
      block_write (fs_device, first_level[0], first_level + 1);
      success = true;
    }
  return success;
}

/* allocates length sectors for a second level indirect block, expects a 
   non-NULL second_level page, and expects the 0th index in second level to 
   contain the second level indirection block's sector */
static bool
allocate_second_level (block_sector_t *second_level, off_t first_ind, 
                       off_t sec_ind, size_t length, 
                       struct inode_disk *disk_inode)
{
  /* YunFan driving */
  bool success = true;
  off_t num_sector;
  block_sector_t *first_level = palloc_get_page (PAL_ZERO);
  if (first_level == NULL)
    return false;

  while (length != 0)
    {
      /* the first level indirection block in the second level indirection block
         needs to be allocated */
      if (second_level[sec_ind] == 0) 
        {
          if (!free_map_allocate (1, second_level + sec_ind))
            {
              palloc_free_page (first_level);
              success = false;
              break;
            }
          first_level[0] = second_level[sec_ind];
        }
      else
        {
          first_level[0] = second_level[sec_ind];
          block_read (fs_device, second_level[sec_ind], first_level + 1);
        }
      /* if the length needed is larger than an indirect block, then truncate */
      num_sector = length > INDIRECT_SECTORS - first_ind ? 
                   INDIRECT_SECTORS - first_ind : length;
      if (!allocate_first_level (first_level, first_ind + 1, num_sector))
        {
          palloc_free_page (first_level);
          success = false;
          break;
        }
      length -= num_sector;
      disk_inode->sectors_allocated += num_sector;
      sec_ind++;
      first_ind = 0;
    }
  /* write the second level indirect block to disk */
  if (success)
    block_write (fs_device, second_level[0], second_level + 1);
  palloc_free_page (first_level);
  return success;
}

/* frees sectors in a first level indirect block, starting from an index */
static bool
free_first_level (struct inode_disk *disk_inode, block_sector_t level_sector, 
                  off_t index, size_t free_sec)
{
  /* Stephen driving */
  ASSERT (level_sector > 1);
  ASSERT (index + free_sec <= INDIRECT_SECTORS);
  block_sector_t *first_level = NULL;
  first_level = palloc_get_page (PAL_ZERO);
  if (first_level == NULL)
    return false;

  /* shouldn't be trying to free sectors corresponding to bitmap or root dir */
  ASSERT (level_sector > 1);
  block_read (fs_device, level_sector, first_level + 1);
  first_level[0] = level_sector;

  /* if we're freeing 0th index in the first level indirect block, then we 
     free the sector containing the blocks */
  if (index == 0)
    free_map_release (first_level, free_sec + 1);
  else
    free_map_release (first_level + index + 1, free_sec);
  disk_inode->sectors_allocated -= free_sec;
  palloc_free_page (first_level);
  return true;
}

/* frees sectors in a second level indirect block, starting from a second 
   level index and a first level index */
static bool
free_second_level (struct inode_disk *disk_inode, off_t first_ind, 
                   off_t sec_ind, size_t free_sec)
{
  /* Stephen driving */
  ASSERT (disk_inode->second_level > 1);
  block_sector_t *second_level = NULL;
  size_t sectors_to_free;

  /* if our starting point is 0 in the second level indirect block and the
     first level indirect block, then we want to free the second level indirect
     block sector */
  bool free_second_level = (first_ind == 0 && sec_ind == 0);

  second_level = palloc_get_page (PAL_ZERO);
  if (second_level == NULL)
    return false;

  /* read in the second level */
  block_read (fs_device, disk_inode->second_level, second_level + 1);
  second_level[0] = disk_inode->second_level;

  while (free_sec > 0)
    {
      /* calculate how many sectors free_first_level will free */
      sectors_to_free = first_ind + free_sec > INDIRECT_SECTORS ? 
                        INDIRECT_SECTORS - first_ind : free_sec;
      if (!free_first_level (disk_inode, second_level[sec_ind], 
                             first_ind, sectors_to_free))
        {
          palloc_free_page (second_level);
          return false;
        }

      first_ind = 0;
      sec_ind++;
      free_sec -= sectors_to_free;            
    }
  if (free_second_level)
    free_map_release (second_level, 1);
  palloc_free_page (second_level);
  return true;
}

/* Frees sectors for a disk inode starting from the sector after the sectors
   needed for the disk inode to have a length of start */
static void
inode_free_sectors (off_t start, struct inode_disk *disk_inode)
{
  /* Stephen driving */
  struct byte_query query;
  size_t sec_len = disk_inode->sectors_allocated - 
                           bytes_to_sectors (start);
  off_t i = -1, j = -1;
  size_t sectors_to_free;
  if (start % BLOCK_SECTOR_SIZE != 0)
    start = start + BLOCK_SECTOR_SIZE;

  calculate_sector_indices (&query, start);
  /* deallocates direct blocks */
  if (query.type == DIRECT_BLOCK && sec_len > 0)
    {
      i = query.direct_block_index;
      /* calculate number of sectors to free */
      sectors_to_free = DIRECT_SECTORS - i >= sec_len ? 
                        sec_len : DIRECT_SECTORS - i;
      free_map_release (disk_inode->direct_blocks + i, sectors_to_free);
      /* increment start and recalculate indices to properly fall through */
      start += BLOCK_SECTOR_SIZE * sectors_to_free;
      sec_len -= sectors_to_free;
      disk_inode->sectors_allocated -= sectors_to_free;
      calculate_sector_indices (&query, start);
    }
  
  /* Matthew driving */
  if (query.type == FIRST_LEVEL && sec_len > 0)
    {
      i = query.first_level_index;
      sectors_to_free = INDIRECT_SECTORS - i >= sec_len ? 
                        sec_len : INDIRECT_SECTORS - i;
      /* freeing a first level should succeed, if it doesn't then we could leak
         block sectors */
      ASSERT (free_first_level (disk_inode, disk_inode->first_level, i, 
                                sectors_to_free));
      start += BLOCK_SECTOR_SIZE * sectors_to_free;
      sec_len -= sectors_to_free;
      calculate_sector_indices (&query, start);
    }
    
  if (query.type == SECOND_LEVEL && sec_len > 0)
    {
      i = query.first_level_index;
      j = query.second_level_index;
      /* freeing a second level should succeed, if it doesn't then we could leak
         block sectors */
      ASSERT (free_second_level (disk_inode, i, j, sec_len));
    }

}
/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;
  /* Check whether this inode is already open. */
  /* David driving */
  /* synchronizes access to open inodes list */
  lock_acquire (&open_inodes_lock);
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          lock_release (&open_inodes_lock);
          inode_reopen (inode);
          return inode; 
        }
    }


  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    {
      lock_release (&open_inodes_lock);
      return NULL;
    }

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init (&inode->inode_lock);
  block_read (fs_device, inode->sector, &inode->data);
  /* initialize directory lock if the inode corresponds to a directory */
  if (inode_is_directory (inode))
    lock_init (&inode->dir_lock);
  lock_release (&open_inodes_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  /* David driving */
  lock_acquire (&inode->inode_lock);
  if (inode != NULL)
    inode->open_cnt++;
  lock_release (&inode->inode_lock);
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk. (Does it?  Check code.)
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;
  /* David driving */
  /* synchronize decrementing inode's open_cnt, and removing from the open
     inodes list */
  lock_acquire (&inode->inode_lock);
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      lock_acquire (&open_inodes_lock);
      list_remove (&inode->elem);
      lock_release (&open_inodes_lock);
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          /* Stephen driving */
          inode_free_sectors (0, &inode->data);
          free_map_release (&inode->sector, 1);
        }
      else
        {
          block_write (fs_device, inode->sector, &inode->data);
        }
      /* unnecessary to release lock because it's going to be freed, 
         but just to be safe */
      lock_release (&inode->inode_lock);
      free (inode);
      inode = NULL; 
    }
  /* check if we freed the inode before we lock release */
  if (inode != NULL)
    lock_release (&inode->inode_lock);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  /* Matthew driving */
  lock_acquire (&inode->inode_lock);
  ASSERT (inode != NULL);
  inode->removed = true;
  lock_release (&inode->inode_lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;
  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* returns whether an inode has been removed or not, must be called with the
   inode lock */
bool
inode_is_removed (struct inode *inode)
{
  /* David driving */
  ASSERT (inode != NULL);
  return inode->removed;
}

/* Determines whether an inode corresponds to a file or to a directory, 
   unsynchronized because whether an inode is a directory or file will not
   change */
bool
inode_is_directory (struct inode *inode)
{
  /* David driving */
  ASSERT (inode != NULL);
  return inode->data.isdir;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  /* David driving */
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;
  off_t inode_len = inode_length (inode);
  off_t new_len = size + offset;
  /* variable to indicate whether extension is necessary */
  bool extended = offset + size > inode_len;
  if (inode->deny_write_cnt)
    return 0;
  if (extended)
    {
      /* synchronize extension of file, acquire and hold the lock until our
         bytes have been written */
      lock_acquire (&inode->inode_lock);
      if (!inode_extend (&inode->data, inode_len, offset + size))
        { 
          inode_free_sectors (inode_length (inode), &inode->data);
          lock_release (&inode->inode_lock);
          return 0;
        }
    }
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      /* if falling into the write, disk inode should have enough sectors to 
         accomodate the write */
      ASSERT (inode->data.sectors_allocated * BLOCK_SECTOR_SIZE > offset);
      ASSERT (sector_idx);
      /* bytes left in sector, inode length may not be updated at this point */
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  /* update length only after writing is finished to ensure atomicity of 
     extending and writing new sectors */
  if (extended && new_len > inode->data.length)
    inode->data.length = new_len;

  if (extended)
    lock_release (&inode->inode_lock);

  free (bounce);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  /* Matthew driving */
  lock_acquire (&inode->inode_lock);
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  lock_release (&inode->inode_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  /* Matthew driving */
  lock_acquire (&inode->inode_lock);
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release (&inode->inode_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
