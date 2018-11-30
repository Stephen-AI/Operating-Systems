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
#define FIRST_LEVEL_SIZE (BLOCK_SECTOR_SIZE * (BLOCK_SECTOR_SIZE / 4))
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
static char zeros[BLOCK_SECTOR_SIZE];

static void inode_free_sectors (struct inode_disk *);
static bool allocate_first_level (block_sector_t *, off_t , size_t);
static bool allocate_second_level (block_sector_t *, off_t, off_t, size_t);

enum level_type
  {
    DIRECT_BLOCK,
    FIRST_LEVEL,
    SECOND_LEVEL,
    ERR
  };

struct byte_query
  {
    enum level_type type;
    off_t direct_block_index;
    off_t second_level_index;
    off_t first_level_index;
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  /* David driving */
  /*
  size_t extra_sectors = 0, remaining_bytes = 0;
  if (size < DIRECT_LIMIT);
  else if (size < FIRST_LEVEL_LIMIT)
    extra_sectors = 1;
  else
    {
      extra_sectors = 2;
      remaining_bytes = size - FIRST_LEVEL_LIMIT;
      extra_sectors += DIV_ROUND_UP (remaining_bytes, FIRST_LEVEL_SIZE);
    }*/
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);// + extra_sectors;
}

static void 
calculate_sector_indices (struct byte_query *byte_query, off_t pos)
{
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

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

bool inode_extend (struct inode_disk *disk_inode, off_t start, off_t length)
{
  struct byte_query index;
  off_t direct_idx = -1, second_idx = -1, first_idx = -1;
  off_t sec_alloc, sec_len;
  bool success = true;
  off_t i;
  block_sector_t *level1, *level2;
  /* calculate number of sectors to allocate */
  sec_len = bytes_to_sectors (length) - bytes_to_sectors (start);
  if (start != 0)
    start += BLOCK_SECTOR_SIZE;
  calculate_sector_indices (&index, start);
  if (index.type == DIRECT_BLOCK && sec_len > 0)
    {
      direct_idx = index.direct_block_index;
      sec_alloc = 10 - direct_idx >= sec_len ? sec_len : 10 - direct_idx;
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
          ASSERT (false);
          success = false;
        }
      
      disk_inode->sectors_allocated += sec_alloc;
      calculate_sector_indices (&index, start);
    }
  
  /* Matthew driving */
  if (success && index.type == FIRST_LEVEL && sec_len > 0)
    {
      ASSERT ((level1 = palloc_get_page (PAL_ZERO)));
      first_idx = index.first_level_index;
      sec_alloc = 128 - first_idx >= sec_len ? sec_len : 128 - first_idx;

      /* Partially filled first level */
      if (disk_inode->first_level != 0)
        block_read (fs_device, disk_inode->first_level, level1 + 1);
      else
        free_map_allocate (1, &disk_inode->first_level);

      level1[0] = disk_inode->first_level;
      
      if (!allocate_first_level (level1, first_idx + 1, sec_alloc))
        {
          success = false;
          ASSERT (success);
        }
      else
        {
          sec_len -= sec_alloc;
          start += BLOCK_SECTOR_SIZE * sec_alloc;
        }
      disk_inode->sectors_allocated += sec_alloc;
      calculate_sector_indices (&index, start);
      palloc_free_page (level1);
    }
    
  if (success && index.type == SECOND_LEVEL && sec_len > 0)
    {
      ASSERT ((level2 = palloc_get_page (PAL_ZERO)));
      first_idx = index.first_level_index;
      second_idx = index.second_level_index;
      
      /* Partially filled first level */
      if (disk_inode->second_level != 0)
        block_read (fs_device, disk_inode->second_level, level2 + 1);
      else
        if (!free_map_allocate (1, &disk_inode->second_level))
          {
            success = false;
            ASSERT (false);
          }

      level2[0] = disk_inode->second_level;
      
      if (!allocate_second_level (level2, first_idx, second_idx + 1, sec_len))
        {
          success = false;
          ASSERT (success);
        }
      disk_inode->sectors_allocated += sec_len;
      palloc_free_page (level2);
    }
  disk_inode->length = length;
  return success;
}

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
      /* first, allocate up to 10 sectors for the direct blocks */
      success = inode_extend (disk_inode, 0, length);

      if (!success)
        {
          inode_free_sectors (disk_inode);
          free (disk_inode);
        }
      else
        {
          ASSERT (disk_inode->sectors_allocated == sectors);
          ASSERT (disk_inode->length == length);
          disk_inode->isdir = dir;
          block_write (fs_device, sector, disk_inode);
        }
    }
  return success;
}

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
          block_write (fs_device, first_level[i], zeros);
        }
      block_write (fs_device, first_level[0], first_level + 1);
      success = true;
    }
  ASSERT (success);
  return success;
}

static bool
allocate_second_level (block_sector_t *second_level, off_t first_ind, 
                       off_t sec_ind, size_t length)
{
  /* YunFan driving */
  bool success = true;
  off_t num_sector;
  block_sector_t *first_level = palloc_get_page (PAL_ZERO);
  ASSERT (first_level != NULL);

  while (length != 0)
    {
      /* the first level in the second level is not allocated */
      if (second_level[sec_ind] == 0) 
        {
          if (!free_map_allocate (1, second_level + sec_ind))
            {
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
      num_sector = length > 128 - first_ind ? 128 - first_ind : length;
      length -= num_sector;
      if (!allocate_first_level (first_level, first_ind + 1, num_sector))
        {
          success = false;
          break;
        }
      sec_ind++;
      first_ind = 0;
    }
  if (success)
    block_write (fs_device, second_level[0], second_level + 1);
  else
    ASSERT (false);
  palloc_free_page (first_level);
  return success;
}

/* Free all sectors allocated to disk_inode */
static void
inode_free_sectors (struct inode_disk *disk_inode)
{
  /* TODO: CHANGE INODE FREE SECTORS TO START FROM A CERTAIN POSITION */
  /* Stephen driving */
  size_t sectors_to_free = disk_inode->sectors_allocated;
  size_t count = 0;
  block_sector_t *first_level = NULL, *second_level = NULL;
  size_t i;

  count = sectors_to_free >= 10 ? 10 : sectors_to_free;
  free_map_release (disk_inode->direct_blocks, count);
  sectors_to_free -= count;

  if (sectors_to_free == 0)
    return;

  count = sectors_to_free >= 128 ? 128 : sectors_to_free;
  first_level = palloc_get_page (PAL_ZERO);
  ASSERT (first_level != NULL);

  block_read (fs_device, disk_inode->first_level, first_level + 1);
  first_level[0] = disk_inode->first_level;
  free_map_release (first_level, count + 1);
  sectors_to_free -= count;

  if (sectors_to_free == 0)
    {
      palloc_free_page (first_level);
      return;
    }

  second_level = palloc_get_page (PAL_ZERO);
  ASSERT (second_level != NULL);
  block_read (fs_device, disk_inode->second_level, second_level);
  i = 0;
  while (sectors_to_free > 0)
    {
      count = sectors_to_free >= 128 ? 128 : sectors_to_free;
      block_read (fs_device, second_level[i], first_level + 1);
      first_level[0] = second_level[i++];
      free_map_release (first_level, count + 1);
      sectors_to_free -= count;
    }

  free_map_release (&disk_inode->second_level, 1);
  palloc_free_page (first_level);
  palloc_free_page (second_level);

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
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }


  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read (fs_device, inode->sector, &inode->data);
  if (inode_is_directory (inode))
    lock_init (&inode->dir_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
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

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          /* Stephen driving */
          inode_free_sectors (&inode->data);
          free_map_release (&inode->sector, 1);
        }
      else
        {
          block_write (fs_device, inode->sector, &inode->data);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
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

/* Determines whether an inode corresponds to a file or to a directory */
bool
inode_is_directory (struct inode *inode)
{
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
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;
  off_t inode_len = inode_length (inode);
  if (inode->deny_write_cnt)
    return 0;
  if (offset + size > inode_len)
    {
      inode_extend (&inode->data, inode_len, offset + size);
      ASSERT (inode_length (inode) >= offset + size);
    }
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

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
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
