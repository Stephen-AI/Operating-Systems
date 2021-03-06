#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include <list.h>
#include "threads/synch.h"

struct bitmap;

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    size_t sectors_allocated;           /* # of sectors allocated to file */
    off_t length;                       /* File size in bytes. */
    bool isdir;                         /* Is this inode for a directory? */
    size_t num_files;                   /* Number of files under a directory */
    unsigned magic;                     /* Magic number. */
    block_sector_t direct_blocks[10];   /* Direct data blocks */
    block_sector_t first_level;         /* 1st level indirection block */
    block_sector_t second_level;        /* 2nd level indirection block */
    uint32_t unused[111];               /* Not used. */
  };

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    struct lock dir_lock;               /* lock for directory */
    struct lock inode_lock;             /* lock for extending files */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

void inode_init (void);
bool inode_create (block_sector_t, off_t, bool);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);
bool inode_extend (struct inode_disk *, off_t, off_t);
bool inode_is_directory (struct inode *);
bool inode_is_removed (struct inode *);
#endif /* filesys/inode.h */
