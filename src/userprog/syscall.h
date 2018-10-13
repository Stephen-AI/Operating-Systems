#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/pagedir.h"
#include "threads/vaddr.h"

void syscall_init (void);
bool is_valid_ptr (void *ptr);
#endif /* userprog/syscall.h */
