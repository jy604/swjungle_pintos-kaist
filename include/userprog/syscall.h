#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"

void syscall_init (void);
struct lock filesys_lock; // 파일이 cpu 점유할 때 필요

#endif /* userprog/syscall.h */
