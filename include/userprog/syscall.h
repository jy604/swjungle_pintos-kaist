#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
// struct lock filesys_lock; // 파일이 cpu 점유할 때 필요

// int add_file_to_fdt(struct file *file);

// void halt(void);
// void exit(int status);
// tid_t fork (const char *thread_name);
// int exec (const char *file);
// int wait (tid_t pid);
// bool create (const char *file, unsigned initial_size);
// bool remove (const char *file);
// int open (const char *file);
// struct file *search_file_from_fdt(int fd);
// int filesize (int fd);
// int read (int fd, void *buffer, unsigned size);
// int write (int fd, const void *buffer, unsigned size);
// void seek (int fd, unsigned position);
// unsigned tell (int fd);
// void fdt_remove_file(int fd);
// void close (int fd);

#endif /* userprog/syscall.h */
