#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

// 과제 2 : 주소 유효성 검사 함수
void check_address(void *addr) {
	// kernel이 vm에게 못가게, 할당된 page가 존재하도록 유효성 검사 시행
	// 유저영역이 아니거나, 빈공간에 접근했거나, 
	// 포인터가 유저 주소를 가리키고 있지만, 아직 페이지로 할당되지 않은 공간에 접근했다면
	// 프로세스 즉시 종료
	struct thread *curr = thread_current();
	if (!is_user_vaddr(addr) || addr == NULL || pml4_get_page(curr->pml4, addr) == NULL)
		{
			exit(-1);
		} 
}

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n"); // printf는 write call을 부름, 지우고 시작 
	// thread_exit ();
	int sys_number = f->R.rax; // syscall 번호는 rax에 저장되어있음
	/* 
	인자 들어오는 순서:
	1번째 인자: %rdi
	2번째 인자: %rsi
	3번째 인자: %rdx
	4번째 인자: %r10
	5번째 인자: %r8
	6번째 인자: %r9 
	*/
	
	switch (sys_number)
	{
	case SYS_HALT:
			halt();
			break;
	case SYS_EXIT:
			exit(f->R.rdi);
			break;
	case SYS_FORK:
			f->R.rax = fork(f->R.rdi);
			break;
	case SYS_EXEC:
			exec(f->R.rdi);
			break;
	case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
	case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
	case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
	case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
	case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
	case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
	case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
	case SYS_SEEK:
			f->R.rax = seek(f->R.rdi, f->R.rsi);
			break;
	case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
	case SYS_CLOSE:
			close(f->R.rdi);
			break; 
	default:
		thread_exit();
	}
}

void
halt (void) {
	power_off();
}

// 현재 프로세스만 종료하는 call
void
exit (int status) {
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s : exit(%d)\n", curr->name, status);
	thread_exit();
}

pid_t
fork (const char *thread_name){
	return (pid_t) syscall1 (SYS_FORK, thread_name);
}

int
exec (const char *file) {
	return (pid_t) syscall1 (SYS_EXEC, file);
}

int
wait (pid_t pid) {
	return syscall1 (SYS_WAIT, pid);
}

// 파일을 생성하는 syscall
bool
create (const char *file, unsigned initial_size) {
	check_address(file);
		if (filesys_create(file, initial_size)) {
		return true;
	}
	else {
		return false;
	}
	}

bool
remove (const char *file) {
	check_address(file);
	if (filesys_remove(file)) {
		return true;
	}
	else {
		return false;
	}
}

// 현재 프로세스의 fdt에 파일을 넣는 함수
int add_file_to_fdt(struct file *file) {
	struct thread *curr = thread_current();
	struct file **fdt = curr->fdt;
	int fd = curr->next_fd;

	//fdt테이블에서 2부터 탐색하면서 null값을 만나면 거기에 fdt테이블이 open_file을 가리키게끔 해줌
	// 함수
	while (curr->fdt[fd] != NULL && fd < FDCOUNT) {
		fd++;
	}
	//fdt가 가득 찼으면
	if (fd >= FDCOUNT)
		return -1;
	
	curr->next_fd = fd;
	fdt[fd] = file;

	return fd;

	// for (fd = 0; siezof(fdt); fd++) {
	// 	if (fdt[fd] == NULL) {
	// 		fdt[fd] = open_file;
	// 	}
	// }
}

int
open (const char *file) {
	check_address(file);
	struct file *open_file = filesys_open(file);
	
	if (open_file == NULL) {
		return -1;
	} 
	// 현재 프로세스의 fdt에 파일을 넣는 구문
	int fd = add_file_to_fdt(open_file);
	
	//add 함수 실행했는데, 가득 차서 -1을 받은 경우
	if (fd == -1) {
		file_close(open_file);
	}
	return fd;
}

int
filesize (int fd) {
	return syscall1 (SYS_FILESIZE, fd);
}

int
read (int fd, void *buffer, unsigned size) {
	return syscall3 (SYS_READ, fd, buffer, size);
}

int
write (int fd, const void *buffer, unsigned size) {
	return syscall3 (SYS_WRITE, fd, buffer, size);
}

void
seek (int fd, unsigned position) {
	syscall2 (SYS_SEEK, fd, position);
}

unsigned
tell (int fd) {
	return syscall1 (SYS_TELL, fd);
}

void
close (int fd) {
	struct thread *curr = thread_current();
}

int
dup2 (int oldfd, int newfd){
	return syscall2 (SYS_DUP2, oldfd, newfd);
}

void *
mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
	return (void *) syscall5 (SYS_MMAP, addr, length, writable, fd, offset);
}

void
munmap (void *addr) {
	syscall1 (SYS_MUNMAP, addr);
}

bool
chdir (const char *dir) {
	return syscall1 (SYS_CHDIR, dir);
}

bool
mkdir (const char *dir) {
	return syscall1 (SYS_MKDIR, dir);
}

bool
readdir (int fd, char name[READDIR_MAX_LEN + 1]) {
	return syscall2 (SYS_READDIR, fd, name);
}

bool
isdir (int fd) {
	return syscall1 (SYS_ISDIR, fd);
}

int
inumber (int fd) {
	return syscall1 (SYS_INUMBER, fd);
}

int
symlink (const char* target, const char* linkpath) {
	return syscall2 (SYS_SYMLINK, target, linkpath);
}

int
mount (const char *path, int chan_no, int dev_no) {
	return syscall3 (SYS_MOUNT, path, chan_no, dev_no);
}

int
umount (const char *path) {
	return syscall1 (SYS_UMOUNT, path);
}
