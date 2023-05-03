#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/synch.h"

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
	lock_init(&filesys_lock);
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
			seek(f->R.rdi, f->R.rsi);
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

tid_t
fork (const char *thread_name){
	return;
}

int
exec (const char *file) {
	return;
}

int
wait (tid_t pid) {
	return;
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

//fdt에 넣은 파일을 찾는 함수
struct file *search_file_from_fdt(int fd) {
	// 예외처리 : fd가 0보다 작거나 테이블의 범위를 넘어서면 파일이 없는 것임
	if (fd < 0 || fd >= FDCOUNT) {
		return NULL;
	}
	struct thread *curr = thread_current();
	struct file **fdt = curr->fdt;

	struct file *file = fdt[fd];
	return file;
}

// 파일 크기 정보 > file : inode > inode_disk : off_t length
int
filesize (int fd) {
	//file.c의 file_length() 활용
	//fdt에 넣은 파일을 찾는 함수
	struct file *file = search_file_from_fdt(fd);
	if (file == NULL) {
		return -1;
	}
	file_length(file);
}

// 파일의 값을 읽어서 size를 버퍼에 반환하는 함수
int
read (int fd, void *buffer, unsigned size) {
	check_address(buffer);
	struct file *read_file = search_file_from_fdt(fd);
	unsigned char *buf = buffer; // 읽어들인 데이터를 1바이트 단위로 저장
	int read_byte;
	if (read_file == NULL) {
		return -1;
	}

	//STDIN(fd = 0)일경우, input_getc()를 이용해 키보드 입력을 읽어옴
	//STDOUT(fd = 1)일 경우, -1을 반환
	// 그외, fd로부터 파일을 찾고, size 바이트만큼 파일을 읽어 버퍼에 저장<lock 사용
	if (fd == STDIN_FILENO) {
		for(int i = 0; i < size; i++) {
			char input_key = input_getc(); // 키보드 입력을 저장
			*buf++ = input_key; // 버퍼에 1바이트씩 넣음
			if (input_key == '\0') { //엔터값
				break;
			}
		}
	}
	else if (fd == STDOUT_FILENO){
		return -1;
	}
	else {
		lock_acquire(&filesys_lock);
		read_byte = file_read(read_file, buffer, size);
		lock_release(&filesys_lock);
	}

	return read_byte;
}

// 버퍼로부터 값을 읽어서 파일에 데이터를 작성하는 함수
int
write (int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	int write_byte;
	
	// STDOUT(fd = 1)일 경우, putbuf로 콘솔에 작성 후 바이트 size 리턴
	if (fd == STDIN_FILENO) {
		return -1;
	}
	else if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
		return size;
	}
	else {
		struct file *write_file = search_file_from_fdt(fd);		
		lock_acquire(&filesys_lock);
		write_byte = file_write(write_file, buffer, size);
		lock_release(&filesys_lock);
	}
	return write_byte;
}

void
seek (int fd, unsigned position) {
	//syscall2 (SYS_SEEK, fd, position);
}

// unsigned tell (int fd) {
// 	return;
// }

void
close (int fd) {
	struct thread *curr = thread_current();
}

// int
// dup2 (int oldfd, int newfd){
// 	return syscall2 (SYS_DUP2, oldfd, newfd);
// }

// void *
// mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
// 	return (void *) syscall5 (SYS_MMAP, addr, length, writable, fd, offset);
// }

// void
// munmap (void *addr) {
// 	syscall1 (SYS_MUNMAP, addr);
// }

// bool
// chdir (const char *dir) {
// 	return syscall1 (SYS_CHDIR, dir);
// }

// bool
// mkdir (const char *dir) {
// 	return syscall1 (SYS_MKDIR, dir);
// }

// bool
// readdir (int fd, char name[READDIR_MAX_LEN + 1]) {
// 	return syscall2 (SYS_READDIR, fd, name);
// }

// bool
// isdir (int fd) {
// 	return syscall1 (SYS_ISDIR, fd);
// }

// int
// inumber (int fd) {
// 	return syscall1 (SYS_INUMBER, fd);
// }

// int
// symlink (const char* target, const char* linkpath) {
// 	return syscall2 (SYS_SYMLINK, target, linkpath);
// }

// int
// mount (const char *path, int chan_no, int dev_no) {
// 	return syscall3 (SYS_MOUNT, path, chan_no, dev_no);
// }

// int
// umount (const char *path) {
// 	return syscall1 (SYS_UMOUNT, path);
// }
