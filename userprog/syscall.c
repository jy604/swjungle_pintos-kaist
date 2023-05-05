#include "userprog/syscall.h"
#include "lib/user/syscall.h"
#include "lib/stdio.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "include/filesys/filesys.h"
#include "include/filesys/file.h"
int add_file_to_fdt(struct file *file);

void halt(void);
void exit(int status);
pid_t _fork (const char *thread_name, struct intr_frame *f);
int exec (const char *file);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
struct file *search_file_from_fdt(int fd);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void fdt_remove_file(int fd);
void close (int fd);

struct lock filesys_lock; // 파일이 cpu 점유할 때 필요
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
			f->R.rax = _fork(f->R.rdi, f);
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
		exit(-1); ///////
		break;
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
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

pid_t _fork (const char *thread_name, struct intr_frame *f) {
	// check_address(thread_name);
	return process_fork(thread_name, f);
}

// 현재 실행중인 프로세스를 cmd_line에 지정된 실행 파일로 변경하고 인수 전달
int exec (const char *file) {
	check_address(file);

	int size = strlen(file) + 1; // null 값 포함한 파일 사이즈
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if ((fn_copy) == NULL) {
		exit(-1);
	}
	strlcpy(fn_copy, file, size);

	if (process_exec(fn_copy) == -1) {
		return -1;
	}

	NOT_REACHED();
	return 0;
}

int
wait (pid_t pid) {
	process_wait(pid);
}

// 파일을 생성하는 syscall
bool create (const char *file, unsigned initial_size) {
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove (const char *file) {
	check_address(file);
	return filesys_remove(file);
}

// int add_file_to_fdt (struct file *f){
// /* 파일 객체를 파일 디스크립터 테이블에 추가*/
// 	struct thread *curr = thread_current();
// 	int fd = curr->next_fd;
// 	if(fd >64){ //크기 지정 어캐하징.
// 		return -1;
// 	}
// 	curr->fdt[fd] = f;
// 	curr->next_fd +=1; /* 파일 디스크립터의 최대값 1 증가 */
// 	return fd; /* 파일 디스크립터 리턴 */
// }

// 현재 프로세스의 fdt에 파일을 넣는 함수
int add_file_to_fdt(struct file *file) {
	// struct thread *curr = thread_current();
	// struct file **fdt = curr->fdt;
	// int fd = curr->next_fd;

	// //fdt테이블에서 2부터 탐색하면서 null값을 만나면 거기에 fdt테이블이 open_file을 가리키게끔 해줌
	// // 함수
	// while (curr->fdt[fd] != NULL && fd < FDCOUNT) {
	// 	fd++;
	// }
	// //fdt가 가득 찼으면
	// if (fd >= FDCOUNT)
	// 	return -1;
	
	// curr->next_fd = fd;
	// fdt[fd] = file;

	// return fd;

	struct thread *curr = thread_current();
  //파일 디스크립터 테이블에서 비어있는 자리를 찾습니다.
	while (curr->next_fd < FDCOUNT  && curr->fdt[curr->next_fd] != NULL) {
		curr->next_fd++;
	}

	// 파일 디스크립터 테이블이 꽉 찬 경우 에러를 반환
	if (curr->next_fd >= FDCOUNT ) {
		return -1;
	}

	curr->fdt[curr->next_fd] = file;
	return curr->next_fd;

	// for (fd = 0; siezof(fdt); fd++) {
	// 	if (fdt[fd] == NULL) {
	// 		fdt[fd] = open_file;
	// 	}
	// }
}

int open (const char *file) {
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
	return file_length(file);
}

// 파일의 값을 읽어서 size를 버퍼에 반환하는 함수
int
read (int fd, void *buffer, unsigned size) {
	// check_address(buffer);
	lock_acquire(&filesys_lock);
	if(fd == 0){
		input_getc();
		lock_release(&filesys_lock);
		return size;
	}
  	struct file *fileobj= search_file_from_fdt(fd);
	size = file_read(fileobj,buffer,size);
	lock_release(&filesys_lock);	
	return size;

	// struct file *read_file = search_file_from_fdt(fd);
	// unsigned char *buf = buffer; // 읽어들인 데이터를 1바이트 단위로 저장
	// int read_byte;
	// if (read_file == NULL) {
	// 	return -1;
	// }

	// //STDIN(fd = 0)일경우, input_getc()를 이용해 키보드 입력을 읽어옴
	// //STDOUT(fd = 1)일 경우, -1을 반환
	// // 그외, fd로부터 파일을 찾고, size 바이트만큼 파일을 읽어 버퍼에 저장<lock 사용
	// if (fd == STDIN_FILENO) {
	// 	for(int i = 0; i < size; i++) {
	// 		char input_key = input_getc(); // 키보드 입력을 저장
	// 		*buf++ = input_key; // 버퍼에 1바이트씩 넣음
	// 		if (input_key == '\0') { //엔터값
	// 			break;
	// 		}
	// 	}
	// }
	// else if (fd == STDOUT_FILENO){
	// 	return -1;
	// }
	// else {
	// 	lock_acquire(&filesys_lock);
	// 	read_byte = file_read(read_file, buffer, size);
	// 	lock_release(&filesys_lock);
	// }

	// return read_byte;
}

// 버퍼로부터 값을 읽어서 파일에 데이터를 작성하는 함수
int
write (int fd, const void *buffer, unsigned size) {
	lock_acquire(&filesys_lock);
	if(fd == 1){
		 putbuf(buffer, size);  //문자열을 화면에 출력해주는 함수
		//putbuf(): 버퍼 안에 들어있는 값 중 사이즈 N만큼을 console로 출력
		lock_release(&filesys_lock);
		return size;
	}
	struct file *fileobj= search_file_from_fdt(fd);
	if(fileobj == NULL){
		lock_release(&filesys_lock);
		return -1;
	}
	
	size = file_write(fileobj,buffer,size);
	lock_release(&filesys_lock);
	return size;
	// check_address(buffer);
	// int write_byte;
	
	// // STDOUT(fd = 1)일 경우, putbuf로 콘솔에 작성 후 바이트 size 리턴
	// if (fd == STDIN_FILENO) {
	// 	return -1;
	// }
	// else if (fd == STDOUT_FILENO) {
	// 	putbuf(buffer, size);
	// 	return size;
	// }
	// else {
	// 	struct file *write_file = search_file_from_fdt(fd);		
	// 	lock_acquire(&filesys_lock);
	// 	write_byte = file_write(write_file, buffer, size);
	// 	lock_release(&filesys_lock);
	// }
	// return write_byte;
}

// 열린 파일의 위치(offset)를 이동하는 syscall
// position 0은 파일의 시작 위치
void
seek (int fd, unsigned position) {
	struct file *file = search_file_from_fdt(fd);
	check_address(file);

	if (fd <= STDOUT_FILENO) {
		return;
	}

	file_seek(file, position);
}

// 열린 파일의 위치(offset)을 알려주는 syscall
unsigned tell (int fd) {
	struct file *file = search_file_from_fdt(fd);
	check_address(file);

	if (fd <= STDOUT_FILENO) {
		return;
	}
	return file_tell(fd);
}

void fdt_remove_file(int fd) {
	struct thread *curr = thread_current();

	if (fd < 0 || fd > FDCOUNT) {
		return;
	}

	curr->fdt[fd] = NULL;
	
}
// 열린 파일 닫는 syscall
// 파일 닫고 fd 제거
void
close (int fd) {
	// struct thread *curr = thread_current();
	// struct file *file = search_file_from_fdt(fd);

	// if (fd <= STDOUT_FILENO) {
	// 	return;
	// }

	// fdt_remove_file(fd);

	// file_close(file);
	struct thread *curr = thread_current();
	curr->fdt[fd] = 0;
	
}
