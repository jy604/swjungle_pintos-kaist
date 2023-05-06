#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include <filesys/filesys.h>
#include <filesys/file.h>
#include <stdio.h>
#include "threads/palloc.h"
#include "lib/kernel/stdio.h"
#include "threads/synch.h"
#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void check_address(void *addr);
void half(void);
void exit(int status);
tid_t fork (const char *thread_name,struct intr_frame *f);
int exec (const char *file);
int wait (tid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size) ;
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

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
struct lock filesys_lock;
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
    switch (f->R.rax) // rax는 system call number이다.
    {
	case SYS_HALT:
        halt();
        break;
    case SYS_EXIT:
        exit(f->R.rdi); //실행할 때 첫번째 인자가 R.rdi에 저장됨
        break;
    case SYS_FORK:
        f->R.rax = fork(f->R.rdi, f);
        break;
    case SYS_EXEC:
        exec(f->R.rdi);
        break;
    case SYS_WAIT:
        f->R.rax = process_wait(f->R.rdi);
        break;		
    case SYS_CREATE:
        f->R.rax = create((const char *)f->R.rdi, f->R.rsi);
        break;
    case SYS_REMOVE:
        f->R.rax = remove((const char *)f->R.rdi);
        break;		
    case SYS_OPEN:
        f->R.rax = open((const char *)f->R.rdi);
        break;
    case SYS_FILESIZE:
        f->R.rax = filesize(f->R.rdi);
        break;
    case SYS_READ:
        f->R.rax = read(f->R.rdi, (void *) f->R.rsi, f->R.rdx);
        break;
    case SYS_WRITE:
        f->R.rax = write(f->R.rdi, (const void *)f->R.rsi, f->R.rdx);
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
        exit(-1);
        break;
    }
}
void halt(void)
{
    power_off();
}
// userprog/syscall.c
void exit(int status)
{
    struct thread *cur = thread_current();
    cur->exit_status = status;                         // 종료시 상태를 확인, 정상종료면 state = 0
    printf("%s: exit(%d)\n", thread_name(), status); // 종료 메시지 출력
    thread_exit();                                     // thread 종료
}
tid_t fork (const char *thread_name,struct intr_frame *f){
	return process_fork(thread_name,f);
}

int exec (const char *file){
/*
현재의 프로세스가 cmd_line에서 이름이 주어지는 실행가능한 프로세스로 변경됩니다. 
이때 주어진 인자들을 전달합니다. 성공적으로 진행된다면 어떤 것도 반환하지 않습니다. 
만약 프로그램이 이 프로세스를 로드하지 못하거나 다른 이유로 돌리지 못하게 되면 
exit state -1을 반환하며 프로세스가 종료됩니다. 
1. filename이 프로세스의 유저영역 메모리에 있는지 확인
2. filename을 저장해줄 페이지 할당받고, 해당 페이지에 filename 넣어줌
3. process_exec()를 실행 해, 현재 실행중인 프로세스를 filename으로 context switching하는 작업을 진행
*/
	check_address(file);
	// 문제점) SYS_EXEC - process_exec의 process_cleanup 때문에 f->R.rdi 날아감.
	// 여기서 file_name 동적할당해서 복사한 뒤, 그걸 넘겨주기
	int siz = strlen(file)+1;
	char *file_copy = palloc_get_page(PAL_ZERO); //근데 이해 안감,,
	strlcpy(file_copy,file,siz);

	if(process_exec(file_copy) == -1)
		return -1;
	
	NOT_REACHED();
	return 0;
}
int wait (tid_t pid){
	return process_wait(pid);
}
bool create(const char *file, unsigned initial_size){
	check_address(file);
	return filesys_create(file,initial_size);
}

bool remove(const char *file){
	check_address(file);
	return filesys_remove(file);
}
int open (const char *file){
/* 파일을 open */
/* 해당 파일 객체에 파일 디스크립터 부여 */
/* 파일 디스크립터 리턴 */
/* 해당 파일이 존재하지 않으면 -1 리턴 */
	check_address(file);

	struct file *fileobj = filesys_open(file);
	if(fileobj == NULL)
		return -1;
	int fd = add_file_to_fdt(fileobj);
	if(fd == -1) //fd table 꽉참
		file_close(fileobj);
	return fd;
}

int filesize (int fd){
/* 파일 디스크립터를 이용하여 파일 객체 검색 */
  struct file *fileobj= search_file_to_fdt(fd);
  if(fileobj == NULL){ /* 해당 파일이 존재하지 않으면 -1 리턴 */
	return -1;
  }
/* 해당 파일의 길이를 리턴 */
	return file_length(fileobj);
}
int read (int fd, void *buffer, unsigned size) {
	/* 파일에 동시 접근이 일어날 수 있으므로 Lock 사용 */
/* 파일 디스크립터를 이용하여 파일 객체 검색 */
/* 파일 디스크립터가 0일 경우 키보드에 입력을 버퍼에 저장 후
버퍼의 저장한 크기를 리턴 (input_getc() 이용) */
/* 파일 디스크립터가 0이 아닐 경우 파일의 데이터를 크기만큼 저
장 후 읽은 바이트 수를 리턴  */ 
	lock_acquire(&filesys_lock);
	if(fd == 0){
		input_getc();
		lock_release(&filesys_lock);
		return size;
	}
  	struct file *fileobj= search_file_to_fdt(fd);
	size = file_read(fileobj,buffer,size);
	lock_release(&filesys_lock);	
	return size;
}

int write (int fd, const void *buffer, unsigned size) {
	/* 파일에 동시 접근이 일어날 수 있으므로 Lock 사용 */
/* 파일 디스크립터를 이용하여 파일 객체 검색 */
/* 파일 디스크립터가 1일 경우 버퍼에 저장된 값을 화면에 출력
후 버퍼의 크기 리턴 (putbuf() 이용) */
/* 파일 디스크립터가 1이 아닐 경우 버퍼에 저장된 데이터를 크기
만큼 파일에 기록후 기록한 바이트 수를 리턴 */
	lock_acquire(&filesys_lock);
	if(fd == 1){
		 putbuf(buffer, size);  //문자열을 화면에 출력해주는 함수
		//putbuf(): 버퍼 안에 들어있는 값 중 사이즈 N만큼을 console로 출력
		lock_release(&filesys_lock);
		return size;
	}
	struct file *fileobj= search_file_to_fdt(fd);
	if(fileobj == NULL){
		lock_release(&filesys_lock);
		return -1;
	}
	
	size = file_write(fileobj,buffer,size);
	lock_release(&filesys_lock);
	return size;
}

void seek (int fd, unsigned position) {
	/* 파일 디스크립터를 이용하여 파일 객체 검색 */
	struct file *fileobj = search_file_to_fdt(fd);
	file_seek(fileobj, position);
/* 해당 열린 파일의 위치(offset)를 position만큼 이동 */
}

unsigned tell (int fd) {
	/* 파일 디스크립터를 이용하여 파일 객체 검색 */
	struct file *fileobj = search_file_to_fdt(fd);
	file_tell(fileobj);
/* 해당 열린 파일의 위치를 반환 */
}

void close (int fd) {
// 	/* 해당 파일 디스크립터에 해당하는 파일을 닫음 */
	struct thread *curr = thread_current();
	curr->fdt[fd] = 0; /* 파일 디스크립터 엔트리 초기화 */
	// struct thread *curr = thread_current();
	// for (int i = 2; i < FDCOUNT; i++) {
	// 	file_close(curr->fdt[i]);
	// 	curr->fdt[i] = 0;
	// }
}


void check_address(void *addr){
	struct thread *curr = thread_current();
	if(addr== NULL || !is_user_vaddr(addr)|| pml4_get_page(curr->pml4, addr) == NULL){
		exit(-1);
	} 
}



// #include "userprog/syscall.h"
// #include <stdio.h>
// #include <syscall-nr.h>
// #include "threads/interrupt.h"
// #include "threads/thread.h"
// #include "threads/loader.h"
// #include "userprog/gdt.h"
// #include "threads/flags.h"
// #include "intrinsic.h"

// #include "threads/synch.h"

// void syscall_entry (void);
// void syscall_handler (struct intr_frame *);

// int add_file_to_fdt(struct file *file);
// void check_address(void *addr);

// void halt(void);
// void exit(int status);
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
// void close (int fd);


// struct lock filesys_lock; // 파일이 cpu 점유할 때 필요
// /* System call.
//  *
//  * Previously system call services was handled by the interrupt handler
//  * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
//  * efficient path for requesting the system call, the `syscall` instruction.
//  *
//  * The syscall instruction works by reading the values from the the Model
//  * Specific Register (MSR). For the details, see the manual. */

// #define MSR_STAR 0xc0000081         /* Segment selector msr */
// #define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
// #define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

// void
// syscall_init (void) {
// 	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
// 			((uint64_t)SEL_KCSEG) << 32);
// 	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

// 	/* The interrupt service rountine should not serve any interrupts
// 	 * until the syscall_entry swaps the userland stack to the kernel
// 	 * mode stack. Therefore, we masked the FLAG_FL. */
// 	write_msr(MSR_SYSCALL_MASK,
// 			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
// 	lock_init(&filesys_lock);
// }

// /* The main system call interface */
// void
// syscall_handler (struct intr_frame *f UNUSED) {
// 	// TODO: Your implementation goes here.
// 	// printf ("system call!\n");
// 	// thread_exit ();
// 	int sys_number = f->R.rax;

// 	switch (sys_number) {
// 		case SYS_HALT:
// 				halt();
// 				break;
// 		case SYS_EXIT:
// 				exit(f->R.rdi);
// 				break;
// 		// case SYS_FORK:
// 		// 		// f->R.rax = _fork(f->R.rdi, f);
// 		// 		break;
// 		// case SYS_EXEC:
// 		// 		// exec(f->R.rdi);
// 		// 		break;
// 		// case SYS_WAIT:
// 		// 		// f->R.rax = wait(f->R.rdi);
// 		// 		break;
// 		case SYS_CREATE:
// 				f->R.rax = create(f->R.rdi, f->R.rsi);
// 				break;
// 		case SYS_REMOVE:
// 				f->R.rax = remove(f->R.rdi);
// 				break;
// 		case SYS_OPEN:
// 				f->R.rax = open(f->R.rdi);
// 				break;
// 		// case SYS_FILESIZE:
// 		// 		f->R.rax = filesize(f->R.rdi);
// 		// 		break;
// 		// case SYS_READ:
// 		// 		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
// 		// 		break;
// 		case SYS_WRITE:
// 				f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
// 				break;
// 		case SYS_SEEK:
// 				seek(f->R.rdi, f->R.rsi);
// 				break;
// 		case SYS_TELL:
// 				f->R.rax = tell(f->R.rdi);
// 				break;
// 		case SYS_CLOSE:
// 				close(f->R.rdi);
// 				break; 
// 		default:
// 			exit(-1); ///////
// 			break;
// 		}
// }

// void halt (void) {
// 	power_off();
// }

// // 현재 프로세스만 종료하는 call
// void exit (int status) {
// 	struct thread *curr = thread_current();
// 	curr->exit_status = status;
// 	printf("%s: exit(%d)\n", curr->name, status);
// 	thread_exit();
// }

// // 파일을 생성하는 syscall
// bool create (const char *file, unsigned initial_size) {
// 	check_address(file);
// 	return filesys_create(file, initial_size);
// }

// bool remove (const char *file) {
// 	check_address(file);
// 	return filesys_remove(file);
// }

// int open (const char *file) {
// 	check_address(file);
// 	struct file *open_file = filesys_open(file);
	
// 	if (open_file == NULL) {
// 		return -1;
// 	} 
// 	// 현재 프로세스의 fdt에 파일을 넣는 구문
// 	int fd = add_file_to_fdt(open_file);
	
// 	//add 함수 실행했는데, 가득 차서 -1을 받은 경우
// 	if (fd == -1) {
// 		file_close(open_file);
// 	}
// 	return fd;
// }

// // 버퍼로부터 값을 읽어서 파일에 데이터를 작성하는 함수
// int
// write (int fd, const void *buffer, unsigned size) {
// 	lock_acquire(&filesys_lock);
// 	if(fd == 1){
// 		 putbuf(buffer, size);  //문자열을 화면에 출력해주는 함수
// 		//putbuf(): 버퍼 안에 들어있는 값 중 사이즈 N만큼을 console로 출력
// 		lock_release(&filesys_lock);
// 		return size;
// 	}
// 	struct file *fileobj= search_file_from_fdt(fd);
// 	if(fileobj == NULL){
// 		lock_release(&filesys_lock);
// 		return -1;
// 	}
	
// 	size = file_write(fileobj,buffer,size);
// 	lock_release(&filesys_lock);
// 	return size;
// 	// //check_address(buffer);
// 	// int write_byte;
	
// 	// // STDOUT(fd = 1)일 경우, putbuf로 콘솔에 작성 후 바이트 size 리턴
// 	// if (fd == 1) {
// 	// 	return -1;
// 	// }
// 	// else if (fd == 2) {
// 	// 	putbuf(buffer, size);
// 	// 	return size;
// 	// }
// 	// else {
// 	// 	struct file *write_file = search_file_from_fdt(fd);		
// 	// 	lock_acquire(&filesys_lock);
// 	// 	write_byte = file_write(write_file, buffer, size);
// 	// 	lock_release(&filesys_lock);
// 	// }
// 	// return write_byte;

	
// }

// // 파일의 값을 읽어서 size를 버퍼에 반환하는 함수
// int
// read (int fd, void *buffer, unsigned size) {
// 	// check_address(buffer);
// 	lock_acquire(&filesys_lock);
// 	if(fd == 0){
// 		input_getc();
// 		lock_release(&filesys_lock);
// 		return size;
// 	}
//   	struct file *fileobj= search_file_from_fdt(fd);
// 	size = file_read(fileobj,buffer,size);
// 	lock_release(&filesys_lock);	
// 	return size;

// 	// struct file *read_file = search_file_from_fdt(fd);
// 	// unsigned char *buf = buffer; // 읽어들인 데이터를 1바이트 단위로 저장
// 	// int read_byte;
// 	// if (read_file == NULL) {
// 	// 	return -1;
// 	// }

// 	// //STDIN(fd = 0)일경우, input_getc()를 이용해 키보드 입력을 읽어옴
// 	// //STDOUT(fd = 1)일 경우, -1을 반환
// 	// // 그외, fd로부터 파일을 찾고, size 바이트만큼 파일을 읽어 버퍼에 저장<lock 사용
// 	// if (fd == STDIN_FILENO) {
// 	// 	for(int i = 0; i < size; i++) {
// 	// 		char input_key = input_getc(); // 키보드 입력을 저장
// 	// 		*buf++ = input_key; // 버퍼에 1바이트씩 넣음
// 	// 		if (input_key == '\0') { //엔터값
// 	// 			break;
// 	// 		}
// 	// 	}
// 	// }
// 	// else if (fd == STDOUT_FILENO){
// 	// 	return -1;
// 	// }
// 	// else {
// 	// 	lock_acquire(&filesys_lock);
// 	// 	read_byte = file_read(read_file, buffer, size);
// 	// 	lock_release(&filesys_lock);
// 	// }

// 	// return read_byte;
// }

// // 열린 파일의 위치(offset)를 이동하는 syscall
// // position 0은 파일의 시작 위치
// void
// seek (int fd, unsigned position) {
// 	struct file *file = search_file_from_fdt(fd);
// 	check_address(file);

// 	if (fd <= 1) {
// 		return;
// 	}

// 	file_seek(file, position);
// }

// // 열린 파일의 위치(offset)을 알려주는 syscall
// unsigned tell (int fd) {
// 	struct file *file = search_file_from_fdt(fd);
// 	check_address(file);

// 	if (fd <= 1) {
// 		return;
// 	}
// 	return file_tell(fd);
// }

// // 열린 파일 닫는 syscall
// // 파일 닫고 fd 제거
// void
// close (int fd) {
// 	// struct thread *curr = thread_current();
// 	// struct file *file = search_file_from_fdt(fd);

// 	// if (fd <= STDOUT_FILENO) {
// 	// 	return;
// 	// }

// 	// fdt_remove_file(fd);

// 	// file_close(file);
// 	struct thread *curr = thread_current();
// 	curr->fdt[fd] = 0;
	
// }

// //fdt에 넣은 파일을 찾는 함수
// struct file *search_file_from_fdt(int fd) {
// 	// 예외처리 : fd가 0보다 작거나 테이블의 범위를 넘어서면 파일이 없는 것임
// 	if (fd < 0 || fd >= FDCOUNT) {
// 		return NULL;
// 	}
// 	struct thread *curr = thread_current();
// 	struct file **fdt = curr->fdt;

// 	struct file *file = fdt[fd];
// 	return file;
// }


// int add_file_to_fdt(struct file *file) {
// 	struct thread *curr = thread_current();
// 	struct file **fdt = curr->fdt;
// 	int fd = curr->next_fd;

// 	//fdt테이블에서 2부터 탐색하면서 null값을 만나면 거기에 fdt테이블이 open_file을 가리키게끔 해줌
// 	// 함수
// 	while (curr->fdt[fd] != NULL && fd < FDCOUNT) {
// 		fd++;
// 	}
// 	//fdt가 가득 찼으면
// 	if (fd >= FDCOUNT)
// 		return -1;
	
// 	curr->next_fd = fd;
// 	fdt[fd] = file;

// 	return fd;
// }

// // //fdt에 넣은 파일을 찾는 함수
// // struct file *search_file_from_fdt(int fd) {
// // 	// 예외처리 : fd가 0보다 작거나 테이블의 범위를 넘어서면 파일이 없는 것임
// // 	if (fd < 0 || fd >= FDCOUNT) {
// // 		return NULL;
// // 	}
// // 	struct thread *curr = thread_current();
// // 	struct file **fdt = curr->fdt;

// // 	struct file *file = fdt[fd];
// // 	return file;
// // }

// // 과제 2 : 주소 유효성 검사 함수
// void check_address(void *addr) {
// 	// kernel이 vm에게 못가게, 할당된 page가 존재하도록 유효성 검사 시행
// 	// 유저영역이 아니거나, 빈공간에 접근했거나, 
// 	// 포인터가 유저 주소를 가리키고 있지만, 아직 페이지로 할당되지 않은 공간에 접근했다면
// 	// 프로세스 즉시 종료
// 	struct thread *curr = thread_current();
// 	if (!is_user_vaddr(addr) || addr == NULL || pml4_get_page(curr->pml4, addr) == NULL)
// 		{
// 			exit(-1);
// 		} 
// }