#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"

#define USER_ADDR_FLOOR ((void *) 0x08048000)
#define MAX_SYS_ARGS 3

enum sys_call_size
{
	create_t = 2,
	remove_t = 1,
	open_t = 1,
	filesize_t = 1,
	read_t = 3,
	write_t = 3,
	seek_t = 2,
	tell_t = 1,
	close_t = 1,
	halt_t = 1,
	exit_t = 1,
	exec_t = 1,
	wait_t = 1
};

struct lock file_lock;

struct file_info
{
	struct file *file;
	int fd;
	struct list_elem elem;
};
typedef struct file_info p_file_t;

static void syscall_handler (struct intr_frame *);
void check_ptr_validity(const void * vaddr);
void get_arg(struct intr_frame *f, int *arg, int size);
void check_valid_buffer(void *buffer, unsigned size);
void child_process_init(child_t *cp, int pid);
int user_to_kernel_ptr(const void *vaddr);

int add_process_file(struct file *new_file);
struct file * get_process_file(int fd);

void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int arg[MAX_SYS_ARGS];
	check_ptr_validity((const void *) f->esp);
	switch( * (int *) f->esp)
	{
		case SYS_WRITE:
		{
			get_arg(f, &arg[0], write_t);
		  	check_valid_buffer((void *) arg[1], (unsigned) arg[2]);
		  	arg[1] = user_to_kernel_ptr((const void *) arg[1]);
		    f->eax = write(arg[0], (const void *) arg[1],
		        (unsigned) arg[2]);
		  	break;
		}
		case SYS_READ:
		{
			get_arg(f, &arg[0], read_t);
			check_valid_buffer((void *) arg[1], (unsigned) arg[2]);
			arg[1] = user_to_kernel_ptr((const void *) arg[1]);
			f->eax = read(arg[0], (void *) arg[1],
					(unsigned) arg[2]);
			break;
		}
		case SYS_EXIT:
		{
			get_arg(f, &arg[0], exit_t);
			exit(arg[0]);
			break;
		}
		case SYS_SEEK:
		{
			get_arg(f, &arg[0], seek_t);
			seek(arg[0], (unsigned) arg[1]);
			break;
		}
		case SYS_TELL:
		{
			get_arg(f, &arg[0], tell_t);
			f->eax = tell(arg[0]);
			break;
		}
	}
}

pid_t exec(const char *cmd_line)
{
	pid_t pid = process_execute(cmd_line);
	child_t *cp = get_child(pid);
	ASSERT(cp);
	while(cp->load == NOT_LOADED)
	{
		barrier();
	}
	if(cp->load == LOAD_FAILED)
	{
		return ER_FAIL;
	}
	return pid;
}

int wait(pid_t pid)
{
	return process_wait(pid);
}

void exit(int status)
{
	struct thread *cur = thread_current();
	if(thread_status(cur->parent))
	{
		cur->cp->status = status;
	}
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}

bool create(const char *file, unsigned initial_size)
{
	bool success = false;

	lock_acquire(&file_lock);
	success = filesys_create(file, initial_size);
	lock_release(&file_lock);
	return success;
}

bool remove(const char *file)
{
	bool success = false;

	lock_acquire(&file_lock);
	success = filesys_remove(file);
	lock_release(&file_lock);

	return success;
}

int open(const char *file)
{
	int fd;
	struct file *file_temp;

	lock_acquire(&file_lock);
	file_temp = filesys_open(file);
	if(!file_temp)
	{
		lock_release(&file_lock);
		return ER_FAIL;
	}
	fd = add_process_file(file_temp);
	return fd;
}

int filesize(int fd)
{
	struct file *file_temp;
	int size;

	lock_acquire(&file_lock);
	file_temp = get_process_file(fd);
	if(!file_temp)
	{
		lock_release(&file_lock);
		return ER_FAIL;
	}
	size = file_length(file_temp);
	lock_release(&file_lock);
	return size;
}

int read(int fd, void *buffer, unsigned size)
{
	struct file *file_temp;
	int size_read;

	if(fd == STDIN_FILENO)
	{
		unsigned i;
		uint8_t *temp_buf = (uint8_t *)buffer;
		for(i = 0; i < size; i++)
		{
			temp_buf[i] = input_getc();
		}
		return size;
	}

	lock_acquire(&file_lock);
	file_temp = get_process_file(fd);
	size_read = file_read(file_temp, buffer, size);
	lock_release(&file_lock);
	return size_read;
}

int write (int fd, const void *buffer, unsigned length)
{
	int write_size = 0;

	if(fd == STDOUT_FILENO)
	{
		putbuf(buffer, length);
		return length;
	}

	lock_acquire(&file_lock);
	struct file *temp_file = get_process_file(fd);
	if(!temp_file)
	{
		lock_release(&file_lock);
		return ER_FAIL;
	}

	write_size = file_write(temp_file, buffer, length);
	lock_release(&file_lock);
	return write_size;
}

void seek(int fd, unsigned position)
{
	lock_acquire(&file_lock);
	struct file *file_temp = get_process_file(fd);
	if(!file_temp)
	{
		lock_release(&file_lock);
		return;
	}
	file_seek(file_temp, position);
	lock_release(&file_lock);
}

unsigned tell(int fd)
{
	unsigned offset;
	lock_acquire(&file_lock);
	struct file *file_temp = get_process_file(fd);
	if(!file_temp)
	{
		lock_release(&file_lock);
		return ER_FAIL;
	}
	offset = file_tell(file_temp);
	lock_release(&file_lock);
	return offset;
}

void check_ptr_validity(const void * vaddr)
{
	if(!(vaddr < PHYS_BASE) || vaddr < USER_ADDR_FLOOR)
	{
		exit(ER_FAIL);
	}
}

void check_valid_buffer(void *buffer, unsigned size)
{
	unsigned i = 0;
	char *temp_buffer = (char *)buffer;

	for(i = 0; i < size; i++)
	{
		check_ptr_validity((const void *)temp_buffer);
		temp_buffer++;
	}
}

int user_to_kernel_ptr(const void *vaddr)
{
	check_ptr_validity(vaddr);
	void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
	if(!ptr)
	{
		exit(ER_FAIL);
	}
	return (int) ptr;
}

void get_arg(struct intr_frame *f, int *arg, int size)
{
	int i = 0;
	int *ptr;

	for(i = 0; i < size; i++)
	{
		ptr = (int *) f->esp + i + 1;
		check_ptr_validity((const void *) ptr);
		arg[i] = *ptr;
	}
}

int add_process_file(struct file *new_file)
{
	p_file_t *p_file = malloc(sizeof(p_file_t));
	p_file->file = new_file;
	p_file->fd = thread_current()->fd;
	thread_current()->fd++;
	list_push_back(&thread_current()->file_list, &p_file->elem);
	return p_file->fd;
}

void close_process_file(int fd)
{
	struct thread *cur = thread_current();
	struct list_elem *file_elem = list_begin(&cur->file_list);
	struct list_elem *next;

	while(file_elem != list_end(&cur->file_list))
	{
		next = list_next(file_elem);
		p_file_t *file_temp = list_entry(file_elem, p_file_t, elem);
		if(file_temp->fd == fd || fd == CLOSE_FILES)
		{
			file_close(file_temp->file);
			list_remove(&file_temp->elem);
			free(file_temp);
			if(fd != CLOSE_FILES)
			{
				break;
			}
		}
	}
}

struct file * get_process_file(int fd)
{
	struct thread *cur = thread_current();
	struct list_elem *file_elem = NULL;

	for(file_elem = list_begin(&cur->file_list);
			file_elem != list_end(&cur->file_list);
			file_elem = list_next(file_elem))
	{
		p_file_t *p_file = list_entry(file_elem, p_file_t, elem);
		if(p_file->fd == fd)
		{
			return p_file->file;
		}
	}
	return NULL;
}

child_t* add_child(int pid)
{
	child_t *cp = (child_t *)malloc(sizeof(child_t));
	child_process_init(cp, pid);
	list_push_back(&thread_current()->child_list, &cp->elem);
	return cp;
}

void child_process_init(child_t *cp, int pid)
{
	cp->pid = pid;
	cp->load = NOT_LOADED;
	cp->wait = false;
	cp->exit = false;
	lock_init(&cp->wait_lock);
}

child_t* get_child(int pid)
{
	struct thread *cur = thread_current();
	struct list_elem *thread_elem;
	child_t	*found = NULL;

	for(thread_elem = list_begin(&cur->child_list);
			thread_elem != list_end(&cur->child_list);
			thread_elem = list_next(thread_elem))
	{
		child_t *cp = list_entry(thread_elem, child_t, elem);
		if(cp->pid == pid)
		{
			found = cp;
			break;
		}
	}
	return found;
}

/* used for when parent waits on child */
void remove_child(child_t *cp)
{
	list_remove(&cp->elem);
	free(cp);
}

/* used when parent is exiting */
void remove_all_child(void)
{
	struct thread *cur = thread_current();
	struct list_elem *thread_elem, *next;

	thread_elem = list_begin(&cur->child_list);
	while(thread_elem != list_end(&cur->child_list))
	{
		next = list_next(thread_elem);
		child_t *cp = list_entry(thread_elem, child_t, elem);
		list_remove(&cp->elem);
		free(cp);
		thread_elem = next;
	}
}
