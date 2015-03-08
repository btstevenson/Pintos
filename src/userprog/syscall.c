#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"

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
		case SYS_EXIT:
		{
			get_arg(f, &arg[0], exit_t);
			exit(arg[0]);
			break;
		}
	}
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
