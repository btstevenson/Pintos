#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"


void syscall_init (void);

#define ER_FAIL		-1
#define CLOSE_FILES -1

typedef enum
{
	NOT_LOADED,
	LOADED,
	LOAD_FAILED,
}load_status_t;

struct child_process
{
	int pid;
	load_status_t load;
	bool wait;
	bool exit;
	int status;
	struct lock wait_lock;
	struct list_elem elem;
};
typedef struct child_process child_t;

child_t* add_child(int pid);
child_t* get_child(int pid);

void close_process_file(int fd);

void remove_child(child_t *cp);
void remove_all_child(void);

#endif /* userprog/syscall.h */
