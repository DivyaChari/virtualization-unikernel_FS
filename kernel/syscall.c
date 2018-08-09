/*
 * Copyright (c) 2010, Stefan Lankes, RWTH Aachen University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the University nor the names of its contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <hermit/stddef.h>
#include <hermit/stdio.h>
#include <hermit/tasks.h>
#include <hermit/errno.h>
#include <hermit/syscall.h>
#include <hermit/spinlock.h>
#include <hermit/semaphore.h>
#include <hermit/time.h>
#include <hermit/rcce.h>
#include <hermit/memory.h>
#include <hermit/signal.h>
#include <hermit/logging.h>
#include <asm/uhyve.h>
#include <sys/poll.h>
#include <hermit/fs.h>

#include <lwip/sockets.h>
#include <lwip/err.h>
#include <lwip/stats.h>

/*
 * Note that linker symbols are not variables, they have no memory allocated for
 * maintaining a value, rather their address is their value.
 */
extern const void kernel_start;

//TODO: don't use one big kernel lock to comminicate with all proxies
static spinlock_irqsave_t lwip_lock = SPINLOCK_IRQSAVE_INIT;

extern spinlock_irqsave_t stdio_lock;
extern int32_t isle;
extern int32_t possible_isles;
extern volatile int libc_sd;
//size_t ramdisk;
//size_t root_dir_addr = 0;
static inline int socket_send(int fd, const 	void* buf, size_t len)
{
	int ret, sz = 0;

	do {
		ret = lwip_write(fd, (char*)buf + sz, len-sz);
		if (ret >= 0)
			sz += ret;
		else
			return ret;
	} while(sz < len);

	return len;
}

static inline int socket_recv(int fd, void* buf, size_t len)
{
	int ret, sz = 0;

	do {
		ret = lwip_read(fd, (char*)buf + sz, len-sz);
		if (ret >= 0)
			sz += ret;
		else
			return ret;
	} while(sz < len);

	return len;
}

tid_t sys_getpid(void)
{
	task_t* task = per_core(current_task);

	return task->id;
}

int sys_getprio(tid_t* id)
{
	task_t* task = per_core(current_task);

	if (!id || (task->id == *id))
		return task->prio;
	return -EINVAL;
}

int sys_setprio(tid_t* id, int prio)
{
	return -ENOSYS;
}

void NORETURN do_exit(int arg);

typedef struct {
	int sysnr;
	int arg;
} __attribute__((packed)) sys_exit_t;

/** @brief To be called by the systemcall to exit tasks */
void NORETURN sys_exit(int arg)
{
	if (is_uhyve()) {
		uhyve_send(UHYVE_PORT_EXIT, (unsigned) virt_to_phys((size_t) &arg));
	} else {
		sys_exit_t sysargs = {__NR_exit, arg};

		spinlock_irqsave_lock(&lwip_lock);
		if (libc_sd >= 0)
		{
			int s = libc_sd;

			socket_send(s, &sysargs, sizeof(sysargs));
			libc_sd = -1;

			spinlock_irqsave_unlock(&lwip_lock);

			// switch to LwIP thread
			reschedule();

			lwip_close(s);
		} else {
			spinlock_irqsave_unlock(&lwip_lock);
		}
	}

	do_exit(arg);
}

typedef struct {
	int sysnr;
	int fd;
	size_t len;
} __attribute__((packed)) sys_read_t;

typedef struct {
	int fd;
	char* buf;
        size_t len;
	ssize_t ret;
} __attribute__((packed)) uhyve_read_t;

ssize_t sys_read(int fd, char* buf, size_t len)
{
	sys_read_t sysargs = {__NR_read, fd, len};
	ssize_t j, ret;

	// do we have an LwIP file descriptor?
	if (fd & LWIP_FD_BIT) {
		ret = lwip_read(fd & ~LWIP_FD_BIT, buf, len);
		if (ret < 0)
			return -errno;

		return ret;
	}

	if (is_uhyve()) {
		uhyve_read_t uhyve_args = {fd, (char*) virt_to_phys((size_t) buf), len, -1};

		uhyve_send(UHYVE_PORT_READ, (unsigned)virt_to_phys((size_t)&uhyve_args));

		return uhyve_args.ret;
	}

	spinlock_irqsave_lock(&lwip_lock);
	if (libc_sd < 0) {
		spinlock_irqsave_unlock(&lwip_lock);
		return -ENOSYS;
	}

	int s = libc_sd;
	socket_send(s, &sysargs, sizeof(sysargs));

	socket_recv(s, &j, sizeof(j));
	if (j > 0)
	{
		ret = socket_recv(s, buf, j);
		if (ret < 0) {
			spinlock_irqsave_unlock(&lwip_lock);
			return ret;
		}
	}

	spinlock_irqsave_unlock(&lwip_lock);

	return j;
}

ssize_t readv(int d, const struct iovec *iov, int iovcnt)
{
	return -ENOSYS;
}

typedef struct {
	int sysnr;
	int fd;
	size_t len;
} __attribute__((packed)) sys_write_t;

typedef struct {
	int fd;
	const char* buf;
	size_t len;
} __attribute__((packed)) uhyve_write_t;

ssize_t sys_write(int fd, const char* buf, size_t len)
{
	if (BUILTIN_EXPECT(!buf, 0))
		return -EINVAL;

	ssize_t i, ret;
	sys_write_t sysargs = {__NR_write, fd, len};

	// do we have an LwIP file descriptor?
	if (fd & LWIP_FD_BIT) {
		ret = lwip_write(fd & ~LWIP_FD_BIT, buf, len);
		if (ret < 0)
			return -errno;

		return ret;
	}

	if (is_uhyve()) {
		uhyve_write_t uhyve_args = {fd, (const char*) virt_to_phys((size_t) buf), len};

		uhyve_send(UHYVE_PORT_WRITE, (unsigned)virt_to_phys((size_t)&uhyve_args));

		return uhyve_args.len;
	}

	spinlock_irqsave_lock(&lwip_lock);
	if (libc_sd < 0)
	{
		spinlock_irqsave_unlock(&lwip_lock);

		spinlock_irqsave_lock(&stdio_lock);
		for(i=0; i<len; i++)
			kputchar(buf[i]);
		spinlock_irqsave_unlock(&stdio_lock);

		return len;
	}

	int s = libc_sd;
	socket_send(s, &sysargs, sizeof(sysargs));

	i=0;
	while(i < len)
	{
		ret = socket_send(s, (char*)buf+i, len-i);
		if (ret < 0) {
			spinlock_irqsave_unlock(&lwip_lock);
			return ret;
		}

		i += ret;
	}

	if (fd > 2)
		i = socket_recv(s, &i, sizeof(i));

	spinlock_irqsave_unlock(&lwip_lock);

	return i;
}

ssize_t writev(int fildes, const struct iovec *iov, int iovcnt)
{
	return -ENOSYS;
}

ssize_t sys_sbrk(ssize_t incr)
{
	ssize_t ret;
	vma_t* heap = per_core(current_task)->heap;
	static spinlock_t heap_lock = SPINLOCK_INIT;

	if (BUILTIN_EXPECT(!heap, 0)) {
		LOG_ERROR("sys_sbrk: missing heap!\n");
		do_abort();
	}

	spinlock_lock(&heap_lock);

	ret = heap->end;

	// check heapp boundaries
	if ((heap->end >= HEAP_START) && (heap->end+incr < HEAP_START + HEAP_SIZE)) {
		heap->end += incr;

		// reserve VMA regions
		if (PAGE_FLOOR(heap->end) > PAGE_FLOOR(ret)) {
			// region is already reserved for the heap, we have to change the
			// property
			vma_free(PAGE_FLOOR(ret), PAGE_CEIL(heap->end));
			vma_add(PAGE_FLOOR(ret), PAGE_CEIL(heap->end), VMA_HEAP|VMA_USER);
		}
	} else ret = -ENOMEM;

	// allocation and mapping of new pages for the heap
	// is catched by the pagefault handler

	spinlock_unlock(&heap_lock);

	return ret;
}

typedef struct {
	const char* name;
	int flags;
	int mode;
	int ret;
} __attribute__((packed)) uhyve_open_t;

int sys_open(const char* name, int flags, int mode)
{
	if (is_uhyve()) {
		uhyve_open_t uhyve_open = {(const char*)virt_to_phys((size_t)name), flags, mode, -1};

		uhyve_send(UHYVE_PORT_OPEN, (unsigned)virt_to_phys((size_t) &uhyve_open));

		return uhyve_open.ret;
	}

	int s, i, ret, sysnr = __NR_open;
	size_t len;

	spinlock_irqsave_lock(&lwip_lock);
	if (libc_sd < 0) {
		ret = -EINVAL;
		goto out;
	}

	s = libc_sd;
	len = strlen(name)+1;

	//i = 0;
	//lwip_setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &i, sizeof(i));

	ret = socket_send(s, &sysnr, sizeof(sysnr));
	if (ret < 0)
		goto out;

	ret = socket_send(s, &len, sizeof(len));
	if (ret < 0)
		goto out;

	i=0;
	while(i<len)
	{
		ret = socket_send(s, name+i, len-i);
		if (ret < 0)
			goto out;
		i += ret;
	}

	ret = socket_send(s, &flags, sizeof(flags));
	if (ret < 0)
		goto out;

	ret = socket_send(s, &mode, sizeof(mode));
	if (ret < 0)
		goto out;

	//i = 1;
	//lwip_setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &i, sizeof(i));

	socket_recv(s, &ret, sizeof(ret));

out:
	spinlock_irqsave_unlock(&lwip_lock);

	return ret;
}

typedef struct {
	int sysnr;
	int fd;
} __attribute__((packed)) sys_close_t;

typedef struct {
        int fd;
        int ret;
} __attribute__((packed)) uhyve_close_t;

int sys_close(int fd)
{
	int ret, s;
	sys_close_t sysargs = {__NR_close, fd};

	// do we have an LwIP file descriptor?
	if (fd & LWIP_FD_BIT) {
		ret = lwip_close(fd & ~LWIP_FD_BIT);
		if (ret < 0)
			return -errno;

		return 0;
	}

	if (is_uhyve()) {
		uhyve_close_t uhyve_close = {fd, -1};

		uhyve_send(UHYVE_PORT_CLOSE, (unsigned)virt_to_phys((size_t) &uhyve_close));

		return uhyve_close.ret;
	}

	spinlock_irqsave_lock(&lwip_lock);
	if (libc_sd < 0) {
		ret = 0;
		goto out;
	}

	s = libc_sd;
	ret = socket_send(s, &sysargs, sizeof(sysargs));
	if (ret != sizeof(sysargs))
		goto out;
	socket_recv(s, &ret, sizeof(ret));

out:
	spinlock_irqsave_unlock(&lwip_lock);

	return ret;
}

int sys_spinlock_init(spinlock_t** lock)
{
	int ret;

	if (BUILTIN_EXPECT(!lock, 0))
		return -EINVAL;

	*lock = (spinlock_t*) kmalloc(sizeof(spinlock_t));
	if (BUILTIN_EXPECT(!(*lock), 0))
		return -ENOMEM;

	ret = spinlock_init(*lock);
	if (ret) {
		kfree(*lock);
		*lock = NULL;
	}

	return ret;
}

int sys_spinlock_destroy(spinlock_t* lock)
{
	int ret;

	if (BUILTIN_EXPECT(!lock, 0))
		return -EINVAL;

	ret = spinlock_destroy(lock);
	if (!ret)
		kfree(lock);

	return ret;
}

int sys_spinlock_lock(spinlock_t* lock)
{
	if (BUILTIN_EXPECT(!lock, 0))
		return -EINVAL;

	return spinlock_lock(lock);
}

int sys_spinlock_unlock(spinlock_t* lock)
{
	if (BUILTIN_EXPECT(!lock, 0))
		return -EINVAL;

	return spinlock_unlock(lock);
}

void sys_msleep(unsigned int ms)
{
	if (ms * TIMER_FREQ / 1000 > 0)
		timer_wait(ms * TIMER_FREQ / 1000);
	else if (ms > 0)
		udelay(ms * 1000);
}

int sys_sem_init(sem_t** sem, unsigned int value)
{
	int ret;

	if (BUILTIN_EXPECT(!sem, 0))
		return -EINVAL;

	*sem = (sem_t*) kmalloc(sizeof(sem_t));
	if (BUILTIN_EXPECT(!(*sem), 0))
		return -ENOMEM;

	ret = sem_init(*sem, value);
	if (ret) {
		kfree(*sem);
		*sem = NULL;
	}

	return ret;
}

int sys_sem_destroy(sem_t* sem)
{
	int ret;

	if (BUILTIN_EXPECT(!sem, 0))
		return -EINVAL;

	ret = sem_destroy(sem);
	if (!ret)
		kfree(sem);

	return ret;
}

int sys_sem_wait(sem_t* sem)
{
	if (BUILTIN_EXPECT(!sem, 0))
		return -EINVAL;

	return sem_wait(sem, 0);
}

int sys_sem_post(sem_t* sem)
{
	if (BUILTIN_EXPECT(!sem, 0))
		return -EINVAL;

	return sem_post(sem);
}

int sys_sem_timedwait(sem_t *sem, unsigned int ms)
{
	if (BUILTIN_EXPECT(!sem, 0))
		return -EINVAL;

	return sem_wait(sem, ms);
}

int sys_sem_cancelablewait(sem_t* sem, unsigned int ms)
{
	if (BUILTIN_EXPECT(!sem, 0))
		return -EINVAL;

	return sem_wait(sem, ms);
}

int sys_clone(tid_t* id, void* ep, void* argv)
{
	return clone_task(id, ep, argv, per_core(current_task)->prio);
}

typedef struct {
	int sysnr;
	int fd;
	off_t offset;
	int whence;
} __attribute__((packed)) sys_lseek_t;

typedef struct {
	int fd;
	off_t offset;
	int whence;
} __attribute__((packed)) uhyve_lseek_t;

off_t sys_lseek(int fd, off_t offset, int whence)
{
	if (is_uhyve()) {
		uhyve_lseek_t uhyve_lseek = { fd, offset, whence };

		outportl(UHYVE_PORT_LSEEK, (unsigned)virt_to_phys((size_t) &uhyve_lseek));

		return uhyve_lseek.offset;
	}

	off_t off;
	sys_lseek_t sysargs = {__NR_lseek, fd, offset, whence};
	int s;

	spinlock_irqsave_lock(&lwip_lock);

	if (libc_sd < 0) {
		spinlock_irqsave_unlock(&lwip_lock);
		return -ENOSYS;
	}

	s = libc_sd;
	socket_send(s, &sysargs, sizeof(sysargs));
	socket_recv(s, &off, sizeof(off));

	spinlock_irqsave_unlock(&lwip_lock);

	return off;
}

int sys_rcce_init(int session_id)
{
	int i, err = 0;
	size_t paddr = 0;

	if (is_single_kernel())
		return -ENOSYS;

	if (session_id <= 0)
		return -EINVAL;

	islelock_lock(rcce_lock);

	for(i=0; i<MAX_RCCE_SESSIONS; i++)
	{
		if (rcce_mpb[i].id == session_id)
			break;
	}

	// create new session
	if (i >=MAX_RCCE_SESSIONS)
	{
		for(i=0; i<MAX_RCCE_SESSIONS; i++)
		{
			if (rcce_mpb[i].id == 0) {
				rcce_mpb[i].id = session_id;
				break;
			}
		}
	}

	if (i >= MAX_RCCE_SESSIONS)
	{
		err = -EINVAL;
		goto out;
	}

	if (is_hbmem_available())
		paddr = hbmem_get_pages(RCCE_MPB_SIZE / PAGE_SIZE);
	else
		paddr = get_pages(RCCE_MPB_SIZE / PAGE_SIZE);
	if (BUILTIN_EXPECT(!paddr, 0))
	{
		err = -ENOMEM;
		goto out;
	}

	rcce_mpb[i].mpb[isle] = paddr;

out:
	islelock_unlock(rcce_lock);

	LOG_INFO("Create MPB for session %d at 0x%zx, using of slot %d\n", session_id, paddr, i);

	return err;
}

size_t sys_rcce_malloc(int session_id, int ue)
{
	size_t vaddr = 0;
	int i, counter = 0;

	if (is_single_kernel())
		return -ENOSYS;

	if (session_id <= 0)
		return -EINVAL;

	// after 120 retries (= 120*300 ms) we give up
	do {
		for(i=0; i<MAX_RCCE_SESSIONS; i++)
		{
			if ((rcce_mpb[i].id == session_id) && rcce_mpb[i].mpb[ue])
				break;
		}

		if (i >= MAX_RCCE_SESSIONS) {
			counter++;
			timer_wait((300*TIMER_FREQ)/1000);
		}
	} while((i >= MAX_RCCE_SESSIONS) && (counter < 120));

	LOG_DEBUG("i = %d, counter = %d, max %d\n", i, counter, MAX_RCCE_SESSIONS);

	// create new session
	if (i >= MAX_RCCE_SESSIONS)
		goto out;

	vaddr = vma_alloc(RCCE_MPB_SIZE, VMA_READ|VMA_WRITE|VMA_USER|VMA_CACHEABLE);
        if (BUILTIN_EXPECT(!vaddr, 0))
		goto out;

	if (page_map(vaddr, rcce_mpb[i].mpb[ue], RCCE_MPB_SIZE / PAGE_SIZE, PG_RW|PG_USER|PG_PRESENT)) {
		vma_free(vaddr, vaddr + 2*PAGE_SIZE);
		goto out;
	}

	LOG_INFO("Map MPB of session %d at 0x%zx, using of slot %d, isle %d\n", session_id, vaddr, i, ue);

	if (isle == ue)
		memset((void*)vaddr, 0x0, RCCE_MPB_SIZE);

	return vaddr;

out:
	LOG_ERROR("Didn't find a valid MPB for session %d, isle %d\n", session_id, ue);

	return 0;
}

int sys_rcce_fini(int session_id)
{
	int i, j;
	int ret = 0;

	// we have to free the MPB

	if (is_single_kernel())
		return -ENOSYS;

	if (session_id <= 0)
		return -EINVAL;

	islelock_lock(rcce_lock);

	for(i=0; i<MAX_RCCE_SESSIONS; i++)
	{
		if (rcce_mpb[i].id == session_id)
			break;
	}

	if (i >= MAX_RCCE_SESSIONS) {
		ret = -EINVAL;
		goto out;
	}

	if (rcce_mpb[i].mpb[isle]) {
		if (is_hbmem_available())
			hbmem_put_pages(rcce_mpb[i].mpb[isle], RCCE_MPB_SIZE / PAGE_SIZE);
		else
			put_pages(rcce_mpb[i].mpb[isle], RCCE_MPB_SIZE / PAGE_SIZE);
	}
	rcce_mpb[i].mpb[isle] = 0;

	for(j=0; (j<MAX_ISLE) && !rcce_mpb[i].mpb[j]; j++) {
		PAUSE;
	}

	// rest full session
	if (j >= MAX_ISLE)
		rcce_mpb[i].id = 0;

out:
	islelock_unlock(rcce_lock);

	return ret;
}

size_t sys_get_ticks(void)
{
	return get_clock_tick();
}

int sys_stat(const char* file, /*struct stat *st*/ void* st)
{
	return -ENOSYS;
}

void sys_yield(void)
{
#if 0
	check_workqueues();
#else
	if (BUILTIN_EXPECT(go_down, 0))
		shutdown_system();
	check_scheduling();
#endif
}

int sys_kill(tid_t dest, int signum)
{
	if(signum < 0) {
		return -EINVAL;
	}
	return hermit_kill(dest, signum);
}

int sys_signal(signal_handler_t handler)
{
	return hermit_signal(handler);
}

//added...

int sys_my_syscall(int x)
{
return x + 42;
}

int sys_rename(const char *oldpath, const char *newpath)
{
/* you will do the implementation later, for now just return success :) */
return 0;
}

ssize_t sys_group_filewrite(size_t *fd, char* buf, size_t len)
{
	LOG_INFO("Inside file WRITE syscall.....\n");
	LOG_INFO("Ram Disk start address: %d \n", ramdisk);
	//int ret, sz = 0;
	fd = ramdisk;
	LOG_INFO("Ram Disk start address after assignment: %d \n", fd);
	//LOG_INFO("Per char value inside fd: %d \n", *fd);
	//LOG_INFO("Per char value inside buf: %d \n", *buf);

	do {
	
		LOG_INFO("Per char value inside buffer: %c \n", *buf);
		//memset(fd, *buf, sizeof(char));
		*fd = *buf;
		LOG_INFO("Per char value stored inside RAM: %c \n", *fd);
		fd = fd + 1;
		buf = buf + 1;
		//ret = lwip_read(fd, (char*)buf + sz, len-sz);
		//if (ret >= 0)
		//	sz += ret;
		//else
		//	return ret;
			
		len = len - 1;
	} while(len > 0);

	return len;

}
ssize_t sys_group_fileread(size_t *fd, char* buf, size_t len)
{
	//LOG_INFO("Inside file READ syscall.....\n");
	//LOG_INFO("Ram Disk start address: %d \n", ramdisk);
	fd = ramdisk;
	//LOG_INFO("Ram Disk start address after assignment: %d \n", fd);
	//int ret, sz = 0;

	do {
		//LOG_INFO("Per char value stored inside RAM: %c \n", *fd);
		//memset(fd, *buf, sizeof(char));
		*buf = *fd;
		//LOG_INFO("Per char value read into buf: %c \n", *buf);
		fd = fd + 1;
		buf = buf + 1;
		//ret = lwip_read(fd, (char*)buf + sz, len-sz);
		//if (ret >= 0)
		//	sz += ret;
		//else
		//	return ret;
		len = len - 1;
	} while(len > 0);

	return len;

}

ssize_t sys_fs_ls(char* buf)
{
	struct fs_Dentry *curr_dir;
	int i = 0;
	//ssize_t addr;
	curr_dir = fs_list(ramdisk);
	while(curr_dir->dir_child[i]!= NULL)
	{	struct fs_Inode *node; //= size_t *child_Inode;
		node = curr_dir->dir_child[i];
		/*LOG_INFO("inside LS syscall..\n");
		LOG_INFO("child name: %s \n", node->Inode_name);
		LOG_INFO("value in buffer before copy: %s \n", (buf));*/

		strcpy((buf), node->Inode_name);
		//LOG_INFO("child name copied to buffer: %s \n", (buf));
		++i; 
		buf = buf+(sizeof(char)*100);
	}

	return 0;
} 

ssize_t sys_fs_cwd(char* buf)
{
	struct fs_Dentry *curr_dir;
	int i = 0;
	//ssize_t addr;
	curr_dir = fs_list(ramdisk);
	//*buf = curr_dir->dir_path;
	strcpy(buf, curr_dir->dir_path);	
	//LOG_INFO("value read into buf: %s \n", buf);
	return 0;
} 


ssize_t sys_fs_mkdir(char *name)
{
	fs_makedir(ramdisk, root_dir_addr, name);
	return 0;
}

ssize_t sys_fs_cd(char *name){

	fs_change_dir(ramdisk, name);
	return 0;

}

size_t sys_fs_fopen(char *name, char *mode)
{
	struct fs_Superblk *super;	
	struct fs_Inode *node, *stub_node;
	super=ramdisk;
	node=super->pwd;
	
	for(int i=0;i<NUMBER_INODES;i++){
		if(node->child[i] != NULL){
			stub_node=node->child[i];
			if(strcmp(name,stub_node->Inode_name)==0 && strcmp(stub_node->Inode_type,"F")==0){
				super->pfd=node->child[i];
				return stub_node->Inode_index;
			}
		}	
	}
	
	return fs_fileopen(ramdisk, root_dir_addr, name, mode);	

}


size_t sys_fs_fclose(char *name){

	fs_fileclose(ramdisk, name);
	return 0;
}



size_t sys_fs_fwrite(size_t index, char *buf, char *mode, size_t len){

	struct fs_File *curr_file;
	struct FileBlock_list_node *head_block, *curr_block;
	//int no_recursions = len/(1024*4);
	//no_recursions++;
	
	curr_file = fs_fileread(index, ramdisk, root_dir_addr); //read info about the open file


	head_block = curr_file->content_buf_head;
	curr_block = curr_file->content_buf_curr;//how far have the data block list chain expanded

	//LOG_INFO("data inside kernel buffer: %s \n", curr_block->content_buf);

	int i=0,j=0,count=0;
	size_t block_size = BLOCK_SIZE_MAX;

	if(curr_block == NULL){

		curr_block = fs_filewrite(index, ramdisk, root_dir_addr, fileB_start_addr);	
	}
	else{
		count = curr_block->curr_write_ptr;
	}	
	
	//LOG_INFO("current value of count:%d\n",count);
	while(j < len-1){
		
		if(count== block_size)
		{	//LOG_INFO("writing to the next block with offset:%d \n", block_size);
			//LOG_INFO("Copied data into Memory:%s with j count: %d and count value: %d \n", curr_block->content_buf,j, count);
			block_size += BLOCK_SIZE_MAX;
			curr_block = fs_filewrite(index, ramdisk, root_dir_addr, fileB_start_addr);
			count =0;		

			/*if(curr_block->block_next !=NULL){
				curr_block=curr_block->block_next;
				LOG_INFO("There is a next block.....\n");
				count =0;
			}
			else{
				break;			
			}*/
		}

		if(buf[j] == NULL)//if(buf[j] == NULL)
			curr_block->content_buf[count] = '.';
		else
			curr_block->content_buf[count] = buf[j];
		j++;
		count++;
	}

	curr_block->curr_write_ptr = count;
	
	//buf[j] = '\0';
	//curr_file->curr_read_blk = curr_block;

/*	for(j=0;j<no_recursions;j++){
		if(curr_block !=NULL){
			for(i =0; i<(4*1024); i++){
				buf[i] = curr_block->content_buf[i];
			}
			
			curr_block=curr_block->next;
		}	
		else
			break;
	}	
	curr_file->curr_read_blk = curr_block;
	buf[len-1] = '\0';*/

	//LOG_INFO("Copied data into user buffer:%s with j count: %d \n", buf,j);
	return 0;

}


size_t sys_fs_fwrite_TODO(size_t index, char *buf, char *mode, size_t len){

	struct fs_Superblk *super;	
	struct fs_Inode *curr_file;
	struct FileBlock_list_node *fp;	
	size_t rem_space_currBlk;
	int blocks=0, overflow=0;
	char *buf_stub; 

	super = ramdisk;
	curr_file = super->pfd;
	//struct FileBlock_list_node *curr_block;
	if(strcmp(mode, "append") ==0){
		//LOG_INFO("Inode size append start %d \n", curr_file->Inode_size);
		rem_space_currBlk = (1024*4) - curr_file->Inode_size;
		//LOG_INFO("Remaining space in the current file %d \n", rem_space_currBlk);
		if(rem_space_currBlk > 0){
			//LOG_INFO("Remaining space in the current file\n");
			fp = curr_file->fcontent_buf_curr;
			int i, j;
			if(rem_space_currBlk >= len){	
				//LOG_INFO("Remaining space %d in the current file is greater than write buffer size %d \n",rem_space_currBlk, len);
				for(i=(curr_file->Inode_size), j=0; j<len; i++,j++ ){
					if(buf[j]=='\0')
						fp->content_buf[i] = '.';		
					else
						fp->content_buf[i] = buf[j];

					
					//LOG_INFO("copied string buf status from %c at %d to %c at %d\n", fp->content_buf[i], i,buf[j],j);			
				}
				//LOG_INFO("Copied data into file: %s \n", fp->content_buf);
				curr_file->Inode_size = curr_file->Inode_size + len;
				//LOG_INFO("Inode size after append in the same inode %d \n", curr_file->Inode_size);
				//rem_space_currBlk = (1024*4) - curr_file->Inode_size;
				return 0;
			}

			else{
				//LOG_INFO("Remaining space %d in the current file is less than write buffer size %d \n",rem_space_currBlk, len);		
				for(i=(curr_file->Inode_size), j=0; i< BLOCK_SIZE_MAX ; i++,j++ ){

					if(buf[j]=='\0')
						fp->content_buf[i] = '.';		
					else
						fp->content_buf[i] = buf[j];

					//LOG_INFO("copied string buf status from %c at %d to %c at %d\n", fp->content_buf[i], i,buf[j],j);		
				}
				curr_file->Inode_size = BLOCK_SIZE_MAX;

				/*LOG_INFO("Inode size after append in the same inode(OVERFLOW) %d \n", curr_file->Inode_size);
				LOG_INFO("current value of j :%d\n", j);				
				LOG_INFO("current addr of buf :%d\n", buf);*/

				int c=0;
				for(int p=j;p<len;p++){
					if(buf[p]=='\0')
						buf_stub[c] = '.';
					else	
						buf_stub[c] = buf[p];

					//LOG_INFO("copied string buf status from %c at %d to %c at %d\n", buf_stub[c], c,buf[p],p);			
					c++;					
				}
									
				buf_stub = (buf +j);
				//buf = &buf_stub;		
				//len = sizeof(buf);
				len = len - rem_space_currBlk;
				rem_space_currBlk = (1024*4) - curr_file->Inode_size;
				
				if(len>rem_space_currBlk){
					blocks = (len- rem_space_currBlk)/(1024*4);
					overflow = (len- rem_space_currBlk) % (1024*4);	
				}
					
				//if(blocks == 0 && overflow > 0)
				//	blocks = 1;
				//else if(blocks > 0 && overflow > 0)
				//	blocks++;	
			
				//LOG_INFO("BLOCKS: %d OV: %d\n", blocks, overflow);
				for(int b =0; b<blocks; b++){
					//fs_filewrite(index, ramdisk, root_dir_addr, fileB_start_addr, buf_stub, len);
					curr_file->Inode_size = len;
					buf_stub = (buf +(1024*4));
					len = len - (1024*4);
					//buf = buf + (1024*4);
					//len = len - (1024*4);		
				}

				//if(blocks == 0 && overflow > 0)



				//LOG_INFO("remaining buffer data to be copied to new inode starts at addr: %d with value: %s (OVERFLOW) \n", buf, buf[0]);	
				return 0;
			}						
			
		}

		/*if((len- rem_space_currBlk) > 0){
			LOG_INFO("inside this impossibility......\n");
			blocks = (len- rem_space_currBlk)/(1024*4);
			overflow = (len- rem_space_currBlk) % (1024*4);	
			LOG_INFO("BLOCKS: %d OV: %d\n", blocks, overflow);
		}*/
		/*else{
			blocks = 0;
			overflow = 0;	
			LOG_INFO("BLOCKS: %d OV: %d", blocks, overflow);
		}*/


		//len = len - rem_space_currBlk;
	}
	else if(strcmp(mode, "write") == 0){
		curr_file->Inode_size = curr_file->Inode_size + len;
		//LOG_INFO("Inode size first write %d \n", curr_file->Inode_size);
		blocks = (len)/(1024*4);
		overflow = (len) % (1024*4);			
	}		

	if(blocks == 0 && overflow > 0)
		blocks = 1;
	else if(blocks > 0 && overflow > 0)
		blocks++;	

	//LOG_INFO("BLOCKS: %d OV: %d before loop run to reserve Inodes\n", blocks, overflow);
	for(int i =0; i<blocks; i++){
		//fs_filewrite(index, ramdisk, root_dir_addr, fileB_start_addr, buf, len);
		curr_file->Inode_size = len;
		//buf = buf + (1024*4);
		//len = len - (1024*4);		
	}

	
	//curr_block = fileB_start_addr; //file_block section start	
	//fp = curr_file->location; //inode pointer
	return 0;
}


size_t sys_fs_fread(size_t index, char *buf, char *mode, size_t len){
	
	struct fs_File *curr_file;
	struct FileBlock_list_node *curr_block;
	//int no_recursions = len/(1024*4);
	//no_recursions++;
	
	curr_file = fs_fileread(index, ramdisk, root_dir_addr);
	curr_block = curr_file->content_buf_head;
	//LOG_INFO("data inside kernel buffer: %s \n", curr_block->content_buf);
	int i=0,j=0,count=0;
	size_t block_size = BLOCK_SIZE_MAX;
	while(j < len-1){
		
		if(j== block_size)
		{	//LOG_INFO("reading from next block with offset:%d \n", block_size);
			block_size += BLOCK_SIZE_MAX;			
			if(curr_block->block_next !=NULL){
				curr_block=curr_block->block_next;
				//LOG_INFO("There is a next block.....\n");
				count =0;
			}
			else{
				break;			
			}
		}

		if(curr_block->content_buf[count] == NULL){
			//buf[j] = '.';
			break;
		}
		else
			buf[j] = curr_block->content_buf[count];
		j++;
		count++;
	}
	
	buf[j] = '\0';
	curr_file->curr_read_blk = curr_block;
	curr_block->curr_read_ptr = count;

/*	for(j=0;j<no_recursions;j++){
		if(curr_block !=NULL){
			for(i =0; i<(4*1024); i++){
				buf[i] = curr_block->content_buf[i];
			}
			
			curr_block=curr_block->next;
		}	
		else
			break;
	}	
	curr_file->curr_read_blk = curr_block;
	buf[len-1] = '\0';*/

	//LOG_INFO("Copied data into user buffer:%s with j count: %d \n", buf,j);
	return 0;
}


size_t sys_fs_frm(char *name){

	fs_removeInode(ramdisk, root_dir_addr, name);
	return 0;
}


