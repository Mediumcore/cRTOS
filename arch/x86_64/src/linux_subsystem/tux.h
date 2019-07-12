#ifndef __LINUX_SUBSYSTEM_TUX_H
#define __LINUX_SUBSYSTEM_TUX_H

#include <nuttx/config.h>
#include <nuttx/compiler.h>
#include <nuttx/mm/gran.h>

#include "up_internal.h"

#include <sys/time.h>
#include <sched/sched.h>

#include <arch/io.h>

#define TUX_FD_OFFSET (CONFIG_NFILE_DESCRIPTORS + CONFIG_NSOCKET_DESCRIPTORS + 16)

#define PAGE_SLOT_SIZE 0x1000000

#define FUTEX_WAIT 0x0
#define FUTEX_WAKE 0x1
#define FUTEX_WAKE_OP 0x5
#define FUTEX_PRIVATE_FLAG 0x80

#define FUTEX_OP_SET        0  /* uaddr2 = oparg; */
#define FUTEX_OP_ADD        1  /* uaddr2 += oparg; */
#define FUTEX_OP_OR         2  /* uaddr2 |= oparg; */
#define FUTEX_OP_ANDN       3  /* uaddr2 &= ~oparg; */
#define FUTEX_OP_XOR        4  /* uaddr2 ^= oparg; */

#define FUTEX_OP_ARG_SHIFT  8  /* Use (1 << oparg) as operand */

#define FUTEX_GET_OP(x) ((x >> 28) & 0xf)
#define FUTEX_GET_OPARG(x) ((int32_t)((x >> 12) & 0xfff) << 20 >> 20)

#define FUTEX_OP_CMP_EQ     0  /* if (oldval == cmparg) wake */
#define FUTEX_OP_CMP_NE     1  /* if (oldval != cmparg) wake */
#define FUTEX_OP_CMP_LT     2  /* if (oldval < cmparg) wake */
#define FUTEX_OP_CMP_LE     3  /* if (oldval <= cmparg) wake */
#define FUTEX_OP_CMP_GT     4  /* if (oldval > cmparg) wake */
#define FUTEX_OP_CMP_GE     5  /* if (oldval >= cmparg) wake */

#define FUTEX_GET_CMP(x) ((x >> 24) & 0xf)
#define FUTEX_GET_CMPARG(x) ((int32_t)(x & 0xfff) << 20 >> 20)

#define TUX_O_ACCMODE	00000003
#define TUX_O_RDONLY	00000000
#define TUX_O_WRONLY	00000001
#define TUX_O_RDWR		00000002
#define TUX_O_CREAT		00000100
#define TUX_O_EXCL		00000200
#define TUX_O_NOCTTY	00000400
#define TUX_O_TRUNC		00001000
#define TUX_O_APPEND	00002000
#define TUX_O_NONBLOCK	00004000
#define TUX_O_DSYNC		00010000
#define TUX_O_DIRECT	00040000
#define TUX_O_LARGEFILE	00100000
#define TUX_O_DIRECTORY	00200000
#define TUX_O_NOFOLLOW	00400000
#define TUX_O_NOATIME	01000000
#define TUX_O_CLOEXEC	02000000
#define TUX__O_SYNC	    04000000
#define TUX_O_SYNC		    (TUX__O_SYNC|TUX_O_DSYNC)
#define TUX_O_PATH		   010000000
#define TUX__O_TMPFILE	    020000000
#define TUX_O_TMPFILE       (TUX__O_TMPFILE | TUX_O_DIRECTORY)
#define TUX_O_TMPFILE_MASK  (TUX__O_TMPFILE | TUX_O_DIRECTORY | TUX_O_CREAT)
#define TUX_O_NDELAY	    O_NONBLOCK

#define TUX_FD_SETSIZE 1024
#define TUX_NFDBITS	(8 * (int) sizeof (long int))
#define TUX_FD_ELT(d)   ((d) / TUX_NFDBITS)
#define TUX_FD_MASK(d)  ((long int) (1UL << ((d) % TUX_NFDBITS)))

#define TUX_IPC_CREAT	01000		/* create key if key does not exist. */
#define TUX_IPC_EXCL	02000		/* fail if key exists.  */

#define TUX_IPC_RMID 0     /* remove resource */
#define TUX_IPC_SET  1     /* set ipc_perm options */
#define TUX_IPC_STAT 2     /* get ipc_perm options */
#define TUX_IPC_INFO 3     /* see ipcs */

#define TUX_SHM_LOCK 11

#define TUX_SEM_GETVAL		12		/* get semval */
#define TUX_SEM_GETALL		13		/* get all semval's */
#define TUX_SEM_SETVAL		16		/* set semval */
#define TUX_SEM_SETALL		17		/* set all semval's */

#define TUX_SEM_UNDO        0x1000          /* undo the operation on exit */

extern GRAN_HANDLE tux_mm_hnd;

struct rlimit {
  unsigned long rlim_cur;  /* Soft limit */
  unsigned long rlim_max;  /* Hard limit (ceiling for rlim_cur) */
};

struct tux_sigaction{
    uintptr_t  __sigaction_handler;
    unsigned long sa_mask;
    unsigned long sa_flags;
    void (*sa_restorer) (void);
};

struct tux_fd_set
{
    long int __fds_bits[TUX_FD_SETSIZE / TUX_NFDBITS];
};

struct ipc_perm {
   uint32_t       __key;    /* Key supplied to shmget(2) */
   uint64_t       uid;      /* Effective UID of owner */
   uint64_t       gid;      /* Effective GID of owner */
   uint64_t       cuid;     /* Effective UID of creator */
   uint64_t       cgid;     /* Effective GID of creator */
   unsigned short mode;     /* Permissions + SHM_DEST and
                               SHM_LOCKED flags */
   unsigned short __seq;    /* Sequence number */
};

struct shmid_ds
{
    struct ipc_perm shm_perm;		/* operation permission struct */
    uint64_t shm_segsz;			/* size of segment in bytes */
    uint64_t shm_atime;			/* time of last shmat() */
    uint64_t shm_dtime;			/* time of last shmdt() */
    uint64_t shm_ctime;			/* time of last change by shmctl() */
    uint32_t shm_cpid;			/* pid of creator */
    uint32_t shm_lpid;			/* pid of last shmop */
    uint64_t shm_nattch;		/* number of current attaches */
    uint64_t __glibc_reserved4;
    uint64_t __glibc_reserved5;
};

struct semid_ds
{
    struct ipc_perm sem_perm;		/* operation permission struct */
    uint64_t sem_otime;			/* last semop() time */
    uint64_t __glibc_reserved1;
    uint64_t sem_ctime;			/* last time changed by semctl() */
    uint64_t __glibc_reserved2;
    uint64_t sem_nsems;		/* number of semaphores in set */
    uint64_t __glibc_reserved3;
    uint64_t __glibc_reserved4;
};

union semun {
    int val;			/* value for SETVAL */
    struct semid_ds *buf;	/* buffer for IPC_STAT & IPC_SET */
    unsigned short *array;	/* array for GETALL & SETALL */
    struct seminfo *__buf;	/* buffer for IPC_INFO */
    void *__pad;
};

struct sembuf
{
  unsigned short int sem_num;	/* semaphore number */
  short int sem_op;		/* semaphore operation */
  short int sem_flg;		/* operation flag */
};

static inline uint64_t set_msr(unsigned long nbr){
    uint32_t bitset = *((volatile uint32_t*)0xfb503280 + 4);
    bitset |= (1 << 1);
    *((volatile uint32_t*)0xfb503280 + 4) = bitset;
    return 0;
}

static inline uint64_t unset_msr(unsigned long nbr){
    uint32_t bitset = *((volatile uint32_t*)0xfb503280 + 4);
    bitset &= ~(1 << 1);
    *((volatile uint32_t*)0xfb503280 + 4) = bitset;
    return 0;
}

static inline uint64_t* temp_map_at_0xc0000000(uintptr_t start, uintptr_t end)
{
  uintptr_t k;
  uintptr_t lsb = start & ~HUGE_PAGE_MASK;
  start &= HUGE_PAGE_MASK;

  svcinfo("Temp map %llx - %llx at 0xc0000000\n", start, end);

  // Temporary map the new pdas at high memory 0xc000000 ~
  for(k = start; k < end; k += HUGE_PAGE_SIZE)
    {
      pd[((0xc0000000 + k - start) >> 21) & 0x7ffffff] = k | 0x9b; // No cache
    }

  up_invalid_TLB(start, end);

  return (uint64_t*)(0xc0000000 + lsb);
}

typedef int (*syscall_t)(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6);

void*   find_free_slot(void);
void    release_slot(void* slot);

static inline int tux_success_stub(void){
    return 0;
}

static inline int tux_fail_stub(void){
    return -1;
}

static inline int tux_no_impl(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                              uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                              uintptr_t parm6){
    _alert("Not implemented Linux syscall %d\n", nbr);
    PANIC();
    return -1;
}

int tux_local(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6);

int tux_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6);

int tux_file_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6);

int tux_poll_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6);

int tux_open_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6);

void add_remote_on_exit(struct tcb_s* tcb, void (*func)(int, void *), void *arg);
void tux_on_exit(int val, void* arg);

int     tux_nanosleep   (unsigned long nbr, const struct timespec *rqtp, struct timespec *rmtp);
int     tux_gettimeofday   (unsigned long nbr, struct timeval *tv, struct timezone *tz);

int     tux_clone       (unsigned long nbr, unsigned long flags, void *child_stack,
                         void *ptid, void *ctid, unsigned long tls);

void    tux_mm_init     (void);
void*   tux_mmap        (unsigned long nbr, void* addr, size_t length, int prot, int flags, int fd, off_t offset);
int     tux_munmap      (unsigned long nbr, void* addr, size_t length);

int     tux_shmget      (unsigned long nbr, uint32_t key, uint32_t size, uint32_t flags);
int     tux_shmctl      (unsigned long nbr, int hv, uint32_t cmd, struct shmid_ds* buf);
void*   tux_shmat       (unsigned long nbr, int hv, void* addr, int flags);
int     tux_shmdt       (unsigned long nbr, void* addr);

int     tux_semget      (unsigned long nbr, uint32_t key, int nsems, uint32_t flags);
int     tux_semctl      (unsigned long nbr, int hv, int semnum, int cmd, union semun arg);
int     tux_semop       (unsigned long nbr, int hv, struct sembuf *tsops, unsigned int nops);
int     tux_semtimedop  (unsigned long nbr, int hv, struct sembuf *tsops, unsigned int nops, const struct timespec* timeout);

int     tux_getrlimit   (unsigned long nbr, int resource, struct rlimit *rlim);

int*    _tux_set_tid_address    (struct tcb_s *rtcb, int* tidptr);
int     tux_set_tid_address     (unsigned long nbr, int* tidptr);
void    tux_set_tid_callback    (int val, void* arg);

void*   tux_brk         (unsigned long nbr, void* brk);

int     tux_arch_prctl       (unsigned long nbr, int code, unsigned long addr);

int     tux_futex            (unsigned long nbr, int32_t* uaddr, int opcode, uint32_t val, uint32_t val2, int32_t* uaddr2, uint32_t val3);

int     tux_rt_sigaction     (unsigned long nbr, int sig, const struct tux_sigaction* act, struct tux_sigaction* old_act, uint64_t set_size);
int     tux_alarm            (unsigned long nbr, unsigned int second);

int     tux_select           (unsigned long nbr, int fd, struct tux_fd_set *r, struct tux_fd_set *w, struct tux_fd_set *e, struct timeval *timeout);

static inline int     tux_sched_get_priority_max(unsigned long nbr, uint64_t p) { return sched_get_priority_max(p); };
static inline int     tux_sched_get_priority_min(unsigned long nbr, uint64_t p) { return sched_get_priority_min(p); };

static inline int tux_pipe(unsigned long nbr, int pipefd[2], int flags){
    int ret = pipe2(pipefd, PAGE_SIZE);
    pipefd[0] += CONFIG_TUX_FD_RESERVE;
    pipefd[1] += CONFIG_TUX_FD_RESERVE;
    return ret;
};

#endif//__LINUX_SUBSYSTEM_TUX_H
