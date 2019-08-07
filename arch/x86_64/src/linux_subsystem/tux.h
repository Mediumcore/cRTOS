#ifndef __LINUX_SUBSYSTEM_TUX_H
#define __LINUX_SUBSYSTEM_TUX_H

#include <unistd.h>
#include <fcntl.h>
#include <features.h>

#include <nuttx/config.h>
#include <nuttx/compiler.h>
#include <nuttx/mm/gran.h>

#include "up_internal.h"

#include <sys/time.h>
#include <sched/sched.h>

#include <arch/io.h>

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

#define TUX_WNOHANG		1	/* Don't block waiting.  */
#define TUX_WUNTRACED	2	/* Report status of stopped children.  */
#define TUX_WSTOPPED	2	/* Report stopped child (same as WUNTRACED). */
#define TUX_WEXITED		4	/* Report dead child.  */
#define TUX_WCONTINUED	8	/* Report continued child.  */
#define TUX_WNOWAIT		0x01000000 /* Don't reap, just poll status.  */

typedef unsigned long tux_cpu_mask;
# define TUX_NCPUBITS	(8 * sizeof (tux_cpu_mask))

/* Basic access functions.  */
# define TUX_CPUELT(cpu)	((cpu) / TUX_NCPUBITS)
# define TUX_CPUMASK(cpu)	((tux_cpu_mask) 1 << ((cpu) % TUX_NCPUBITS))

# if __GNUC_PREREQ (2, 91)
#  define TUX_CPU_ZERO_S(setsize, cpusetp) \
  do __builtin_memset (cpusetp, '\0', setsize); while (0)
# else
#  define TUX_CPU_ZERO_S(setsize, cpusetp) \
  do {									      \
    size_t __i;								      \
    size_t __imax = (setsize) / sizeof (tux_cpu_mask);			      \
    tux_cpu_mask *__bits = (cpusetp);				      \
    for (__i = 0; __i < __imax; ++__i)					      \
      __bits[__i] = 0;							      \
  } while (0)
# endif

# define TUX_CPU_SET_S(cpu, setsize, cpusetp) \
  (__extension__							      \
   ({ size_t __cpu = (cpu);						      \
      __cpu / 8 < (setsize)						      \
      ? (((tux_cpu_mask *) ((cpusetp)))[TUX_CPUELT (__cpu)]		      \
	 |= TUX_CPUMASK (__cpu))						      \
      : 0; }))
# define TUX_CPU_CLR_S(cpu, setsize, cpusetp) \
  (__extension__							      \
   ({ size_t __cpu = (cpu);						      \
      __cpu / 8 < (setsize)						      \
      ? (((tux_cpu_mask *) ((cpusetp)))[TUX_CPUELT (__cpu)]		      \
	 &= ~TUX_CPUMASK (__cpu))						      \
      : 0; }))

enum
{
  TUX_SS_ONSTACK = 1,
#define TUX_SS_ONSTACK	TUX_SS_ONSTACK
  TUX_SS_DISABLE
#define TUX_SS_DISABLE	TUX_SS_DISABLE
};


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

typedef struct sigaltstack {
    void *ss_sp;
    int ss_flags;
    size_t ss_size;
} stack_t;

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

int insert_proc_node(int lpid, int rpid);
int delete_proc_node(int rpid);

typedef long (*syscall_t)(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6);

void*   find_free_slot(void);
void    release_slot(void* slot);

static inline long tux_success_stub(void){
    return 0;
}

static inline long tux_fail_stub(void){
    return -1;
}

static inline long tux_no_impl(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                              uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                              uintptr_t parm6){
    _alert("Not implemented Linux syscall %d\n", nbr);
    PANIC();
    return -1;
}

long tux_local(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6);

long tux_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6);

long tux_file_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6);

long tux_poll_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6);

long tux_open_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6);

void add_remote_on_exit(struct tcb_s* tcb, void (*func)(int, void *), void *arg);
void tux_on_exit(int val, void* arg);

long     tux_nanosleep   (unsigned long nbr, const struct timespec *rqtp, struct timespec *rmtp);
long     tux_gettimeofday   (unsigned long nbr, struct timeval *tv, struct timezone *tz);

long     tux_clone       (unsigned long nbr, unsigned long flags, void *child_stack,
                         void *ptid, void *ctid, unsigned long tls);
long     tux_fork        (unsigned long nbr);
long     tux_vfork       (unsigned long nbr);

void    tux_mm_init     (void);
void*   tux_mmap        (unsigned long nbr, void* addr, size_t length, int prot, int flags, int fd, off_t offset);
long     tux_munmap      (unsigned long nbr, void* addr, size_t length);

long     tux_shmget      (unsigned long nbr, uint32_t key, uint32_t size, uint32_t flags);
long     tux_shmctl      (unsigned long nbr, int hv, uint32_t cmd, struct shmid_ds* buf);
void*   tux_shmat       (unsigned long nbr, int hv, void* addr, int flags);
long     tux_shmdt       (unsigned long nbr, void* addr);

long     tux_semget      (unsigned long nbr, uint32_t key, int nsems, uint32_t flags);
long     tux_semctl      (unsigned long nbr, int hv, int semnum, int cmd, union semun arg);
long     tux_semop       (unsigned long nbr, int hv, struct sembuf *tsops, unsigned int nops);
long     tux_semtimedop  (unsigned long nbr, int hv, struct sembuf *tsops, unsigned int nops, const struct timespec* timeout);

long     tux_getrlimit   (unsigned long nbr, int resource, struct rlimit *rlim);

int*    _tux_set_tid_address    (struct tcb_s *rtcb, int* tidptr);
long     tux_set_tid_address     (unsigned long nbr, int* tidptr);
void    tux_set_tid_callback    (int val, void* arg);

void*   tux_brk         (unsigned long nbr, void* brk);

long     tux_arch_prctl       (unsigned long nbr, int code, unsigned long addr);

long     tux_futex            (unsigned long nbr, int32_t* uaddr, int opcode, uint32_t val, uint32_t val2, int32_t* uaddr2, uint32_t val3);

long     tux_rt_sigaction     (unsigned long nbr, int sig, const struct tux_sigaction* act, struct tux_sigaction* old_act, uint64_t set_size);
long     tux_alarm            (unsigned long nbr, unsigned int second);

long     tux_select           (unsigned long nbr, int fd, struct tux_fd_set *r, struct tux_fd_set *w, struct tux_fd_set *e, struct timeval *timeout);

long     tux_getpid      (unsigned long nbr);
long     tux_gettid      (unsigned long nbr);
long     tux_getppid     (unsigned long nbr);
long     tux_pidhook     (unsigned long nbr, int pid, uintptr_t param2, uintptr_t param3, uintptr_t param4, uintptr_t param5, uintptr_t param6);
long     tux_waithook    (unsigned long nbr, uintptr_t param1, uintptr_t param2, uintptr_t param3, uintptr_t param4, uintptr_t param5, uintptr_t param6);

long     tux_exec        (unsigned long nbr, const char* path, char *argv[], char* envp[]);
long     _tux_exec       (char* path, char *argv[], char* envp[]);

long     tux_sigaltstack    (stack_t* ss, stack_t* oss);

static inline long     tux_sched_get_priority_max(unsigned long nbr, uint64_t p) { return sched_get_priority_max(p); };
static inline long     tux_sched_get_priority_min(unsigned long nbr, uint64_t p) { return sched_get_priority_min(p); };

long tux_sched_getaffinity(unsigned long nbr, long pid, unsigned int len, unsigned long *mask);

static inline long tux_pipe(unsigned long nbr, int pipefd[2], int flags){
    int ret = pipe(pipefd);
    pipefd[0] += CONFIG_TUX_FD_RESERVE;
    pipefd[1] += CONFIG_TUX_FD_RESERVE;
    return ret;
};

#endif//__LINUX_SUBSYSTEM_TUX_H
