/****************************************************************************
 *  arch/x86_64/src/broadwell/broadwell_linux_subsystem.c
 *
 *   Copyright (C) 2011-2012, 2014-2015 Gregory Nutt. All rights reserved.
 *   Author: Gregory Nutt <gnutt@nuttx.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <nuttx/arch.h>
#include <nuttx/sched.h>
#include <nuttx/board.h>
#include <nuttx/irq.h>
#include <arch/io.h>
#include <syscall.h>
#include <semaphore.h>
#include <errno.h>

#include "up_internal.h"
#include "sched/sched.h"

#ifdef CONFIG_LIB_SYSCALL

#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003

#define MAP_ANONYMOUS 0x20
#define MAP_NONRESERVE 0x4000

#define FUTEX_WAIT 0x0
#define FUTEX_WAKE 0x1
#define FUTEX_PRIVATE_FLAG 0x80

void* up_brk(void* brk);
int up_prctl(int code, unsigned long addr);
void* up_mmap(void* addr, size_t length, int prot, int flags);
int up_munmap(void* addr, size_t length);
int up_futex(uint32_t* uaddr, int opcode, uint32_t val);

int16_t linux_syscall_table[500] = {
    SYS_read,
    SYS_write,
    SYS_open,
    SYS_close,
    SYS_stat,
    SYS_fstat,
    -1, // sys_lstat
    SYS_poll,
    SYS_lseek,
    -1, // SYS_mmap,
    -1, // SYS_mprotect,
    -1, // SYS_munmap,
    -1, // sys_brk
    SYS_sigaction,
    SYS_sigprocmask,
    -1, // SYS_sigreturn,
    SYS_ioctl,
    SYS_pread,
    SYS_pwrite,
    -1, // sys_readv
    -1, // sys_writev
    -1, // sys_access
    -1, // sys_pipe
    SYS_select,
    SYS_sched_yield,
    -1, // sys_mremap
    -1, // sys_msync
    -1, // sys_mincore
    -1, // sys_madvise
    -1, // SYS_shmget,
    -1, // SYS_shmat,
    -1, // SYS_shmctl,
    SYS_dup,
    SYS_dup2,
    -1, // SYS_pause,
    -1, // SYS_nanosleep,
    -1, // SYS_getitimer,
    -1, // SYS_alarm,
    -1, // SYS_setitimer,
    SYS_getpid,
    -1, // SYS_sendfile,
    SYS_socket,
    SYS_connect,
    SYS_accept,
    SYS_sendto,
    SYS_recvfrom,
    -1, // SYS_sendmsg,
    -1, // SYS_recvmsg,
    -1, // SYS_shutdown,
    SYS_bind,
    SYS_listen,
    -1, // SYS_getsockname,
    -1, // SYS_getpeername,
    -1, // SYS_socketpair,
    SYS_setsockopt,
    SYS_getsockopt,
    -1, // sys_clone,
    -1, // sys_fork
    -1, // sys_vfrok
    -1, // sys_execve
    SYS_exit,
    -1, // sys_wait4
    SYS_kill,
    SYS_uname,
    -1, // SYS_semget,
    -1, // SYS_semop,
    -1, // SYS_semctl,
    -1, // SYS_shmdt,
    -1, // SYS_msgget,
    -1, // SYS_msgsnd,
    -1, // SYS_msgrcv,
    -1, // SYS_msgctl,
    SYS_fcntl,
    -1, // SYS_flock,
    SYS_fsync,
    -1, // SYS_fdatasync,
    -1, // SYS_truncate,
    SYS_ftruncate,
    -1, // SYS_getdents,
    -1, // SYS_getcwd,
    -1, // SYS_chdir,
    -1, // SYS_fchdir,
    SYS_rename,
    SYS_mkdir,
    SYS_rmdir,
    -1, // SYS_creat,
    -1, // SYS_link, Only peusdo pilesystem are supported, not useful, disabled for now
    SYS_unlink,
    -1, // SYS_symlink,
    -1, // SYS_readlink,
    -1, // SYS_chmod,
    -1, // SYS_fchmod,
    -1, // SYS_chown,
    -1, // SYS_fchown,
    -1, // SYS_lchown,
    -1, // SYS_umask,
    -1, // SYS_gettimeofday,
    -1, // SYS_getrlimit,
    -1, // SYS_getrusage,
    -1, // SYS_sysinfo,
    -1, // SYS_times,
    -1, // SYS_ptrace,
    -1, // SYS_getuid,
    -1, // SYS_syslog,
    -1, // SYS_getgid,
    -1, // SYS_setuid,
    -1, // SYS_setgid,
    -1, // SYS_geteuid,
    -1, // SYS_getegid,
    -1, // SYS_setpgid,
    -1, // SYS_getppid,
    -1, // SYS_getpgrp,
    -1, // SYS_setsid,
    -1, // SYS_setreuid,
    -1, // SYS_setregid,
    -1, // SYS_getgroups,
    -1, // SYS_setgroups,
    -1, // SYS_setresuid,
    -1, // SYS_getresuid,
    -1, // SYS_setresgid,
    -1, // SYS_getresgid,
    -1, // SYS_getpgid,
    -1, // SYS_setfsuid,
    -1, // SYS_setfsgid,
    -1, // SYS_getsid,
    -1, // SYS_capget,
    -1, // SYS_capset,
    SYS_sigpending,
    SYS_sigtimedwait,
    -1, // SYS_rt_sigqueueinfo,
    SYS_sigsuspend,
    -1, // SYS_sigaltstack,
    -1, // SYS_utime,
    -1, // SYS_mknod,
    -1, // SYS_uselib,
    -1, // SYS_personality,
    -1, // SYS_ustat,
    SYS_statfs,
    SYS_fstatfs,
    -1, // SYS_sysfs,
    -1, // SYS_getpriority,
    -1, // SYS_setpriority,
    SYS_sched_setparam,
    SYS_sched_getparam,
    SYS_sched_setscheduler,
    SYS_sched_getscheduler,
    -1, // SYS_sched_get_priority_max,
    -1, // SYS_sched_get_priority_min,
    SYS_sched_rr_get_interval,
    -1, // SYS_mlock,
    -1, // SYS_munlock,
    -1, // SYS_mlockall,
    -1, // SYS_munlockall,
    -1, // SYS_vhangup,
    -1, // SYS_modify_ldt,
    -1, // SYS_pivot_root,
    -1, // SYS__sysctl,
    -1, // SYS_prctl,
    -1, // SYS_arch_prctl,
    -1, // SYS_adjtimex,
    -1, // SYS_setrlimit,
    -1, // SYS_chroot,
    -1, // SYS_sync,
    -1, // SYS_acct,
    -1, // SYS_settimeofday,
    SYS_mount,
    SYS_umount2,
    -1, // SYS_swapon,
    -1, // SYS_swapoff,
    -1, // SYS_reboot,
    -1, // SYS_sethostname,
    -1, // SYS_setdomainname,
    -1, // SYS_iopl,
    -1, // SYS_ioperm,
    -1, // SYS_create_module,
    -1, // SYS_init_module,
    -1, // SYS_delete_module,
    -1, // SYS_get_kernel_syms,
    -1, // SYS_query_module,
    -1, // SYS_quotactl,
    -1, // SYS_nfsservctl,
    -1, // SYS_getpmsg,
    -1, // SYS_putpmsg,
    -1, // SYS_afs_syscall,
    -1, // SYS_tuxcall,
    -1, // SYS_security,
    SYS_getpid, // Fake get tid to get pid, not a different in our world heh?
    -1, // SYS_readahead,
    -1, // SYS_setxattr,
    -1, // SYS_lsetxattr,
    -1, // SYS_fsetxattr,
    -1, // SYS_getxattr,
    -1, // SYS_lgetxattr,
    -1, // SYS_fgetxattr,
    -1, // SYS_listxattr,
    -1, // SYS_llistxattr,
    -1, // SYS_flistxattr,
    -1, // SYS_removexattr,
    -1, // SYS_lremovexattr,
    -1, // SYS_fremovexattr,
    -1, // SYS_tkill,
    -1, // SYS_time,
    -1, // SYS_futex,
    -1, // SYS_sched_setaffinity, // Only if we expend to SMP
    -1, // SYS_sched_getaffinity,
    -1, // SYS_set_thread_area,
    -1, // SYS_io_setup,
    -1, // SYS_io_destroy,
    -1, // SYS_io_getevents,
    -1, // SYS_io_submit,
    -1, // SYS_io_cancel,
    -1, // SYS_get_thread_area,
    -1, // SYS_lookup_dcookie,
    -1, // SYS_epoll_create,
    -1, // SYS_epoll_ctl_old,
    -1, // SYS_epoll_wait_old,
    -1, // SYS_remap_file_pages,
    -1, // SYS_getdents64,
    -1, // SYS_set_tid_address,
    -1, // SYS_restart_syscall,
    -1, // SYS_semtimedop,
    -1, // SYS_fadvise64,
    SYS_timer_create,
    SYS_timer_settime,
    SYS_timer_gettime,
    SYS_timer_getoverrun,
    SYS_timer_delete,
    SYS_clock_settime,
    SYS_clock_gettime,
    SYS_clock_getres,
    SYS_clock_nanosleep,
    -1, // SYS_exit_group,
    -1, // SYS_epoll_wait,
    -1, // SYS_epoll_ctl,
    -1, // SYS_tgkill,
    -1, // SYS_utimes,
    -1, // SYS_vserver,
    -1, // SYS_mbind,
    -1, // SYS_set_mempolicy,
    -1, // SYS_get_mempolicy,
    SYS_mq_open,
    SYS_mq_unlink,
    SYS_mq_timedsend,
    SYS_mq_timedreceive,
    SYS_mq_notify,
    -1, // SYS_mq_getsetattr, // Maybe we should glue one out?
    -1, // SYS_kexec_load,
    SYS_waitpid,
    -1, // SYS_add_key,
    -1, // SYS_request_key,
    -1, // SYS_keyctl,
    -1, // SYS_ioprio_set,
    -1, // SYS_ioprio_get,
    -1, // SYS_inotify_init,
    -1, // SYS_inotify_add_watch,
    -1, // SYS_inotify_rm_watch,
    -1, // SYS_migrate_pages,
    -1, // SYS_openat,
    -1, // SYS_mkdirat,
    -1, // SYS_mknodat,
    -1, // SYS_fchownat,
    -1, // SYS_futimesat,
    -1, // SYS_newfstatat,
    -1, // SYS_unlinkat,
    -1, // SYS_renameat,
    -1, // SYS_linkat,
    -1, // SYS_symlinkat,
    -1, // SYS_readlinkat,
    -1, // SYS_fchmodat,
    -1, // SYS_faccessat,
    -1, // SYS_pselect6,
    -1, // SYS_ppoll,
    -1, // SYS_unshare,
    -1, // SYS_set_robust_list,
    -1, // SYS_get_robust_list,
    -1, // SYS_splice,
    -1, // SYS_tee,
    -1, // SYS_sync_file_range,
    -1, // SYS_vmsplice,
    -1, // SYS_move_pages,
    -1, // SYS_utimensat,
    -1, // SYS_epoll_pwait,
    -1, // SYS_signalfd,
    -1, // SYS_timerfd_create,
    -1, // SYS_eventfd,
    -1, // SYS_fallocate,
    -1, // SYS_timerfd_settime,
    -1, // SYS_timerfd_gettime,
    -1, // SYS_accept4,
    -1, // SYS_signalfd4,
    -1, // SYS_eventfd2,
    -1, // SYS_epoll_create1,
    -1, // SYS_dup3,
    SYS_pipe2,
    -1, // SYS_inotify_init1,
    -1, // SYS_preadv,
    -1, // SYS_pwritev,
    -1, // SYS_rt_tgsigqueueinfo,
    -1, // SYS_perf_event_open,
    -1, // SYS_recvmmsg,
    -1, // SYS_fanotify_init,
    -1, // SYS_fanotify_mark,
    -1, // SYS_prlimit64,
    -1, // SYS_name_to_handle_at,
    -1, // SYS_open_by_handle_at,
    -1, // SYS_clock_adjtime,
    -1, // SYS_syncfs,
    -1, // SYS_sendmmsg,
    -1, // SYS_setns,
    -1, // SYS_getcpu,
    -1, // SYS_process_vm_readv,
    -1, // SYS_process_vm_writev,
    -1, // SYS_kcmp,
    -1, // SYS_finit_module,
    -1, // SYS_sched_setattr,
    -1, // SYS_sched_getattr,
    -1, // SYS_renameat2,
    -1, // SYS_seccomp,
    SYS_getrandom,
    -1, // SYS_memfd_create,
    -1, // SYS_kexec_file_load,
    -1, // SYS_bpf,
    -1, // SYS_execveat,
    -1, // SYS_userfaultfd,
    -1, // SYS_membarrier,
    -1, // SYS_mlock2,
    -1, // SYS_copy_file_range,
    -1, // SYS_preadv2,
    -1, // SYS_pwritev2,
    -1, // SYS_pkey_mprotect,
    -1, // SYS_pkey_alloc,
    -1, // SYS_pkey_free,
    -1, // SYS_statx,
    -1, // SYS_io_pgetevents,
    -1 // SYS_rseq,
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

uint64_t linux_interface(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  uint64_t ret;
  int cmd = linux_syscall_table[nbr];

  svcinfo("Linux Entry: nbr: %llu cmd: %lld\n", nbr, cmd);

  // Do some emulated syscall here
  switch(nbr){
    case 9: // SYS_mmap
      // What mmap? I thought u just would like some memory
      ret = up_mmap(parm1, parm2, parm3, parm4);
      break;
    case 11: // SYS_munmap
      // What munmap? I thought u just would like free some memory
      ret = up_munmap(parm1, parm2);
      break;
    case 12: // SYS_brk
      ret = up_brk(parm1);
      break;
    case 21: // SYS_access
      ret = -1; // No such offer
      break;
    case 89: // SYS_readlink
      ret = -EINVAL; // No such offer
      break;
    case 102: // SYS_getuid
    case 104: // SYS_getgid
    case 107: // SYS_geteuid
    case 108: // SYS_getegid
      ret = 0; // I am root
      break;
    case 158: // SYS_prctl
      ret = up_prctl(parm1, parm2);
      break;
    case 202: // SYS_futex
      ret = up_futex(parm1, parm2, parm3);
      break;
    case 231: // SYS_exit_group
      // XXX: We should scan and terminate all threads
      exit(parm1);
      break;
    default:
      /* Verify that the SYS call number is within range */
      DEBUGASSERT(cmd >= CONFIG_SYS_RESERVED && cmd < SYS_maxsyscall);

      /* Call syscall from table. */
      cmd -= CONFIG_SYS_RESERVED;
      ret = ((uint64_t(*)(unsigned long, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t))(g_stublookup[cmd]))(cmd, parm1, parm2, parm3, parm4, parm5, parm6);
      break;
  }

  return ret;
}

void* up_brk(void* brk){
  struct tcb_s *rtcb = this_task();
  if((rtcb->xcp.page_table[0] != 0) && (brk > rtcb->xcp.__min_brk))
  {
    rtcb->xcp.__brk = brk;
    if(rtcb->xcp.__brk >= (void*)PAGE_SLOT_SIZE)
      rtcb->xcp.__brk = (void*)(PAGE_SLOT_SIZE - 1);
  }
  return rtcb->xcp.__brk;
}

int up_prctl(int code, unsigned long addr){
  struct tcb_s *rtcb = this_task();
  int ret = 0;

  switch(code){
    case ARCH_GET_FS:
      *(unsigned long*)addr = read_msr(MSR_FS_BASE);
      break;
    case ARCH_SET_FS:
      rtcb->xcp.fs_base_set = 1;
      rtcb->xcp.fs_base = addr;
      write_msr(MSR_FS_BASE, addr);
      break;
    default:
      ret = -EINVAL;
      break;
  }

  return ret;
}

void* up_mmap(void* addr, size_t length, int prot, int flags){
    if((flags & MAP_ANONYMOUS) == 0) return (void*)-1;
    if((uint64_t)addr != 0) return (void*)-1;

    if(((flags & MAP_NONRESERVE) == 1) && prot == 0) return (void*)-1; // Why glibc require large amount of non accessible memory?

    _info("Allocating %d bytes\n", length);

    void* mm = kmm_zalloc(length);
    if(!mm)
        return (void*)-1;

    return mm;
}

int up_munmap(void* addr, size_t length){
    kmm_free(addr);

    return 0;
}

struct futex_q{
  sem_t sem;
  uint64_t key;
};


#define FUTEX_HT_SIZE 256
struct futex_q futex_hash_table[FUTEX_HT_SIZE];

int up_futex(uint32_t* uaddr, int opcode, uint32_t val){
  uint32_t s_head = (uint64_t)uaddr % FUTEX_HT_SIZE;
  uint32_t hv = s_head;
  irqstate_t flags;
  if(!uaddr) return -1;

  // Discard the private flag
  opcode &= ~FUTEX_PRIVATE_FLAG;

  switch(opcode){
    case FUTEX_WAIT:
      while((futex_hash_table[hv].key != 0) && (futex_hash_table[hv].key != (uint64_t)uaddr)){
          hv++;
          hv %= FUTEX_HT_SIZE;
          if(hv == s_head) return -1; // Out of free futex
      }

      flags = enter_critical_section();

      if(*uaddr == val){
        if(futex_hash_table[hv].key == 0) sem_init(&(futex_hash_table[hv].sem), 0, 0);

        futex_hash_table[hv].key = (uint64_t)uaddr;
        sem_wait(&(futex_hash_table[hv].sem));
      }

      leave_critical_section(flags);

      return 0; // Either not blocked or waken

      break;
    case FUTEX_WAKE:
      while(futex_hash_table[hv].key != (uint64_t)uaddr){
          hv++;
          hv %= FUTEX_HT_SIZE;
          if(hv == s_head) return 0; // ? No such key, wake no one
      }

      int svalue;
      sem_getvalue(&(futex_hash_table[hv].sem), &svalue);
      val = val > -svalue ? -svalue : val;
      for(;val > 0; val--){
        sem_post(&(futex_hash_table[hv].sem));
      }

      flags = enter_critical_section();
      sem_getvalue(&(futex_hash_table[hv].sem), &svalue);
      if(svalue == 0) {
          nxsem_destroy(&(futex_hash_table[hv].sem));
          futex_hash_table[hv].key = 0;
      }
      leave_critical_section(flags);

      return val;

      break;
    default:
      _info("Futex got unfriendly opcode: %d\n", opcode);
      PANIC();
    }
}

#endif
