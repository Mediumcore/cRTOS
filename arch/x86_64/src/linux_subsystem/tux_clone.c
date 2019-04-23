#include <nuttx/arch.h>
#include <nuttx/kmalloc.h>
#include <nuttx/sched.h>

#include <errno.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

# define CSIGNAL       0x000000ff /* Signal mask to be sent at exit.  */
# define CLONE_VM      0x00000100 /* Set if VM shared between processes.  */
# define CLONE_FS      0x00000200 /* Set if fs info shared between processes.  */
# define CLONE_FILES   0x00000400 /* Set if open files shared between processes.  */
# define CLONE_SIGHAND 0x00000800 /* Set if signal handlers shared.  */
# define CLONE_THREAD  0x00010000 /* Set to add to same thread group.  */
# define CLONE_SETTLS  0x00080000 /* Set TLS info.  */
# define CLONE_PARENT_SETTID 0x00100000 /* Store TID in userlevel buffer
					   before MM copy.  */
# define CLONE_CHILD_CLEARTID 0x00200000 /* Register exit futex and memory
					    location to clear.  */
# define CLONE_CHILD_SETTID 0x01000000 /* Store TID in userlevel buffer in
					  the child.  */

int tux_clone(unsigned long nbr, unsigned long flags, void *child_stack,
              void *ptid, void *ctid,
              unsigned long tls){

  int ret;
  struct task_tcb_s *tcb;
  struct tcb_s *rtcb = this_task();
  void* stack;

  /* we only handle CLONE_THREAD */
  if(!(flags & CLONE_THREAD)) return -1;
  /* We don't handle copy on write */
  if(!child_stack) return -1;

  tcb = (FAR struct task_tcb_s *)kmm_zalloc(sizeof(struct task_tcb_s));
  if (!tcb)
    return -1;

  stack = kmm_zalloc(0x8000); //Kernel stack

  ret = task_init((FAR struct tcb_s *)tcb, "clone_thread", rtcb->init_priority,
                  (uint32_t*)stack, 0x8000, NULL, NULL);
  if (ret < 0)
  {
    ret = -get_errno();
    berr("task_init() failed: %d\n", ret);
    goto errout_with_tcb;
  }

  /* Check the flags */
  /* Ignore CLONE_VM, we are on a flat address space */
  /* XXX: Ignore CLONE_FS */
  /* XXX: Ignore CLONE_FILES */
  /* XXX: Ignore CLONE_SIGHAND */
  /* Ignore CLONE_VSEM, not sure how to properly handle this */

  if(flags & CLONE_SETTLS){
    tcb->cmn.xcp.fs_base_set = 1;
    tcb->cmn.xcp.fs_base = (uint64_t)tls;
  }

  if(flags & CLONE_PARENT_SETTID){
    *(uint32_t*)(ptid) = rtcb->pid;
  }

  if(flags & CLONE_CHILD_SETTID){
    *(uint32_t*)(ctid) = tcb->cmn.pid;
  }

  if(flags & CLONE_CHILD_CLEARTID){
    _tux_set_tid_address((struct tcb_s*)tcb, (int*)(ctid));
  }

  /* manual set the stack pointer */
  tcb->cmn.xcp.regs[REG_RSP] = (uint64_t)child_stack;

  /* manual set the instruction pointer */
  tcb->cmn.xcp.regs[REG_RIP] = (uint64_t)(__builtin_return_address(3)); // Directly leaves the syscall

  svcinfo("Cloned a task with RIP=0x%llx, RSP=0x%llx\n",
          tcb->cmn.xcp.regs[REG_RIP],
          tcb->cmn.xcp.regs[REG_RSP]);

  /* clone return 0 to child */
  tcb->cmn.xcp.regs[REG_RAX] = 0;

  sinfo("activate: new task=%d\n", tcb->cmn.pid);
  /* Then activate the task at the provided priority */
  ret = task_activate((FAR struct tcb_s *)tcb);
  if (ret < 0)
  {
    ret = -get_errno();
    berr("task_activate() failed: %d\n", ret);
    goto errout_with_tcbinit;
  }

  return tcb->cmn.pid;

errout_with_tcbinit:
    sched_releasetcb(&tcb->cmn, TCB_FLAG_TTYPE_TASK);
    return -1;

errout_with_tcb:
    kmm_free(tcb);
    kmm_free(stack);
    return -1;
}

