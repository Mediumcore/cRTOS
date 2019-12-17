#include <nuttx/config.h>

#include <sys/mman.h>
#include <stdint.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <debug.h>
#include <sched.h>

#include <nuttx/sched.h>
#include <nuttx/arch.h>
#include <nuttx/mm/gran.h>
#include <arch/irq.h>
#include <arch/io.h>

#include "tux.h"
#include "sched/sched.h"

/****************************************************************************
 * Pre-processor definitions
 ****************************************************************************/

#ifndef __ASSEMBLY__
typedef struct
{
  uint64_t a_type;           /* Entry type */
  union
    {
      uint64_t a_val;                /* Integer value */
      /* We use to have pointer elements added here.  We cannot do that,
         though, since it does not work when using 32-bit definitions
         on 64-bit platforms and vice versa.  */
    } a_un;
} Elf64_auxv_t;
#endif

/****************************************************************************
 * Private Functions
 ****************************************************************************/

void add_remote_on_exit(struct tcb_s* tcb, void (*func)(int, void *), void *arg) {
  FAR struct task_group_s *group = tcb->group;
  int   index;

  /* The following must be atomic */

  if (func)
    {
      sched_lock();

      /* Search for the first available slot.  on_exit() functions are registered
       * from lower to higher arry indices; they must be called in the reverse
       * order of registration when task exists, i.e., from higher to lower
       * indices.
       */

      for (index = 0; index < CONFIG_SCHED_ONEXIT_MAX; index++)
        {
          if (!group->tg_onexitfunc[index])
            {
              group->tg_onexitfunc[index] = func;
              group->tg_onexitarg[index]  = arg;
              break;
            }
        }

      sched_unlock();
    }
}

void tux_on_exit(int val, void* arg){

    return;
}

void rexec_trampoline(const char* path, char *argv[], char* envp[]) {
    _info("Entering rExec Trampoline: %s\n", path);

    // Currently on the kernel stack;
    _tux_exec(path, argv, envp);

    // We should never end up here
    exit(0xff);
}

long rexec(const char* path, int policy, int priority,
           char* argv[], char* envp[], uint64_t shadow_tcb)
{
    struct task_tcb_s *tcb;
    uint64_t stack, kstack, vstack;
    uint64_t heap;
    uint64_t ret;
    uint64_t i;
    int argc, envc;
    int sock = open("/dev/shadow0", O_RDWR);

    // First try to create a new task
    _info("Remote exec: %s, with priority: %d\n", path, priority);

    /* Allocate a TCB for the new task. */
    tcb = (FAR struct task_tcb_s *)kmm_zalloc(sizeof(struct task_tcb_s));
    if (!tcb) {
        return -ENOMEM;
    }

    // First try to create a new task
    _info("New TCB: 0x%016llx\n", tcb);

    // Setup a 8k kernel stack
    kstack = kmm_zalloc(0x8000);

    _info("kstack range: %llx - %llx\n", kstack, kstack+0x8000);

    /* Initialize the task */
    /* The addresses are the virtual address of new task */
    /* the trampoline will be using the kernel stack, and switch to the user stack for us */
    ret = task_init((FAR struct tcb_s *)tcb, argv[0] ? argv[0] : path, priority,
                    (void*)kstack, 0x8000, rexec_trampoline, NULL);
    if (ret < 0)
    {
        ret = -get_errno();
        berr("task_init() failed: %d\n", ret);
        goto errout_with_tcb;
    }

    // Set policy
    // The nuttx SCHED_FIFO/SCHED_RR has the same numbering
    tcb->cmn.flags &= ~TCB_FLAG_POLICY_MASK;
    if(policy == SCHED_FIFO) // SCHED_FIFO
        tcb->cmn.flags |= TCB_FLAG_SCHED_FIFO;
    if(policy == SCHED_RR) // SCHED_RR
        tcb->cmn.flags |= TCB_FLAG_SCHED_RR;

    tcb->cmn.xcp.vma = NULL;
    tcb->cmn.xcp.pda = NULL;

    // We have to copy the path, argv, envp on to kheap
    // Other wise they will be freed by the program loader daemon
    void* ppath = strdup(path);

    for(i = 0; argv[i] != NULL; i++);
    argc = i;

    char** aargv = kmm_zalloc(sizeof(char*) * (argc + 1));
    for(i = 0; argv[i] != NULL; i++) {
        aargv[i] = strdup(argv[i]);
    }
    aargv[i] = NULL;


    for(i = 0; envp[i] != NULL; i++);
    envc = i;

    char** eenvp = kmm_zalloc(sizeof(char*) * (envc + 1));
    for(i = 0; envp[i] != NULL; i++) {
        eenvp[i] = strdup(envp[i]);
    }
    eenvp[i] = NULL;

    // Call the trampoline function to provide synchronized mapping
    tcb->cmn.xcp.regs[REG_RDI] = (uint64_t)ppath;
    tcb->cmn.xcp.regs[REG_RSI] = (uint64_t)aargv;
    tcb->cmn.xcp.regs[REG_RDX] = (uint64_t)eenvp;
    tcb->cmn.xcp.regs[REG_RIP] = (uint64_t)rexec_trampoline; // This is necessary to circumvent the nuttx trampoline

    /* setup some linux handlers */
    tcb->cmn.xcp.is_linux = 2;
    tcb->cmn.xcp.linux_sock = sock;
    _info("LINUX SOCK: %d\n", tcb->cmn.xcp.linux_sock);

    tcb->cmn.xcp.linux_tcb = ~(0xffffULL << 48) & shadow_tcb;
    tcb->cmn.xcp.linux_pid = (0xffff & (shadow_tcb >> 48));
    tcb->cmn.xcp.linux_tid = tcb->cmn.xcp.linux_pid;
    _info("LINUX TCB %lx, PID %lx\n", tcb->cmn.xcp.linux_tcb, tcb->cmn.xcp.linux_pid);

    insert_proc_node(tcb->cmn.pid, tcb->cmn.xcp.linux_pid);

    nxsem_init(&tcb->cmn.xcp.syscall_lock, 1, 0);
    nxsem_setprotocol(&tcb->cmn.xcp.syscall_lock, SEM_PRIO_NONE);

    /*add_remote_on_exit((struct tcb_s*)tcb, tux_on_exit, NULL);*/

    tcb->cmn.xcp.pd1 = tux_mm_new_pd1();

    tcb->cmn.xcp.fd[0] = 0;
    tcb->cmn.xcp.fd[1] = 1;
    tcb->cmn.xcp.fd[2] = 2;

    tcb->cmn.xcp.signal_stack_flag = TUX_SS_DISABLE;

    sinfo("activate: new task=%d\n", tcb->cmn.pid);
    /* Then activate the task at the provided priority */
    ret = task_activate((FAR struct tcb_s *)tcb);
    if (ret < 0)
    {
        ret = -get_errno();
        berr("task_activate() failed: %d\n", ret);
        goto errout_with_tcbinit;
    }

    return OK;

errout_with_tcbinit:
    tcb->cmn.stack_alloc_ptr = NULL;
    sched_releasetcb(&tcb->cmn, TCB_FLAG_TTYPE_TASK);
    return ret;

errout_with_tcb:
    kmm_free(tcb);
    return ret;
}
