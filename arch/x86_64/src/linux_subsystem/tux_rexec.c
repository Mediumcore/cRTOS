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
  struct tcb_s *rtcb = this_task();
  uint64_t params[7];

  if(rtcb->xcp.is_linux && rtcb->xcp.linux_sock)
  {
    // Shutdown remote shadow process
    params[0] = 60;
    params[1] = val;

    write(rtcb->xcp.linux_sock, params, sizeof(params));
    close(rtcb->xcp.linux_sock);

    delete_proc_node(rtcb->xcp.linux_pid);

  } else {
    _err("Non-linux process calling linux syscall or invalid sock fd %d, %d\n", rtcb->xcp.is_linux, rtcb->xcp.linux_sock);
    PANIC();
  }
}

void rexec_trampoline(const char* path, char *argv[], char* envp[]) {
    _info("Entering rExec Trampoline: %s\n", path);

    // Currently on the kernel stack;
    _tux_exec(path, argv, envp);

    // We should never end up here
    exit(0xff);


    /*Stack is allocated and will be placed at the high mem of the task*/
    /*stack = (uint64_t)gran_alloc(tux_mm_hnd, 0x800000);*/
    /*heap = (uint64_t)gran_alloc(tux_mm_hnd, 0x200000);*/

    /*First we need to clean the user stack*/
    /*memset(stack, 0, 0x800000);*/
    /*memset(heap, 0, 0x800000);*/


     /*Put the arguments etc. on to the user stack*/
    /*vstack = execvs_setupargs(tcb, stack, argc, argv, envc, envv);*/
    /*if (vstack < 0)*/
    /*{*/
        /*ret = -get_errno();*/
        /*berr("execvs_setupargs() failed: %d\n", ret);*/
        /*goto errout_with_tcbinit;*/
    /*}*/

    /*_info("STACK: %llx, KSTACK: %llx, RSP: %llx, VSTACK: %llx\n", stack, kstack, tcb->cmn.xcp.regs[REG_RSP], vstack);*/

     /*setup the tcb page_table entries as not present on creation*/
    /*struct vma_s* program_mapping = kmm_malloc(sizeof(struct vma_s));*/
    /*struct vma_s* program_mapping_pda = kmm_malloc(sizeof(struct vma_s));*/
    /*struct vma_s* stack_mapping = kmm_malloc(sizeof(struct vma_s));*/
    /*struct vma_s* stack_mapping_pda = kmm_malloc(sizeof(struct vma_s));*/
    /*struct vma_s* heap_mapping = kmm_malloc(sizeof(struct vma_s));*/
    /*struct vma_s* heap_mapping_pda = kmm_malloc(sizeof(struct vma_s));*/

    /*tcb->cmn.xcp.vma = program_mapping;*/
    /*tcb->cmn.xcp.pda = program_mapping_pda;*/

    /*program_mapping->va_start = vbase;*/
    /*program_mapping->va_end = vbase + bsize;*/
    /*program_mapping->pa_start = pbase;*/
    /*program_mapping->proto = 3;*/
    /*program_mapping->_backing = "[Program Image]";*/

    /*program_mapping_pda->va_start = (uint64_t)vbase & HUGE_PAGE_MASK;*/
    /*program_mapping_pda->va_end = ((uint64_t)vbase + bsize + HUGE_PAGE_SIZE - 1) & HUGE_PAGE_MASK;*/
    /*program_mapping_pda->pa_start = (void*)gran_alloc(tux_mm_hnd, PAGE_SIZE * (program_mapping_pda->va_end - program_mapping_pda->va_start) / HUGE_PAGE_SIZE);*/
    /*program_mapping_pda->proto = 0x3;*/
    /*program_mapping_pda->_backing = "[Program Image]";*/
    /*memset(program_mapping_pda->pa_start, 0, PAGE_SIZE * (program_mapping_pda->va_end - program_mapping_pda->va_start) / HUGE_PAGE_SIZE);*/
    /*for(i = program_mapping->va_start; i < program_mapping->va_end; i += PAGE_SIZE){*/
        /*((uint64_t*)(program_mapping_pda->pa_start))[((i - program_mapping_pda->va_start) >> 12) & 0x3ffff] = (program_mapping->pa_start + i - program_mapping->va_start) | program_mapping->proto;*/
    /*}*/

    /*program_mapping->next = heap_mapping;*/
    /*program_mapping_pda->next = heap_mapping_pda;*/

    /*heap_mapping->va_start = 123 * HUGE_PAGE_SIZE;*/
    /*heap_mapping->va_end = 124 * HUGE_PAGE_SIZE;*/
    /*heap_mapping->pa_start = heap;*/
    /*heap_mapping->proto = 3;*/
    /*heap_mapping->_backing = "[Heap]";*/

    /*heap_mapping_pda->va_start = 123 * HUGE_PAGE_SIZE;*/
    /*heap_mapping_pda->va_end = 124 * HUGE_PAGE_SIZE;*/
    /*heap_mapping_pda->pa_start = (void*)gran_alloc(tux_mm_hnd, PAGE_SIZE * (heap_mapping_pda->va_end - heap_mapping_pda->va_start) / HUGE_PAGE_SIZE);*/
    /*heap_mapping_pda->proto = 0x3;*/
    /*heap_mapping_pda->_backing = "[Heap]";*/
    /*memset(heap_mapping_pda->pa_start, 0, PAGE_SIZE * (heap_mapping_pda->va_end - heap_mapping_pda->va_start) / HUGE_PAGE_SIZE);*/
    /*for(i = heap_mapping->va_start; i < heap_mapping->va_end; i += PAGE_SIZE){*/
        /*((uint64_t*)(heap_mapping_pda->pa_start))[((i - heap_mapping_pda->va_start) >> 12) & 0x3ffff] = (heap_mapping->pa_start + i - heap_mapping->va_start) | heap_mapping->proto;*/
    /*}*/

    /*heap_mapping->next = stack_mapping;*/
    /*heap_mapping_pda->next = stack_mapping_pda;*/

    /*stack_mapping->va_start = 124 * HUGE_PAGE_SIZE;*/
    /*stack_mapping->va_end = 128 * HUGE_PAGE_SIZE;*/
    /*stack_mapping->pa_start = stack;*/
    /*stack_mapping->proto = 3;*/
    /*stack_mapping->_backing = "[Stack]";*/

    /*stack_mapping_pda->va_start = 124 * HUGE_PAGE_SIZE;*/
    /*stack_mapping_pda->va_end = 128 * HUGE_PAGE_SIZE;*/
    /*stack_mapping_pda->pa_start = (void*)gran_alloc(tux_mm_hnd, PAGE_SIZE * (stack_mapping_pda->va_end - stack_mapping_pda->va_start) / HUGE_PAGE_SIZE);*/
    /*stack_mapping_pda->proto = 0x3;*/
    /*stack_mapping_pda->_backing = "[Stack]";*/
    /*memset(stack_mapping_pda->pa_start, 0, PAGE_SIZE * (stack_mapping_pda->va_end - stack_mapping_pda->va_start) / HUGE_PAGE_SIZE);*/
    /*for(i = stack_mapping->va_start; i < stack_mapping->va_end; i += PAGE_SIZE){*/
        /*((uint64_t*)(stack_mapping_pda->pa_start))[((i - stack_mapping_pda->va_start) >> 12) & 0x3ffff] = (stack_mapping->pa_start + i - stack_mapping->va_start) | stack_mapping->proto;*/
    /*}*/

    /*stack_mapping->next = NULL;*/
    /*stack_mapping_pda->next = NULL;*/

     /*set brk*/
    /*tcb->cmn.xcp.__min_brk = (void*)(heap_mapping->va_start);*/
    /*tcb->cmn.xcp.__brk = tcb->cmn.xcp.__min_brk;*/
    /*sinfo("Set min_brk at: %llx\n", tcb->cmn.xcp.__min_brk);*/


    /*stack*/
    /*tux_delegate(9, (((uint64_t)pstack) << 32) | (uint64_t)(124 * HUGE_PAGE_SIZE), 4 * HUGE_PAGE_SIZE,*/
                 /*0, MAP_ANONYMOUS, 0, 0);*/

    /*heap*/
    /*tux_delegate(9, (((uint64_t)pheap) << 32) | (uint64_t)(123 * HUGE_PAGE_SIZE), 1 * HUGE_PAGE_SIZE,*/
                 /*0, MAP_ANONYMOUS, 0, 0);*/

    /*uint64_t sp;*/

     /*Set the stack pointer to user stack*/
    /*sp = 124 * HUGE_PAGE_SIZE + (uint64_t)vstack - (uint64_t)pstack;*/

     /*Jump to the actual entry point, not using call to preserve stack*/
     /*Clear the registers, otherwise the libc_main will*/
     /*mistaken the trash value in registers as arguments*/

    /*asm volatile ("mov %0, %%rsp; xor %%rdi, %%rdi; xor %%rsi, %%rsi; xor %%rdx, %%rdx; xor %%rcx, %%rcx; xor %%r8, %%r8; xor %%r9, %%r9; jmpq %1"::"g"(sp), "g"(entry));*/

    /*_exit(255);  We should never end up here*/
}

long rexec(const char* path, int priority,
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

    add_remote_on_exit((struct tcb_s*)tcb, tux_on_exit, NULL);

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
