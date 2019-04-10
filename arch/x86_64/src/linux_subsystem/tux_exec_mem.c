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

#define LINUX_ELF_OFFSET 0x400000

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

void* find_free_slot(void) {
  void* ret = NULL;
  uint64_t i;

  irqstate_t flags;

  flags = enter_critical_section();

  // each slot is 16MB .text .data, stack is allocated on special slots
  // slot 0 is used by non affected nuttx threads
  // We have total 512MB/2 of memory available to be used
  for(i = 1; i < 16; i++){
      if(page_map[i] == NULL){
          page_map[i] = (void*)(i * PAGE_SLOT_SIZE); // 16MB blocks
          ret = page_map[i]; // 16MB blocks
          break;
      }
  }

  leave_critical_section(flags);

  return ret;
}

void release_slot(void* slot) {
  uint64_t i;

  irqstate_t flags;

  flags = enter_critical_section();

  for(i = 1; i < 16; i++){
      if(page_map[i] == (void*)((uint64_t)slot & ~(HUGE_PAGE_SIZE - 1))){
          page_map[i] = NULL; // 16MB blocks
          break;
      }
  }

  leave_critical_section(flags);
}

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

  } else {
    _err("Non-linux process calling linux syscall or invalid sock fd %d, %d\n", rtcb->xcp.is_linux, rtcb->xcp.linux_sock);
    PANIC();
  }
}

void* execvs_setupargs(struct task_tcb_s* tcb, uint64_t pstack,
    int argc, char* argv[], int envc, char* envv[]){
    // Now we have to organize the stack as Linux exec will do
    // ---------
    // argv
    // ---------
    // NULL
    // ---------
    // envv
    // ---------
    // NULL
    // ---------
    // auxv
    // ---------
    // a_type = AT_NULL(0)
    // ---------
    // Stack_top
    // ---------

    Elf64_auxv_t* auxptr;
    uint64_t argv_size, envv_size, total_size;
    uint64_t done;
    char** argv_ptr, ** envv_ptr;
    void* sp;

    argv_size = 0;
    for(int i = 0; i < argc; i++){
        argv_size += strlen(argv[i]) + 1;
    }
    envv_size = 0;
    for(int i = 0; i < envc; i++){
        envv_size += strlen(envv[i]) + 1;
    }
    total_size = argv_size + envv_size;

    total_size += sizeof(uint64_t);         // argc
    total_size += sizeof(char*) * (argc + 1); // argvs + NULL
    total_size += sizeof(char*) * (envc + 1); // envp + NULL
    total_size += sizeof(Elf64_auxv_t) * 6; // 6 aux vectors
    total_size += sizeof(uint64_t);         // AT_RANDOM

    sp = pstack + 0x800000 - total_size;
    if (!sp) return -ENOMEM;

    sinfo("Setting up stack args at %p\n", sp);

    *((uint64_t*)sp) = argc;
    sp += sizeof(uint64_t);

    sinfo("Setting up stack argc is %d\n", *(((uint64_t*)sp) - 1));

    done = 0;
    argv_ptr = ((char**)sp);
    for(int i = 0; i < argc; i++){
        argv_ptr[i] = (char*)(sp + total_size - argv_size - envv_size + done);
        strcpy(argv_ptr[i], argv[i]);
        done += strlen(argv[i]) + 1;

        argv_ptr[i] += -pstack + 124 * HUGE_PAGE_SIZE;
    }

    done = 0;
    envv_ptr = ((char**)sp + (argc + 1));
    for(int i = 0; i < envc; i++){
        envv_ptr[i] = (char*)(sp + total_size - envv_size + done);
        strcpy(envv_ptr[i], envv[i]);
        done += strlen(envv[i]) + 1;

        envv_ptr[i] += -pstack + 124 * HUGE_PAGE_SIZE;
    }

    auxptr = (Elf64_auxv_t*)(sp + (argc + 1 + envc + 1) * sizeof(char*));

    auxptr[0].a_type = 6; //AT_PAGESZ
    auxptr[0].a_un.a_val = 0x1000;

    auxptr[1].a_type = 25; //AT_RANDOM
    auxptr[1].a_un.a_val = (uint64_t)(sp + total_size - argv_size - envv_size - 8 - pstack + 124 * HUGE_PAGE_SIZE);
    _info("AT_RANDOM: %llx\n", auxptr[1].a_un.a_val);

    auxptr[2].a_type = 33; //AT_SYSINFO_EHDR
    auxptr[2].a_un.a_val = 0x0;

    auxptr[3].a_type = 0; //AT_NULL
    auxptr[3].a_un.a_val = 0x0;

    auxptr[4].a_type = 0; //AT_NULL
    auxptr[4].a_un.a_val = 0x0;

    auxptr[5].a_type = 0; //AT_NULL
    auxptr[5].a_un.a_val = 0x0;

    return sp - sizeof(uint64_t);
}

void exec_trampoline(void* entry, void* pstack, void* vstack) {
    tux_delegate(9, (((uint64_t)pstack) << 32) | (uint64_t)(124 * HUGE_PAGE_SIZE), 4 * HUGE_PAGE_SIZE,
                 0, MAP_ANONYMOUS, 0, 0);

    register uint64_t sp asm("rsp");
    register uint64_t rdi asm("rdi");
    register uint64_t rsi asm("rsi");
    register uint64_t rdx asm("rdx");
    register uint64_t rcx asm("rcx");
    register uint64_t r8 asm("r8");
    register uint64_t r9 asm("r9");

    // Set the stack pointer to user stack
    sp = 124 * HUGE_PAGE_SIZE + (uint64_t)vstack - (uint64_t)pstack;

    // Jump to the actual entry point, not using call to preserve stack
    // Clear the registers, otherwise the libc_main will
    // mistaken the trash value in registers as arguments
    rdi = 0;
    rsi = 0;
    rdx = 0;
    rcx = 0;
    r8 = 0;
    r9 = 0;

    goto *entry;

    _exit(255); // We should never end up here
}

int execvs(void* pbase, void* vbase, int bsize,
           void* entry, int priority,
           int argc, char* argv[],
           int envc, char* envv[], uint64_t shadow_tcb)
{
    struct task_tcb_s *tcb;
    uint64_t stack, kstack, vstack;
    uint64_t ret;
    uint64_t i;
    int sock = open("/dev/shadow0", O_RDWR);

    // First try to create a new task
    _info("Entry: 0x%016llx, pbase: 0x%016llx, vbase: 0x%016llx\n", entry, pbase, vbase);

    /* Allocate a TCB for the new task. */

    tcb = (FAR struct task_tcb_s *)kmm_zalloc(sizeof(struct task_tcb_s));
    if (!tcb)
    {
        return -ENOMEM;
    }

    // First try to create a new task
    _info("New TCB: 0x%016llx\n", tcb);

    /* Initialize the user heap and stack */
    /*umm_initialize((FAR void *)CONFIG_ARCH_HEAP_VBASE,*/
                 /*up_addrenv_heapsize(&binp->addrenv));*/

    //Stack is allocated and will be placed at the high mem of the task
    stack = (uint64_t)gran_alloc(tux_mm_hnd, 0x800000);

    //First we need to clean the user stack
    memset(stack, 0, 0x800000);

    // Setup a 8k kernel stack
    kstack = kmm_zalloc(0x8000);

    /* Initialize the task */
    /* The addresses are the virtual address of new task */
    /* the trampoline will be using the kernel stack, and switch to the user stack for us */
    ret = task_init((FAR struct tcb_s *)tcb, argv[0], priority,
                    (void*)kstack, 0x8000, entry, NULL);
    if (ret < 0)
    {
        ret = -get_errno();
        berr("task_init() failed: %d\n", ret);
        goto errout_with_tcb;
    }

    /* Put the arguments etc. on to the user stack */
    vstack = execvs_setupargs(tcb, stack, argc, argv, envc, envv);
    if (vstack < 0)
    {
        ret = -get_errno();
        berr("execvs_setupargs() failed: %d\n", ret);
        goto errout_with_tcbinit;
    }

    _info("STACK: %llx, KSTACK: %llx, RSP: %llx, VSTACK: %llx\n", stack, kstack, tcb->cmn.xcp.regs[REG_RSP], vstack);

    // setup the tcb page_table entries
    for(i = 0; i < 128; i++)
    {
        tcb->cmn.xcp.page_table[i] = 0x82; // Not present on creation
    }
    for(i = (uint64_t)vbase; i < (uint64_t)vbase + bsize; i += HUGE_PAGE_SIZE)
    {
        tcb->cmn.xcp.page_table[i / HUGE_PAGE_SIZE] = ((uint64_t)pbase + i - (uint64_t)vbase) | 0x83;
    }
    tcb->cmn.xcp.page_table[(uint64_t)vbase / HUGE_PAGE_SIZE] |= 0x200;

    for(i = 124; i < 128; i++)
    {
        tcb->cmn.xcp.page_table[i] = (HUGE_PAGE_SIZE * (i - 124) + stack) | 0x83;
    }
    tcb->cmn.xcp.page_table[124] |= 0x200;

    // set brk
    tcb->cmn.xcp.__min_brk = (void*)kmm_zalloc(0x800000);
    tcb->cmn.xcp.__brk = tcb->cmn.xcp.__min_brk;
    sinfo("Set min_brk at: %llx\n", tcb->cmn.xcp.__min_brk);

    // Call the trampoline function to provide synchronized mapping
    tcb->cmn.xcp.regs[REG_RDI] = (uint64_t)entry;
    tcb->cmn.xcp.regs[REG_RSI] = (uint64_t)stack;
    tcb->cmn.xcp.regs[REG_RDX] = (uint64_t)vstack;
    tcb->cmn.xcp.regs[REG_RIP] = (uint64_t)exec_trampoline;

    /* setup some linux handlers */
    tcb->cmn.xcp.is_linux = 2;
    tcb->cmn.xcp.linux_sock = sock;
    _info("LINUX SOCK: %d\n", tcb->cmn.xcp.linux_sock);
    tcb->cmn.xcp.linux_tcb = shadow_tcb;

    add_remote_on_exit((struct tcb_s*)tcb, tux_on_exit, NULL);

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
