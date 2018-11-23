#include <nuttx/config.h>

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <debug.h>

#include <nuttx/sched.h>
#include <nuttx/arch.h>
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

/****************************************************************************
 * Private Functions
 ****************************************************************************/

void* page_map[32];

void* find_free_slot(void) {
    uint64_t i;
    // each slot is 16MB .text .data, stack is allocated using kernel heap
    // slot 0 is used by non affected nuttx threads
    // We have total 512MB of memory available to be used
    for(i = 1; i < 32; i++){
        if(page_map[i] == NULL){
            page_map[i] = (void*)(i * PAGE_SLOT_SIZE); // 16MB blocks
            return page_map[i]; // 16MB blocks
        }
    }
    return NULL;
}

int execvs_setupargs(struct task_tcb_s* tcb,
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

    total_size += sizeof(char*) * (argc + 1); // argvs + NULL
    total_size += sizeof(char*) * (envc + 1); // envp + NULL
    total_size += sizeof(Elf64_auxv_t) * 3; // 3 aux vectors
    total_size += sizeof(uint64_t);         // argc

    sp = up_stack_frame((struct tcb_s*)tcb, total_size);
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
    }

    done = 0;
    envv_ptr = ((char**)sp + sizeof(char*) * (argc + 1));
    for(int i = 0; i < envc; i++){
        envv_ptr[i] = (char*)(sp + total_size - envv_size + done);
        strcpy(envv_ptr[i], argv[i]);
        done += strlen(envv[i]) + 1;
    }

    auxptr = (Elf64_auxv_t*)(sp + (argc + 1 + envc + 1) * sizeof(char*));

    auxptr[0].a_type = 1; //AT_IGNORE
    auxptr[0].a_un.a_val = 0x0;

    auxptr[1].a_type = 1; //AT_PHDR
    auxptr[1].a_un.a_val = 0x0;

    auxptr[2].a_type = 0; //AT_NULL
    auxptr[2].a_un.a_val = 0x0;

    return OK;
}

int execvs(void* base, int bsize,
           void* entry, int priority,
           int argc, char* argv[],
           int envc, char* envv[])
{
    struct task_tcb_s *tcb;
    uint64_t new_page_start_address;
    uint64_t stack;
    pid_t pid;
    int ret;

    // First try to create a new task
    printf("Entry: %016llx, base: %016llx\n", entry, base);

    /* Allocate a TCB for the new task. */

    tcb = (FAR struct task_tcb_s *)kmm_zalloc(sizeof(struct task_tcb_s));
    if (!tcb)
    {
        return -ENOMEM;
    }

    /* Initialize the user heap and stack */
    /*umm_initialize((FAR void *)CONFIG_ARCH_HEAP_VBASE,*/
                 /*up_addrenv_heapsize(&binp->addrenv));*/

    //Stack start at the end of address space
    /*stack = (uint64_t)kmm_zalloc(0x800000);*/

    /* Initialize the task */
    /* The addresses are the virtual address of new task */
    ret = task_init((FAR struct tcb_s *)tcb, argv[0], priority,
                    (uint32_t*)base + 0xe00000, 0x200000, entry, NULL);
    if (ret < 0)
    {
        ret = -get_errno();
        berr("task_init() failed: %d\n", ret);
        goto errout_with_tcb;
    }

    ret = execvs_setupargs(tcb, argc, argv, envc, envv);
    if (ret < 0)
    {
        ret = -get_errno();
        berr("execvs_setupargs() failed: %d\n", ret);
        goto errout_with_tcbinit;
    }

    // Allocate the newly created task to a new address space
    /* Find new pages for the task, every task is assumed to be 64MB, 32 pages */
    /*new_page_start_address = (uint64_t)find_free_slot();*/
    /*if (new_page_start_address == -1)*/
    /*{*/
        /*sinfo("page exhausted\n");*/
        /*ret = -ENOMEM;*/
        /*goto errout_with_tcbinit;*/
    /*}*/

    // clear and copy the memory
    /*memset((void*)new_page_start_address, 0, PAGE_SLOT_SIZE);*/
    /*memcpy((void*)new_page_start_address + LINUX_ELF_OFFSET, base, bsize); //Load to the mighty 0x400000*/

    // setup the tcb page_table entries
    // load the pages for now, going to do some setup
    for(int i = 0; i < (PAGE_SLOT_SIZE - STACK_SLOT_SIZE) / HUGE_PAGE_SIZE; i++)
    {
        tcb->cmn.xcp.page_table[i] = ((uint64_t)base + 0x200000 * i) | 0x83;
    }

    // set brk
    tcb->cmn.xcp.__min_brk = (void*)((uint64_t)LINUX_ELF_OFFSET + bsize + 0x1000);
    if(tcb->cmn.xcp.__min_brk >= (void*)(PAGE_SLOT_SIZE - STACK_SLOT_SIZE)) tcb->cmn.xcp.__min_brk = (void*)(PAGE_SLOT_SIZE - STACK_SLOT_SIZE - 1);
    tcb->cmn.xcp.__brk = tcb->cmn.xcp.__min_brk;
    sinfo("Set min_brk at: %llx\n", tcb->cmn.xcp.__min_brk);


    // Don't given a fuck about nuttx task start and management, we are doing this properly in Linux way
    tcb->cmn.xcp.regs[REG_RSP] += 8; // up_stack_frame left a hole on stack
    tcb->cmn.xcp.regs[REG_RIP] = (uint64_t)entry;

    /* Get the assigned pid before we start the task */
    pid = tcb->cmn.pid;

    sinfo("activate: new task=%d\n", pid);
    /* Then activate the task at the provided priority */
    ret = task_activate((FAR struct tcb_s *)tcb);
    if (ret < 0)
    {
        ret = -get_errno();
        berr("task_activate() failed: %d\n", ret);
        goto errout_with_tcbinit;
    }

    exit(0);

    return OK; //Although we shall never return

errout_with_tcbinit:
    tcb->cmn.stack_alloc_ptr = NULL;
    sched_releasetcb(&tcb->cmn, TCB_FLAG_TTYPE_TASK);
    return ret;

errout_with_tcb:
    kmm_free(tcb);
    return ret;
}
