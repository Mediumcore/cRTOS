#include <nuttx/arch.h>
#include <string.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"
#include <sched/sched.h>
#include <group/group.h>
#include <task/task.h>

#define TUX_PROC_HT_SIZE 256

struct proc_node {
    int lpid;
    int rpid;
    struct proc_node* next;
};

struct proc_node* tux_proc_hashtable[TUX_PROC_HT_SIZE];

int insert_proc_node(int lpid, int rpid) {
    struct proc_node **ptr= &tux_proc_hashtable[rpid % TUX_PROC_HT_SIZE];
    while(*ptr != NULL) {
        if((*ptr)->rpid == rpid) return -EEXIST;
        ptr = &((*ptr)->next);
    }

    *ptr = kmm_zalloc(sizeof(struct proc_node));
    if(!*ptr) {
        return -ENOMEM;
    }

    (*ptr)->lpid = lpid;
    (*ptr)->rpid = rpid;

    return 0;
}

int delete_proc_node(int rpid) {
    struct proc_node **ptr= &tux_proc_hashtable[rpid % TUX_PROC_HT_SIZE];
    while(*ptr != NULL) {
        if((*ptr)->rpid == rpid) {
            kmm_free(*ptr);
            return 0;
        };
        ptr = &((*ptr)->next);
    }

    return -EEXIST;
}

long get_nuttx_pid(int rpid) {
    struct proc_node **ptr= &tux_proc_hashtable[rpid % TUX_PROC_HT_SIZE];
    while(*ptr != NULL) {
        if((*ptr)->rpid == rpid) {
            return (*ptr)->lpid;
        };
        ptr = &((*ptr)->next);
    }

    return -EEXIST;
}

long get_linux_pid(int lpid) {
    struct tcb_s *rtcb;

    if(lpid == 0)
        lpid = this_task()->pid;

    rtcb = sched_gettcb(lpid);

    return rtcb->xcp.linux_pid;
}

long tux_getppid(unsigned long nbr){
    struct task_group_s *pgrp;
    struct task_group_s *ppgrp;
    struct tcb_s *tcb;
    gid_t pgid;

    tcb = sched_gettcb(this_task()->pid);
    if (!tcb) {
        return -EEXIST;
    }

    DEBUGASSERT(tcb->group);
    pgrp = tcb->group;

    pgid = pgrp->tg_pgid;

    ppgrp = group_findbygid(pgid);
    if (!ppgrp) {
      return -ESRCH;
    }

    return ppgrp->tg_task;
};

long tux_pidhook(unsigned long nbr, int pid, uintptr_t param2, uintptr_t param3, uintptr_t param4, uintptr_t param5, uintptr_t param6) {
    int lpid;
    if(pid > 0){
        lpid = get_nuttx_pid(pid);
        if (lpid < 0) return lpid;
    } else {
        lpid = pid;
    }

    return tux_local(nbr, lpid, param2, param3, param4, param5, param6);
}

long tux_getpid(unsigned long nbr) {
    return this_task()->xcp.linux_pid;
}

long tux_gettid(unsigned long nbr) {
    return this_task()->xcp.linux_tid;
}

long tux_getpgid (unsigned long nbr, int pid) {
    int rpid;

    rpid = 0;
    if(pid){
        rpid = get_linux_pid(pid);
        if(!rpid) return -EINVAL;
    }

    return tux_delegate(nbr, rpid, 0, 0, 0, 0, 0);
}

long tux_setpgid (unsigned long nbr, int pid, int pgid) {
    int rpid;
    int rpgid;

    rpid = 0;
    if(pid){
        rpid = get_linux_pid(pid);
        if(!rpid) return -EINVAL;
    }

    rpgid = 0;
    if(pid){
        rpgid = get_linux_pid(pgid);
        if(!rpgid) return -EINVAL;
    }

    return tux_delegate(nbr, rpid, rpgid, 0, 0, 0, 0);
}

long tux_getsid (unsigned long nbr, int pid) {
    int rpid;

    rpid = 0;
    if(pid){
        rpid = get_linux_pid(pid);
        if(!rpid) return -EINVAL;
    }

    return tux_delegate(nbr, rpid, 0, 0, 0, 0, 0);
}

