#include <nuttx/arch.h>
#include <string.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"
#include <sched/sched.h>
#include <group/group.h>
#include <task/task.h>
#include <nuttx/wqueue.h>

#define TUX_PROC_HT_SIZE 256

struct proc_node {
    int lpid;
    int rpid;
    int retain;
    struct proc_node* next;
};

struct proc_node* tux_proc_hashtable[TUX_PROC_HT_SIZE];
struct work_s tux_proc_deletework;

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
    (*ptr)->retain = 1;
    (*ptr)->next = NULL;

    return 0;
}

void print_proc_nodes(void) {
    struct proc_node **ptr;
    int i;

    for (i = 0; i < TUX_PROC_HT_SIZE; i++) {
        if (!tux_proc_hashtable[i]) continue;

        _info("head: %llx\n", tux_proc_hashtable[i]);
        ptr = &tux_proc_hashtable[i];
        while(*ptr != NULL) {
            _info("on: %llx\n", *ptr);
            ptr = &((*ptr)->next);
        }
    }
}


void _delete_proc_nodes(void* arg) {
    struct proc_node **ptr;
    struct proc_node *to_free;
    int i;

    for (i = 0; i < TUX_PROC_HT_SIZE; i++) {
        if (!tux_proc_hashtable[i]) continue;

        ptr = &tux_proc_hashtable[i];
        while(*ptr != NULL) {
            if((*ptr)->retain == 0) {
                to_free = *ptr;
                *ptr = (*ptr)->next;
                kmm_free(to_free);
            }

            /* necessary additional check
             * *ptr might become NULL when removing the last node */
            if(*ptr)
                ptr = &((*ptr)->next);
        }
    }
}

int delete_proc_node(int rpid) {
    struct proc_node **ptr= &tux_proc_hashtable[rpid % TUX_PROC_HT_SIZE];
    while(*ptr != NULL) {
        if((*ptr)->rpid == rpid) {
            (*ptr)->retain = 0;
            work_queue(LPWORK, &tux_proc_deletework, _delete_proc_nodes, NULL, 0);
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

long search_linux_pid(int lpid) {
    struct proc_node **ptr;
    int i;

    if(lpid == 0)
        lpid = this_task()->pid;

    for (i = 0; i < TUX_PROC_HT_SIZE; i++) {
        if (!tux_proc_hashtable[i]) continue;

        ptr = &tux_proc_hashtable[i];
        while(*ptr != NULL) {
            if((*ptr)->lpid == lpid) {
                return (*ptr)->rpid;
            }
            ptr = &((*ptr)->next);
        }
    }

    return -EEXIST;
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

long tux_waithook(unsigned long nbr, uintptr_t param1, uintptr_t param2, uintptr_t param3, uintptr_t param4, uintptr_t param5, uintptr_t param6) {
    /* wait and wait4 return the pid exited
     * We need to hook it and return the linux pid to fake it
     * The problem here is that tcb is already freed
     * We do the reserve lookup by searching in the pid mapping table
     * The Entry is delayed to be freed in LP WQ
     * This make any task running lower or equal priority against LP WG
     * Might not get the right pid */

    long pid = tux_pidhook(nbr, param1, param2, param3, param4, param5, param6);
    if(pid > 0)
        pid = search_linux_pid(pid); // This is a O(n) search might be slow

    if(pid > 0)
        return pid;
    else
        return -EALREADY;
}

long tux_getpid(unsigned long nbr) {
    return this_task()->xcp.linux_pid;
}

long tux_gettid(unsigned long nbr) {
    return this_task()->xcp.linux_tid;
}
