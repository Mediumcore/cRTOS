#include <nuttx/arch.h>
#include <string.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"
#include <sched/sched.h>
#include <group/group.h>
#include <task/task.h>

long get_linux_pid(int lpid) {
    struct tcb_s *rtcb;
    int rpid;

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

long tux_getpgid (unsigned long nbr, int pid) {
    int rpid;

    rpid = 0;
    if(pid){
        rpid = get_linux_pid(pid);
        if(!rpid) return -EINVAL;
    }

    return tux_delegate(nbr, rpid, NULL, NULL, NULL, NULL, NULL);
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

    return tux_delegate(nbr, rpid, rpgid, NULL, NULL, NULL, NULL);
}

long tux_getsid (unsigned long nbr, int pid) {
    int rpid;

    rpid = 0;
    if(pid){
        rpid = get_linux_pid(pid);
        if(!rpid) return -EINVAL;
    }

    return tux_delegate(nbr, rpid, NULL, NULL, NULL, NULL, NULL);
}

