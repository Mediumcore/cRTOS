#include <nuttx/arch.h>
#include <nuttx/sched.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

int _tux_set_tid_address(struct tcb_s *rtcb, int* tidptr){
  irqstate_t flags;

  flags = enter_critical_section();

  if(rtcb->xcp.clear_child_tid == NULL)
  {
    // XXX: This will break if task group is enabled,
    // on_exit only in effect on group's last exit
    add_remote_on_exit(rtcb, tux_set_tid_callback, NULL);
  }
  rtcb->xcp.clear_child_tid = tidptr;

  leave_critical_section(flags);
  return 0;
}

int tux_set_tid_address(unsigned long nbr, int* tidptr){
  struct tcb_s *rtcb = this_task();
  _tux_set_tid_address(rtcb, tidptr);
  return rtcb->pid;
}

void tux_set_tid_callback(int val, void* arg){
  struct tcb_s *rtcb = this_task();
  if(rtcb->xcp.clear_child_tid != NULL)
  {
    // According to man pages
    *(rtcb->xcp.clear_child_tid) = 0;
    tux_futex(0, rtcb->xcp.clear_child_tid, FUTEX_WAKE, 1, 0, 0, 0);
  }
}
