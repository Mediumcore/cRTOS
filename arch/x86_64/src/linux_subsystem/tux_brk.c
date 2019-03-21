#include <nuttx/arch.h>
#include <nuttx/sched.h>

#include <semaphore.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

void* tux_brk(unsigned long nbr, void* brk){
  struct tcb_s *rtcb = this_task();
  if((rtcb->xcp.page_table[0] != 0) && (brk > rtcb->xcp.__min_brk))
  {
    rtcb->xcp.__brk = brk;
    if(rtcb->xcp.__brk >= rtcb->xcp.__min_brk + 0x800000)
      rtcb->xcp.__brk = rtcb->xcp.__min_brk + 0x800000;
  }
  return rtcb->xcp.__brk;
}

