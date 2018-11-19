#include <nuttx/arch.h>
#include <nuttx/sched.h>

#include <semaphore.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

void* tux_brk(void* brk){
  struct tcb_s *rtcb = this_task();
  if((rtcb->xcp.page_table[0] != 0) && (brk > rtcb->xcp.__min_brk))
  {
    rtcb->xcp.__brk = brk;
    if(rtcb->xcp.__brk >= (void*)PAGE_SLOT_SIZE - STACK_SLOT_SIZE)
      rtcb->xcp.__brk = (void*)(PAGE_SLOT_SIZE - STACK_SLOT_SIZE - 1);
  }
  return rtcb->xcp.__brk;
}

