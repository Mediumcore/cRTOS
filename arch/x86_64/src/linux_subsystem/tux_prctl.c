#include <nuttx/arch.h>
#include <nuttx/sched.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003

int tux_arch_prctl(int code, unsigned long addr){
  struct tcb_s *rtcb = this_task();
  int ret = 0;

  switch(code){
    case ARCH_GET_FS:
      *(unsigned long*)addr = read_msr(MSR_FS_BASE);
      break;
    case ARCH_SET_FS:
      rtcb->xcp.fs_base_set = 1;
      rtcb->xcp.fs_base = addr;
      write_msr(MSR_FS_BASE, addr);
      break;
    default:
      ret = -1;
      break;
  }

  return ret;
}
