#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <nuttx/arch.h>
#include <nuttx/sched.h>
#include <nuttx/kmalloc.h>
#include <stdint.h>

#include "up_internal.h"
#include "tux.h"
#include "sched/sched.h"

#define MAP_ANONYMOUS 0x20
#define MAP_NONRESERVE 0x4000

void* tux_mmap(unsigned long nbr, void* addr, size_t length, int prot, int flags){
  struct tcb_s *tcb = this_task();
  int i;

  if((flags & MAP_ANONYMOUS) == 0) return (void*)-1;
  if((uint64_t)addr != 0) return (void*)-1;

  if(((flags & MAP_NONRESERVE) == 1) && prot == 0) return (void*)-1; // Why glibc require large amount of non accessible memory?

  svcinfo("TUX: mmap trying to allocate %lld bytes\n", length);

  //XXX: Possible race condition, lock scheduler perhaps?

  for(i = 0; i < 64; i++){
      if(tcb->xcp.vma[i][0] == 0) break;
  }

  if(i == 64){
    svcinfo("TUX: mmap failed to allocate vma exhausted\n");
    return (void*)-1; // vma exhuasted
  }

  void* mm = kmm_zalloc(length);
  if(!mm){
    svcinfo("TUX: mmap failed to allocated %d bytes\n", length);
    return (void*)-1;
  }

  tcb->xcp.vma[i][0] = (uint64_t)mm;
  tcb->xcp.vma[i][1] = (uint64_t)mm + (uint64_t)length;

  svcinfo("TUX: mmap allocated %d bytes\n", length);

  return mm;
}

int tux_munmap(unsigned long nbr, void* addr, size_t length){
  struct tcb_s *tcb = this_task();
  int i;

  if(addr == NULL) return -1;

  // XXX: this might work but if partial of the block is unmaped, we will start to leak vma
  for(i = 0; i < 64; i++){
    if(tcb->xcp.vma[i][0] >= (uint64_t)addr) {
      if(tcb->xcp.vma[i][1] <= (uint64_t)addr + length) {
        kmm_free((void*)tcb->xcp.vma[i][0]);
        tcb->xcp.vma[i][0] = 0;
        tcb->xcp.vma[i][1] = 0;
      }
    }
  }

  return 0;
}

