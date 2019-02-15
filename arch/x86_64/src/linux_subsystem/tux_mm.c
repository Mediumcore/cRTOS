#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <nuttx/arch.h>
#include <nuttx/sched.h>
#include <nuttx/kmalloc.h>
#include <stdint.h>

#include "up_internal.h"
#include "tux.h"
#include "sched/sched.h"

#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_NONRESERVE 0x4000

int get_free_vma_index(void) {
  struct tcb_s *tcb = this_task();
  int i;

  //XXX: Possible race condition, lock scheduler perhaps?
  for(i = 0; i < 64; i++){
      if(tcb->xcp.vma[i][0] == 0) break;
  }

  if(i == 64){
    svcinfo("TUX: mmap failed to allocate vma, exhausted\n");
    return -1; // vma exhuasted
  }

  return i;
}

int get_free_ma_index(void) {
  struct tcb_s *tcb = this_task();
  int i;

  //XXX: Possible race condition, lock scheduler perhaps?
  for(i = 0; i < 64; i++){
      if(tcb->xcp.ma[i][0] == 0) break;
  }

  if(i == 64){
    svcinfo("TUX: mmap failed to allocate ma, exhausted\n");
    return -1; // ma exhuasted
  }

  return i;
}

void* tux_mmap(unsigned long nbr, void* addr, size_t length, int prot, int flags, int fd, off_t offset){
  struct tcb_s *tcb = this_task();
  int i;
  int vma, ma;
  uint64_t scan_addr;
  int can_fix_pos = 0;
  uint64_t* ma_ptr;

  svcinfo("TUX: mmap with flags: %x\n", flags);

  if(((flags & MAP_NONRESERVE) == 1) && prot == 0) return (void*)-1; // Why glibc require large amount of non accessible memory?

  // XXX
  // We only support dividing a memory region smaller
  // We don't support merging 2 memory regions

  if(((uint64_t)addr != 0))
    {
      for(i = 0; i < 64; i++)
        {
          if(tcb->xcp.vma[i][0] == 0) continue;
          if((tcb->xcp.vma[i][1] <= (uint64_t)addr) && (tcb->xcp.vma[i][2] >= (uint64_t)addr + length))
            {
              can_fix_pos = 1;
              break;
            }
       }
    }

  if((flags & MAP_FIXED) && ((uint64_t)addr == 0)) return (void*)-1;
  if((flags & MAP_FIXED) && !can_fix_pos) return (void*)-1;

  if(!can_fix_pos) // Split out the vma region from existing vma
    {
      svcinfo("TUX: mmap trying to allocate 0x%llx bytes\n", length);

      void* mm = kmm_zalloc(length);
      if(!mm){
        svcinfo("TUX: mmap failed to allocate 0x%llx bytes\n", length);
        return (void*)-1;
      }

      svcinfo("TUX: mmap allocated 0x%llx bytes\n", length);

      ma = get_free_ma_index();
      if(ma == -1) {kmm_free(mm); return (void*)-1;}
      tcb->xcp.ma[ma][0] = (uint64_t)mm; // base address
      tcb->xcp.ma[ma][1] = 1; // Reference count

      ma_ptr = &(tcb->xcp.ma[ma][0]);

      addr = mm;
    }
  else
    {
      svcinfo("TUX: mmap used existing map to fix position at %llx\n", addr);
      tux_munmap(0, addr, length);
      ma_ptr = (uint64_t*)tcb->xcp.vma[i][0];
      ma_ptr[1]++;
    }

  vma = get_free_vma_index();
  if(vma == -1) return (void*)-1;

  tcb->xcp.vma[vma][0] = (uint64_t)ma_ptr;
  tcb->xcp.vma[vma][1] = (uint64_t)addr;
  tcb->xcp.vma[vma][2] = (uint64_t)addr + (uint64_t)length;

  svcinfo("TUX: mmap maped 0x%llx bytes at 0x%llx\n", length, addr);

  svcinfo("Current Map: \n");
  for(i = 0; i < 64; i++){
    if(tcb->xcp.vma[i][0] == 0) continue;
    svcinfo("0x%llx - 0x%llx\n", tcb->xcp.vma[i][1], tcb->xcp.vma[i][2]);
  }

  if((flags & MAP_ANONYMOUS)) return addr;

  if(tux_delegate(nbr, addr, length, prot, flags, fd - TUX_FD_OFFSET, offset) != -1)
    {
      return addr;
    }
  else
    {
      tux_munmap(0, addr, length); // Recycle memory
      return (void*)-1;
    }
}

int tux_munmap(unsigned long nbr, void* addr, size_t length){
  struct tcb_s *tcb = this_task();
  int i;
  uint64_t* ptr;
  int vma;

  if(addr == NULL) return -1;

  svcinfo("Current Map: \n");
  for(i = 0; i < 64; i++){
    if(tcb->xcp.vma[i][0] == 0) continue;
    svcinfo("0x%llx - 0x%llx\n", tcb->xcp.vma[i][1], tcb->xcp.vma[i][2]);
  }

  svcinfo("TUX: Trying to unmap 0x%llx bytes from 0x%llx\n", length, addr);
  for(i = 0; i < 64; i++){
    if(tcb->xcp.vma[i][0] == 0) continue;

    ptr = (uint64_t*)(tcb->xcp.vma[i][0]);

    if(((uint64_t)addr > tcb->xcp.vma[i][1]) && ((uint64_t)addr < tcb->xcp.vma[i][2]) && (tcb->xcp.vma[i][2] <= (uint64_t)addr + length)) {
      svcinfo("TUX: Cut End\n");
      tcb->xcp.vma[i][2] = (uint64_t)addr;
    }else if(((uint64_t)addr <= tcb->xcp.vma[i][1]) && (tcb->xcp.vma[i][2] > (uint64_t)addr + length) && (tcb->xcp.vma[i][1] < (uint64_t)addr + length)) {
      svcinfo("TUX: Cut Beginning\n");
      tcb->xcp.vma[i][1] = (uint64_t)addr + length;
    }else if(((uint64_t)addr <= tcb->xcp.vma[i][1]) && (tcb->xcp.vma[i][2] <= (uint64_t)addr + length)) {
        // Simply free this

        svcinfo("TUX: Founded a whole mapping\n");
        ptr[1]--;

        tcb->xcp.vma[i][0] = 0;
    }else if(((uint64_t)addr > tcb->xcp.vma[i][1]) && (tcb->xcp.vma[i][2] > (uint64_t)addr + length)) {
        // Divide to 2 regions

        svcinfo("TUX: Divide a mapping to 2\n");
        vma = get_free_vma_index();
        if(vma == -1) return -1;

        tcb->xcp.vma[vma][0] = tcb->xcp.vma[i][0];

        tcb->xcp.vma[vma][1] = (uint64_t)addr + length;
        tcb->xcp.vma[vma][2] = tcb->xcp.vma[i][2];
        ptr[1]++;

        tcb->xcp.vma[i][2] = (uint64_t)addr;
    }

    if(ptr && !ptr[1]){
        svcinfo("TUX: Freeing non-used memory: %llx\n", ptr[0]);
        kmm_free((void*)ptr[0]);
    }
  }

  svcinfo("Current Map: \n");
  for(i = 0; i < 64; i++){
    if(tcb->xcp.vma[i][0] == 0) continue;
    svcinfo("0x%llx - 0x%llx\n", tcb->xcp.vma[i][1], tcb->xcp.vma[i][2]);
  }

      return 0;
}

