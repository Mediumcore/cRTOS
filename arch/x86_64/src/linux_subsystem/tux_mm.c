#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <nuttx/arch.h>
#include <nuttx/sched.h>
#include <nuttx/kmalloc.h>
#include <stdint.h>

#include "up_internal.h"
#include "arch/io.h"
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

int get_free_pg_index(void) {
  struct tcb_s *tcb = this_task();
  int i;

  //XXX: Possible race condition, lock scheduler perhaps?
  for(i = 8; i < 128; i++){
      if(tcb->xcp.page_table[i] == 0x82) break;
  }

  if(i == 128){
    svcinfo("TUX: mmap failed to allocate page table entry, exhausted\n");
    return -1; // page_table entry exhuasted
  }

  return i;
}

void* tux_mmap(unsigned long nbr, void* addr, size_t length, int prot, int flags, int fd, off_t offset){
  struct tcb_s *tcb = this_task();
  int i, j;
  int vma, ma, pg;
  uint64_t scan_addr;
  int can_fix_pos = 0;
  uint64_t* ma_ptr;
  void *mm;

  svcinfo("TUX: mmap with flags: %x\n", flags);

  if(((flags & MAP_NONRESERVE)) && (prot == 0)) return (void*)-1; // Why glibc require large amount of non accessible memory?

  if((flags & MAP_FIXED) && ((uint64_t)addr < 8 * HUGE_PAGE_SIZE)) return (void*)-1;

  if(!(flags & MAP_FIXED)) // Fixed mapping?
    {
      svcinfo("TUX: mmap trying to allocate 0x%llx bytes\n", length);

      // Calculate page to be mapped
      uint64_t num_of_pages = (length + HUGE_PAGE_SIZE - 1) / HUGE_PAGE_SIZE;

      mm = kmm_memalign(HUGE_PAGE_SIZE, num_of_pages * HUGE_PAGE_SIZE);
      if(!mm){
        svcinfo("TUX: mmap failed to allocate 0x%llx bytes\n", num_of_pages * HUGE_PAGE_SIZE);
        return (void*)-1;
      }

      svcinfo("TUX: mmap allocated 0x%llx bytes at 0x%llx\n", num_of_pages * HUGE_PAGE_SIZE, mm);

      // Find a free page_table entry
      pg = get_free_pg_index();
      if(pg == -1) {kmm_free(mm); return (void*)-1;}
      addr = pg * HUGE_PAGE_SIZE;

      // Map it
      for(i = 0; i < num_of_pages; i++) {
          tcb->xcp.page_table[pg + i] = ((uint64_t)mm + (i) * HUGE_PAGE_SIZE) | 0x83;
          pd[pg + i] = ((uint64_t)mm + (i) * HUGE_PAGE_SIZE) | 0x83;
      }

      // Mark the starting page, used in release_stack to recycle
      tcb->xcp.page_table[pg] |= 1 << 9;
      pd[pg] |= 1 << 9;

      svcinfo("TUX: mmap maped 0x%llx bytes at 0x%llx, backed by 0x%llx\n", length, addr, mm);
    }
  else
    {
      svcinfo("TUX: mmap try to fix position at %llx\n", addr);

      /* Round to page boundary */
      uint64_t bb = (uint64_t)addr & ~(HUGE_PAGE_SIZE - 1);
      pg = bb / HUGE_PAGE_SIZE;

      // Calculate page to be mapped
      uint64_t num_of_pages = (length + (uint64_t)addr - bb + HUGE_PAGE_SIZE - 1) / HUGE_PAGE_SIZE;

      for(i = 0; i < num_of_pages; i++) {
          if(tcb->xcp.page_table[pg + i] & 1) continue; // Already mapped

          // Scan the continuous block
          for(j = i; !(tcb->xcp.page_table[pg + j] & 1) && (j < num_of_pages); j++);

          // Create backing memory
          mm = kmm_memalign(HUGE_PAGE_SIZE, (j - i) * HUGE_PAGE_SIZE);
          if(!mm){
            svcinfo("TUX: mmap failed to allocate 0x%llx bytes\n", (j - i) * HUGE_PAGE_SIZE);
            return (void*)-1;
          }
          svcinfo("TUX: mmap allocated 0x%llx bytes at 0x%llx\n", (j - i) * HUGE_PAGE_SIZE, mm);

          // Map it
          for(j = i; !(tcb->xcp.page_table[pg + j] & 1) && (j < num_of_pages); j++){
              tcb->xcp.page_table[pg + j] = ((uint64_t)mm + (j) * HUGE_PAGE_SIZE) | 0x83;
              pd[pg + j] = ((uint64_t)mm + (j) * HUGE_PAGE_SIZE) | 0x83;
          }

          // Mark the starting page, used in release_stack to recycle
          tcb->xcp.page_table[pg + i] |= 1 << 9;
          pd[pg + i] |= 1 << 9;

          svcinfo("TUX: mmap maped 0x%llx bytes at 0x%llx, backed by 0x%llx\n", (j - i) * HUGE_PAGE_SIZE, (pg + i) * HUGE_PAGE_SIZE, mm);
          i = j - 1;
      }
    }

  svcinfo("Current Map: \n");
  for(i = 0; i < 128; i++)
    {
      if(!(tcb->xcp.page_table[i] & 1)) continue;
      for(j = i; (tcb->xcp.page_table[j] & 1) &&  (j < 128); j++);
      svcinfo("0x%llx - 0x%llx\n", HUGE_PAGE_SIZE * i, HUGE_PAGE_SIZE * j - 1);
      i = j - 1;
    }

  if((flags & MAP_ANONYMOUS)) return pg * HUGE_PAGE_SIZE;


  // temporary memory for receive the file content
  void* tmp_mm = kmm_malloc(length);
  if(!tmp_mm){
    svcinfo("TUX: mmap failed to allocate 0x%llx bytes\n", length);
    return (void*)-1;
  }

  if(tux_delegate(nbr, tmp_mm, length, prot, flags, fd - TUX_FD_OFFSET, offset) != -1)
    {
      memcpy(addr, tmp_mm, length);
      kmm_free(tmp_mm);
      return addr;
    }
  else
    {
      kmm_free(tmp_mm);
      return (void*)-1;
    }
}

int tux_munmap(unsigned long nbr, void* addr, size_t length){
  struct tcb_s *tcb = this_task();
  int i;
  uint64_t* ptr;
  int vma;

  return 0;
}

