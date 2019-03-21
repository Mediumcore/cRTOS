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

int create_and_map_pages(void** physical, void* virtual, uint64_t num_of_pages){
  struct tcb_s *tcb = this_task();
  int i;

  int pg_index = (uint64_t)virtual / HUGE_PAGE_SIZE;

  if(pg_index >= 128) return -1; // Mapping out of bound

  // Create backing memory
  void* mm = kmm_memalign(HUGE_PAGE_SIZE, num_of_pages * HUGE_PAGE_SIZE);
  if(!mm)
    {
      svcinfo("TUX: mmap failed to allocate 0x%llx bytes\n", num_of_pages * HUGE_PAGE_SIZE);
      return (void*)-1;
    }
  svcinfo("TUX: mmap allocated 0x%llx bytes at 0x%llx\n", num_of_pages * HUGE_PAGE_SIZE, mm);

  // Zero fill the page
  memset(mm, 0, num_of_pages * HUGE_PAGE_SIZE);

  // Give back the physical memory
  *physical = mm;

  // Map it
  pd[pg_index] = tcb->xcp.page_table[pg_index] = ((uint64_t)mm) | 0x283;
  for(i = 1; i < num_of_pages; i++)
    {
      pd[pg_index + i] = tcb->xcp.page_table[pg_index + i] = ((uint64_t)mm + (i) * HUGE_PAGE_SIZE) | 0x83;
    }

  // Trigger the shadow process to gain the same mapping
  if(tux_delegate(9, (((uint64_t)*physical) << 32) | (uint64_t)virtual, num_of_pages * HUGE_PAGE_SIZE,
              0, MAP_ANONYMOUS, 0, 0) == -1)
    {
      return -1;
    }

  svcinfo("TUX: mmap maped 0x%llx bytes at 0x%llx, backed by 0x%llx\n", num_of_pages * HUGE_PAGE_SIZE, virtual, *physical);

  return OK;
}

void print_mapping(void) {
  struct tcb_s *tcb = this_task();
  int i, j;

  svcinfo("Current Map: \n");
  for(i = 0; i < 128; i++)
    {
      if(!(tcb->xcp.page_table[i] & 1)) continue;
      for(j = i + 1; (tcb->xcp.page_table[j] & 1) &&  (j < 128) && !(tcb->xcp.page_table[j] & 0x200); j++);
      svcinfo("0x%llx - 0x%llx : backed by 0x%llx\n", HUGE_PAGE_SIZE * i, HUGE_PAGE_SIZE * j - 1, tcb->xcp.page_table[i]);
      i = j - 1;
    }

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
      uint64_t num_of_pages = (uint64_t)(length + HUGE_PAGE_SIZE - 1) / HUGE_PAGE_SIZE;

      // Find a free page_table entry
      pg = get_free_pg_index();
      if(pg == -1) {return (void*)-1;}
      addr = pg * HUGE_PAGE_SIZE;

      if(create_and_map_pages(&mm, addr, num_of_pages)) return (void*)-1;
    }
  else
    {
      svcinfo("TUX: mmap try to fix position at %llx\n", addr);

      /* Round to page boundary */
      uint64_t bb = (uint64_t)addr & ~(HUGE_PAGE_SIZE - 1);

      // Calculate page to be mapped
      uint64_t num_of_pages = (length + (uint64_t)addr - bb + HUGE_PAGE_SIZE - 1) / HUGE_PAGE_SIZE;

      // Calculate starting page tale entry
      pg = bb / HUGE_PAGE_SIZE;

      for(i = 0; i < num_of_pages; i++) {
          if(tcb->xcp.page_table[pg + i] & 1) continue; // Already mapped

          // Scan the continuous block
          for(j = i; !(tcb->xcp.page_table[pg + j] & 1) && (j < num_of_pages); j++);

          if(create_and_map_pages(&mm, (pg + i) * HUGE_PAGE_SIZE, (j - i))) return (void*)-1;

          i = j - 1;
      }
    }

  print_mapping();

  if(!(flags & MAP_ANONYMOUS))
    {
      if(tux_delegate(nbr, addr, length, prot, flags, fd - TUX_FD_OFFSET, offset) == -1)
        {
          return (void*)-1;
        }
    }

  return addr;
}

int tux_munmap(unsigned long nbr, void* addr, size_t length){
  struct tcb_s *tcb = this_task();
  int i;
  uint64_t* ptr;
  int vma;

  return 0;
}

