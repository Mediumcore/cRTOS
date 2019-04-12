#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <nuttx/arch.h>
#include <nuttx/sched.h>
#include <nuttx/kmalloc.h>
#include <nuttx/mm/gran.h>
#include <stdint.h>
#include <string.h>

#include "up_internal.h"
#include "arch/io.h"
#include "tux.h"
#include "sched/sched.h"

#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_NONRESERVE 0x4000

GRAN_HANDLE tux_mm_hnd;

void tux_mm_init(void) {
  tux_mm_hnd = gran_initialize((void*)0x1000000, (0x34000000 - 0x1000000), 12, 12); // 2^21 is 2MB, the HUGE_PAGE_SIZE
}

void revoke_vma(struct vma_s* vma){
  struct tcb_s *tcb = this_task();
  struct vma_s* ptr;
  struct vma_s* pptr;

  if(vma == NULL) return;

  for(pptr = tcb->xcp.vma, ptr = tcb->xcp.vma->next; ptr; pptr = ptr, ptr = ptr->next) {
    if(ptr == vma){
      pptr->next = ptr->next;
      kmm_free(ptr);
    }
  }

  return;
}

struct vma_s* get_free_vma(uint64_t size) {
  struct tcb_s *tcb = this_task();
  struct vma_s* ptr;
  struct vma_s* pptr;
  struct vma_s* ret = kmm_malloc(sizeof(struct vma_s));
  if(!ret) return ret;

  ret->next = NULL;

  // The first should always be empty_mapping, skip it
  // Should always exist at least 3 entries, start from the third one
  for(pptr = tcb->xcp.vma->next, ptr = tcb->xcp.vma->next->next; ptr; pptr = ptr, ptr = ptr->next) {
    if(ptr == &g_vm_full_map) continue;
    if(ptr == &g_vm_empty_map) continue;
    if(ptr->va_start - pptr->va_end >= size)
      {
        ret->next = ptr;
        break;
      }
  }

  pptr->next = ret;
  ret->va_start = pptr->va_end;
  ret->va_end = ret->va_start + size;
  return ret;
}

struct vma_s* make_vma_free(uint64_t va_start, uint64_t va_end) {
  struct tcb_s *tcb = this_task();
  struct vma_s* ptr;
  struct vma_s* pptr;
  struct vma_s* ret = kmm_malloc(sizeof(struct vma_s));

  if(!ret) return ret;

  ret->va_start = va_start;
  ret->va_end = va_end;
  ret->next = NULL;

  // The first should always be empty_mapping, skip it
  for(pptr = tcb->xcp.vma, ptr = tcb->xcp.vma->next; ptr; pptr = ptr, ptr = ptr->next) {
    if(ptr == &g_vm_full_map) continue;
    if(ptr == &g_vm_empty_map) continue;
    if(ptr == ret) continue;
    if(va_start <= ptr->va_start && va_end >= ptr->va_end)
      {
        // Whole covered, remove this mapping
        pptr->next = ret;
        ret->next = ptr->next;

        _info("removing covered\n");

        _info("pptr: %llx %llx\n", pptr->va_start, pptr->va_end);
        _info("ptr: %llx %llx\n", ptr->va_start, ptr->va_end);
        _info("nptr: %llx %llx\n", ptr->next->va_start, ptr->next->va_end);

        gran_free(tux_mm_hnd, (void*)(ptr->pa_start), ptr->va_end - ptr->va_start);
        kmm_free(ptr);

        ptr = ret;
      }
    else if(va_start >= ptr->va_start && va_start < ptr->va_end)
      {
        if(va_end <= ptr->va_end)
          {
            // Break to 2
            _info("Break2\n");
            struct vma_s* new_mapping = kmm_malloc(sizeof(struct vma_s));
            memcpy(new_mapping, ptr, sizeof(struct vma_s));
            ptr->va_end = va_start;
            new_mapping->va_start = va_end;
            new_mapping->pa_start += va_end - ptr->va_start;
            ptr->next = ret;
            ret->next = new_mapping;

            gran_free(tux_mm_hnd, (void*)(ptr->pa_start + ptr->va_end - ptr->va_start), va_end - va_start);
            return ret;
          }
        else
          {
            // Shrink End
            _info("Shrink End\n");
            gran_free(tux_mm_hnd, (void*)(ptr->pa_start + va_start - ptr->va_start), ptr->va_end - va_start);
            ptr->va_end = va_start;
            ret->next = ptr->next;
            ptr->next = ret;
          }
      }
    else if(va_end > ptr->va_start && va_end <= ptr->va_end)
      {
        if(va_start < ptr->va_start)
          {

            _info("Shrink Head\n");
            // Shrink Head
            gran_free(tux_mm_hnd, (void*)(ptr->pa_start), va_end - ptr->va_start);
            ptr->va_start = va_end;
            pptr->next = ret;
            ret->next = ptr;
          }
      }
    else if((va_start >= pptr->va_end || pptr == &g_vm_empty_map) && va_end <= ptr->va_start)
      {
        pptr->next = ret;
        ret->next = ptr;
        return ret;
      }
  }

  if(!ret->next) pptr->next = ret;

  return ret;
}

int create_and_map_pages(void** physical, void* virtual, uint64_t num_of_pages, uint64_t proto){
  struct tcb_s *tcb = this_task();
  int i;

  int pg_index = (uint64_t)virtual / PAGE_SIZE;

  if((uint64_t)virtual >= 0x34000000) return -1; // Mapping out of bound
  if(num_of_pages >= 0x34000) return -1; // Mapping out of bound

  _info("Creating mapping %llx %llx\n", virtual, num_of_pages);

  // Create backing memory
  // The allocated physical memory is non-accessible from this process, must be mapped
  _info("Getting Physical pages\n");
  void* mm = gran_alloc(tux_mm_hnd, num_of_pages * PAGE_SIZE);
  _info("Get Physical pages\n");
  if(!mm)
    {
      svcinfo("TUX: mmap failed to allocate 0x%llx bytes\n", num_of_pages * PAGE_SIZE);
      return -1;
    }
  svcinfo("TUX: mmap allocated 0x%llx bytes at 0x%llx\n", num_of_pages * PAGE_SIZE, mm);

  // Give back the physical memory
  *physical = mm;

  _info("Get physical block %llx %llx\n", mm, num_of_pages);

  _info("Starting to map\n");
  // Map it
  for(i = 0; i < num_of_pages; i++)
    {
      pt[(((uint64_t)virtual >> 12) & 0x7ffffff) + i] = ((uint64_t)mm + (i) * PAGE_SIZE) | proto;
    }

  _info("mapped\n");

  // Zero fill the page via virtual memory
  memset(virtual, 0, num_of_pages * PAGE_SIZE);

  // Trigger the shadow process to gain the same mapping
  // TODO: Pass proto
  if(tux_delegate(9, (((uint64_t)*physical) << 32) | (uint64_t)virtual, num_of_pages * PAGE_SIZE,
              0, MAP_ANONYMOUS, 0, 0) == -1)
    {
      return -1;
    }

  svcinfo("TUX: mmap maped 0x%llx bytes at 0x%llx, backed by 0x%llx\n", num_of_pages * PAGE_SIZE, virtual, *physical);

  return OK;
}

void print_mapping(void) {
  struct tcb_s *tcb = this_task();
  struct vma_s* ptr;
  uint64_t p = 0;

  svcinfo("Current Map: \n");
  for(ptr = tcb->xcp.vma; ptr && p < 32; ptr = ptr->next, p++)
    {
      if(ptr == &g_vm_full_map) continue;
      if(ptr == &g_vm_empty_map) continue;

      svcinfo("0x%llx - 0x%llx : backed by 0x%llx \n", ptr->va_start, ptr->va_end, ptr->pa_start);
    }
}

void* tux_mmap(unsigned long nbr, void* addr, size_t length, int prot, int flags, int fd, off_t offset){
  struct tcb_s *tcb = this_task();
  int i, j;
  void *mm;
  struct vma_s* vma;

  svcinfo("TUX: mmap with flags: %x\n", flags);

  print_mapping();

  if(((flags & MAP_NONRESERVE)) && (prot == 0)) return (void*)-1; // Why glibc require large amount of non accessible memory?

  if(!(flags & MAP_FIXED)) // Fixed mapping?
    {
      svcinfo("TUX: mmap trying to allocate 0x%llx bytes\n", length);

      // Calculate page to be mapped
      uint64_t num_of_pages = (uint64_t)(length + PAGE_SIZE - 1) / PAGE_SIZE;

      // Free page_table entries
      vma = get_free_vma(num_of_pages * PAGE_SIZE);
      if(!vma) {return (void*)-1;}
      // TODO: process proto
      vma->proto = 0x3;
      vma->_backing = "Memory";
      addr = vma->va_start;

      if(create_and_map_pages(&mm, addr, num_of_pages, vma->proto))
        {
          revoke_vma(vma);
          return (void*)-1;
        }
      vma->pa_start = (uint64_t)mm;
    }
  else
    {
      svcinfo("TUX: mmap try to fix position at %llx\n", addr);

      /* Round to page boundary */
      uint64_t bb = (uint64_t)addr & ~(PAGE_SIZE - 1);

      // Calculate page to be mapped
      uint64_t num_of_pages = (length + (uint64_t)addr - bb + PAGE_SIZE - 1) / PAGE_SIZE;

      // Free page_table entries
      vma = make_vma_free(bb, bb + num_of_pages * PAGE_SIZE);
      if(!vma) {return (void*)-1;}
      // TODO: process proto
      vma->proto = 0x3;
      vma->_backing = "Memory";

      if(create_and_map_pages(&mm, bb, num_of_pages, vma->proto))
        {
          revoke_vma(vma);
          return (void*)-1;
        }
      vma->pa_start = (uint64_t)mm;
    }

  print_mapping();

  if(!(flags & MAP_ANONYMOUS))
    {
      vma->_backing = "File";
      if(tux_delegate(nbr, (uint64_t)addr, length, prot, flags, fd - TUX_FD_OFFSET, offset) == -1)
        {
          revoke_vma(vma);
          return (void*)-1;
        }
    }

  return addr;
}

int tux_munmap(unsigned long nbr, void* addr, size_t length){
  struct tcb_s *tcb = this_task();

  /*if(length > HUGE_PAGE_SIZE * 32)*/
    /*{*/
      /*errno = -EINVAL;*/
      /*return -1;*/
    /*}*/

  /*[> Round to page boundary <]*/
  /*uint64_t bb = (uint64_t)addr & ~(HUGE_PAGE_SIZE - 1);*/

  /*// Calculate page to be unmapped*/
  /*uint64_t num_of_pages = (length + (uint64_t)addr - bb + HUGE_PAGE_SIZE - 1) / HUGE_PAGE_SIZE;*/

  /*// Calculate starting page table entry*/
  /*int pg = bb / HUGE_PAGE_SIZE;*/

  /*for(int i = 0; i < num_of_pages; i++) {*/
      /*if(!(tcb->xcp.page_table[pg + i] & 1)) continue; // Already unmapped*/

      /*gran_free(tux_mm_hnd, (void*)(tcb->xcp.page_table[pg + i] & HUGE_PAGE_MASK), HUGE_PAGE_SIZE);*/
      /*tcb->xcp.page_table[pg + i] = 0x82;*/
  /*}*/

  /*print_mapping();*/

  return 0;
}

