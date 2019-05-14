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
  tux_mm_hnd = gran_initialize((void*)0x1000000, (0x34000000 - 0x1000000), 12, 12); // 2^12 is 4KB, the PAGE_SIZE
}

void revoke_vma(struct vma_s* vma){
  struct tcb_s *tcb = this_task();
  struct vma_s* ptr;
  struct vma_s** pptr;

  if(vma == NULL) return;

  for(pptr = &tcb->xcp.vma, ptr = tcb->xcp.vma; ptr; pptr = &(ptr->next), ptr = ptr->next) {
    if(ptr == vma){
      *pptr = ptr->next;
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

  // Should always exist at least 2 entries, start from the second one
  for(pptr = tcb->xcp.vma, ptr = tcb->xcp.vma->next; ptr; pptr = ptr, ptr = ptr->next) {
    if(ptr->va_start - pptr->va_end >= size)
      {
        // Find a large enough hole
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
  struct vma_s** pptr;
  struct vma_s* ret = kmm_malloc(sizeof(struct vma_s));
  uint64_t prev_end = 0;

  if(!ret) return ret;

  ret->va_start = va_start;
  ret->va_end = va_end;
  ret->next = NULL;

  for(prev_end = 0, pptr = &tcb->xcp.vma, ptr = tcb->xcp.vma; ptr; prev_end = ptr->va_end, pptr = &(ptr->next), ptr = ptr->next) {
    if(ptr == &g_vm_full_map) continue;
    if(ptr == ret) continue;
    if(va_start <= ptr->va_start && va_end >= ptr->va_end)
      {
        // Whole covered, remove this mapping
        *pptr = ret;
        ret->next = ptr->next;

        svcinfo("removing covered\n");

        gran_free(tux_mm_hnd, (void*)(ptr->pa_start), ptr->va_end - ptr->va_start);
        kmm_free(ptr);

        ptr = ret;
      }
    else if(va_start > ptr->va_start && va_start < ptr->va_end)
      {
        if(va_end < ptr->va_end)
          {
            // Break to 2
            svcinfo("Break2\n");
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
            svcinfo("Shrink End\n");
            gran_free(tux_mm_hnd, (void*)(ptr->pa_start + va_start - ptr->va_start), ptr->va_end - va_start);
            ptr->va_end = va_start;
            ret->next = ptr->next;
            ptr->next = ret;
          }
      }
    else if(va_end > ptr->va_start && va_end <= ptr->va_end)
      {
        if(va_start <= ptr->va_start)
          {

            svcinfo("Shrink Head\n");
            // Shrink Head
            gran_free(tux_mm_hnd, (void*)(ptr->pa_start), va_end - ptr->va_start);
            ptr->va_start = va_end;
            *pptr = ret;
            ret->next = ptr;
            // In strictly increasing order, we end here
            return ret;
          }
      }
    else if((va_start >= prev_end) && va_end <= ptr->va_start)
      {
        // Hole
        *pptr = ret;
        ret->next = ptr;
        return ret;
      }
  }

  if(!ret->next) *pptr = ret;

  return ret;
}

uint64_t* temp_map_at_0xc0000000(uintptr_t start, uintptr_t end)
{
  uintptr_t k;
  uintptr_t lsb = start & ~HUGE_PAGE_MASK;
  start &= HUGE_PAGE_MASK;

  svcinfo("Temp map %llx - %llx at 0xc0000000\n", start, end);

  // Temporary map the new pdas at high memory 0xc000000 ~
  for(k = start; k < end; k += HUGE_PAGE_SIZE)
    {
      pd[((0xc0000000 + k - start) >> 21) & 0x7ffffff] = k | 0x9b; // No cache
    }

  up_invalid_TLB(start, end);

  return 0xc0000000 + lsb;
}

int create_and_map_pages(struct vma_s* vma){
  struct tcb_s *tcb = this_task();
  uint64_t i, j, k;
  uint64_t prev_end;
  struct vma_s* pda;
  struct vma_s* ptr;
  struct vma_s** pptr;
  uint64_t *tmp_pd;

  int pg_index = (uint64_t)vma->va_start / PAGE_SIZE;

  if(vma->va_start >= 0x34000000) return -1; // Mapping out of bound
  if(vma->va_end - vma->va_start > 0x34000000) return -1; // Mapping out of bound

  svcinfo("Creating mapping %llx %llx\n", vma->va_start, vma->va_end);

  // Create backing memory
  // The allocated physical memory is non-accessible from this process, must be mapped
  void* mm = gran_alloc(tux_mm_hnd, vma->va_end - vma->va_start);
  if(!mm)
    {
      svcinfo("TUX: mmap failed to allocate 0x%llx bytes\n", vma->va_end - vma->va_start);
      return -1;
    }
  svcinfo("TUX: mmap allocated 0x%llx bytes at 0x%llx\n", vma->va_end - vma->va_start, mm);

  // Give back the physical memory
  vma->pa_start = mm;

  // Search the pdas for insertion, map the un mapped pd duriong the creation of new pda
  svcinfo("Mapping: %llx - %llx\n", vma->va_start, vma->va_end);
  i = vma->va_start;
  for(prev_end = 0, pptr = &tcb->xcp.pda, ptr = tcb->xcp.pda; ptr; prev_end = ptr->va_end, pptr = &(ptr->next), ptr = ptr->next)
    {
          if(i < ptr->va_start && i >= prev_end)
            {
              // Fall between 2 pda
              // Preserving the starting addr
              svcinfo("%llx, Between: %llx, and %llx - %llx\n", i, prev_end, ptr->va_start, ptr->va_end);

              pda = kmm_malloc(sizeof(struct vma_s));

              // pda's size should cover sufficient size of the Hole
              pda->va_start = i & HUGE_PAGE_MASK;
              for(pda->va_end = i; pda->va_end < ptr->va_start && pda->va_end < vma->va_end; pda->va_end += PAGE_SIZE); // Scan the hole size;
              pda->va_end = (pda->va_end + HUGE_PAGE_SIZE - 1) & HUGE_PAGE_MASK;

              // TODO: process proto
              pda->proto = 0x3;
              pda->_backing = vma->_backing;

              pda->pa_start = (void*)gran_alloc(tux_mm_hnd, PAGE_SIZE * VMA_SIZE(pda) / HUGE_PAGE_SIZE);
              if(!pda->pa_start)
                {
                  svcinfo("TUX: mmap failed to allocate 0x%llx bytes for new pda\n", PAGE_SIZE * VMA_SIZE(pda) / HUGE_PAGE_SIZE);
                  return -1;
                }

              svcinfo("New pda: %llx - %llx %llx\n", pda->va_start, pda->va_end, pda->pa_start);

              // Temporary map the memory for writing
              tmp_pd = temp_map_at_0xc0000000(pda->pa_start, pda->pa_start + PAGE_SIZE * VMA_SIZE(pda) / HUGE_PAGE_SIZE);

              // Clear the page directories
              memset(tmp_pd, 0, PAGE_SIZE * VMA_SIZE(pda) / HUGE_PAGE_SIZE);

              // Fill in the new mappings to page directories
              for(j = i; j < ptr->va_start && j < vma->va_end; j += PAGE_SIZE) // Scan the hole size;
                tmp_pd[((j - pda->va_start) >> 12) & 0x3ffff] = (vma->pa_start + j - vma->va_start) | vma->proto;

              up_invalid_TLB(i, j);

              // Link it to the pdas list
              *pptr = pda;
              pda->next = ptr;

              // Map it via page directories
              for(j = pda->va_start; j < pda->va_end; j += HUGE_PAGE_SIZE) {
                pd[(j >> 21) & 0x7ffffff] = (((j - pda->va_start) >> 9) + pda->pa_start) | pda->proto;
              }

              i = ptr->va_start < vma->va_end ? ptr->va_start : vma->va_end;
            }

          if(i >= ptr->va_start && i < ptr->va_end)
            {
              svcinfo("%llx Overlapping: %llx - %llx\n", i, ptr->va_start, ptr->va_end);
              // In this pda

              // Temporary map the memory for writing
              tmp_pd = temp_map_at_0xc0000000(ptr->pa_start, ptr->pa_start + PAGE_SIZE * VMA_SIZE(ptr) / HUGE_PAGE_SIZE);

              // Map it via page directories
              for(; i < ptr->va_end && i < vma->va_end; i += PAGE_SIZE)
                  tmp_pd[((i - ptr->va_start) >> 12) & 0x3ffff] = (vma->pa_start + i - vma->va_start) | vma->proto;
            }

      if(i == vma->va_end) break;
    }

    if(i < vma->va_end)
      {
        svcinfo("Insert at End\n");
        // Fall after all pdas
        // Preserving the starting addr
        pda = kmm_malloc(sizeof(struct vma_s));

        // pda's size should cover sufficient size of the Hole
        pda->va_start = i & HUGE_PAGE_MASK;
        pda->va_end = (vma->va_end + HUGE_PAGE_SIZE - 1) & HUGE_PAGE_MASK;

        // TODO: process proto
        pda->proto = 0x3;
        pda->_backing = vma->_backing;

        svcinfo("New pda: %llx - %llx %llx\n", pda->va_start, pda->va_end, pda->pa_start);

        pda->pa_start = (void*)gran_alloc(tux_mm_hnd, PAGE_SIZE * VMA_SIZE(pda) / HUGE_PAGE_SIZE);
        if(!pda->pa_start)
          {
            svcinfo("TUX: mmap failed to allocate 0x%llx bytes for new pda\n", PAGE_SIZE * VMA_SIZE(pda) / HUGE_PAGE_SIZE);
            return -1;
          }

        // Temporary map the memory for writing
        tmp_pd = temp_map_at_0xc0000000(pda->pa_start, pda->pa_start + VMA_SIZE(pda));

        // Clear the page directories
        memset(tmp_pd, 0, PAGE_SIZE * VMA_SIZE(pda) / HUGE_PAGE_SIZE);

        // Fill in the new mappings to page directories
        for(j = i; j < ptr->va_start && j < vma->va_end; j += PAGE_SIZE) // Scan the hole size;
          tmp_pd[((j - pda->va_start) >> 12) & 0x3ffff] = (vma->pa_start + j - vma->va_start) | vma->proto;

        up_invalid_TLB(i, j);

        // Link it to the pdas list
        *pptr = pda;
        pda->next = NULL;

        // Map it via page directories
        for(j = pda->va_start; j < pda->va_end; j += HUGE_PAGE_SIZE) {
          pd[(j >> 21) & 0x7ffffff] = ((j >> 9) + pda->pa_start) | pda->proto;
        }
      }

  // Zero fill the page via virtual memory
  memset(vma->va_start, 0, vma->va_end - vma->va_start);

  // Trigger the shadow process to gain the same mapping
  // TODO: Pass proto
  if(tux_delegate(9, (((uint64_t)vma->pa_start) << 32) | (uint64_t)vma->va_start, vma->va_end - vma->va_start,
              0, MAP_ANONYMOUS, 0, 0) == -1)
    {
      return -1;
    }

  svcinfo("TUX: mmap maped 0x%llx bytes at 0x%llx, backed by 0x%llx\n", vma->va_end - vma->va_start, vma->va_start, vma->pa_start);

  return OK;
}

struct graninfo_s granib;
struct graninfo_s grania;

void print_mapping(void) {
  struct tcb_s *tcb = this_task();
  struct vma_s* ptr;
  uint64_t p = 0;

  svcinfo("Current Map: \n");
  for(ptr = tcb->xcp.vma; ptr && p < 512; ptr = ptr->next, p++)
    {
      if(ptr == &g_vm_full_map) continue;
      svcinfo("0x%08llx - 0x%08llx : backed by 0x%08llx 0x%08llx %s\n", ptr->va_start, ptr->va_end, ptr->pa_start, ptr->pa_start + VMA_SIZE(ptr), ptr->_backing);
    }

  p = 0;
  svcinfo("Current PDAS: \n");
  for(ptr = tcb->xcp.pda; ptr && p < 64; ptr = ptr->next, p++)
    {
      if(ptr == &g_vm_full_map) continue;
      svcinfo("0x%08llx - 0x%08llx : 0x%08llx 0x%08llx\n", ptr->va_start, ptr->va_end, ptr->pa_start, ptr->pa_start + VMA_SIZE(ptr));
    }

  gran_info(tux_mm_hnd, &grania);
  svcinfo("GRANDULE  BEFORE AFTER\n");
  svcinfo("======== ======== ========\n");
  svcinfo("nfree    %8x %8x\n", granib.nfree, grania.nfree);
  svcinfo("mxfree   %8x %8x\n", granib.mxfree, grania.mxfree);
  granib = grania;
}

void* tux_mmap(unsigned long nbr, void* addr, size_t length, int prot, int flags, int fd, off_t offset){
  struct tcb_s *tcb = this_task();
  int i, j;
  struct vma_s* vma;

  svcinfo("TUX: mmap with flags: %x\n", flags);

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
      vma->_backing = "[Memory]";
      addr = vma->va_start;

      if(create_and_map_pages(vma))
        {
          revoke_vma(vma);
          return (void*)-1;
        }
    }
  else
    {
      svcinfo("TUX: mmap try to fix position at %llx\n", addr);

      /* Round to page boundary */
      if((uint64_t)addr & ~PAGE_MASK)
        {
          revoke_vma(vma);
          return (void*)-1;
        }

      // Calculate page to be mapped
      uint64_t num_of_pages = (length + PAGE_SIZE - 1) / PAGE_SIZE;

      // Free page_table entries
      vma = make_vma_free(addr, addr + num_of_pages * PAGE_SIZE);
      if(!vma) {return (void*)-1;}
      // TODO: process proto
      vma->proto = 0x3;
      vma->_backing = "[Memory]";

      if(create_and_map_pages(vma))
        {
          revoke_vma(vma);
          return (void*)-1;
        }
    }

  if(!(flags & MAP_ANONYMOUS))
    {

#ifdef CONFIG_DEBUG_SYSCALL_INFO
      char proc_fs_path[64] = "/proc/self/fd/";
      char tmp[64];
      memset(tmp, 0, 64);

      uint64_t t = fd - TUX_FD_OFFSET;
      int k = 0;
      while(t){
          tmp[k++] = (t % 10) + '0';
          t /= 10;
      }
      k--;

      int l = 14;
      while(k >= 0){
          proc_fs_path[l++] = tmp[k--];
      }
      proc_fs_path[l] = 0;

      char* file_path = kmm_zalloc(128);

      l = tux_delegate(89, proc_fs_path, file_path, 127, 0, 0, 0);
      if(l == -1)
        {
          revoke_vma(vma);
          return (void*)-1;
        }

      if(l < 120){
          t = offset;
          k = 0;
          tmp[0] = (t >> 28) & 0xf;
          tmp[1] = (t >> 24) & 0xf;
          tmp[2] = (t >> 20) & 0xf;
          tmp[3] = (t >> 16) & 0xf;
          tmp[4] = (t >> 12) & 0xf;
          tmp[5] = (t >> 8) & 0xf;
          tmp[6] = (t >> 4) & 0xf;
          tmp[7] = (t >> 0) & 0xf;
          for(k = 0; k < 8; k++){
              if(tmp[k] <= 9) tmp[k] += '0';
              else tmp[k] += 'a' - 10;
          }

          file_path[l++] = ' ';
          file_path[l++] = ':';
          file_path[l++] = ' ';
          file_path[l++] = '0';
          file_path[l++] = 'x';

          _info("tmp: %s\n", tmp);
          for(k = 0; k < 8; k++){
              file_path[l++] = tmp[k];
          }
      }
      file_path[l] = 0;

      vma->_backing = file_path;
#else
      vma->_backing = "[File]";
#endif
      if(tux_delegate(nbr, (uint64_t)addr, length, prot, flags, fd - TUX_FD_OFFSET, offset) == -1)
        {
          revoke_vma(vma);
          return (void*)-1;
        }
    }

  print_mapping();

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

