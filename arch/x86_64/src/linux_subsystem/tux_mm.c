#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <nuttx/arch.h>
#include <nuttx/sched.h>
#include <nuttx/kmalloc.h>
#include <stdint.h>

#include "up_internal.h"
#include "tux.h"

#define MAP_ANONYMOUS 0x20
#define MAP_NONRESERVE 0x4000

void* tux_mmap(void* addr, size_t length, int prot, int flags){
  if((flags & MAP_ANONYMOUS) == 0) return (void*)-1;
  if((uint64_t)addr != 0) return (void*)-1;

  if(((flags & MAP_NONRESERVE) == 1) && prot == 0) return (void*)-1; // Why glibc require large amount of non accessible memory?

  _info("TUX: mmap trying to allocate %d bytes\n", length);

  void* mm = kmm_zalloc(length);
  if(!mm){
    _info("TUX: mmap failed to allocated %d bytes\n", length);
    return (void*)-1;
  }

  _info("TUX: mmap allocated %d bytes\n", length);

  return mm;
}

int tux_munmap(void* addr, size_t length){
  //XXX: What if the addr + length have multiple regions to unmap?
  kmm_free(addr);
  return 0;
}

