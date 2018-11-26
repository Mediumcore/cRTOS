#include <nuttx/arch.h>

#include "tux.h"
#include "up_internal.h"

#define FUTEX_HT_SIZE 256

struct futex_q{
  sem_t sem;
  uint64_t key;
};

struct futex_q futex_hash_table[FUTEX_HT_SIZE];

int tux_futex(unsigned long nbr, int32_t* uaddr, int opcode, uint32_t val){
  uint32_t s_head = (uint64_t)uaddr % FUTEX_HT_SIZE;
  uint32_t hv = s_head;
  irqstate_t flags;
  if(!uaddr) return -1;

  // Discard the private flag
  opcode &= ~FUTEX_PRIVATE_FLAG;

  switch(opcode){
    case FUTEX_WAIT:
      while((futex_hash_table[hv].key != 0) && (futex_hash_table[hv].key != (uint64_t)uaddr)){
          hv++;
          hv %= FUTEX_HT_SIZE;
          if(hv == s_head) return -1; // Out of free futex
      }

      flags = enter_critical_section();

      if(*uaddr == val){
        if(futex_hash_table[hv].key == 0) sem_init(&(futex_hash_table[hv].sem), 0, 0);

        futex_hash_table[hv].key = (uint64_t)uaddr;
        sem_wait(&(futex_hash_table[hv].sem));
      }

      leave_critical_section(flags);

      return 0; // Either not blocked or waken

      break;
    case FUTEX_WAKE:
      while(futex_hash_table[hv].key != (uint64_t)uaddr){
          hv++;
          hv %= FUTEX_HT_SIZE;
          if(hv == s_head) return 0; // ? No such key, wake no one
      }

      int svalue;
      sem_getvalue(&(futex_hash_table[hv].sem), &svalue);
      val = val > -svalue ? -svalue : val;
      for(;val > 0; val--){
        sem_post(&(futex_hash_table[hv].sem));
      }

      flags = enter_critical_section();
      sem_getvalue(&(futex_hash_table[hv].sem), &svalue);
      if(svalue == 0) {
          nxsem_destroy(&(futex_hash_table[hv].sem));
          futex_hash_table[hv].key = 0;
      }
      leave_critical_section(flags);

      return val;

      break;
    default:
      _info("Futex got unfriendly opcode: %d\n", opcode);
      PANIC();
    }
}

