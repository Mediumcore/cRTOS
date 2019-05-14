#include <nuttx/arch.h>

#include "tux.h"
#include "up_internal.h"

#define FUTEX_HT_SIZE 256

struct futex_q{
  sem_t sem;
  uint64_t key;
};

struct futex_q futex_hash_table[FUTEX_HT_SIZE];

int tux_futex(unsigned long nbr, int32_t* uaddr, int opcode, uint32_t val, uint32_t val2, int32_t* uaddr2, uint32_t val3){
  uint32_t s_head = (uint64_t)uaddr % FUTEX_HT_SIZE;
  uint32_t hv = s_head;
  uint32_t hv2 = s_head;
  int ret;
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
      ret = val;
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

      return ret;

      break;
    case FUTEX_WAKE_OP:
      while(futex_hash_table[hv].key != (uint64_t)uaddr){
          hv++;
          hv %= FUTEX_HT_SIZE;
          if(hv == s_head) return 0; // ? No such key, wake no one
      }

      while(futex_hash_table[hv2].key != (uint64_t)uaddr2){
          hv2++;
          hv2 %= FUTEX_HT_SIZE;
          if(hv2 == s_head) return 0; // ? No such key, wake no one
      }

      int32_t oparg = FUTEX_GET_OPARG(val3);
      if(FUTEX_GET_OP(val3) & FUTEX_OP_ARG_SHIFT)
          if(oparg < 0 || oparg > 31)
              oparg &= 31;
          oparg <<= 1;

      flags = enter_critical_section();

      int32_t oldval = *(int *) uaddr2;
      switch(FUTEX_GET_OP(val3)) {
          case FUTEX_OP_SET:
              *(volatile int *) uaddr2 = oparg;
              break;
          case FUTEX_OP_ADD:
              *(volatile int *) uaddr2 += oparg;
              break;
          case FUTEX_OP_OR:
              *(volatile int *) uaddr2 |= oparg;
              break;
          case FUTEX_OP_ANDN:
              *(volatile int *) uaddr2 &= ~oparg;
              break;
          case FUTEX_OP_XOR:
              *(volatile int *) uaddr2 ^= oparg;
              break;
      }

      ret = tux_futex(nbr, uaddr, FUTEX_WAKE, val, 0, 0, 0);

      int cmpflag = 0;
      switch(FUTEX_GET_CMP(val3)) {
          case FUTEX_OP_CMP_EQ:
              cmpflag = (oldval == FUTEX_GET_CMPARG(val3));
              break;
          case FUTEX_OP_CMP_NE:
              cmpflag = (oldval != FUTEX_GET_CMPARG(val3));
              break;
          case FUTEX_OP_CMP_LT:
              cmpflag = (oldval < FUTEX_GET_CMPARG(val3));
              break;
          case FUTEX_OP_CMP_LE:
              cmpflag = (oldval <= FUTEX_GET_CMPARG(val3));
              break;
          case FUTEX_OP_CMP_GT:
              cmpflag = (oldval > FUTEX_GET_CMPARG(val3));
              break;
          case FUTEX_OP_CMP_GE:
              cmpflag = (oldval >= FUTEX_GET_CMPARG(val3));
              break;
      }
      if(cmpflag)
          ret += tux_futex(nbr, uaddr2, FUTEX_WAKE, val2, 0, 0, 0);
      leave_critical_section(flags);

      return ret;

      break;
    default:
      _info("Futex got unfriendly opcode: %d\n", opcode);
      PANIC();
    }
}

