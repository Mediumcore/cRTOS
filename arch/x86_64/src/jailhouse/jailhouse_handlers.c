/****************************************************************************
 *  arch/x86_64/src/jailhouse/jailhouse_handlers.c
 *
 *   Copyright (C) 2011-2012, 2014-2015 Gregory Nutt. All rights reserved.
 *   Author: Gregory Nutt <gnutt@nuttx.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <nuttx/arch.h>
#include <nuttx/board.h>
#include <arch/io.h>
#include <syscall.h>

#include "up_internal.h"

uint64_t g_latency_trace[8];

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/
#define X2APIC_EOI		0x80b

#define APIC_EOI_ACK		0

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static void idt_outb(uint8_t val, uint16_t addr) noinline_function;

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: idt_outb
 *
 * Description:
 *   A slightly slower version of outb
 *
 ****************************************************************************/

static void idt_outb(uint8_t val, uint16_t addr)
{
  outb(val, addr);
}

/****************************************************************************
 * Name: common_handler
 *
 * Description:
 *   Common logic for the ISR/IRQ handlers
 *
 ****************************************************************************/

#ifndef CONFIG_SUPPRESS_INTERRUPTS
static uint64_t *common_handler(int irq, uint64_t *regs)
{
  board_autoled_on(LED_INIRQ);

  /* Current regs non-zero indicates that we are processing an interrupt;
   * g_current_regs is also used to manage interrupt level context switches.
   *
   * Nested interrupts are not supported.
   */

  DEBUGASSERT(g_current_regs == NULL);
  g_current_regs = regs;

  /* Deliver the IRQ */

  irq_dispatch(irq, regs);

#if defined(CONFIG_ARCH_FPU) || defined(CONFIG_ARCH_ADDRENV)
  /* Check for a context switch.  If a context switch occurred, then
   * g_current_regs will have a different value than it did on entry.  If an
   * interrupt level context switch has occurred, then restore the floating
   * point state and the establish the correct address environment before
   * returning from the interrupt.
   */

  if (regs != g_current_regs)
    {
#ifdef CONFIG_ARCH_FPU
      /* Restore floating point registers */

      up_restorefpu((uint64_t*)g_current_regs);
#endif

#ifdef CONFIG_ARCH_ADDRENV
      /* Make sure that the address environment for the previously
       * running task is closed down gracefully (data caches dump,
       * MMU flushed) and set up the address environment for the new
       * thread at the head of the ready-to-run list.
       */

      (void)group_addrenv(NULL);
#endif
    }
#endif

  /* If a context switch occurred while processing the interrupt then
   * g_current_regs may have change value.  If we return any value different
   * from the input regs, then the lower level will know that a context
   * switch occurred during interrupt processing.
   */

  regs = (uint64_t*)g_current_regs;

  /* Set g_current_regs to NULL to indicate that we are no longer in an
   * interrupt handler.
   */

  g_current_regs = NULL;
  return regs;
}
#endif

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: isr_handler
 *
 * Description:
 *   This gets called from ISR vector handling logic in jailhouse_vectors.S
 *
 ****************************************************************************/

uint64_t *isr_handler(uint64_t *regs, uint64_t irq)
{
#ifdef CONFIG_SUPPRESS_INTERRUPTS
  board_autoled_on(LED_INIRQ);
  PANIC(); /* Doesn't return */
  return regs;               /* To keep the compiler happy */
#else
  uint64_t *ret;
  int i, j;
  uint64_t mxcsr;
  uint64_t rbp;
  asm volatile ("stmxcsr %0"::"m"(mxcsr):"memory");
  printf("----------------CUT HERE-----------------\n");
  printf("PANIC:\n");
  printf("Exception %lld occurred with error code %lld:\n", irq, regs[REG_ERRCODE]);
  printf("Gerneral Informations:\n");
  printf("CPL: %d, RPL: %d\n", regs[REG_CS] & 0x3, regs[REG_DS] & 0x3);
  printf("RIP: %016llx, RSP: %016llx\n", regs[REG_RIP], regs[REG_RSP]);
  printf("RBP: %016llx, RFLAGS: %016llx\n", regs[REG_RBP], regs[REG_RFLAGS]);
  printf("MSR_STAR: %016llx, MSR_LSTAR: %016llx\n", read_msr(0xc0000081), read_msr(0xc0000082));
  printf("MXCSR: %016llx\n", mxcsr);
  printf("Selector Dump:\n");
  printf("CS: %016llx, DS: %016llx, SS: %016llx\n", regs[REG_CS], regs[REG_DS], regs[REG_SS]);
  printf("Register Dump:\n");
  printf("RAX: %016llx, RBX: %016llx\n", regs[REG_RAX], regs[REG_RBX]);
  printf("RCX: %016llx, RDX: %016llx\n", regs[REG_RCX], regs[REG_RDX]);
  printf("RDI: %016llx, RSI: %016llx\n", regs[REG_RDI], regs[REG_RSI]);
  printf("Stack Dump (64 bytes):\n");
  for(i = 0; i < 8; i++){
    for(j = 0; j < 8; j++){
      printf("%02x ", *((uint8_t*)(regs[REG_RSP] + i * 8 + j)));
    }
    printf("  %016llx ", *((uint64_t*)(regs[REG_RSP] + i * 8)));
    printf("\n");
  }
  printf("Frame Dump (64 bytes):\n");
  rbp = regs[REG_RBP];
  for(i = 0; i < 8; i++){
    printf("  %016llx ", *((uint64_t*)(rbp)));
    printf("  %016llx ", *((uint64_t*)(rbp + 1 * 8)));
    printf("\n");
    if(rbp)
        rbp = *(uint64_t*)rbp;
    else
        break;
  }
  printf("-----------------------------------------\n");

  /*asm("mov $1300, %%eax;vmcall;":::"eax");*/
  asm("mov $0, %%al":::);
  asm("mov $0xfa, %%dx":::);
  asm("out %%al, (%%dx)":::);

  /* Dispatch the interrupt */

  board_autoled_on(LED_INIRQ);
  ret = common_handler((int)irq, regs);
  board_autoled_off(LED_INIRQ);
  return ret;
#endif
}

/****************************************************************************
 * Name: isr_handler
 *
 * Description:
 *   This gets called from IRQ vector handling logic in jailhouse_vectors.S
 *
 ****************************************************************************/

uint64_t *irq_handler(uint64_t *regs, uint64_t irq_no)
{
#ifdef CONFIG_SUPPRESS_INTERRUPTS
  board_autoled_on(LED_INIRQ);
  PANIC(); /* Doesn't return */
  return regs;               /* To keep the compiler happy */
#else
  uint64_t *ret;
  int irq;

  board_autoled_on(LED_INIRQ);

  /* Get the IRQ number */
  irq = (int)irq_no;

  /*g_latency_trace[0] = _rdtsc();*/

  /* Dispatch the interrupt */
  ret = common_handler(irq, regs);

  /* Send an EOI (end of interrupt) signal to the APIC */
  write_msr(X2APIC_EOI, APIC_EOI_ACK);
  board_autoled_off(LED_INIRQ);
  return ret;
#endif
}

/****************************************************************************
 * Name: syscall_handler
 *
 * Description:
 *   syscall fast calling interface will go here
 *
 ****************************************************************************/

#ifdef CONFIG_LIB_SYSCALL
uint64_t syscall_handler(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  uint64_t ret;

  svcinfo("SYSCALL Entry: cmd: %lld\n", nbr);
  svcinfo("  PARAM: %016llx %016llx %016llx\n",
          parm1,  parm2,  parm3);
  svcinfo("       : %016llx %016llx %016llx\n",
          parm4,  parm5,  parm6);

  /* Verify that the SYS call number is within range */

  DEBUGASSERT(cmd >= CONFIG_SYS_RESERVED && cmd < SYS_maxsyscall);

  /* Call syscall from table. */
  nbr -= CONFIG_SYS_RESERVED;
  ret = ((uint64_t(*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t))(g_stublookup + nbr))(parm1, parm2, parm3, parm4, parm5, parm6);

  return ret;
}
#else
uint64_t syscall_handler(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
    return 0;
}

#endif
