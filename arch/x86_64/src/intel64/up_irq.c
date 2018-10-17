/****************************************************************************
 * arch/x86/src/i486/up_irq.c
 * arch/x86/src/chip/up_irq.c
 *
 *   Copyright (C) 2011 Gregory Nutt. All rights reserved.
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

#include <stdint.h>
#include <string.h>
#include <debug.h>

#include <nuttx/irq.h>
#include <nuttx/arch.h>
#include <arch/irq.h>
#include <arch/io.h>

#include "up_arch.h"
#include "up_internal.h"
#include "broadwell.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define X2APIC_SPIV		0x80f

#define IOAPIC_BASE             ((void *)0xfec00000)
#define IOAPIC2_BASE             ((void *)0xfec00000)
#define IOAPIC_REG_INDEX        0x00
#define IOAPIC_REG_DATA         0x10
#define IOAPIC_REDIR_TBL_START  0x10

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static void idt_outb(uint8_t val, uint16_t addr) noinline_function;
static void up_apic_init(void);
static void up_ioapic_init(void);
static void up_idtentry(unsigned int index, uint64_t base, uint16_t sel,
                        uint8_t flags);
static inline void up_idtinit(void);

/****************************************************************************
 * Public Data
 ****************************************************************************/

volatile uint64_t *g_current_regs;

/****************************************************************************
 * Private Data
 ****************************************************************************/

static struct idt_entry_s idt_entries[256];

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
 * Name: up_ioapic_pin_set_vector
 *
 * Description:
 *  Bind a hardware IRQ number to APIC IRQ number
 *
 ****************************************************************************/

void up_ioapic_pin_set_vector(unsigned int pin, enum ioapic_trigger_mode trigger_mode, unsigned int vector)
{
  mmio_write32(IOAPIC_BASE + IOAPIC_REG_INDEX,
    IOAPIC_REDIR_TBL_START + pin * 2 + 1);
  mmio_write32(IOAPIC_BASE + IOAPIC_REG_DATA, cpu_id() << (56 - 32));

  mmio_write32(IOAPIC_BASE + IOAPIC_REG_INDEX,
    IOAPIC_REDIR_TBL_START + pin * 2);
  mmio_write32(IOAPIC_BASE + IOAPIC_REG_DATA, trigger_mode | vector);

}

/****************************************************************************
 * Name: up_init_apic
 *
 * Description:
 *  Initialize the APIC
 *
 ****************************************************************************/

static void up_apic_init(void)
{
  write_msr(X2APIC_SPIV, 0x1ff);
}

/****************************************************************************
 * Name: up_init_ioapic
 *
 * Description:
 *  Initialize the IOAPIC
 *
 ****************************************************************************/

static void up_ioapic_init(void)
{
    // Already initialized the memory map in head.S using assembly
    return;
}

/****************************************************************************
 * Name: up_idtentry
 *
 * Description:
 *   Initialize one IDT entry.
 *
 ****************************************************************************/

static void up_idtentry(unsigned int index, uint64_t base, uint16_t sel,
                       uint8_t flags)
{
  struct idt_entry_s *entry = &idt_entries[index];

  entry->lobase  = base & 0xffff;
  entry->hibase  = (base >> 16) & 0xffff;
  entry->xhibase = (base >> 32) & 0xffffffff;
  entry->ist     = 0 & 0x7;
  entry->sel     = sel;
  entry->zero    = 0;

  /* We must uncomment the OR below when we get to using user-mode. It sets the
   * interrupt gate's privilege level to 3.
   */

  entry->flags  = flags /* | 0x60 */;
}

/****************************************************************************
 * Name: up_idtinit
 *
 * Description:
 *   Initialize the IDT. The Interrupt Descriptor Table (IDT) is a data
 *   structure used by the x86 architecture to implement an interrupt vector
 *   table. The IDT is used by the processor to determine the correct
 *   response to interrupts and exceptions.
 *
 ****************************************************************************/

struct idt_ptr_s idt_ptr;

static inline void up_idtinit(void)
{
  idt_ptr.limit = sizeof(struct idt_entry_s) * NR_IRQS - 1;
  idt_ptr.base  = (uint64_t)&idt_entries;

  memset(&idt_entries, 0, sizeof(struct idt_entry_s)*256);

  /* Set each ISR/IRQ to the appropriate vector with selector=8 and with
   * 32-bit interrupt gate.  Interrupt gate (vs. trap gate) will leave
   * interrupts enabled when the IRS/IRQ handler is entered.
   */

  up_idtentry(ISR0,  (uint64_t)vector_isr0 , 0x08, 0x8e);
  up_idtentry(ISR1,  (uint64_t)vector_isr1 , 0x08, 0x8e);
  up_idtentry(ISR2,  (uint64_t)vector_isr2 , 0x08, 0x8e);
  up_idtentry(ISR3,  (uint64_t)vector_isr3 , 0x08, 0x8e);
  up_idtentry(ISR4,  (uint64_t)vector_isr4 , 0x08, 0x8e);
  up_idtentry(ISR5,  (uint64_t)vector_isr5 , 0x08, 0x8e);
  up_idtentry(ISR6,  (uint64_t)vector_isr6 , 0x08, 0x8e);
  up_idtentry(ISR7,  (uint64_t)vector_isr7 , 0x08, 0x8e);
  up_idtentry(ISR8,  (uint64_t)vector_isr8 , 0x08, 0x8e);
  up_idtentry(ISR9,  (uint64_t)vector_isr9 , 0x08, 0x8e);
  up_idtentry(ISR10, (uint64_t)vector_isr10, 0x08, 0x8e);
  up_idtentry(ISR11, (uint64_t)vector_isr11, 0x08, 0x8e);
  up_idtentry(ISR12, (uint64_t)vector_isr12, 0x08, 0x8e);
  up_idtentry(ISR13, (uint64_t)vector_isr13, 0x08, 0x8e);
  up_idtentry(ISR14, (uint64_t)vector_isr14, 0x08, 0x8e);
  up_idtentry(ISR15, (uint64_t)vector_isr15, 0x08, 0x8e);
  up_idtentry(ISR16, (uint64_t)vector_isr16, 0x08, 0x8e);
  up_idtentry(ISR17, (uint64_t)vector_isr17, 0x08, 0x8e);
  up_idtentry(ISR18, (uint64_t)vector_isr18, 0x08, 0x8e);
  up_idtentry(ISR19, (uint64_t)vector_isr19, 0x08, 0x8e);
  up_idtentry(ISR20, (uint64_t)vector_isr20, 0x08, 0x8e);
  up_idtentry(ISR21, (uint64_t)vector_isr21, 0x08, 0x8e);
  up_idtentry(ISR22, (uint64_t)vector_isr22, 0x08, 0x8e);
  up_idtentry(ISR23, (uint64_t)vector_isr23, 0x08, 0x8e);
  up_idtentry(ISR24, (uint64_t)vector_isr24, 0x08, 0x8e);
  up_idtentry(ISR25, (uint64_t)vector_isr25, 0x08, 0x8e);
  up_idtentry(ISR26, (uint64_t)vector_isr26, 0x08, 0x8e);
  up_idtentry(ISR27, (uint64_t)vector_isr27, 0x08, 0x8e);
  up_idtentry(ISR28, (uint64_t)vector_isr28, 0x08, 0x8e);
  up_idtentry(ISR29, (uint64_t)vector_isr29, 0x08, 0x8e);
  up_idtentry(ISR30, (uint64_t)vector_isr30, 0x08, 0x8e);
  up_idtentry(ISR31, (uint64_t)vector_isr31, 0x08, 0x8e);

  up_idtentry(IRQ0,  (uint64_t)vector_irq0,  0x08, 0x8e);
  up_idtentry(IRQ1,  (uint64_t)vector_irq1,  0x08, 0x8e);
  up_idtentry(IRQ2,  (uint64_t)vector_irq2,  0x08, 0x8e);
  up_idtentry(IRQ3,  (uint64_t)vector_irq3,  0x08, 0x8e);
  up_idtentry(IRQ4,  (uint64_t)vector_irq4,  0x08, 0x8e);
  up_idtentry(IRQ5,  (uint64_t)vector_irq5,  0x08, 0x8e);
  up_idtentry(IRQ6,  (uint64_t)vector_irq6,  0x08, 0x8e);
  up_idtentry(IRQ7,  (uint64_t)vector_irq7,  0x08, 0x8e);
  up_idtentry(IRQ8,  (uint64_t)vector_irq8,  0x08, 0x8e);
  up_idtentry(IRQ9,  (uint64_t)vector_irq9,  0x08, 0x8e);
  up_idtentry(IRQ10, (uint64_t)vector_irq10, 0x08, 0x8e);
  up_idtentry(IRQ11, (uint64_t)vector_irq11, 0x08, 0x8e);
  up_idtentry(IRQ12, (uint64_t)vector_irq12, 0x08, 0x8e);
  up_idtentry(IRQ13, (uint64_t)vector_irq13, 0x08, 0x8e);
  up_idtentry(IRQ14, (uint64_t)vector_irq14, 0x08, 0x8e);
  up_idtentry(IRQ15, (uint64_t)vector_irq15, 0x08, 0x8e);

  /* Then program the IDT */

  idt_flush((uint64_t)&idt_ptr);
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_irqinitialize
 ****************************************************************************/

void up_irqinitialize(void)
{
  /* currents_regs is non-NULL only while processing an interrupt */

  g_current_regs = NULL;

  /* Initialize the APIC */

  up_apic_init();

  /* Initialize the IOAPIC */

  up_ioapic_init();

  /* Initialize the IDT */

  up_idtinit();

  /* And finally, enable interrupts */

#ifndef CONFIG_SUPPRESS_INTERRUPTS
  up_irq_restore(X86_64_RFLAGS_IF);
#endif
}

/****************************************************************************
 * Name: up_disable_irq
 *
 * Description:
 *   Disable the IRQ line specified by 'irq'
 *
 ****************************************************************************/

void up_disable_irq(int irq)
{
}

/****************************************************************************
 * Name: up_enable_irq
 *
 * Description:
 *   Enable the IRQ line specified by 'irq'
 *
 ****************************************************************************/

void up_enable_irq(int irq)
{
}

/****************************************************************************
 * Name: up_prioritize_irq
 *
 * Description:
 *   Set the priority of an IRQ.
 *
 *   Since this API is not supported on all architectures, it should be
 *   avoided in common implementations where possible.
 *
 ****************************************************************************/

#ifdef CONFIG_ARCH_IRQPRIO
int up_prioritize_irq(int irq, int priority)
{
#warning "Missing Logic"
  return OK;
}
#endif
