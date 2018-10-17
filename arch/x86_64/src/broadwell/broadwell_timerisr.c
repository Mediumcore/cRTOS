/****************************************************************************
 * arch/x86/src/broadwell/broadwell_timerisr.c
 *
 *   Copyright (C) 2011, 2017 Gregory Nutt. All rights reserved.
 *   Author: Gregory Nutt <gnutt@nuttx.org>
 *
 *   Based on Bran's kernel development tutorials. Rewritten for JamesM's
 *   kernel development tutorials.
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

#include <stdint.h>
#include <time.h>
#include <debug.h>

#include <nuttx/arch.h>
#include <arch/irq.h>
#include <arch/io.h>
#include <arch/board/board.h>

#include "clock/clock.h"
#include "up_internal.h"
#include "up_arch.h"

#include <stdio.h>

#include "chip.h"
#include "broadwell.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/
#define NS_PER_USEC		1000UL
#define NS_PER_MSEC		1000000UL
#define NS_PER_SEC		1000000000UL

#define IA32_TSC_DEADLINE	0x6e0

#define X2APIC_LVTT		0x832
#define LVTT_TSC_DEADLINE	(1 << 18)
#define X2APIC_TMICT		0x838
#define X2APIC_TMCCT		0x839
#define X2APIC_TDCR		0x83e

/****************************************************************************
 * Private Data
 ****************************************************************************/

static unsigned long apic_tick_freq;
static unsigned long tsc_freq, tsc_overflow;
static unsigned long tsc_last;
static unsigned long tsc_overflows;
static bool tsc_deadline;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Function:  tsc_init
 *
 * Description:
 *   calculate the TSC frequency from comm region
 *
 ****************************************************************************/

unsigned long tsc_init(void)
{
	tsc_freq = comm_region->tsc_khz * 1000L;
	tsc_overflow = (0x100000000L * NS_PER_SEC) / tsc_freq;

	return tsc_freq;
}


unsigned long tsc_read(void)
{
	unsigned long tmr;

	tmr = ((rdtsc() & 0xffffffffLL) * NS_PER_SEC) / tsc_freq;
	if (tmr < tsc_last)
		tsc_overflows += tsc_overflow;
	tsc_last = tmr;
	return tmr + tsc_overflows;
}

/****************************************************************************
 * Function:  apic_timer_set
 *
 * Description:
 *   Set a time for APIC timer to fire
 *
 ****************************************************************************/

void apic_timer_set(unsigned long timeout_ns)
{
	unsigned long long ticks =
		(unsigned long long)timeout_ns * apic_tick_freq / NS_PER_SEC;
	if (tsc_deadline)
		write_msr(IA32_TSC_DEADLINE, rdtsc() + ticks);
	else
		write_msr(X2APIC_TMICT, ticks);
}

/****************************************************************************
 * Function: broadwell_timerisr
 *
 * Description:
 *   The timer ISR will perform a variety of services for various portions
 *   of the systems.
 *
 ****************************************************************************/
extern uint64_t g_latency_trace[8];

static int broadwell_timerisr(int irq, uint32_t *regs, void *arg)
{
  /* Process timer interrupt */

  /*g_latency_trace[1] = _rdtsc();*/
  switch (comm_region->msg_to_cell) {
  case BROADWELL_MSG_SHUTDOWN_REQUEST:
    comm_region->cell_state = BROADWELL_CELL_SHUT_DOWN;
    for(;;){
      asm("cli");
      asm("hlt");
    }
    break;
  default:
    break;
  }
  /*g_latency_trace[2] = _rdtsc();*/
  sched_process_timer();
  apic_timer_set(CONFIG_USEC_PER_TICK * NS_PER_USEC);
  return 0;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Function:  x86_64_timer_initialize
 *
 * Description:
 *   This function is called during start-up to initialize
 *   the timer interrupt.
 *
 ****************************************************************************/

void x86_64_timer_initialize(void)
{
    unsigned long ecx;
    uint32_t vector = IRQ0;

    (void)irq_attach(IRQ0, (xcpt_t)broadwell_timerisr, NULL);

    asm volatile("cpuid" : "=c" (ecx) : "a" (1)
        : "rbx", "rdx", "memory");
    tsc_deadline = !!(ecx & (1 << 24));

    if (tsc_deadline) {
        vector |= LVTT_TSC_DEADLINE;
        apic_tick_freq = tsc_init();
    } else {
        apic_tick_freq = comm_region->apic_khz * 1000 / 16;
    }

    write_msr(X2APIC_LVTT, vector);

    /* Required when using TSC deadline mode. */
    asm volatile("mfence" : : : "memory");

    apic_timer_set(NS_PER_MSEC);

    return;

  /*[> And enable IRQ0 <]*/

  /*up_enable_irq(IRQ0);*/
}
