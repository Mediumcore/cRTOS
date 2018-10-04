/****************************************************************************
 * arch/x86_64/src/jailhouse/jailhouse_tickless.c
 *
 *   Copyright (C) 2014 Gregory Nutt. All rights reserved.
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
 * Tickless OS Support.
 *
 * When CONFIG_SCHED_TICKLESS is enabled, all support for timer interrupts
 * is suppressed and the platform specific code is expected to provide the
 * following custom functions.
 *
 *   void sim_timer_initialize(void): Initializes the timer facilities.  Called
 *     early in the intialization sequence (by up_intialize()).
 *   int up_timer_gettime(FAR struct timespec *ts):  Returns the current
 *     time from the platform specific time source.
 *   int up_timer_cancel(void):  Cancels the interval timer.
 *   int up_timer_start(FAR const struct timespec *ts): Start (or re-starts)
 *     the interval timer.
 *
 * The RTOS will provide the following interfaces for use by the platform-
 * specific interval timer implementation:
 *
 *   void sched_timer_expiration(void):  Called by the platform-specific
 *     logic when the interval timer expires.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include <nuttx/arch.h>
#include <nuttx/clock.h>

#ifdef CONFIG_SCHED_TICKLESS
#ifdef CONFIG_SCHED_TICKLESS_ALARM

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

static unsigned long tsc_freq;

static struct timespec g_goal_time;
static uint64_t g_start_tsc;
static bool g_alarm_active;
static bool tsc_deadline;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

void up_alarm_expire(void);

/****************************************************************************
 * Name: x86_64_timer_initialize
 *
 * Description:
 *   Initializes all platform-specific timer facilities.  This function is
 *   called early in the initialization sequence by up_intialize().
 *   On return, the current up-time should be available from
 *   up_timer_gettime() and the interval timer is ready for use (but not
 *   actively timing.
 *
 *   Provided by platform-specific code and called from the architecture-
 *   specific logic.
 *
 * Input Parameters:
 *   None
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   Called early in the initialization sequence before any special
 *   concurrency protections are required.
 *
 ****************************************************************************/

void x86_64_timer_initialize(void)
{
  unsigned long ecx;

  (void)irq_attach(IRQ0, (xcpt_t)up_alarm_expire, NULL);

  asm volatile("cpuid" : "=c" (ecx) : "a" (1)
      : "rbx", "rdx", "memory");
  tsc_deadline = !!(ecx & (1 << 24));

  if (tsc_deadline) {
      tsc_freq = comm_region->tsc_khz * 1000L;
  } else {
      PANIC();
  }

  g_start_tsc = rdtsc();

  /* Enable TSC Deadline interrupt */
  write_msr(X2APIC_LVTT, IRQ0 | LVTT_TSC_DEADLINE);
  /* Required when using TSC deadline mode. */
  asm volatile("mfence" : : : "memory");

  return;
}

/****************************************************************************
 * Name: up_timer_gettime
 *
 * Description:
 *   Return the elapsed time since power-up (or, more correctly, since
 *   sim_timer_initialize() was called).  This function is functionally
 *   equivalent to:
 *
 *      int clock_gettime(clockid_t clockid, FAR struct timespec *ts);
 *
 *   when clockid is CLOCK_MONOTONIC.
 *
 *   This function provides the basis for reporting the current time and
 *   also is used to eliminate error build-up from small erros in interval
 *   time calculations.
 *
 *   Provided by platform-specific code and called from the RTOS base code.
 *
 * Input Parameters:
 *   ts - Provides the location in which to return the up-time.
 *
 * Returned Value:
 *   Zero (OK) is returned on success; a negated errno value is returned on
 *   any failure.
 *
 * Assumptions:
 *   Called from the normal tasking context.  The implementation must
 *   provide whatever mutual exclusion is necessary for correct operation.
 *   This can include disabling interrupts in order to assure atomic register
 *   operations.
 *
 ****************************************************************************/

int up_timer_gettime(FAR struct timespec *ts)
{
  uint64_t diff = (rdtsc() - g_start_tsc);
  ts->tv_sec  = (diff / tsc_freq);
  ts->tv_nsec = (diff - (ts->tv_sec) * tsc_freq) * NSEC_PER_SEC / tsc_freq;
  return OK;
}

/****************************************************************************
 * Name: up_timer_cancel
 *
 * Description:
 *   Cancel the interval timer and return the time remaining on the timer.
 *   These two steps need to be as nearly atomic as possible.
 *   sched_timer_expiration() will not be called unless the timer is
 *   restarted with up_timer_start().
 *
 *   If, as a race condition, the timer has already expired when this
 *   function is called, then that pending interrupt must be cleared so
 *   that up_timer_start() and the remaining time of zero should be
 *   returned.
 *
 *   Provided by platform-specific code and called from the RTOS base code.
 *
 * Input Parameters:
 *   ts - Location to return the remaining time.  Zero should be returned
 *        if the timer is not active.
 *
 * Returned Value:
 *   Zero (OK) is returned on success; a negated errno value is returned on
 *   any failure.
 *
 * Assumptions:
 *   May be called from interrupt level handling or from the normal tasking
 *   level.  Interrupts may need to be disabled internally to assure
 *   non-reentrancy.
 *
 ****************************************************************************/

int up_alarm_cancel(FAR struct timespec *ts)
{
  irqstate_t flags = enter_critical_section();

  g_alarm_active           = false;

  write_msr(IA32_TSC_DEADLINE, UINT64_MAX);

  tmrinfo("alarm canceled\n");
  if (ts != NULL){
    if (g_alarm_active)
    {
      ts->tv_sec  = g_goal_time.tv_sec;
      ts->tv_nsec = g_goal_time.tv_nsec;
    }
    else
    {
      ts->tv_sec  = 0;
      ts->tv_nsec = 0;
      }
  }

  leave_critical_section(flags);

  return OK;
}

/****************************************************************************
 * Name: up_timer_start
 *
 * Description:
 *   Start the interval timer.  sched_timer_expiration() will be
 *   called at the completion of the timeout (unless up_timer_cancel
 *   is called to stop the timing.
 *
 *   Provided by platform-specific code and called from the RTOS base code.
 *
 * Input Parameters:
 *   ts - Provides the time interval until sched_timer_expiration() is
 *        called.
 *
 * Returned Value:
 *   Zero (OK) is returned on success; a negated errno value is returned on
 *   any failure.
 *
 * Assumptions:
 *   May be called from interrupt level handling or from the normal tasking
 *   level.  Interrupts may need to be disabled internally to assure
 *   non-reentrancy.
 *
 ****************************************************************************/

int up_alarm_start(FAR const struct timespec *ts)
{
  irqstate_t flags = enter_critical_section();
  unsigned long long ticks =
    (unsigned long long)ts->tv_nsec * tsc_freq / NS_PER_SEC + ts->tv_sec * tsc_freq;
  tmrinfo("alarm started: %llu\n", ticks);
  g_alarm_active           = true;

  write_msr(IA32_TSC_DEADLINE, (ticks + rdtsc()));

  g_goal_time.tv_sec = ts->tv_sec;
  g_goal_time.tv_nsec = ts->tv_nsec;

  leave_critical_section(flags);
  return OK;
}

/****************************************************************************
 * Name: up_timer_update
 *
 * Description:
 *   Called as the IRQ handler for alarm expiration.
 *
 * Input Parameters:
 *   None
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void up_alarm_expire(void)
{
  struct timespec now;
  tmrinfo("alarm expired\n");

  g_alarm_active = false;

  up_timer_gettime(&now);

  sched_alarm_expiration(&now);

  return;
}

#endif /* CONFIG_SCHED_TICKLESS_ALARM */
#endif /* CONFIG_SCHED_TICKLESS */
