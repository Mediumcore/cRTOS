/****************************************************************************
 * arch/x86_64/src/common/up_checktasks.c
 *
 *   Copyright (C) 2011, 2013-2015 Gregory Nutt. All rights reserved.
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

#include <stdbool.h>
#include <sched.h>
#include <debug.h>

#include <nuttx/arch.h>
#include <nuttx/sched.h>

#include "sched/sched.h"
#include "group/group.h"
#include "up_internal.h"

#include <arch/board/shadow.h>

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_checktasks
 *
 * Description:
 *   The currently executing task at the head of the ready to run list must
 *   be stopped.  Save its context and move it to the inactive list specified
 *   by task_state.
 *
 * Input Parameters:
 *   None
 *
 ****************************************************************************/

void up_checktasks(void)
{
  uint64_t buf[3];
  struct tcb_s *rtcb;
  irqstate_t flags;

    return;

  if(!gshadow) return;
  if(!(gshadow->flags & SHADOW_PROC_FLAG_RUN)) return;

  /* the IRQ of shadow process might race with us */
  flags = enter_critical_section();

  while(shadow_proc_rx_avail(gshadow)) {
      shadow_proc_receive(gshadow, buf);

      rtcb = (struct tcb_s *)buf[2];

      shadow_proc_enable_rx_irq(gshadow);

      if(rtcb){
        rtcb->xcp.syscall_ret = buf[0];

        /* The task will be the new holder of the semaphore when
         * it is awakened.
         */
        nxsem_addholder_tcb(rtcb, &rtcb->xcp.syscall_lock);

        /* It is, let the task take the semaphore */
        rtcb->waitsem = NULL;

        sched_removeblocked(rtcb);

        /* Add the task in the correct location in the prioritized
         * ready-to-run task list
         */
        sched_addprioritized(rtcb, (FAR dq_queue_t *)&g_pendingtasks);
        rtcb->task_state = TSTATE_TASK_PENDING;
      }
  }

  leave_critical_section(flags);
}
