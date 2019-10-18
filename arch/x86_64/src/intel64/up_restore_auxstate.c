/****************************************************************************
 * arch/x86_64/src/intel64/up_restore_auxstate.c
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

#include <debug.h>

#include <nuttx/arch.h>
#include <nuttx/sched.h>

#include <arch/arch.h>
#include <arch/irq.h>
#include <arch/io.h>

#include "up_internal.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Public Functions
 ****************************************************************************/
/****************************************************************************
 * Name: up_restore_auxstate
 *
 * Description:
 *   This function saves the interrupt level context information in the
 *   TCB.  This would just be a up_copystate.
 *
 ****************************************************************************/

extern uint64_t full_map_pd1[512];

void up_restore_auxstate(struct tcb_s *rtcb)
{
  struct vma_s* ptr;
  uint64_t i, j;

  /* some dirty hack to speed up the switching of full mapping */
  static int cached = 0;

  if(rtcb->xcp.pd1 == NULL){
      if(!cached) {
          for(j = 0, i = 0; i < 0x40000000; i += HUGE_PAGE_SIZE, j += PAGE_SIZE) {
            full_map_pd1[(i >> 21) & 0x7ffffff] = (j + (uint64_t)pt) | 0x3;
          }
          cached = 1;
      }
      pdpt[0] = (uintptr_t)full_map_pd1 | 0x23;
  } else {
    pdpt[0] = (uintptr_t)rtcb->xcp.pd1 | 0x23;
  }


  set_pcid(rtcb->pid);
  if(rtcb->xcp.fs_base_set){
    write_msr(MSR_FS_BASE, rtcb->xcp.fs_base);
  }else{
    write_msr(MSR_FS_BASE, 0x0);
  }

  sinfo("resuming %d\n", rtcb->pid);

}
