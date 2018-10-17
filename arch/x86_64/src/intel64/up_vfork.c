/****************************************************************************
 * arch/mips/src/mips32/up_vfork.c
 *
 *   Copyright (C) 2013 Gregory Nutt. All rights reserved.
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

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <debug.h>

#include <nuttx/sched.h>
#include <nuttx/arch.h>
#include <arch/irq.h>

#include "up_vfork.h"
#include "sched/sched.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

void* page_map[256];

void* find_free_page(struct task_tcb_s * tcb){
    uint64_t i;
    for(i = 1; i < 256; i++){
        if(page_map[i] == NULL){
            page_map[i] = tcb;
            return (void*)(i * 0x4000000);
        }
    }
    return (void*)-1;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_vfork
 *
 * Description:
 *   The vfork() function has the same effect as fork(), except that the
 *   behavior is undefined if the process created by vfork() either modifies
 *   any data other than a variable of type pid_t used to store the return
 *   value from vfork(), or returns from the function in which vfork() was
 *   called, or calls any other function before successfully calling _exit()
 *   or one of the exec family of functions.
 *
 *   The overall sequence is:
 *
 *   1) User code calls vfork().  vfork() collects context information and
 *      transfers control up up_vfork().
 *   2) up_vfork()and calls task_vforksetup().
 *   3) task_vforksetup() allocates and configures the child task's TCB.  This
 *      consists of:
 *      - Allocation of the child task's TCB.
 *      - Initialization of file descriptors and streams
 *      - Configuration of environment variables
 *      - Setup the intput parameters for the task.
 *      - Initialization of the TCB (including call to up_initial_state()
 *   4) up_vfork() provides any additional operating context. up_vfork must:
 *      - Allocate and initialize the stack
 *      - Initialize special values in any CPU registers that were not
 *        already configured by up_initial_state()
 *   5) up_vfork() then calls task_vforkstart()
 *   6) task_vforkstart() then executes the child thread.
 *
 * task_vforkabort() may be called if an error occurs between steps 3 and 6.
 *
 * Input Parameters:
 *   context - Caller context information saved by vfork()
 *
 * Returned Value:
 *   Upon successful completion, vfork() returns 0 to the child process and
 *   returns the process ID of the child process to the parent process.
 *   Otherwise, -1 is returned to the parent, no child process is created,
 *   and errno is set to indicate the error.
 *
 ****************************************************************************/

pid_t up_vfork(const void* context, uint64_t* ret_rip)
{
  struct tcb_s *parent = this_task();
  struct task_tcb_s *child;
  uint64_t new_page_start_address;

  /* Allocate and initialize a TCB for the child task. */
  child = task_vforksetup((void*)*ret_rip);
  if (!child)
    {
      sinfo("task_vforksetup failed\n");
      return (pid_t)ERROR;
    }

  sinfo("Parent=%p Child=%p\n", parent, child);

  /* Find new pages for the task, every task is assumed to be 64MB, 8 pages */
  new_page_start_address = (uint64_t)find_free_page(child);
  if (new_page_start_address == -1)
    {
      sinfo("page exhausted\n");
      return (pid_t)ERROR;
    }

  memset((void*)new_page_start_address, 0, 0x4000000);
  for(int i = 0; i < 32; i++)
    {
      child->cmn.xcp.page_table[i] = (new_page_start_address + 0x200000 * i) | 0x83;
    }

  /* Allocate the stack for the TCB */
  /* the stack will be clear */
  child->cmn.adj_stack_ptr  = (void*)0x4000000; // top of private memory space
  child->cmn.adj_stack_size = 0x800000; // 8MB Linux default stack limit

  /* Update the stack saved registers. When the child TCB was
   * initialized, all of the values were set to zero.
   * up_initial_state() altered a few values, but the
   * return value in rax should be cleared to zero, providing the
   * indication to the newly started child thread.
   */

  // Copy everything
  memcpy(child->cmn.xcp.regs, context, 672);

  child->cmn.xcp.regs[REG_RAX] = 0;
  child->cmn.xcp.regs[REG_RSP] = child->cmn.adj_stack_ptr;

  /* And, finally, start the child task.  On a failure, task_vforkstart()
   * will discard the TCB by calling task_vforkabort().
   */

  return task_vforkstart(child);
}
