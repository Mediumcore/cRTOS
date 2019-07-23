/****************************************************************************
 * arch/x86_64/src/intel64/up_schedulesigaction.c
 *
 *   Copyright (C) 2011, 2015-2016 Gregory Nutt. All rights reserved.
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
#include <sched.h>
#include <debug.h>

#include <nuttx/irq.h>
#include <nuttx/arch.h>

#include "sched/sched.h"
#include "up_internal.h"
#include "up_arch.h"

#ifndef CONFIG_DISABLE_SIGNALS

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
 * Name: up_schedule_sigaction
 *
 * Description:
 *   This function is called by the OS when one or more signal handling
 *   actions have been queued for execution.  The architecture specific code
 *   must configure things so that the 'sigdeliver' callback is executed on
 *   the thread specified by 'tcb' as soon as possible.
 *
 *   This function may be called from interrupt handling logic.
 *
 *   This operation should not cause the task to be unblocked nor should it
 *   cause any immediate execution of sigdeliver. Typically, a few cases need
 *   to be considered:
 *
 *   (1) This function may be called from an interrupt handler. During
 *       interrupt processing, all xcptcontext structures should be valid for
 *       all tasks.  That structure should be modified to invoke sigdeliver()
 *       either on return from (this) interrupt or on some subsequent context
 *       switch to the recipient task.
 *   (2) If not in an interrupt handler and the tcb is NOT the currently
 *       executing task, then again just modify the saved xcptcontext
 *       structure for the recipient task so it will invoke sigdeliver when
 *       that task is later resumed.
 *   (3) If not in an interrupt handler and the tcb IS the currently
 *       executing task -- just call the signal handler now.
 *
 ****************************************************************************/

void up_schedule_sigaction(struct tcb_s *tcb, sig_deliver_t sigdeliver)
{
  irqstate_t flags;
  uint64_t curr_rsp, new_rsp, kstack;

  sinfo("tcb=0x%p sigdeliver=0x%p\n", tcb, sigdeliver);

  /* Make sure that interrupts are disabled */

  flags = enter_critical_section();

  /* Refuse to handle nested signal actions */

  if (!tcb->xcp.sigdeliver)
    {
      /* First, handle some special cases when the signal is being delivered
       * to the currently executing task.
       */

      sinfo("rtcb=0x%p g_current_regs=0x%p\n", this_task(), g_current_regs);

      if (tcb == this_task())
        {
          /* CASE 1:  We are not in an interrupt handler and a task is
           * signalling itself for some reason.
           */

          if (!g_current_regs)
            {
              /* In this case just deliver the signal with a function call now. */

                if(tcb->xcp.is_linux) {

                  /* possible BUG, if the compiler use rsp to address local varible, we are doomed */
                  asm volatile("mov %%rsp, %0":"=m"(curr_rsp));

                  /* 1. move to the user stack */
                  /* 2. if currently in kernel stack, we need to prevent an overwrite */
                  /* 3. if signal stack is set use it instead */
                  kstack = (uint64_t)tcb->adj_stack_ptr;
                  if((curr_rsp < kstack) && (curr_rsp > kstack - tcb->adj_stack_size)) {
                      tcb->xcp.saved_rsp = curr_rsp;
                      tcb->xcp.saved_kstack = kstack;
                      tcb->adj_stack_ptr = (void*)(curr_rsp - 8);

                      if(tcb->xcp.signal_stack_flag) { // SS_DISABLE
                          new_rsp = *((uint64_t*)kstack - 1) - 8; // Read out the user stack address
                      } else {
                          tcb->xcp.signal_stack_flag = 1;
                          new_rsp =  (tcb->xcp.signal_stack + tcb->xcp.signal_stack_size) & (-0x10);
                      }

                      asm volatile("mov %%rsp, %%r12   \t\n\
                                    mov %0, %%rsp    \t\n\
                                    mov %1, %%rdi    \t\n\
                                    call *%2  \t\n\
                                    mov %%r12, %%rsp"::"g"(new_rsp), "g"(tcb), "g"(sigdeliver):"r12","rdi");

                      if(tcb->xcp.signal_stack_flag == 1)
                          tcb->xcp.signal_stack_flag = 0;

                      tcb->adj_stack_ptr = (void*)tcb->xcp.saved_kstack;
                      tcb->xcp.saved_rsp = 0;
                      tcb->xcp.saved_kstack = 0;
                  }else{
                      if(tcb->xcp.signal_stack_flag) { // SS_DISABLE
                          sigdeliver(tcb);
                      } else {
                          new_rsp =  (tcb->xcp.signal_stack + tcb->xcp.signal_stack_size) & (-0x10);
                          tcb->xcp.signal_stack_flag = 1;
                          asm volatile("mov %%rsp, %%r12   \t\n\
                                        mov %0, %%rsp    \t\n\
                                        mov %1, %%rdi    \t\n\
                                        call *%2  \t\n\
                                        mov %%r12, %%rsp"::"g"(new_rsp), "g"(tcb), "g"(sigdeliver):"r12","rdi");
                          tcb->xcp.signal_stack_flag = 0;
                      }
                  }
                } else {
                  sigdeliver(tcb);
                }
            }

          /* CASE 2:  We are in an interrupt handler AND the interrupted task
           * is the same as the one that must receive the signal, then we will
           * have to modify the return state as well as the state in the TCB.
           *
           * Hmmm... there looks like a latent bug here: The following logic
           * would fail in the strange case where we are in an interrupt
           * handler, the thread is signalling itself, but a context switch to
           * another task has occurred so that g_current_regs does not refer to
           * the thread of this_task()!
           */

          else
            {
              /* Save the return lr and cpsr and one scratch register. These
               * will be restored by the signal trampoline after the signals
               * have been delivered.
               */

              tcb->xcp.sigdeliver       = sigdeliver;
              tcb->xcp.saved_rip        = g_current_regs[REG_RIP];
              tcb->xcp.saved_rflags     = g_current_regs[REG_RFLAGS];

              if(tcb->xcp.is_linux) {
                  /* 1. move to the user stack */
                  /* 2. if currently in kernel stack, we need to prevent an overwrite */
                  /* 3. if signal stack is set use it instead */
                  kstack = (uint64_t)tcb->adj_stack_ptr;
                  curr_rsp = g_current_regs[REG_RSP];

                  if((g_current_regs[REG_RSP] < kstack) && (g_current_regs[REG_RSP] > kstack - tcb->adj_stack_size)) {
                      tcb->xcp.saved_rsp = curr_rsp;
                      tcb->xcp.saved_kstack = kstack;

                      tcb->adj_stack_ptr = (void*)(curr_rsp - 8);
                      g_current_regs[REG_RSP] = *((uint64_t*)kstack - 1) - 8; // Read out the user stack address
                  }

                  if(!tcb->xcp.signal_stack_flag) { // !SS_DISABLE
                      tcb->xcp.saved_rsp = curr_rsp;

                      tcb->xcp.signal_stack_flag = 1;
                      g_current_regs[REG_RSP] =  (tcb->xcp.signal_stack + tcb->xcp.signal_stack_size) & (-0x10);
                  }
              }

              /* Then set up to vector to the trampoline with interrupts
               * disabled
               */

              g_current_regs[REG_RIP]     = (uint64_t)up_sigdeliver;
              g_current_regs[REG_RFLAGS]  = 0;

              /* And make sure that the saved context in the TCB
               * is the same as the interrupt return context.
               */

              up_savestate(tcb->xcp.regs);
            }
        }

      /* Otherwise, we are (1) signaling a task is not running
       * from an interrupt handler or (2) we are not in an
       * interrupt handler and the running task is signalling
       * some non-running task.
       */

      else
        {
          /* Save the return lr and cpsr and one scratch register
           * These will be restored by the signal trampoline after
           * the signals have been delivered.
           */

          tcb->xcp.sigdeliver       = sigdeliver;
          tcb->xcp.saved_rip        = tcb->xcp.regs[REG_RIP];
          tcb->xcp.saved_rflags     = tcb->xcp.regs[REG_RFLAGS];

          if(tcb->xcp.is_linux) {

              /* move to the user stack */
              /* if in kernel stack, we need to prevent an overwrite*/
              kstack = (uint64_t)tcb->adj_stack_ptr;
              curr_rsp = g_current_regs[REG_RSP];

              if((tcb->xcp.regs[REG_RSP] < kstack) && (tcb->xcp.regs[REG_RSP] > kstack - tcb->adj_stack_size) && tcb->xcp.is_linux) {

                  /* preserve the values */
                  tcb->xcp.saved_rsp = curr_rsp;
                  tcb->xcp.saved_kstack = kstack;

                  /* Move to User Stack */
                  tcb->xcp.regs[REG_RSP] = *((uint64_t*)kstack - 1) - 8; // Read out the user stack address

                  /* move the kstack starting point to somewhere unused */
                  tcb->adj_stack_ptr = (void*)(curr_rsp - 8);
              }

              if(!tcb->xcp.signal_stack_flag) { // !SS_DISABLE
                  tcb->xcp.saved_rsp = curr_rsp;

                  tcb->xcp.signal_stack_flag = 1;
                  g_current_regs[REG_RSP] =  (tcb->xcp.signal_stack + tcb->xcp.signal_stack_size) & (-0x10);
              }
          }

          /* Then set up to vector to the trampoline with interrupts
           * disabled
           */

          tcb->xcp.regs[REG_RIP]    = (uint64_t)up_sigdeliver;
          tcb->xcp.regs[REG_RFLAGS]  = 0;
        }
    }

  leave_critical_section(flags);
}

#endif /* !CONFIG_DISABLE_SIGNALS */
