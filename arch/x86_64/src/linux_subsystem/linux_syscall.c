/****************************************************************************
 *  arch/x86_64/src/broadwell/broadwell_linux_subsystem.c
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
#include <nuttx/sched.h>
#include <nuttx/board.h>
#include <nuttx/irq.h>
#include <arch/io.h>
#include <syscall.h>
#include <semaphore.h>
#include <errno.h>

#include "up_internal.h"
#include "sched/sched.h"

#include "tux.h"
#include "tux_syscall_table.h"

#ifdef CONFIG_LIB_SYSCALL

/****************************************************************************
 * Private Functions
 ****************************************************************************/

uint64_t linux_interface(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  uint64_t ret;

  svcinfo("Linux Subsystem call: %d, %d\n", nbr, linux_syscall_table[nbr]);

  /* Call syscall from table. */
  if(linux_syscall_table[nbr] == -1){
    ret = -1;
    _alert("Not implemented Linux syscall %d\n", nbr);
    PANIC();
  }else if(linux_syscall_table[nbr] >= SYS_maxsyscall){ // XXX: hacky way to check if the content is address
    ret = ((uint64_t(*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t)) \
          (linux_syscall_table[nbr])) \
          (parm1, parm2, parm3, parm4, parm5, parm6);
  }else{
    ret = ((uint64_t(*)(unsigned long, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t)) \
          (g_stublookup[linux_syscall_table[nbr] - CONFIG_SYS_RESERVED])) \
          (linux_syscall_table[nbr] - CONFIG_SYS_RESERVED, parm1, parm2, parm3, parm4, parm5, parm6);
  }

  return ret;
}


#endif
