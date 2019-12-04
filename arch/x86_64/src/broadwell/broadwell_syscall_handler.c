/****************************************************************************
 *  arch/x86_64/src/broadwell/broadwell_syscall.c
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
#include <errno.h>

#include "sched/sched.h"
#include "up_internal.h"

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: syscall_handler
 *
 * Description:
 *   syscall fast calling interface will go here
 *
 ****************************************************************************/

#ifdef CONFIG_LIB_SYSCALL

uint64_t __attribute__ ((noinline))
syscall_handler(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  uint64_t ret;

  svcinfo("SYSCALL Entry nbr: %llu\n", nbr);
  svcinfo("SYSCALL Task: %d SRC: %016llx\n", this_task()->pid, __builtin_return_address(1));
  svcinfo("SYSCALL JMP: %016llx\n", g_stublookup[nbr]);
  svcinfo("  PARAM: %016llx %016llx %016llx\n",
          parm1,  parm2,  parm3);
  svcinfo("       : %016llx %016llx %016llx\n",
          parm4,  parm5,  parm6);
  if(nbr < CONFIG_SYS_RESERVED){
    /* Invork Linux subsystem */
    ret = linux_interface(nbr, parm1, parm2, parm3, parm4, parm5, parm6);
  }else{
    /* Verify that the SYS call number is within range */
    DEBUGASSERT(nbr >= CONFIG_SYS_RESERVED && nbr < SYS_maxsyscall);

    /* Call syscall from table. */
    nbr -= CONFIG_SYS_RESERVED;
    ret = ((uint64_t(*)(unsigned long, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t))(g_stublookup[nbr]))(nbr, parm1, parm2, parm3, parm4, parm5, parm6);
  }

  svcinfo("END SYSCALL %d Task: %d ret:%llx\n", nbr, this_task()->pid, ret);

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
