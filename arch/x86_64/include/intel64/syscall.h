/****************************************************************************
 * arch/x86_64/include/intel64/syscall.h
 *
 *   Copyright (C) 2011, 2015 Gregory Nutt. All rights reserved.
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

/* This file should never be included directed but, rather, only indirectly
 * through include/syscall.h or include/sys/sycall.h
 */

#ifndef __ARCH_X86_64_INCLUDE_INTEL64_SYSCALL_H
#define __ARCH_X86_64_INCLUDE_INTEL64_SYSCALL_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <stdint.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Public Types
 ****************************************************************************/

/****************************************************************************
 * Public Data
 ****************************************************************************/

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

#ifndef __ASSEMBLY__
#ifdef __cplusplus
#define EXTERN extern "C"
extern "C"
{
#else
#define EXTERN extern
#endif

void enable_syscall(void);
void syscall_entry(void);
uint64_t syscall_handler(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6);

/* SWI with SYS_ call number and six parameters */

static inline uintptr_t sys_call6(unsigned int nbr, uintptr_t parm1, uintptr_t parm2,
                    uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                    uintptr_t parm6);

/* SWI with SYS_ call number and no parameters */

static inline uintptr_t sys_call0(unsigned int nbr)
{
  return sys_call6(nbr, 0, 0, 0, 0, 0, 0);
}

/* SWI with SYS_ call number and one parameter */

static inline uintptr_t sys_call1(unsigned int nbr, uintptr_t parm1)
{
  return sys_call6(nbr, parm1, 0, 0, 0, 0, 0);
}

/* SWI with SYS_ call number and two parameters */

static inline uintptr_t sys_call2(unsigned int nbr, uintptr_t parm1,
                                  uintptr_t parm2)
{
  return sys_call6(nbr, parm1, parm2, 0, 0, 0, 0);
}

/* SWI with SYS_ call number and three parameters */

static inline uintptr_t sys_call3(unsigned int nbr, uintptr_t parm1,
                                  uintptr_t parm2, uintptr_t parm3)
{
  return sys_call6(nbr, parm1, parm2, parm3, 0, 0, 0);
}

/* SWI with SYS_ call number and four parameters */

static inline uintptr_t sys_call4(unsigned int nbr, uintptr_t parm1,
                                  uintptr_t parm2, uintptr_t parm3,
                                  uintptr_t parm4)
{
  return sys_call6(nbr, parm1, parm2, parm3, parm4, 0, 0);
}

/* SWI with SYS_ call number and five parameters */

static inline uintptr_t sys_call5(unsigned int nbr, uintptr_t parm1,
                                  uintptr_t parm2, uintptr_t parm3,
                                  uintptr_t parm4, uintptr_t parm5)
{
  return sys_call6(nbr, parm1, parm2, parm3, parm4, parm5, 0);
}

static inline uintptr_t sys_call6(unsigned int nbr, uintptr_t parm1,
                                  uintptr_t parm2, uintptr_t parm3,
                                  uintptr_t parm4, uintptr_t parm5,
                                  uintptr_t parm6)
{
  register long reg0 __asm__("rax") = (long)(nbr);
  register long reg1 __asm__("rdi") = (long)(parm1);
  register long reg2 __asm__("rsi") = (long)(parm2);
  register long reg3 __asm__("rdx") = (long)(parm3);
  register long reg4 __asm__("r10") = (long)(parm4);
  register long reg5 __asm__("r8") = (long)(parm5);
  register long reg6 __asm__("r9") = (long)(parm6);

  __asm__ __volatile__
  (
    "syscall"
    : "=r"(reg0)
    : "r"(reg0), "r"(reg1), "r"(reg2),
      "r"(reg3), "r"(reg4), "r"(reg5), "r"(reg6)
    : "memory"
  );

  return reg0;
}

#undef EXTERN
#ifdef __cplusplus
}
#endif
#endif

#endif /* __ARCH_X86_64_INCLUDE_INTEL64_SYSCALL_H */

