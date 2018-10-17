/****************************************************************************
 * arch/x86_64/src/broadwell/broadwell_head.S
 *
 *   Copyright (C) 2011 Gregory Nutt. All rights reserved.
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

	.file	"broadwell_syscall.S"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * .text
 ****************************************************************************/

	.text
    .code64

/****************************************************************************
 * Public Symbols
 ****************************************************************************/
    .global syscall_entry
    .global enable_syscall

/****************************************************************************
 * Macros
 ****************************************************************************/

/* Trace macros, use like trace 'i' to print char to serial port. */

	.macro	trace, ch
	mov		$0x3f8, %dx
	mov		$\ch, %al
	out		%al, %dx
	.endm


/****************************************************************************
 * Name: syscall_entry
 *
 * Description:
 *   This is the syscall_entry point. It saves the user reg and stack, sets up for
 *   kernel mode stacks, and dispatch the syscall.
 *
 ****************************************************************************/

	.type	syscall_entry, @function
syscall_entry:
    /* RCX is the userspace RIP, R11 is userspace RFLAGS */
    pushq %rcx
    pushq %r11

    mov %r10, %rcx

	call	syscall_handler

    popq %r11
    popq %rcx

	sysretq

	.size	syscall_entry, . - syscall_entry


/****************************************************************************
 * Name: enable_syscall
 *
 * Description:
 *   Setup syscall related MSRs.
 *
 ****************************************************************************/

#define MSR_EFER		0xc0000080
#define MSR_STAR		0xc0000081
#define MSR_LSTAR		0xc0000082
#define MSR_FMASK		0xc0000084

#define EFER_SCE		0x00000001

#define R0_GDT_INDEX 8
#define R3_GDT_INDEX 24

	.type	enable_syscall, @function
enable_syscall:
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx

	movl $MSR_EFER, %ecx
	rdmsr
	or $EFER_SCE, %eax
	wrmsr

	movl $MSR_STAR, %ecx
    xor %rdx, %rdx
    or $R3_GDT_INDEX, %rdx
    shl $16, %rdx
    or $R0_GDT_INDEX, %rdx
	wrmsr
    xor %rdx, %rdx

	movl $MSR_LSTAR, %ecx
	mov  $syscall_entry, %rax
	wrmsr

	movl $MSR_FMASK, %ecx
    mov $0, %rax
    wrmsr

    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    ret
    .size   enable_syscall, . - enable_syscall
