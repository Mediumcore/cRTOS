/****************************************************************************
 * arch/x86/src/i486/up_regdump.c
 *
 *   Copyright (C) 2011, 2016 Gregory Nutt. All rights reserved.
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
#include <nuttx/irq.h>

#include "up_internal.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_registerdump
 ****************************************************************************/

void up_registerdump(uint64_t *regs)
{
  int i, j;
  uint64_t mxcsr;
  uint64_t rbp;
  asm volatile ("stmxcsr %0"::"m"(mxcsr):"memory");
  _alert("----------------CUT HERE-----------------\n");
  _alert("PANIC:\n");
  _alert("Exception %lld occurred with error code %lld:\n", irq, regs[REG_ERRCODE]);
  _alert("Gerneral Informations:\n");
  _alert("CPL: %d, RPL: %d\n", regs[REG_CS] & 0x3, regs[REG_DS] & 0x3);
  _alert("RIP: %016llx, RSP: %016llx\n", regs[REG_RIP], regs[REG_RSP]);
  _alert("RBP: %016llx, RFLAGS: %016llx\n", regs[REG_RBP], regs[REG_RFLAGS]);
  _alert("MSR_STAR: %016llx, MSR_LSTAR: %016llx\n", read_msr(0xc0000081), read_msr(0xc0000082));
  _alert("MXCSR: %016llx\n", mxcsr);
  _alert("Selector Dump:\n");
  _alert("CS: %016llx, DS: %016llx, SS: %016llx\n", regs[REG_CS], regs[REG_DS], regs[REG_SS]);
  _alert("Register Dump:\n");
  _alert("RAX: %016llx, RBX: %016llx\n", regs[REG_RAX], regs[REG_RBX]);
  _alert("RCX: %016llx, RDX: %016llx\n", regs[REG_RCX], regs[REG_RDX]);
  _alert("RDI: %016llx, RSI: %016llx\n", regs[REG_RDI], regs[REG_RSI]);
  _alert("Stack Dump (+-64 bytes):\n");
  for(i = 0; i < 16; i++){
    _alert(" %016llx   ", (regs[REG_RSP] + i * 8 - 64));
    for(j = 0; j < 8; j++){
      _alert("%02x ", *((uint8_t*)(regs[REG_RSP] + i * 8 + j - 64)));
    }
    _alert("  %016llx   ", *((uint64_t*)(regs[REG_RSP] + i * 8 - 64)));
    for(j = 0; j < 8; j++){
      if(!((*((uint8_t*)(regs[REG_RSP] + i * 8 + j - 64)) > 126) || (*((uint8_t*)(regs[REG_RSP] + i * 8 + j - 64)) < 32)))
        _alert("%c", *((uint8_t*)(regs[REG_RSP] + i * 8 + j - 64)));
      else
        _alert(".");
    }
    _alert("\n");
  }
  _alert("Frame Dump (64 bytes):\n");
  rbp = regs[REG_RBP];
  for(i = 0; i < 8; i++){
    if(!rbp)
        break;
    if(rbp > CONFIG_RAM_SIZE)
        break;
    _alert("  %016llx ", *((uint64_t*)(rbp)));
    _alert("  %016llx ", *((uint64_t*)(rbp + 1 * 8)));
    _alert("\n");
    if((rbp) && *((uint64_t*)(rbp + 1 * 8)) )
        rbp = *(uint64_t*)rbp;
    else
        break;
  }
  _alert("-----------------------------------------\n");
}
