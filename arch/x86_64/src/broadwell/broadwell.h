/************************************************************************************
 * arch/x86_64/src/broadwell/broadwell.h
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
 ************************************************************************************/

#ifndef __ARCH_X86_64_SRC_BROADWELL_BROADWELL_H
#define __ARCH_X86_64_SRC_BROADWELL_BROADWELL_H

/************************************************************************************
 * Included Files
 ************************************************************************************/

#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#include "up_internal.h"
#include "chip.h"

/************************************************************************************
 * Pre-processor Definitions
 ************************************************************************************/

/* Configuration ********************************************************************/

/************************************************************************************
 * Public Types
 ************************************************************************************/

/************************************************************************************
 * Inline Functions
 ************************************************************************************/

#ifndef __ASSEMBLY__

/************************************************************************************
 * Public Data
 ************************************************************************************/

#undef EXTERN
#if defined(__cplusplus)
#define EXTERN extern "C"
extern "C"
{
#else
#define EXTERN extern
#endif

/************************************************************************************
 * Public Function Prototypes
 ************************************************************************************/

/************************************************************************************
 * Name: intel64_clockconfig
 *
 * Description:
 *   Called to initialize the LPC17XX.  This does whatever setup is needed to put the
 *   MCU in a usable state.  This includes the initialization of clocking using the
 *   settings in board.h.
 *
 ************************************************************************************/

void intel64_clockconfig(void);

/************************************************************************************
 * Name: intel64_lowsetup
 *
 * Description:
 *   Called at the very beginning of _start.  Performs low level initialization
 *   including setup of the console UART.  This UART done early so that the serial
 *   console is available for debugging very early in the boot sequence.
 *
 ************************************************************************************/

void intel64_lowsetup(void);

/****************************************************************************
 * Name: intel64_dmachannel
 *
 * Description:
 *   Allocate a DMA channel.  This function sets aside a DMA channel and
 *   gives the caller exclusive access to the DMA channel.
 *
 * Returned Value:
 *   One success, this function returns a non-NULL, void* DMA channel
 *   handle.  NULL is returned on any failure.  This function can fail only
 *   if no DMA channel is available.
 *
 ****************************************************************************/

#ifdef CONFIG_INTEL64_GPDMA
DMA_HANDLE intel64_dmachannel(void);
#endif

/****************************************************************************
 * Name: intel64_dmafree
 *
 * Description:
 *   Release a DMA channel.  NOTE:  The 'handle' used in this argument must
 *   NEVER be used again until intel64_dmachannel() is called again to re-gain
 *   a valid handle.
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

#ifdef CONFIG_INTEL64_GPDMA
void intel64_dmafree(DMA_HANDLE handle);
#endif

/****************************************************************************
 * Name: intel64_dmasetup
 *
 * Description:
 *   Configure DMA for one transfer.
 *
 ****************************************************************************/

#ifdef CONFIG_INTEL64_GPDMA
int intel64_dmarxsetup(DMA_HANDLE handle, uint32_t control, uint32_t config,
                    uint32_t srcaddr, uint32_t destaddr, size_t nbytes);
#endif

/****************************************************************************
 * Name: intel64_dmastart
 *
 * Description:
 *   Start the DMA transfer
 *
 ****************************************************************************/

#ifdef CONFIG_INTEL64_GPDMA
int intel64_dmastart(DMA_HANDLE handle, dma_callback_t callback, void *arg);
#endif

/****************************************************************************
 * Name: intel64_dmastop
 *
 * Description:
 *   Cancel the DMA.  After intel64_dmastop() is called, the DMA channel is
 *   reset and intel64_dmasetup() must be called before intel64_dmastart() can be
 *   called again
 *
 ****************************************************************************/

#ifdef CONFIG_INTEL64_GPDMA
void intel64_dmastop(DMA_HANDLE handle);
#endif

/****************************************************************************
 * Name: intel64_dmasample
 *
 * Description:
 *   Sample DMA register contents
 *
 ****************************************************************************/

#ifdef CONFIG_INTEL64_GPDMA
#ifdef CONFIG_DEBUG_DMA
void intel64_dmasample(DMA_HANDLE handle, struct intel64_dmaregs_s *regs);
#else
#  define intel64_dmasample(handle,regs)
#endif
#endif

/****************************************************************************
 * Name: intel64_dmadump
 *
 * Description:
 *   Dump previously sampled DMA register contents
 *
 ****************************************************************************/

#ifdef CONFIG_INTEL64_GPDMA
#ifdef CONFIG_DEBUG_DMA
void intel64_dmadump(DMA_HANDLE handle, const struct intel64_dmaregs_s *regs,
                  const char *msg);
#else
#  define intel64_dmadump(handle,regs,msg)
#endif
#endif

/****************************************************************************
 * Name: vector_*
 *
 * Description:
 *   These are the various ISR/IRQ vector address exported from
 *   broadwell_vectors.S.  These addresses need to have global scope so that they
 *   can be known to the interrupt initialization logic in broadwell_irq.c.
 *
 ****************************************************************************/

void vector_isr0(void);
void vector_isr1(void);
void vector_isr2(void);
void vector_isr3(void);
void vector_isr4(void);
void vector_isr5(void);
void vector_isr6(void);
void vector_isr7(void);
void vector_isr8(void);
void vector_isr9(void);
void vector_isr10(void);
void vector_isr11(void);
void vector_isr12(void);
void vector_isr13(void);
void vector_isr14(void);
void vector_isr15(void);
void vector_isr16(void);
void vector_isr17(void);
void vector_isr18(void);
void vector_isr19(void);
void vector_isr20(void);
void vector_isr21(void);
void vector_isr22(void);
void vector_isr23(void);
void vector_isr24(void);
void vector_isr25(void);
void vector_isr26(void);
void vector_isr27(void);
void vector_isr28(void);
void vector_isr29(void);
void vector_isr30(void);
void vector_isr31(void);
void vector_irq0(void);
void vector_irq1(void);
void vector_irq2(void);
void vector_irq3(void);
void vector_irq4(void);
void vector_irq5(void);
void vector_irq6(void);
void vector_irq7(void);
void vector_irq8(void);
void vector_irq9(void);
void vector_irq10(void);
void vector_irq11(void);
void vector_irq12(void);
void vector_irq13(void);
void vector_irq14(void);
void vector_irq15(void);

#undef EXTERN
#if defined(__cplusplus)
}
#endif

#endif /* __ASSEMBLY__ */
#endif /* __ARCH_X86_64_SRC_BROADWELL_BROADWELL_H */
