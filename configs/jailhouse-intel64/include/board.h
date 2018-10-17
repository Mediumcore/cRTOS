/************************************************************************************
 * configs/jailhouse-intel64/include/board.h
 * include/arch/board/board.h
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
 ************************************************************************************/

#ifndef _CONFIGS_JAILHOUSE_INTEL64_INCLUDE_BOARD_H
#define _CONFIGS_JAILHOUSE_INTEL64_INCLUDE_BOARD_H

/************************************************************************************
 * Included Files
 ************************************************************************************/

#include <nuttx/config.h>

/************************************************************************************
 * Pre-processor Definitions
 ************************************************************************************/

/* Clocking *************************************************************************/

/* Programmable interval timer (PIT) */

#define PIT_CLOCK 1041816 /* PIT input clock */

/* LED definitions ******************************************************************/

/* Button definitions ***************************************************************/

/* Alternate pin selections *********************************************************/

/* Jailhouse Comm Region */
#define COMM_REGION_BASE CONFIG_COMM_REGION_BASE

#define JAILHOUSE_MSG_NONE			0

/* messages to cell */
#define JAILHOUSE_MSG_SHUTDOWN_REQUEST		1
#define JAILHOUSE_MSG_RECONFIG_COMPLETED	2

/* replies from cell */
#define JAILHOUSE_MSG_UNKNOWN			1
#define JAILHOUSE_MSG_REQUEST_DENIED		2
#define JAILHOUSE_MSG_REQUEST_APPROVED		3
#define JAILHOUSE_MSG_RECEIVED			4

/* cell state, initialized by hypervisor, updated by cell */
#define JAILHOUSE_CELL_RUNNING			0
#define JAILHOUSE_CELL_RUNNING_LOCKED		1
#define JAILHOUSE_CELL_SHUT_DOWN		2 /* terminal state */
#define JAILHOUSE_CELL_FAILED			3 /* terminal state */
#define JAILHOUSE_CELL_FAILED_COMM_REV		4 /* terminal state */

#define COMM_REGION_ABI_REVISION		0
#define COMM_REGION_MAGIC			"JHCOMM"

#define COMM_REGION_GENERIC_HEADER					\
	/** Communication region magic JHCOMM */			\
	char signature[6];						\
	/** Communication region ABI revision */			\
	uint16_t revision;							\
	/** Cell state, initialized by hypervisor, updated by cell. */	\
	volatile uint32_t cell_state;					\
	/** Message code sent from hypervisor to cell. */		\
	volatile uint32_t msg_to_cell;					\
	/** Reply code sent from cell to hypervisor. */			\
	volatile uint32_t reply_from_cell;					\
	/** \privatesection */						\
	volatile uint32_t padding;						\
	/** \publicsection */

#define comm_region     ((struct jailhouse_comm_region *)COMM_REGION_BASE)


/************************************************************************************
 * Public Types
 ************************************************************************************/

#ifndef __ASSEMBLY__

struct jailhouse_comm_region {
	COMM_REGION_GENERIC_HEADER;

	/** Base address of PCI memory mapped config (x86-specific). */
	uint64_t pci_mmconfig_base;
	/** I/O port address of the PM timer (x86-specific). */
	uint16_t pm_timer_address;
	/** Number of CPUs available to the cell (x86-specific). */
	uint16_t num_cpus;
	/** Calibrated TSC frequency in kHz (x86-specific). */
	uint32_t tsc_khz;
	/** Calibrated APIC timer frequency in kHz or 0 if TSC deadline timer
	 * is available (x86-specific). */
	uint32_t apic_khz;
};

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

#undef EXTERN
#if defined(__cplusplus)
}
#endif

#endif /* __ASSEMBLY__ */
#endif  /* _CONFIGS_JAILHOUSE_INTEL64_INCLUDE_BOARD_H */
