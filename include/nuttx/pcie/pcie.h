/****************************************************************************
 * include/nuttx/pcie/pcie.h
 *
 *   Copyright(C) 2009-2012, 2016 Gregory Nutt. All rights reserved.
 *   Author: Gregory Nutt <gnutt@nuttx.org>
 *           ChungFan Yang <sonicyang@softlab.cs.tsukuba.ac.jp>
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
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES(INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

#ifndef __INCLUDE_NUTTX_PCIE_H
#define __INCLUDE_NUTTX_PCIE_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/types.h>
#include <stdint.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define PCI_CFG_VENDOR_ID      0x000
#define PCI_CFG_DEVICE_ID      0x002
#define PCI_CFG_COMMAND		0x004
# define PCI_CMD_IO		(1 << 0)
# define PCI_CMD_MEM		(1 << 1)
# define PCI_CMD_MASTER		(1 << 2)
# define PCI_CMD_INTX_OFF	(1 << 10)
#define PCI_CFG_STATUS		0x006
# define PCI_STS_INT		(1 << 3)
# define PCI_STS_CAPS		(1 << 4)
#define PCI_CFG_BAR		0x010
# define PCI_BAR_64BIT		0x4
#define PCI_CFG_CAP_PTR		0x034
#define PCI_PM_CTRL		4	/* PM control and status register */
#define  PCI_PM_CTRL_STATE_MASK	0x0003	/* Current power state (D0 to D3) */

#define PCI_ID_ANY		0xffff

#define PCI_DEV_CLASS_OTHER	0xff

#define PCI_CAP_PM		0x01
#define PCI_CAP_MSI		0x05
#define PCI_CAP_MSIX		0x11

#define MSIX_CTRL_ENABLE	0x8000
#define MSIX_CTRL_FMASK		0x4000

#define PCI_REG_ADDR_PORT	0xcf8
#define PCI_REG_DATA_PORT	0xcfc

#define PCI_CONE		(1 << 31)

/****************************************************************************
 * Public Type Definitions
 ****************************************************************************/
struct pcie_dev_t{
    uint16_t vendor;
    uint16_t device;
    uint32_t class_rev;
    int (*probe)(uint16_t bdf);
};

int pci_register(struct pcie_dev_t* dev);

uint32_t pci_read_config(uint16_t bdf, uintptr_t addr, unsigned int size);
void pci_write_config(uint16_t bdf, uintptr_t addr, uint32_t value, unsigned int size);
uint64_t pci_cfg_read64(uint16_t bdf, uintptr_t addr);
void pci_cfg_write64(uint16_t bdf, uintptr_t addr, uint64_t val);

int pci_find_device(uint16_t vendor, uint16_t device, uint16_t start_bdf);
int pci_find_cap(uint16_t bdf, uint16_t cap);

int pci_msi_set_vector(uint16_t bdf, unsigned int vector);
int pci_msix_set_vector(uint16_t bdf, unsigned int vector, uint32_t index);

void* pci_alloc_mem_region(size_t length);
void pci_set_bar32(uint16_t bdf, int bar, uint32_t value);
void pci_set_bar64(uint16_t bdf, int bar, uint64_t value);

uint32_t pci_get_bar32(uint16_t bdf, int bar);
uint64_t pci_get_bar64(uint16_t bdf, int bar);

int pci_enable_device(uint16_t bdf, uint32_t flags);

#endif /* __INCLUDE_NUTTX_PCIE_H */
