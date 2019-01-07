/****************************************************************************
 * drivers/pcie/pcie_config.c
 *
 *   Copyright (C) 2016 Gregory Nutt. All rights reserved.
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

#include <assert.h>
#include <debug.h>
#include <errno.h>

#include <arch/io.h>

#include <nuttx/irq.h>
#include <nuttx/pcie/pcie.h>

/****************************************************************************
 * Global values
 ****************************************************************************/

uint32_t pci_remap_region[CONFIG_PCIE_IO_REMAP_NUM];

struct pcie_dev_t* pci_device_type_list[CONFIG_PCIE_DEV_TYPE_NUM];

/****************************************************************************
 * Private Functions
 ****************************************************************************/

uint32_t pci_read_config(uint16_t bdf, uintptr_t addr, unsigned int size)
{
  outl(PCI_CONE | ((uint32_t)bdf << 8) | (addr & 0xfc), PCI_REG_ADDR_PORT);
  switch (size)
    {
      case 1:
        return inb(PCI_REG_DATA_PORT + (addr & 0x3));
      case 2:
        return inw(PCI_REG_DATA_PORT + (addr & 0x3));
      case 4:
        return inl(PCI_REG_DATA_PORT);
      default:
        return -1;
    }
}

void pci_write_config(uint16_t bdf, uintptr_t addr, uint32_t value, unsigned int size)
{
  outl(PCI_CONE | ((uint32_t)bdf << 8) | (addr & 0xfc), PCI_REG_ADDR_PORT);
  switch (size)
    {
      case 1:
        outb(value, PCI_REG_DATA_PORT + (addr & 0x3));
        break;
      case 2:
        outw(value, PCI_REG_DATA_PORT + (addr & 0x3));
        break;
      case 4:
        outl(value, PCI_REG_DATA_PORT);
        break;
    }
}

uint64_t pci_cfg_read64(uint16_t bdf, uintptr_t addr)
{
    uint64_t bar;

    bar = ((uint64_t)pci_read_config(bdf, addr + 4, 4) << 32) |
          pci_read_config(bdf, addr, 4);
    return bar;
}

void pci_cfg_write64(uint16_t bdf, uintptr_t addr, uint64_t val)
{
    pci_write_config(bdf, addr + 4, (uint32_t)(val >> 32), 4);
    pci_write_config(bdf, addr, (uint32_t)val, 4);
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: pci_register
 *
 * Description:
 *  Register a PCI-e device using vendor and device ID.
 *  Provided callback will be called when a device is probed.
 *
 * Input Parameters:
 *   dev - structure containing device vendor ID, device ID and callback
 *   function.
 *
 * Returned Value:
 *   -ENOMEM: Too many device types
 *        OK: Succeed
 *
 ****************************************************************************/

int pci_register(struct pcie_dev_t* dev)
{
  irqstate_t flags;
  int i;

  flags = enter_critical_section();
  for(i = 0; i < CONFIG_PCIE_DEV_TYPE_NUM; i++)
    {
      if(pci_device_type_list[i] == 0)
        {
          pci_device_type_list[i] = dev;
          leave_critical_section(flags);

          _info("Register PIC-e device type %04x:%04x, class/reversion %04x\n",
                  dev->vendor, dev->device, dev->class_rev);
          return OK;
        }
    }

  leave_critical_section(flags);
  return -ENOMEM;
}

/****************************************************************************
 * Name: pci_initialize
 *
 * Description:
 *  Enumerate the PCI-e bus and probe the devices using the register device
 *  list
 *
 ****************************************************************************/

void pci_initialize(void)
{
  unsigned int bdf;
  uint16_t id;
  int i;

  for (bdf = 0; bdf < 0x10000; bdf++)
    {
        id = pci_read_config(bdf, PCI_CFG_VENDOR_ID, 2);
        if (id == PCI_ID_ANY)
          continue;
        for(i = 0; i < CONFIG_PCIE_DEV_TYPE_NUM; i++)
          {
            if(pci_device_type_list[i] == NULL) continue;
            if(pci_device_type_list[i]->vendor == PCI_ID_ANY ||
                pci_device_type_list[i]->vendor == id)
              {
                if(pci_device_type_list[i]->device == PCI_ID_ANY ||
                    pci_device_type_list[i]->device == pci_read_config(bdf, PCI_CFG_DEVICE_ID, 2))
                  {

                    if(pci_device_type_list[i]->class_rev == PCI_ID_ANY ||
                        pci_device_type_list[i]->class_rev == pci_read_config(bdf, 0x8, 4))
                      {
                        _info("Found %04x:%04x, class/reversion %04x at %02x:%02x.%x\n",
                           pci_read_config(bdf, PCI_CFG_VENDOR_ID, 2),
                           pci_read_config(bdf, PCI_CFG_DEVICE_ID, 2),
                           pci_read_config(bdf, 0x8, 4),
                           bdf >> 8, (bdf >> 3) & 0x1f, bdf & 0x3);
                        pci_device_type_list[i]->probe(bdf);
                        break;
                      }
                  }
              }
          }
    }
  return;
}

/****************************************************************************
 * Name: pci_find_device
 *
 * Description:
 *  Search through the PCI-e enumeration space to find the first device matches
 *  the given vendor ID and device ID.
 *
 * Input Parameters:
 *   vendor    - Device Vendor ID
 *   device    - Device ID
 *   start_bdf - the BDF to start the search
 *
 * Returned Value:
 *   -1: no device found
 *   other: the BDF of the device found
 *
 ****************************************************************************/

int pci_find_device(uint16_t vendor, uint16_t device, uint16_t start_bdf)
{
  unsigned int bdf;
  uint16_t id;

  for (bdf = start_bdf; bdf < 0x10000; bdf++)
    {
        id = pci_read_config(bdf, PCI_CFG_VENDOR_ID, 2);
        if (id == PCI_ID_ANY || (vendor != PCI_ID_ANY && vendor != id))
          continue;
        if (device == PCI_ID_ANY ||
            pci_read_config(bdf, PCI_CFG_DEVICE_ID, 2) == device)
          {
            _info("Found %04x:%04x at %02x:%02x.%x\n",
               pci_read_config(bdf, PCI_CFG_VENDOR_ID, 2),
               pci_read_config(bdf, PCI_CFG_DEVICE_ID, 2),
               bdf >> 8, (bdf >> 3) & 0x1f, bdf & 0x3);
            return bdf;
          }
    }
  return -1;
}

/****************************************************************************
 * Name: pci_find_cap
 *
 * Description:
 *  Search through the PCI-e device capability list to find given capability.
 *
 * Input Parameters:
 *   bdf - Device BDF
 *   cap - Bitmask of capability
 *
 * Returned Value:
 *   -1: Capability not supported
 *   other: the offset in PCI configuration space to the capability structure
 *
 ****************************************************************************/

int pci_find_cap(uint16_t bdf, uint16_t cap)
{
  uint8_t pos = PCI_CFG_CAP_PTR - 1;

  if (!(pci_read_config(bdf, PCI_CFG_STATUS, 2) & PCI_STS_CAPS))
    return -1;

  while (1) {
    pos = pci_read_config(bdf, pos + 1, 1);
    if (pos == 0)
      return -1;
    if (pci_read_config(bdf, pos, 1) == cap)
      return pos;
  }
}

/****************************************************************************
 * Name: pci_msix_set_vector
 *
 * Description:
 *  Map a device MSI-X vector to a platform IRQ vector
 *
 * Input Parameters:
 *   bdf - Device BDF
 *   vector - IRQ number of the platform
 *   index  - Device MSI-X vector number
 *
 * Returned Value:
 *   <0: Mapping failed
 *    0: Mapping succeed
 *
 ****************************************************************************/

int pci_msix_set_vector(uint16_t bdf, unsigned int vector, uint32_t index)
{
  int cap = pci_find_cap(bdf, PCI_CAP_MSIX);
  unsigned int bar;
  uint64_t msix_table_addr = 0;
  uint32_t lo_table_addr;
  uint16_t message_control;
  uint32_t table_bar_ind;

  if (cap < 0)
    return -1;

  message_control = pci_read_config(bdf, cap + 2, 2);

  /* bounds check */
  if (index > (message_control & 0x3ff))
    return -1;

  table_bar_ind = pci_read_config(bdf, cap + 4, 4);

  bar = (table_bar_ind & 7) * 4 + PCI_CFG_BAR;

  lo_table_addr = pci_read_config(bdf, bar, 4);

  if ((lo_table_addr & 6) == PCI_BAR_64BIT)
    {
      msix_table_addr = pci_read_config(bdf, bar + 4, 4);
      msix_table_addr <<= 32;
    }
  msix_table_addr |= lo_table_addr & ~0xf;
  msix_table_addr += table_bar_ind & ~0x7;

  /* enable and mask */
  message_control |= (MSIX_CTRL_ENABLE | MSIX_CTRL_FMASK);
  pci_write_config(bdf, cap + 2, message_control, 2);

  msix_table_addr += 16 * index;
  mmio_write32((uint32_t *)(msix_table_addr     ), 0xfee00000 | up_apic_cpu_id() << 12);
  mmio_write32((uint32_t *)(msix_table_addr + 4 ), 0);
  mmio_write32((uint32_t *)(msix_table_addr + 8 ), vector);
  mmio_write32((uint32_t *)(msix_table_addr + 12), 0);

  /* enable and unmask */
  message_control &= ~MSIX_CTRL_FMASK;
  pci_write_config(bdf, cap + 2, message_control, 2);

  return 0;
}

/****************************************************************************
 * Name: pci_msi_set_vector
 *
 * Description:
 *  Map device MSI vector to a platform IRQ vector
 *
 * Input Parameters:
 *   bdf - Device BDF
 *   vector - IRQ number of the platform
 *
 * Returned Value:
 *   <0: Mapping failed
 *    0: Mapping succeed
 *
 ****************************************************************************/

int pci_msi_set_vector(uint16_t bdf, unsigned int vector)
{
  int cap = pci_find_cap(bdf, PCI_CAP_MSI);
  uint16_t ctl, data;

  if (cap < 0)
    return -1;

  pci_write_config(bdf, cap + 4, 0xfee00000 | (up_apic_cpu_id() << 12), 4);

  ctl = pci_read_config(bdf, cap + 2, 2);
  if (ctl & (1 << 7))
    {
      pci_write_config(bdf, cap + 8, 0, 4);
      data = cap + 0x0c;
    }
  else
    {
      data = cap + 0x08;
    }
  pci_write_config(bdf, data, vector, 2);

  pci_write_config(bdf, cap + 2, 0x0001, 2);

  return OK;
}

/****************************************************************************
 * Name: pci_ioremap64
 *
 * Description:
 *  Map a mamory region for PCI a 64 bit BARs
 *
 * Input Parameters:
 *   bdf - Device BDF
 *   bar - Bar number
 *   length - length of the resource
 *
 * Returned Value:
 *   NULL: Mapping failed
 *  other: Maped Address
 *
 ****************************************************************************/

void* pci_ioremap64(uint16_t bdf, int bar, size_t length)
{
  irqstate_t flags;
  int i, j;
  int fit;

  if(length == 0) return NULL;
  length = (length + PAGE_SIZE - 1) / PAGE_SIZE;

  if(bar & 0x1) return NULL; // check 64bit bars

  flags = enter_critical_section();

  for(i = 0; i < CONFIG_PCIE_IO_REMAP_NUM; i++)
    {
      if(pci_remap_region[i] == 0)
        {
          fit = 1;
          for(j = i; j < length + i; j++)
            {
              if(pci_remap_region[j] != 0)
                {
                  fit = 0;
                }
            }

          if(fit != 1) break;

          for(j = i; j < length + i; j++)
            {
              pci_remap_region[j] = 1;
            }

          leave_critical_section(flags);

          pci_cfg_write64(bdf, PCI_CFG_BAR + bar * 4, CONFIG_PCIE_IO_REMAP_START + PAGE_SIZE * i);
          up_map_region((void*)(CONFIG_PCIE_IO_REMAP_START + PAGE_SIZE * i), length * PAGE_SIZE, 0x10);

          _info("%02x:%02x.%x, BAR %d is at %p, length %d\n",
                  bdf >> 8, (bdf >> 3) & 0x1f, bdf & 0x3, bar,
                  CONFIG_PCIE_IO_REMAP_START + PAGE_SIZE * i, length * PAGE_SIZE);

          return (void*)(CONFIG_PCIE_IO_REMAP_START + PAGE_SIZE * i);
        }
    }

  leave_critical_section(flags);
  return NULL;
}
