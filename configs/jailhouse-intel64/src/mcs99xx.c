#include <nuttx/config.h>
#include <nuttx/arch.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>

#include <arch/io.h>
#include <nuttx/pcie/pcie.h>

#define MIN(a,b) (((a)<(b))?(a):(b))

#define MAX_MCS99xx_DEV 4

/****************************************************************************
 * ivshmem: Fileops Prototypes and Structures
 ****************************************************************************/

static int mcs99xx_count;

/****************************************************************************
 * Initialize device
 ****************************************************************************/

void mcs99xx_probe(uint16_t bdf)
{
  void* bar1mem;
  int cap;
  int pmcsr;

  if (pci_find_cap(bdf, PCI_CAP_MSI) < 0)
    {
      _err("device is not MSI capable\n");
      return;
    }

  bar1mem = (void*)(uint64_t)pci_read_config(bdf, PCI_CFG_BAR + 1 * 4, 4);
  up_map_region(bar1mem, PAGE_SIZE, 0x10);
  _info("MCS99xx BAR1: %x\n", bar1mem);

  // Power management check
  cap = pci_find_cap(bdf, PCI_CAP_PM);
  pmcsr = pci_read_config(bdf, cap + PCI_PM_CTRL, 4);
  _info("MCS99xx PM(%x): %x\n", cap, pmcsr & PCI_PM_CTRL_STATE_MASK);

  if((pmcsr & PCI_PM_CTRL_STATE_MASK) != 0)
    pci_write_config(bdf, cap + PCI_PM_CTRL, pmcsr & ~0x00, 4);

  // Enable MMIO region
  pci_enable_device(bdf, (PCI_CMD_MASTER | PCI_CMD_MEM));

  mmio_write8(bar1mem + 0x280 +  3 * 4, 0x83);
  mmio_write8(bar1mem + 0x280 +  1 * 4, 0x00);
  mmio_write8(bar1mem + 0x280 , 0x01);
  mmio_write8(bar1mem + 0x280 + 3 * 4, 0x03);
  mmio_write8(bar1mem + 0x280 + 2 * 4, 0x00);

  pci_msi_set_vector(bdf, IRQ6 + mcs99xx_count);
}

struct pcie_dev_t pci_mcs99xx = {
    .vendor = 0x9710,
    .device = 0x9912,
    .class_rev = 0x07000200,
    .probe = mcs99xx_probe
};

void up_mcs99xx(void)
{
  pci_register(&pci_mcs99xx);
}
