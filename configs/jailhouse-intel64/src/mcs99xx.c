#include <nuttx/config.h>
#include <nuttx/arch.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>

#include <arch/board/virtio_ring.h>

#include <arch/io.h>
#include <nuttx/pcie/pcie.h>
#include <nuttx/serial/uart_16550.h>

#define MIN(a,b) (((a)<(b))?(a):(b))

#define MAX_MCS99xx_DEV 4

// These are for 16C950
#define UART_ICR_OFFSET UART_LSR_OFFSET
#define UART_EFR_OFFSET UART_IIR_OFFSET

#define UART_ACR_OFFSET 0x00
#define UART_CPR_OFFSET 0x01
#define UART_TCR_OFFSET 0x02
#define UART_CKS_OFFSET 0x03
#define UART_TTL_OFFSET 0x04
#define UART_RTL_OFFSET 0x05

#define UART_EFR_ECB   0b00010000

#define UART_ACR_ASRE  0b10000000
#define UART_ACR_ICRRD 0b01000000
#define UART_ACR_TLE   0b00100000

// MCS99xx specific
#define SER_VEN_REG         (0x204)
#define SER_SOFT_RESET_REG  (0x238)
#define SP_CLK_SELECT_REG   (0x214)

/****************************************************************************
 * ivshmem: Fileops Prototypes and Structures
 ****************************************************************************/

static int mcs99xx_count;

// Helper Functions
//

#define UART_ACR_CONFIG (UART_ACR_TLE)
#define UART_FIFO_DEPTH (16)

//helper function for IO type read
static inline uint8_t serial_in(uint8_t* membase, int offset)
{
  uint8_t tmp1;
  uint8_t* mem = membase + 0x280 + (offset * 4);
  tmp1 = READ_ONCE(*mem);
  return tmp1;
}

//helper function for IO type write
static inline void serial_out(uint8_t* membase, int offset, uint8_t value)
{
  uint8_t* mem = membase + 0x280 + (offset * 4);
  WRITE_ONCE(*mem, value);
}

//Helper function to write to index control register
static void serial_icr_write(uint8_t* membase, int offset, uint8_t value)
{
  serial_out(membase, UART_SCR_OFFSET, offset);
  serial_out(membase, UART_ICR_OFFSET, value);
}

//Helper function to read from index control register
static unsigned int serial_icr_read(uint8_t* membase, int offset)
{
  unsigned int value;
  serial_icr_write(membase, UART_ACR_OFFSET, UART_ACR_CONFIG | UART_ACR_ICRRD);
  serial_out(membase, UART_SCR_OFFSET, offset);
  value = serial_in(membase, UART_ICR_OFFSET);
  serial_icr_write(membase, UART_ACR_OFFSET, UART_ACR_CONFIG);
  return value;
}

//Helper function to set the enhance mode
void setserial_enhance_mode(uint8_t* membase)
{
  uint8_t lcr, efr;

  lcr = serial_in(membase, UART_LCR_OFFSET);
  serial_out(membase, UART_LCR_OFFSET, 0xBF);

  efr = serial_in(membase, UART_EFR_OFFSET);
  efr |= UART_EFR_ECB;
  serial_out(membase, UART_EFR_OFFSET, efr);

  serial_out(membase, UART_LCR_OFFSET, lcr);
}

// Helper function to clear the FIFO and disable it
static inline void serial_clear_fifos(uint8_t* membase)
{
  serial_out(membase, UART_FCR_OFFSET, UART_FCR_FIFOEN);
  serial_out(membase, UART_FCR_OFFSET, UART_FCR_FIFOEN |
           UART_FCR_RXRST | UART_FCR_TXRST);
  serial_out(membase, UART_FCR_OFFSET, 0);
}

/****************************************************************************
 * Initialize device
 ****************************************************************************/

void mcs99xx_probe(uint16_t bdf)
{
  void* bar1mem;
  int cap;
  int pmcsr;
  uint32_t ser_ven_val;

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

  pci_msi_set_vector(bdf, IRQ7 + mcs99xx_count++);

  uint32_t* ssrr_mem = bar1mem + SER_SOFT_RESET_REG;
  WRITE_ONCE(*ssrr_mem, 0x01);
  serial_clear_fifos(bar1mem);
  setserial_enhance_mode(bar1mem);

  //Setting the FIFO trigger Levels
  serial_icr_write(bar1mem, UART_RTL_OFFSET, UART_FIFO_DEPTH);
  serial_icr_write(bar1mem, UART_TTL_OFFSET, UART_FIFO_DEPTH);
  serial_icr_write(bar1mem, UART_ACR_OFFSET, UART_ACR_CONFIG);


  uint32_t* svr_mem = bar1mem + SER_VEN_REG;
  uint32_t* sclr_mem = bar1mem + SP_CLK_SELECT_REG;
  if(mcs99xx_count == 1)
    {
      // This is the console, for the sake of USB serial transciver, use a standard baud */
      // Set the device clock
      ser_ven_val = READ_ONCE(*svr_mem);
      ser_ven_val = 0;
      WRITE_ONCE(*svr_mem, ser_ven_val);

      // 14745600 Hz
      ser_ven_val |= 0x50;
      WRITE_ONCE(*svr_mem, ser_ven_val);
      // Enable pre-scaling for high clock rate
      WRITE_ONCE(*sclr_mem, 0);
    }
  else
    {
      // Others Use a non standard clock for high transmission rate */
      // Set the device clock
      ser_ven_val = READ_ONCE(*svr_mem);
      ser_ven_val = 0;
      WRITE_ONCE(*svr_mem, ser_ven_val);

      // 48000000 Hz
      ser_ven_val |= 0x70;
      WRITE_ONCE(*svr_mem, ser_ven_val);
      // Enable pre-scaling for high clock rate
      WRITE_ONCE(*sclr_mem, 0);
    }

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
