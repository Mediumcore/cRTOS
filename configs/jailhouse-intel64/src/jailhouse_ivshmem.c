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

#include "jailhouse_ivshmem.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

uint8_t g_system_map[131072] = {0xde, 0xad, 0xbe, 0xef, 0x1A, 0x3B, 0xDA};

/****************************************************************************
 * ivshmem: Fileops Prototypes and Structures
 ****************************************************************************/

typedef FAR struct file        file_t;

static int     ivshmem_open(file_t *filep);
static int     ivshmem_close(file_t *filep);
static ssize_t ivshmem_read(file_t *filep, FAR char *buffer, size_t buflen);
static ssize_t ivshmem_write(file_t *filep, FAR const char *buf, size_t buflen);
static int     ivshmem_ioctl(file_t *filep, int cmd, unsigned long arg);
static off_t   ivshmem_seek(file_t *filep, off_t offset, int whence);

static const struct file_operations ivshmem_ops = {
    ivshmem_open,      /* open */
    ivshmem_close,     /* close */
    ivshmem_read,      /* read */
    ivshmem_write,     /* write */
    ivshmem_seek,      /* seek */
    ivshmem_ioctl,     /* ioctl */
};

static int ndevices;

struct ivshmem_dev_data {
    uint16_t bdf;
    uint32_t *registers;
    void *shmem;
    uint32_t *msix_table;
    uint64_t shmemsz;
    uint64_t bar2sz;
    sem_t ivshmem_input_sem;
    int ivshmem_initialized;
    int seek_address;
};

static struct ivshmem_dev_data devs[MAX_NDEV];

/*******************************
 *  ivshmem support functions  *
 *******************************/

static int get_ivpos(struct ivshmem_dev_data *d)
{
    return mmio_read32(d->registers + 0);
}

static void send_irq(struct ivshmem_dev_data *d)
{
    /*_info("IVSHMEM: %02x:%02x.%x sending IRQ\n",*/
           /*d->bdf >> 8, (d->bdf >> 3) & 0x1f, d->bdf & 0x3);*/
    _info("ivshmem sent irq\n");
    mmio_write32(d->registers + 1, 0);
}

static int ivshmem_irq_handler(int irq, uint32_t *regs, void *arg)
{
    int svalue;
    struct ivshmem_dev_data   *priv = (struct ivshmem_dev_data *)arg;

    /*_info("IVSHMEM: got interrupt ... %d\n", irq_counter++);*/
    sem_getvalue(&(priv->ivshmem_input_sem), &svalue);
    if(svalue < 0){
        sem_post(&(priv->ivshmem_input_sem));
    }

    return 0;
}

/****************************************************************************
 * ivshmem: Fileops
 ****************************************************************************/


static int ivshmem_open(file_t *filep)
{
    struct inode              *inode;
    struct ivshmem_dev_data   *priv;

    DEBUGASSERT(filep);
    inode = filep->f_inode;

    DEBUGASSERT(inode && inode->i_private);
    priv  = (struct ivshmem_dev_data *)inode->i_private;

    if(priv->ivshmem_initialized){
        return OK;
    } else {
        errno = EFAULT;
        return -1;
    }
}

static int ivshmem_close(file_t *filep)
{

    return OK;
}

static int ivshmem_ioctl(file_t *filep, int cmd, unsigned long arg)
{
    struct inode              *inode;
    struct ivshmem_dev_data   *priv;

    DEBUGASSERT(filep);
    inode = filep->f_inode;

    DEBUGASSERT(inode && inode->i_private);
    priv  = (struct ivshmem_dev_data *)inode->i_private;

    switch(cmd){
        case IVSHMEM_WAIT:
            sem_wait(&(priv->ivshmem_input_sem));
            break;
        case IVSHMEM_WAKE:
            send_irq(priv);
            break;
    }

    return 0;
}

static off_t ivshmem_seek(file_t *filep, off_t offset, int whence)
{
    int reg;
    struct inode              *inode;
    struct ivshmem_dev_data   *priv;

    DEBUGASSERT(filep);
    inode = filep->f_inode;

    DEBUGASSERT(inode && inode->i_private);
    priv  = (struct ivshmem_dev_data *)inode->i_private;

    switch (whence)
    {
        case SEEK_CUR:  /* Incremental seek */
            reg = priv->seek_address + offset;
            if (0 > reg || reg > priv->shmemsz)
            {
                set_errno(-EINVAL);
                return -1;
            }

            priv->seek_address = reg;
            break;

        case SEEK_END:  /* Seek to the 1st X-data register */
            priv->seek_address = priv->shmemsz;
            break;

        case SEEK_SET:  /* Seek to designated address */
            if (0 > offset || offset > priv->shmemsz)
            {
                set_errno(-EINVAL);
                return -1;
            }

            priv->seek_address = offset;
            break;

        default:        /* invalid whence */
            set_errno(-EINVAL);
            return -1;
    }

    return priv->seek_address;
}

static ssize_t ivshmem_read(file_t *filep, FAR char *buf, size_t buflen)
{
    struct inode              *inode;
    struct ivshmem_dev_data   *priv;
    int                        size;

    DEBUGASSERT(filep);
    inode = filep->f_inode;

    DEBUGASSERT(inode && inode->i_private);
    priv  = (struct ivshmem_dev_data *)inode->i_private;

    size = MIN(buflen, priv->shmemsz - priv->seek_address);

    printf("READ: %x %x %x %x..\n",
            priv->seek_address,
            *((uint32_t*)(priv->shmem + priv->seek_address)),
            *((uint32_t*)(priv->shmem + priv->seek_address) + 1),
            *((uint32_t*)(priv->shmem + priv->seek_address) + 2),
            *((uint32_t*)(priv->shmem + priv->seek_address) + 3));
    memcpy(buf, priv->shmem + priv->seek_address, size);

    priv->seek_address += size;

    return size;
}

static ssize_t ivshmem_write(file_t *filep, FAR const char *buf, size_t buflen)
{
    struct inode              *inode;
    struct ivshmem_dev_data   *priv;
    int                        size;

    DEBUGASSERT(filep);
    inode = filep->f_inode;

    DEBUGASSERT(inode && inode->i_private);
    priv  = (struct ivshmem_dev_data *)inode->i_private;

    size = MIN(buflen, priv->shmemsz - priv->seek_address);

    if(buf == NULL || buflen < 1)
        return -EINVAL;

    memcpy(priv->shmem + priv->seek_address, buf, size);

    priv->seek_address += size;

    return size;
}


/****************************************************************************
 * Initialize device, add /dev/... nodes
 ****************************************************************************/

void ivshmem_probe(uint16_t bdf)
{
    struct ivshmem_dev_data *d;
    char buf[32];

    if(ndevices == MAX_NDEV) return;

    if (pci_find_cap(bdf, PCI_CAP_MSIX) < 0)
      {
        _err("device is not MSI-X capable\n");
        return;
      }

    // Allocate a new device in array
    d = devs + ndevices;
    d->bdf = bdf;
    ndevices++;

    // read and setup the shmem region
    d->shmemsz = pci_cfg_read64(d->bdf, IVSHMEM_CFG_SHMEM_SIZE);
    d->shmem = (void *)pci_cfg_read64(d->bdf, IVSHMEM_CFG_SHMEM_ADDR);
    _info("New share memory region is at 0x%08x, length 0x%x\n", d->shmem, d->shmemsz);

    // map BARs

    d->registers = (uint32_t *)pci_alloc_mem_region(PAGE_SIZE);
    d->msix_table = (uint32_t *)pci_alloc_mem_region(PAGE_SIZE);

    pci_set_bar64(d->bdf, 0, (uint64_t)d->registers);
    pci_set_bar64(d->bdf, 2, (uint64_t)d->msix_table);
    d->bar2sz = PAGE_SIZE; //??

    pci_enable_device(d->bdf, (PCI_CMD_MEM | PCI_CMD_MASTER));

    _info("mapped the bars got position %d\n", get_ivpos(d));

    (void)irq_attach(IRQ0 + ndevices, (xcpt_t)ivshmem_irq_handler, d);
    pci_msix_set_vector(bdf, IRQ0 + ndevices, 0);

    if(sem_init(&(d->ivshmem_input_sem), 0, 0)){
        _info("IVSHMEM semaphore init failed\n");
        PANIC();
    };

    sprintf(buf, "/dev/ivshmem%d", ndevices);
    int ret = register_driver(buf, &ivshmem_ops, 0444, d);
    if(ret){
        _info("IVSHMEM %s register failed with errno=%d\n", buf, ret);
        PANIC();
    };

    d->ivshmem_initialized = 1;

    /* Hard coded to put system_map into first ivshmem region */
    if(ndevices == 1)
        memcpy(devs[0].shmem, g_system_map, 0x20000);
}

struct pcie_dev_t pci_ivshmem = {
    .vendor = VENDORID,
    .device = DEVICEID,
    .class_rev = (PCI_DEV_CLASS_OTHER << 24 |
          JAILHOUSE_SHMEM_PROTO_UNDEFINED << 8 | JAILHOUSE_IVSHMEM_REVERSION),
    .probe = ivshmem_probe
};

void up_ivshmem(void)
{
  memset(devs, 0, sizeof(struct ivshmem_dev_data) * MAX_NDEV);
  pci_register(&pci_ivshmem);
}
