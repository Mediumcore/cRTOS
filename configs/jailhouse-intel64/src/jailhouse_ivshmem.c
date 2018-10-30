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
#include <arch/pci.h>

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

static uint64_t pci_cfg_read64(uint16_t bdf, unsigned int addr)
{
    uint64_t bar;

    bar = ((uint64_t)pci_read_config(bdf, addr + 4, 4) << 32) |
          pci_read_config(bdf, addr, 4);
    return bar;
}

static void pci_cfg_write64(uint16_t bdf, unsigned int addr, uint64_t val)
{
    pci_write_config(bdf, addr + 4, (uint32_t)(val >> 32), 4);
    pci_write_config(bdf, addr, (uint32_t)val, 4);
}

static uint64_t get_bar_sz(uint16_t bdf, uint8_t barn)
{
    uint64_t bar, tmp;
    uint64_t barsz;

    bar = pci_cfg_read64(bdf, PCI_CFG_BAR + (8 * barn));
    pci_cfg_write64(bdf, PCI_CFG_BAR + (8 * barn), 0xffffffffffffffffULL);
    tmp = pci_cfg_read64(bdf, PCI_CFG_BAR + (8 * barn));
    barsz = ~(tmp & ~(0xf)) + 1;
    pci_cfg_write64(bdf, PCI_CFG_BAR + (8 * barn), bar);

    return barsz;
}

static void map_shmem_and_bars(struct ivshmem_dev_data *d)
{
    int cap = pci_find_cap(d->bdf, PCI_CAP_MSIX);

    if (cap < 0) {
        _err("device is not MSI-X capable\n");
        return;
    }

    d->shmemsz = pci_cfg_read64(d->bdf, IVSHMEM_CFG_SHMEM_SZ);
    d->shmem = (void *)pci_cfg_read64(d->bdf, IVSHMEM_CFG_SHMEM_PTR);

    _info("shmem is at %p\n", d->shmem);
    d->registers = (uint32_t *)((uint64_t)(d->shmem + d->shmemsz + PAGE_SIZE - 1)
        & PAGE_MASK);
    pci_cfg_write64(d->bdf, PCI_CFG_BAR, (uint64_t)d->registers);
    _info("bar0 is at %p\n", d->registers);
    d->bar2sz = get_bar_sz(d->bdf, 2);
    d->msix_table = (uint32_t *)((uint64_t)d->registers + PAGE_SIZE);
    pci_cfg_write64(d->bdf, PCI_CFG_BAR + 16, (uint64_t)d->msix_table);
    _info("bar2 is at %p\n", d->msix_table);

    pci_write_config(d->bdf, PCI_CFG_COMMAND,
             (PCI_CMD_MEM | PCI_CMD_MASTER), 2);
    up_map_region((void*)d->shmem, d->shmemsz + PAGE_SIZE + d->bar2sz, 0x10);
}

static int get_ivpos(struct ivshmem_dev_data *d)
{
    return mmio_read32(d->registers + 2);
}

static void send_irq(struct ivshmem_dev_data *d)
{
    /*_info("IVSHMEM: %02x:%02x.%x sending IRQ\n",*/
           /*d->bdf >> 8, (d->bdf >> 3) & 0x1f, d->bdf & 0x3);*/
    mmio_write32(d->registers + 3, 1);
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

void up_ivshmem(void)
{
    int bdf = 0;
    unsigned int class_rev;
    struct ivshmem_dev_data *d;
    char buf[32];

    memset(devs, 0, sizeof(struct ivshmem_dev_data) * MAX_NDEV);

    while ((ndevices < MAX_NDEV) &&
           (-1 != (bdf = pci_find_device(VENDORID, DEVICEID, bdf)))) {
        _info("Found %04x:%04x at %02x:%02x.%x\n",
               pci_read_config(bdf, PCI_CFG_VENDOR_ID, 2),
               pci_read_config(bdf, PCI_CFG_DEVICE_ID, 2),
               bdf >> 8, (bdf >> 3) & 0x1f, bdf & 0x3);
        class_rev = pci_read_config(bdf, 0x8, 4);
        if (class_rev != (PCI_DEV_CLASS_OTHER << 24 |
                  JAILHOUSE_SHMEM_PROTO_UNDEFINED << 8)) {
            _info("class/revision %08x, not supported "
                   "skipping device\n", class_rev);
            bdf++;
            continue;
        }
        ndevices++;
        d = devs + ndevices - 1;
        d->bdf = bdf;

        map_shmem_and_bars(d);
        _info("mapped the bars got position %d\n", get_ivpos(d));

        //XXX: conflict with pre-existing x86 IRQ number?
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

        bdf++;
    }

    if (!ndevices) {
        _warn("No PCI devices found .. nothing to do.\n");
        return;
    }

    /* Hard coded to put system_map into first ivshmem region */
    memcpy(devs[0].shmem + 0x100000, g_system_map, 0x20000);
}
