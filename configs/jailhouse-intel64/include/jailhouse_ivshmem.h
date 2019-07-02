#ifndef __JAILHOUSE_INCLUDE_IVSHMEM_H
#define __JAILHOUSE_INCLUDE_IVSHMEM_H

#define VENDORID	0x1af4
#define DEVICEID	0x1110

#define IVSHMEM_CFG_VENDOR_CAP 0x40
#define IVSHMEM_CFG_VENDOR_LEN 20
#define IVSHMEM_CFG_MSIX_CAP   (IVSHMEM_CFG_VENDOR_CAP+IVSHMEM_CFG_VENDOR_LEN)
#define IVSHMEM_CFG_SHMEM_ADDR (IVSHMEM_CFG_VENDOR_CAP + 4)
#define IVSHMEM_CFG_SHMEM_SIZE (IVSHMEM_CFG_VENDOR_CAP + 12)

#define JAILHOUSE_SHMEM_PROTO_UNDEFINED	0x0000
#define JAILHOUSE_IVSHMEM_REVERSION 0x2

#define IVSHMEM_SIZE 0x120000
#define IVSHMEM_DATA_SIZE 0x100000
#define IVSHMEM_SYSMAP_SIZE 0x20000

#define MAX_NDEV	4

#define IVSHMEM_WAIT 10
#define IVSHMEM_WAKE 11

void up_ivshmem(void);

int ivshmnet_initialize(int intf);

struct ivshmem_regs {
    uint32_t id;
    uint32_t doorbell;
    uint32_t lstate;
    uint32_t rstate;
    uint32_t rstate_write_lo;
    uint32_t rstate_write_hi;
};



#endif /* __JAILHOUSE_INCLUDE_IVSHMEM_H */
