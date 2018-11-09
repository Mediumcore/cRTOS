/****************************************************************************
 * ivshmem-net.c
 *
 *   Copyright (C) 2018 Gregory Nutt. All rights reserved.
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

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <debug.h>

#include <arpa/inet.h>

#include <nuttx/arch.h>
#include <nuttx/irq.h>
#include <nuttx/wdog.h>
#include <nuttx/wqueue.h>
#include <nuttx/net/arp.h>
#include <nuttx/net/netdev.h>

#include <arch/io.h>
#include <arch/pci.h>

#include "virtio_ring.h"
#include "jailhouse_ivshmem.h"

#ifdef CONFIG_NET_PKT
#  include <nuttx/net/pkt.h>
#endif

#ifdef CONFIG_NET_IVSHMEM_NET

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Work queue support is required. */

#if !defined(CONFIG_SCHED_WORKQUEUE)
#  error Work queue support is required in this configuration (CONFIG_SCHED_WORKQUEUE)
#else

/* The low priority work queue is preferred.  If it is not enabled, LPWORK
 * will be the same as HPWORK.
 */

#  if defined(CONFIG_IVSHMEM_NET_HPWORK)
#    define ETHWORK HPWORK
#  elif defined(CONFIG_IVSHMEM_NET_LPWORK)
#    define ETHWORK LPWORK
#  else
#    error Neither CONFIG_IVSHMEM_NET_HPWORK nor CONFIG_IVSHMEM_NET_LPWORK defined
#  endif
#endif

/* CONFIG_IVSHMEM_NET_NINTERFACES determines the number of physical interfaces
 * that will be supported.
 */

#ifndef CONFIG_IVSHMEM_NET_NINTERFACES
# define CONFIG_IVSHMEM_NET_NINTERFACES 1
#else
# if(CONFIG_IVSHMEM_NET_NINTERFACES != 1)
#   error Only support one ivshmem-net interface
# endif
#endif

/* TX poll delay = 1 seconds. CLK_TCK is the number of clock ticks per second */

#define IVSHMEM_NET_WDDELAY   (1*CLK_TCK)

/* TX timeout = 1 minute */

#define IVSHMEM_NET_TXTIMEOUT (60*CLK_TCK)

/* This is a helper pointer for accessing the contents of the Ethernet header */

#define BUF ((struct eth_hdr_s *)priv->sk_dev.d_buf)

#define IVSHM_ALIGN(addr, align) (((addr) + (align - 1)) & ~(align - 1))

#define SMP_CACHE_BYTES 64

#define JAILHOUSE_SHMEM_PROTO_VETH 0x1

#define IVSHMEM_RSTATE_WRITE_ENABLE	(1ULL << 0)
#define IVSHMEM_RSTATE_WRITE_REGION1	(1ULL << 1)

#define IVSHM_NET_STATE_RESET		0
#define IVSHM_NET_STATE_INIT		1
#define IVSHM_NET_STATE_READY		2
#define IVSHM_NET_STATE_RUN		3

#define IVSHM_NET_FLAG_RUN	0

#define IVSHM_NET_MTU_MIN 256
#define IVSHM_NET_MTU_DEF 16384

#define IVSHM_NET_FRAME_SIZE(s) IVSHM_ALIGN(18 + (s), SMP_CACHE_BYTES)

#define IVSHM_NET_VQ_ALIGN 64

#define IVSHM_NET_REGION_TX		0
#define IVSHM_NET_REGION_RX		1

#define IVSHM_NET_VECTOR_STATE		0
#define IVSHM_NET_VECTOR_TX_RX		1

#define IVSHM_NET_NUM_VECTORS		2

#define WRITE_ONCE(var, val) \
        (*((volatile typeof(val) *)(&(var))) = (val))

#define READ_ONCE(var) (*((volatile typeof(var) *)(&(var))))

#define mb() asm volatile("mfence":::"memory")
#define rmb()asm volatile("lfence":::"memory")
#define wmb()asm volatile("sfence" ::: "memory")
#define barrier()asm volatile("" ::: "memory")

#define virt_store_release(p, v)\
    do {\
        barrier();\
        WRITE_ONCE(*p, v);\
    } while (0)

#define virt_load_acquire(p)\
    ({\
        typeof(*p) ___p1 = READ_ONCE(*p);\
        barrier();\
        ___p1;\
     })


/****************************************************************************
 * Private Types
 ****************************************************************************/

struct ivshmem_regs {
    uint32_t id;
    uint32_t doorbell;
    uint32_t lstate;
    uint32_t rstate;
    uint32_t rstate_write_lo;
    uint32_t rstate_write_hi;
};

/* Abstracted vring structure */

struct ivshm_net_queue {
  struct vring vr;
  uint32_t free_head;
  uint32_t num_free;
  uint32_t num_added;
  uint16_t last_avail_idx;
  uint16_t last_used_idx;

  void *data;
  void *end;
  uint32_t size;
  uint32_t head;
  uint32_t tail;
};

/* The ivshmnet_driver_s encapsulates all state information for a single hardware
 * interface
 */

struct ivshmnet_driver_s
{
  /* Nuttx stuff */
  bool sk_bifup;               /* true:ifup false:ifdown */
  WDOG_ID sk_txpoll;           /* TX poll timer */
  WDOG_ID sk_txtimeout;        /* TX timeout timer */
  struct work_s sk_irqwork;    /* For deferring interrupt work to the work queue */
  struct work_s sk_pollwork;   /* For deferring poll work to the work queue */

  /* driver specific */
  struct work_s sk_statework;    /* For deferring interrupt work to the work queue */

  uint32_t bdf;

  struct ivshm_net_queue rx;
  struct ivshm_net_queue tx;

  uint32_t vrsize;
  uint32_t qlen;
  uint32_t qsize;

  uint32_t lstate;
  uint32_t *rstate, last_rstate;

  unsigned long flags;

  struct ivshmem_regs *ivshm_regs;
  void *shm[2];
  size_t shmlen;
  uint32_t peer_id;

  /* This holds the information visible to the NuttX network */

  struct net_driver_s sk_dev;  /* Interface understood by the network */
};

/****************************************************************************
 * Private Data
 ****************************************************************************/

/* These statically allocated structures would mean that only a single
 * instance of the device could be supported.  In order to support multiple
 * devices instances, this data would have to be allocated dynamically.
 */

/* A single packet buffer per device is used in this example.  There might
 * be multiple packet buffers in a more complex, pipelined design.  Many
 * contemporary Ethernet interfaces, for example,  use multiple, linked DMA
 * descriptors in rings to implement such a pipeline.  This example assumes
 * much simpler hardware that simply handles one packet at a time.
 *
 * NOTE that if CONFIG_IVSHMEM_NET_NINTERFACES were greater than 1, you would
 * need a minimum on one packet buffer per instance.  Much better to be
 * allocated dynamically in cases where more than one are needed.
 */

static uint8_t g_pktbuf[MAX_NET_DEV_MTU + CONFIG_NET_GUARDSIZE];

/* Driver state structure */

static struct ivshmnet_driver_s g_ivshmnet[CONFIG_IVSHMEM_NET_NINTERFACES];

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

/* ivshm-net */

static void ivshm_net_state_change(void *in);
static void ivshm_net_set_state(struct ivshmnet_driver_s *in, uint32_t state);
static void ivshm_net_check_state(struct ivshmnet_driver_s *in);


/* Common TX logic */

static int  ivshmnet_transmit(FAR struct ivshmnet_driver_s *priv);
static int  ivshmnet_txpoll(FAR struct net_driver_s *dev);

/* Interrupt handling */

static void ivshmnet_reply(struct ivshmnet_driver_s *priv);
static void ivshmnet_receive(FAR struct ivshmnet_driver_s *priv);
static void ivshmnet_txdone(FAR struct ivshmnet_driver_s *priv);

static void ivshmnet_interrupt_work(FAR void *arg);
static int  ivshmnet_interrupt(int irq, FAR void *context, FAR void *arg);

/* Watchdog timer expirations */

static void ivshmnet_txtimeout_work(FAR void *arg);
static void ivshmnet_txtimeout_expiry(int argc, wdparm_t arg, ...);

static void ivshmnet_poll_work(FAR void *arg);
static void ivshmnet_poll_expiry(int argc, wdparm_t arg, ...);

/* NuttX callback functions */

static int  ivshmnet_ifup(FAR struct net_driver_s *dev);
static int  ivshmnet_ifdown(FAR struct net_driver_s *dev);

static void ivshmnet_txavail_work(FAR void *arg);
static int  ivshmnet_txavail(FAR struct net_driver_s *dev);

#if defined(CONFIG_NET_IGMP) || defined(CONFIG_NET_ICMPv6)
static int  ivshmnet_addmac(FAR struct net_driver_s *dev,
              FAR const uint8_t *mac);
#ifdef CONFIG_NET_IGMP
static int  ivshmnet_rmmac(FAR struct net_driver_s *dev,
              FAR const uint8_t *mac);
#endif
#ifdef CONFIG_NET_ICMPv6
static void ivshmnet_ipv6multicast(FAR struct ivshmnet_driver_s *priv);
#endif
#endif
#ifdef CONFIG_NETDEV_IOCTL
static int  ivshmnet_ioctl(FAR struct net_driver_s *dev, int cmd,
              unsigned long arg);
#endif

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

static void map_veth_shmem_and_bars(struct ivshmnet_driver_s *priv)
{
    int cap = pci_find_cap(priv->bdf, PCI_CAP_MSIX);
    uint64_t shmlen[2];
    uint64_t cap_pos;

    if (cap < 0) {
        _err("device is not MSI-X capable\n");
        return;
    }

    for (int region = 0; region < 2; region++) {
        cap_pos = IVSHMEM_CFG_SHMEM_ADDR + (region + 1) * 16;
        priv->shm[region] = (void*)pci_cfg_read64(priv->bdf, cap_pos);

        cap_pos = IVSHMEM_CFG_SHMEM_SIZE + (region + 1) * 16;
        shmlen[region] = pci_cfg_read64(priv->bdf, cap_pos);

        up_map_region(priv->shm[region], shmlen[region], 0x10);

        _info("%s memory at %016llp, size %08llx\n",
             region == IVSHM_NET_REGION_TX ? "TX" : "RX",
             priv->shm[region], shmlen[region]);
    }

    priv->shmlen = shmlen[0] < shmlen[1] ? shmlen[0] : shmlen[1];

    /* set the bar0 region beyond topmost memory space */
    int himem = priv->shm[0] > priv->shm[1] ? 0 : 1;
    priv->ivshm_regs = (struct ivshmem_regs *)((uint64_t)(priv->shm[himem] + shmlen[himem] + PAGE_SIZE - 1) & PAGE_MASK);
    pci_cfg_write64(priv->bdf, PCI_CFG_BAR, (uint64_t)priv->ivshm_regs);
    _info("bar0 is at %p\n", priv->ivshm_regs);

    int bar2sz = get_bar_sz(priv->bdf, 2);
    uint64_t* msix_table = (uint64_t *)((uint64_t)priv->ivshm_regs + PAGE_SIZE);
    pci_cfg_write64(priv->bdf, PCI_CFG_BAR + 8, (uint64_t)msix_table);
    _info("bar2 is at %p\n", msix_table);

    up_map_region(priv->ivshm_regs, PAGE_SIZE + bar2sz, 0x10);

    pci_write_config(priv->bdf, PCI_CFG_COMMAND, (PCI_CMD_MEM | PCI_CMD_MASTER), 2);
}

/*****************************************
 *  ivshmem-net vring support functions  *
 *****************************************/

static void *ivshm_net_desc_data(
        struct ivshmnet_driver_s *in, struct ivshm_net_queue *q,
        unsigned int region,  struct vring_desc *desc,
        uint32_t *len)
{
    uint64_t offs = READ_ONCE(desc->addr);
    uint32_t dlen = READ_ONCE(desc->len);
    uint16_t flags = READ_ONCE(desc->flags);
    void *data;

    if (flags)
        return NULL;

    if (offs >= in->shmlen)
        return NULL;

    data = in->shm[region] + offs;

    if (data < q->data || data >= q->end)
        return NULL;

    if (dlen > q->end - data)
        return NULL;

    *len = dlen;

    return data;
}

static void ivshm_net_init_queue(
        struct ivshmnet_driver_s *in, struct ivshm_net_queue *q,
        void *mem, unsigned int len)
{
    memset(q, 0, sizeof(*q));

    vring_init(&q->vr, len, mem, IVSHM_NET_VQ_ALIGN);
    q->data = mem + in->vrsize;
    q->end = q->data + in->qsize;
    q->size = in->qsize;
}

static void ivshm_net_init_queues(struct ivshmnet_driver_s *in)
{
    void *tx;
    void *rx;
    int i;
    void* tmp;

    tx = in->shm[IVSHM_NET_REGION_TX] + 4;
    rx = in->shm[IVSHM_NET_REGION_RX] + 4;

    memset(tx, 0, in->shmlen - 4);

    ivshm_net_init_queue(in, &in->tx, tx, in->qlen);
    ivshm_net_init_queue(in, &in->rx, rx, in->qlen);

    tmp = in->rx.vr.used;
    in->rx.vr.used = in->tx.vr.used;
    in->tx.vr.used = tmp;

    in->tx.num_free = in->tx.vr.num;

    for (i = 0; i < in->tx.vr.num - 1; i++)
        in->tx.vr.desc[i].next = i + 1;
}

static int ivshm_net_calc_qsize(struct ivshmnet_driver_s *in)
{
    unsigned int vrsize;
    unsigned int qsize;
    unsigned int qlen;

    for (qlen = 4096; qlen > 32; qlen >>= 1) {
        vrsize = vring_size(qlen, IVSHM_NET_VQ_ALIGN);
        vrsize = IVSHM_ALIGN(vrsize, IVSHM_NET_VQ_ALIGN);
        if (vrsize < (in->shmlen - 4) / 8)
            break;
    }

    if (vrsize > in->shmlen - 4)
        return -EINVAL;

    qsize = in->shmlen - 4 - vrsize;

    if (qsize < 4 * IVSHM_NET_MTU_MIN)
        return -EINVAL;

    in->vrsize = vrsize;
    in->qlen = qlen;
    in->qsize = qsize;

    return 0;
}

/*****************************************
 *  ivshmem-net IRQ support functions  *
 *****************************************/

static void ivshm_net_notify_tx(struct ivshmnet_driver_s *in, unsigned int num)
{
    uint16_t evt, old, new;

    mb();

    evt = READ_ONCE(vring_avail_event(&in->tx.vr));
    old = in->tx.last_avail_idx - num;
    new = in->tx.last_avail_idx;

    if (vring_need_event(evt, new, old)) {
        in->ivshm_regs->doorbell = IVSHM_NET_VECTOR_TX_RX;
    }
}

static void ivshm_net_enable_rx_irq(struct ivshmnet_driver_s *in)
{
    vring_avail_event(&in->rx.vr) = in->rx.last_avail_idx;
    wmb();
}

static void ivshm_net_notify_rx(struct ivshmnet_driver_s *in, unsigned int num)
{
    uint16_t evt, old, new;

    mb();

    evt = vring_used_event(&in->rx.vr);
    old = in->rx.last_used_idx - num;
    new = in->rx.last_used_idx;

    if (vring_need_event(evt, new, old)) {
        in->ivshm_regs->doorbell = IVSHM_NET_VECTOR_TX_RX;
    }
}

static void ivshm_net_enable_tx_irq(struct ivshmnet_driver_s *in)
{
    vring_used_event(&in->tx.vr) = in->tx.last_used_idx;
    wmb();
}

/*************************************
 *  ivshmem-net vring syntax sugars  *
 *************************************/

static struct vring_desc *ivshm_net_rx_desc(struct ivshmnet_driver_s *in)
{
    struct ivshm_net_queue *rx = &in->rx;
    struct vring *vr = &rx->vr;
    unsigned int avail;
    uint16_t avail_idx;

    avail_idx = virt_load_acquire(&vr->avail->idx);

    if (avail_idx == rx->last_avail_idx)
        return NULL;

    avail = vr->avail->ring[rx->last_avail_idx++ & (vr->num - 1)];
    if (avail >= vr->num) {
        _err("invalid rx avail %d\n", avail);
        return NULL;
    }

    return &vr->desc[avail];
}

static bool ivshm_net_rx_avail(struct ivshmnet_driver_s *in)
{
    mb();
    return READ_ONCE(in->rx.vr.avail->idx) != in->rx.last_avail_idx;
}

static void ivshm_net_rx_finish(struct ivshmnet_driver_s *in, struct vring_desc *desc)
{
    struct ivshm_net_queue *rx = &in->rx;
    struct vring *vr = &rx->vr;
    unsigned int desc_id = desc - vr->desc;
    unsigned int used;

    used = rx->last_used_idx++ & (vr->num - 1);
    vr->used->ring[used].id = desc_id;
    vr->used->ring[used].len = 1;

    virt_store_release(&vr->used->idx, rx->last_used_idx);
}

static size_t ivshm_net_tx_space(struct ivshmnet_driver_s *in)
{
    struct ivshm_net_queue *tx = &in->tx;
    uint32_t tail = tx->tail;
    uint32_t head = tx->head;
    uint32_t space;

    if (head < tail)
        space = tail - head;
    else
        space = (tx->size - head) > tail ? (tx->size - head) : tail;

    return space;
}

static bool ivshm_net_tx_ok(struct ivshmnet_driver_s *in, unsigned int mtu)
{
    return in->tx.num_free >= 2 &&
        ivshm_net_tx_space(in) >= 2 * IVSHM_NET_FRAME_SIZE(mtu);
}

static uint32_t ivshm_net_tx_advance(struct ivshm_net_queue *q, uint32_t *pos, uint32_t len)
{
    uint32_t p = *pos;

    len = IVSHM_NET_FRAME_SIZE(len);

    if (q->size - p < len)
        p = 0;
    *pos = p + len;

    return p;
}

static int ivshm_net_tx_frame(struct ivshmnet_driver_s *in, void* data, int len)
{
    struct ivshm_net_queue *tx = &in->tx;
    struct vring *vr = &tx->vr;
    struct vring_desc *desc;
    unsigned int desc_idx;
    unsigned int avail;
    uint32_t head;
    void *buf;
    irqstate_t flags;

    DEBUGASSERT(tx->num_free < 1);

    flags = enter_critical_section();

    desc_idx = tx->free_head;
    desc = &vr->desc[desc_idx];
    tx->free_head = desc->next;
    tx->num_free--;

    leave_critical_section(flags);

    head = ivshm_net_tx_advance(tx, &tx->head, len);

    buf = tx->data + head;
    memcpy(buf, data, len);

    desc->addr = buf - in->shm[IVSHM_NET_REGION_TX];
    desc->len = len;
    desc->flags = 0;

    avail = tx->last_avail_idx++ & (vr->num - 1);
    vr->avail->ring[avail] = desc_idx;
    tx->num_added++;

    virt_store_release(&vr->avail->idx, tx->last_avail_idx);
    ivshm_net_notify_tx(in, tx->num_added);
    tx->num_added = 0;

    return 0;
}

static void ivshm_net_tx_clean(struct ivshmnet_driver_s *in)
{
    struct ivshm_net_queue *tx = &in->tx;
    struct vring_used_elem *used;
    struct vring *vr = &tx->vr;
    struct vring_desc *desc;
    struct vring_desc *fdesc;
    unsigned int num;
    uint16_t used_idx;
    uint16_t last;
    uint32_t fhead;
    irqstate_t flags;

    flags = enter_critical_section();

    used_idx = virt_load_acquire(&vr->used->idx);
    last = tx->last_used_idx;

    fdesc = NULL;
    fhead = 0;
    num = 0;

    while (last != used_idx) {
        void *data;
        uint32_t len;
        uint32_t tail;

        used = vr->used->ring + (last % vr->num);
        if (used->id >= vr->num || used->len != 1) {
            _err("invalid tx used->id %d ->len %d\n",
                   used->id, used->len);
            break;
        }

        desc = &vr->desc[used->id];

        data = ivshm_net_desc_data(in, &in->tx, IVSHM_NET_REGION_TX,
                       desc, &len);
        if (!data) {
            _err("bad tx descriptor, data == NULL\n");
            break;
        }

        tail = ivshm_net_tx_advance(tx, &tx->tail, len);
        if (data != tx->data + tail) {
            _err("bad tx descriptor\n");
            break;
        }

        if (!num)
            fdesc = desc;
        else
            desc->next = fhead;

        fhead = used->id;
        last++;
        num++;
    }

    tx->last_used_idx = last;

    leave_critical_section(flags);

    if (num) {
        flags = enter_critical_section();
        fdesc->next = tx->free_head;
        tx->free_head = fhead;
        tx->num_free += num;
        DEBUGASSERT(tx->num_free > vr->num);
        leave_critical_section(flags);
    }
}

/*****************************************
 *  ivshmem-net support functions  *
 *****************************************/

static void ivshm_net_run(struct ivshmnet_driver_s *in)
{
  irqstate_t flags;

  if (in->lstate < IVSHM_NET_STATE_READY)
    return;

  /* test_and_set_bit */
  flags = enter_critical_section();
  if(in->flags & IVSHM_NET_FLAG_RUN){
    in->flags |= IVSHM_NET_FLAG_RUN;
    leave_critical_section(flags);
    return;
  }

  in->flags |= IVSHM_NET_FLAG_RUN;
  leave_critical_section(flags);

  ivshm_net_set_state(in, IVSHM_NET_STATE_RUN);
  in->sk_bifup = true;

  return;
}

static void ivshm_net_do_stop(struct ivshmnet_driver_s *in)
{
  irqstate_t flags;

  in->sk_bifup = false;

  ivshm_net_set_state(in, IVSHM_NET_STATE_RESET);

  /* test_and_clear_bit */
  flags = enter_critical_section();
  if(!(in->flags & IVSHM_NET_FLAG_RUN)){
    in->flags &= ~IVSHM_NET_FLAG_RUN;
    leave_critical_section(flags);
    return;
  }

  in->flags &= ~IVSHM_NET_FLAG_RUN;
  leave_critical_section(flags);

  return;
}

/****************************************************************************
 * State Machine
 ****************************************************************************/

static void ivshm_net_state_change(void *arg)
{
  struct ivshmnet_driver_s *in = (struct ivshmnet_driver_s*)arg;
  uint32_t rstate = READ_ONCE(*in->rstate);

  _info("Rstate: %08lx, Lstate: %08lx\n", rstate, in->lstate);

  switch (in->lstate) {
  case IVSHM_NET_STATE_RESET:
    if (rstate < IVSHM_NET_STATE_READY)
        ivshm_net_set_state(in, IVSHM_NET_STATE_INIT);
    break;

  case IVSHM_NET_STATE_INIT:
    if (rstate > IVSHM_NET_STATE_RESET) {
        ivshm_net_init_queues(in);
        ivshm_net_set_state(in, IVSHM_NET_STATE_READY);
    }
    break;

  case IVSHM_NET_STATE_READY:
  case IVSHM_NET_STATE_RUN:
    if (rstate >= IVSHM_NET_STATE_READY) {
        ivshm_net_run(in);
    } else {
        ivshm_net_do_stop(in);
    }
    break;
  }

  wmb();
  WRITE_ONCE(in->last_rstate, rstate);
}

static void ivshm_net_set_state(struct ivshmnet_driver_s *in, uint32_t state)
{
  wmb();
  WRITE_ONCE(in->lstate, state);
  WRITE_ONCE(in->ivshm_regs->lstate,  state);
}

static void ivshm_net_check_state(struct ivshmnet_driver_s *in)
{
  irqstate_t flags;

  _info("Remote state changed\n");

  /* test_bit */
  flags = enter_critical_section();

  if (*in->rstate != in->last_rstate || !(IVSHM_NET_FLAG_RUN & in->flags)){
    work_queue(ETHWORK, &in->sk_statework, ivshm_net_state_change, in, 0);
  }

  leave_critical_section(flags);
}

/****************************************************************************
 * State IRQ Handlers
 ****************************************************************************/

static int ivshmnet_state_handler(int irq, uint32_t *regs, void *arg)
{
  struct ivshmnet_driver_s *priv = arg;

  ivshm_net_check_state(priv);

  return 0;
}

/****************************************************************************
 * Private Functions
 ****************************************************************************/

#define bswap16 __builtin_bswap16
#define bswap32 __builtin_bswap32
#define bswap64 __builtin_bswap64

static void dump_ethernet_frame(void *data, int len){
    uint8_t* ptr8 = data;
    uint16_t* ptr16 = data;
    uint32_t* ptrip = (uint32_t*)(ptr8 + 14);
    uint16_t etype;

    ninfo("======= Dumping Ethernet Frame =======\n");
    ninfo("Dest MAC: %x:%x:%x:%x:%x:%x\n", ptr8[0], ptr8[1], ptr8[2], ptr8[3], ptr8[4], ptr8[5]);
    ninfo("Src  MAC: %x:%x:%x:%x:%x:%x\n", ptr8[6], ptr8[7], ptr8[8], ptr8[9], ptr8[10], ptr8[11]);
    etype = bswap16(ptr16[6]);
    ninfo("Ether Type: 0x%x\n", etype);
    if(etype == 0x806) // ARP
    {
      ninfo("------- Begin ARP Frame -------\n");
      ninfo("HW type: 0x%lx, Proto type: 0x%lx\n", bswap16((ptrip[0]) & 0xffff), bswap16((ptrip[0] >> 16) & 0xffff));
      ninfo("HW addr len: 0x%lx, Proto addr len: 0x%lx\n", (ptrip[1]) & 0xff, (ptrip[1] >> 8) & 0xff);
      ninfo("Operation: 0x%lx\n", bswap16((ptrip[1] >> 16) & 0xffff));
      ninfo("Sender hardware address: %x:%x:%x:%x:%x:%x\n",
              (ptrip[2]) & 0xff,
              (ptrip[2] >> 8) & 0xff,
              (ptrip[2] >> 16) & 0xff,
              (ptrip[2] >> 24) & 0xff,
              (ptrip[3]) & 0xff,
              (ptrip[3] >> 8) & 0xff
              );
      ninfo("Sender protocol address: %x:%x:%x:%x\n",
              (ptrip[3] >> 16) & 0xff,
              (ptrip[3] >> 24) & 0xff,
              (ptrip[4]) & 0xff,
              (ptrip[4] >> 8) & 0xff
              );
      ninfo("Target hardware address: %x:%x:%x:%x:%x:%x\n",
              (ptrip[4] >> 16) & 0xff,
              (ptrip[4] >> 24) & 0xff,
              (ptrip[5]) & 0xff,
              (ptrip[5] >> 8) & 0xff,
              (ptrip[5] >> 16) & 0xff,
              (ptrip[5] >> 24) & 0xff
              );
      ninfo("Target protocol address: %x:%x:%x:%x\n",
              (ptrip[6]) & 0xff,
              (ptrip[6] >> 8) & 0xff,
              (ptrip[6] >> 16) & 0xff,
              (ptrip[6] >> 24) & 0xff
              );
    }
    else if(etype == 0x800) //IPV4
    {
      int hdr_len = (ptrip[0]) & 0xf;
      ninfo("------- Begin IP Frame -------\n");
      ninfo("Version: %d, Hdr len: 0x%lx\n", (ptrip[0] >> 4) & 0xf, hdr_len);
      ninfo("Diff Service: 0x%lx\n", (ptrip[0] >> 8) & 0xff);
      ninfo("Total Length: 0x%lx\n", (ptrip[0] >> 16) & 0xffff);
      ninfo("Identification: 0x%lx\n", (ptrip[1]) & 0xffff);
      ninfo("Flags: 0x%lx, Frags: 0x%lx\n", (ptrip[1] >> 16) & 0x7, bswap16((ptrip[1] >> 16) & 0xffff) & 0x1fff);
      ninfo("TTL: %d, Protocol: 0x%lx\n", (ptrip[2]) & 0xff, (ptrip[2] >> 8) & 0xff);
      ninfo("Hdr checksum: 0x%lx\n", (ptrip[2] >> 16) & 0xffff);
      ninfo("Src  address: %d.%d.%d.%d\n", (ptrip[3]) & 0xff, (ptrip[3] >> 8) & 0xff, (ptrip[3] >> 16) & 0xff, (ptrip[3] >> 24) & 0xff);
      ninfo("Dest address: %d.%d.%d.%d\n", (ptrip[4]) & 0xff, (ptrip[4] >> 8) & 0xff, (ptrip[4] >> 16) & 0xff, (ptrip[4] >> 24) & 0xff);

      ninfo("Src  port: %d\n", bswap16(ptrip[hdr_len] >> 16) & 0xffff);
      ninfo("Dest port: %d\n", bswap16(ptrip[hdr_len]) & 0xffff);
    }

    return;
}

/****************************************************************************
 * Name: ivshmnet_transmit
 *
 * Description:
 *   Start hardware transmission.  Called either from the txdone interrupt
 *   handling or from watchdog based polling.
 *
 * Input Parameters:
 *   priv - Reference to the driver state structure
 *
 * Returned Value:
 *   OK on success; a negated errno on failure
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static int ivshmnet_transmit(FAR struct ivshmnet_driver_s *priv)
{
  /* Verify that the hardware is ready to send another packet.  If we get
   * here, then we are committed to sending a packet; Higher level logic
   * must have assured that there is no transmission in progress.
   */

  /* Increment statistics */

  NETDEV_TXPACKETS(priv->sk_dev);

  /* Send the packet: address=priv->sk_dev.d_buf, length=priv->sk_dev.d_len */
  ivshm_net_tx_clean(priv);

  ASSERT(ivshm_net_tx_ok(priv, IVSHM_NET_MTU_DEF));

  ivshm_net_tx_frame(priv, priv->sk_dev.d_buf, priv->sk_dev.d_len);

  /* Enable Tx interrupts */
  ivshm_net_enable_tx_irq(priv);

  /* Setup the TX timeout watchdog (perhaps restarting the timer) */
  (void)wd_start(priv->sk_txtimeout, IVSHMEM_NET_TXTIMEOUT,
                 ivshmnet_txtimeout_expiry, 1, (wdparm_t)priv);
  return OK;
}

/****************************************************************************
 * Name: ivshmnet_txpoll
 *
 * Description:
 *   The transmitter is available, check if the network has any outgoing
 *   packets ready to send.  This is a callback from devif_poll().
 *   devif_poll() may be called:
 *
 *   1. When the preceding TX packet send is complete,
 *   2. When the preceding TX packet send timesout and the interface is reset
 *   3. During normal TX polling
 *
 * Input Parameters:
 *   dev - Reference to the NuttX driver state structure
 *
 * Returned Value:
 *   OK on success; a negated errno on failure
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static int ivshmnet_txpoll(FAR struct net_driver_s *dev)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)dev->d_private;

  /* If the polling resulted in data that should be sent out on the network,
   * the field d_len is set to a value > 0.
   */

  if (priv->sk_dev.d_len > 0)
    {
      /* Look up the destination MAC address and add it to the Ethernet
       * header.
       */

#ifdef CONFIG_NET_IPv4
#ifdef CONFIG_NET_IPv6
      if (IFF_IS_IPv4(priv->sk_dev.d_flags))
#endif
        {
          arp_out(&priv->sk_dev);
        }
#endif /* CONFIG_NET_IPv4 */

#ifdef CONFIG_NET_IPv6
#ifdef CONFIG_NET_IPv4
      else
#endif
        {
          neighbor_out(&priv->sk_dev);
        }
#endif /* CONFIG_NET_IPv6 */

      /* Send the packet */

      ivshmnet_transmit(priv);

      /* Check if there is room in the device to hold another packet. If not,
       * return a non-zero value to terminate the poll.
       */
    }

  /* If zero is returned, the polling will continue until all connections have
   * been examined.
   */

  return 0;
}

/****************************************************************************
 * Name: ivshmnet_reply
 *
 * Description:
 *   After a packet has been received and dispatched to the network, it
 *   may return return with an outgoing packet.  This function checks for
 *   that case and performs the transmission if necessary.
 *
 * Input Parameters:
 *   priv - Reference to the driver state structure
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static void ivshmnet_reply(struct ivshmnet_driver_s *priv)
{
  /* If the packet dispatch resulted in data that should be sent out on the
   * network, the field d_len will set to a value > 0.
   */

  if (priv->sk_dev.d_len > 0)
    {
      /* Update the Ethernet header with the correct MAC address */

#ifdef CONFIG_NET_IPv4
#ifdef CONFIG_NET_IPv6
      /* Check for an outgoing IPv4 packet */

      if (IFF_IS_IPv4(priv->sk_dev.d_flags))
#endif
        {
          arp_out(&priv->sk_dev);
        }
#endif

#ifdef CONFIG_NET_IPv6
#ifdef CONFIG_NET_IPv4
      /* Otherwise, it must be an outgoing IPv6 packet */

      else
#endif
        {
          neighbor_out(&ivshmnet->sk_dev);
        }
#endif

      /* And send the packet */

      ivshmnet_transmit(priv);
    }
}

/****************************************************************************
 * Name: ivshmnet_receive
 *
 * Description:
 *   An interrupt was received indicating the availability of a new RX packet
 *
 * Input Parameters:
 *   priv - Reference to the driver state structure
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static void ivshmnet_receive(FAR struct ivshmnet_driver_s *priv)
{
  int received = 0;

  do
    {
      struct vring_desc *desc;
      void *data;
      uint32_t len;

      /* Check for errors and update statistics */
      ninfo("processing receive\n");

      desc = ivshm_net_rx_desc(priv); /* get next avail rx descriptor from avail ring */
      if (!desc)
        break;

      data = ivshm_net_desc_data(priv, &priv->rx, IVSHM_NET_REGION_RX,
                   desc, &len); /* Unpack descriptor and get the physical address in SHMEM and fill in len */
      if (!data) {
        _err("bad rx descriptor\n");
        break;
      }

      dump_ethernet_frame(data, len);

      /* Check if the packet is a valid size for the network buffer
       * configuration.
       */

      /* Copy the data data from the hardware to priv->sk_dev.d_buf.  Set
       * amount of data in priv->sk_dev.d_len
       */
      memcpy(priv->sk_dev.d_buf, data, len);
      priv->sk_dev.d_len = len;

      ivshm_net_rx_finish(priv, desc); /* Release the read descriptor in to the used ring */

#ifdef CONFIG_NET_PKT
      /* When packet sockets are enabled, feed the frame into the packet tap */

       pkt_input(&priv->sk_dev);
#endif

#ifdef CONFIG_NET_IPv4
      /* Check for an IPv4 packet */

      if (BUF->type == HTONS(ETHTYPE_IP))
        {
          ninfo("IPv4 frame\n");
          NETDEV_RXIPV4(&priv->sk_dev);

          /* Handle ARP on input, then dispatch IPv4 packet to the network
           * layer.
           */

          arp_ipin(&priv->sk_dev);
          ipv4_input(&priv->sk_dev);

          /* Check for a reply to the IPv4 packet */

          ivshmnet_reply(priv);
        }
      else
#endif
#ifdef CONFIG_NET_IPv6
      /* Check for an IPv6 packet */

      if (BUF->type == HTONS(ETHTYPE_IP6))
        {
          ninfo("Iv6 frame\n");
          NETDEV_RXIPV6(&priv->sk_dev);

          /* Dispatch IPv6 packet to the network layer */

          ipv6_input(&priv->sk_dev);

          /* Check for a reply to the IPv6 packet */

          ivshmnet_reply(priv);
        }
      else
#endif
#ifdef CONFIG_NET_ARP
      /* Check for an ARP packet */

      if (BUF->type == htons(ETHTYPE_ARP))
        {
          /* Dispatch ARP packet to the network layer */

          arp_arpin(&priv->sk_dev);
          NETDEV_RXARP(&priv->sk_dev);

          /* If the above function invocation resulted in data that should be
           * sent out on the network, the field  d_len will set to a value > 0.
           */

          if (priv->sk_dev.d_len > 0)
            {
              ivshmnet_transmit(priv);
            }
        }
      else
#endif
        {
          NETDEV_RXDROPPED(&priv->sk_dev);
        }
      received++;
    }
  while (true); /* Whether are there more packets to be processed is checked above */

  ivshm_net_enable_rx_irq(priv); /* enable the irq by writing the last avail index to the end of the ring */
  if (ivshm_net_rx_avail(priv)) /* More stuff to read?, which is very unlikely*/
    work_queue(ETHWORK, &priv->sk_irqwork, ivshmnet_interrupt_work, priv, 0); /* schedule the work again */

  if (received)
    ivshm_net_notify_rx(priv, received); /* We had did some work, notify we had rx the data by triggering door bell*/
}

/****************************************************************************
 * Name: ivshmnet_txdone
 *
 * Description:
 *   An interrupt was received indicating that the last TX packet(s) is done
 *
 * Input Parameters:
 *   priv - Reference to the driver state structure
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static void ivshmnet_txdone(FAR struct ivshmnet_driver_s *priv)
{
  /* Check for errors and update statistics */

  NETDEV_TXDONE(priv->sk_dev);

  /* Check if there are pending transmissions */

  /* If no further transmissions are pending, then cancel the TX timeout and
   * disable further Tx interrupts.
   */

  wd_cancel(priv->sk_txtimeout);

  /* And disable further TX interrupts. */

  /* In any event, poll the network for new TX data */

  (void)devif_poll(&priv->sk_dev, ivshmnet_txpoll);
}

/****************************************************************************
 * Name: ivshmnet_interrupt_work
 *
 * Description:
 *   Perform interrupt related work from the worker thread
 *
 * Input Parameters:
 *   arg - The argument passed when work_queue() was called.
 *
 * Returned Value:
 *   OK on success
 *
 * Assumptions:
 *   Runs on a worker thread.
 *
 ****************************************************************************/

static void ivshmnet_interrupt_work(FAR void *arg)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)arg;

  /* Lock the network and serialize driver operations if necessary.
   * NOTE: Serialization is only required in the case where the driver work
   * is performed on an LP worker thread and where more than one LP worker
   * thread has been configured.
   */

  ninfo("processing int\n");

  net_lock();

  /* Process pending Ethernet interrupts */

  /* Get and clear interrupt status bits */

  /*ivshm_net_tx_clean(priv);*/

  /* Handle interrupts according to status bit settings */

  /* Check if we received an incoming packet, if so, call ivshmnet_receive() */
  if(ivshm_net_rx_avail(priv))
    {

      ivshmnet_receive(priv);
    }
  else
    {
      /* Check if a packet transmission just completed.  If so, call ivshmnet_txdone.
       * This may disable further Tx interrupts if there are no pending
       * transmissions.
       */

      /* XXX: Assuming single interrupt only represent TX or RX might not be a good idea */

      ivshmnet_txdone(priv);
    }

  net_unlock();

  /* Re-enable Ethernet interrupts */

  /*up_enable_irq(CONFIG_IVSHMEM_NET_IRQ);*/
}

/****************************************************************************
 * Name: ivshmnet_interrupt
 *
 * Description:
 *   Hardware interrupt handler
 *
 * Input Parameters:
 *   irq     - Number of the IRQ that generated the interrupt
 *   context - Interrupt register state save info (architecture-specific)
 *
 * Returned Value:
 *   OK on success
 *
 * Assumptions:
 *   Runs in the context of a the Ethernet interrupt handler.  Local
 *   interrupts are disabled by the interrupt logic.
 *
 ****************************************************************************/

static int ivshmnet_interrupt(int irq, FAR void *context, FAR void *arg)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)arg;

  DEBUGASSERT(priv != NULL);

  /* Disable further Ethernet interrupts.  Because Ethernet interrupts are
   * also disabled if the TX timeout event occurs, there can be no race
   * condition here.
   */

  /*up_disable_irq(CONFIG_IVSHMEM_NET_IRQ);*/

  /* TODO: Determine if a TX transfer just completed */

    {
      /* If a TX transfer just completed, then cancel the TX timeout so
       * there will be no race condition between any subsequent timeout
       * expiration and the deferred interrupt processing.
       */

       /*wd_cancel(priv->sk_txtimeout);*/
    }

  ninfo("Got an net tx/rx int\n");

  /* Schedule to perform the interrupt processing on the worker thread. */

  work_queue(ETHWORK, &priv->sk_irqwork, ivshmnet_interrupt_work, priv, 0);
  return OK;
}

/****************************************************************************
 * Name: ivshmnet_txtimeout_work
 *
 * Description:
 *   Perform TX timeout related work from the worker thread
 *
 * Input Parameters:
 *   arg - The argument passed when work_queue() as called.
 *
 * Returned Value:
 *   OK on success
 *
 ****************************************************************************/

static void ivshmnet_txtimeout_work(FAR void *arg)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)arg;

  /* Lock the network and serialize driver operations if necessary.
   * NOTE: Serialization is only required in the case where the driver work
   * is performed on an LP worker thread and where more than one LP worker
   * thread has been configured.
   */

  net_lock();

  /* Increment statistics and dump debug info */

  NETDEV_TXTIMEOUTS(priv->sk_dev);

  /* Then reset the hardware */

  /* Then poll the network for new XMIT data */

  (void)devif_poll(&priv->sk_dev, ivshmnet_txpoll);
  net_unlock();
}

/****************************************************************************
 * Name: ivshmnet_txtimeout_expiry
 *
 * Description:
 *   Our TX watchdog timed out.  Called from the timer interrupt handler.
 *   The last TX never completed.  Reset the hardware and start again.
 *
 * Input Parameters:
 *   argc - The number of available arguments
 *   arg  - The first argument
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   Runs in the context of a the timer interrupt handler.  Local
 *   interrupts are disabled by the interrupt logic.
 *
 ****************************************************************************/

static void ivshmnet_txtimeout_expiry(int argc, wdparm_t arg, ...)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)arg;

  /* Disable further Ethernet interrupts.  This will prevent some race
   * conditions with interrupt work.  There is still a potential race
   * condition with interrupt work that is already queued and in progress.
   */

  /*up_disable_irq(CONFIG_IVSHMEM_NET_IRQ);*/

  /* Schedule to perform the TX timeout processing on the worker thread. */

  work_queue(ETHWORK, &priv->sk_irqwork, ivshmnet_txtimeout_work, priv, 0);
}

/****************************************************************************
 * Name: ivshmnet_poll_work
 *
 * Description:
 *   Perform periodic polling from the worker thread
 *
 * Input Parameters:
 *   arg - The argument passed when work_queue() as called.
 *
 * Returned Value:
 *   OK on success
 *
 * Assumptions:
 *   Run on a work queue thread.
 *
 ****************************************************************************/

static void ivshmnet_poll_work(FAR void *arg)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)arg;

  /* Lock the network and serialize driver operations if necessary.
   * NOTE: Serialization is only required in the case where the driver work
   * is performed on an LP worker thread and where more than one LP worker
   * thread has been configured.
   */

  net_lock();

  /* Perform the poll */

  /* Check if there is room in the send another TX packet.  We cannot perform
   * the TX poll if he are unable to accept another packet for transmission.
   */

  /* If so, update TCP timing states and poll the network for new XMIT data.
   * Hmmm.. might be bug here.  Does this mean if there is a transmit in
   * progress, we will missing TCP time state updates?
   */

  (void)devif_timer(&priv->sk_dev, ivshmnet_txpoll);

  /* Setup the watchdog poll timer again */

  (void)wd_start(priv->sk_txpoll, IVSHMEM_NET_WDDELAY, ivshmnet_poll_expiry, 1,
                 (wdparm_t)priv);
  net_unlock();
}

/****************************************************************************
 * Name: ivshmnet_poll_expiry
 *
 * Description:
 *   Periodic timer handler.  Called from the timer interrupt handler.
 *
 * Input Parameters:
 *   argc - The number of available arguments
 *   arg  - The first argument
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   Runs in the context of a the timer interrupt handler.  Local
 *   interrupts are disabled by the interrupt logic.
 *
 ****************************************************************************/

static void ivshmnet_poll_expiry(int argc, wdparm_t arg, ...)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)arg;

  /* Schedule to perform the interrupt processing on the worker thread. */

  work_queue(ETHWORK, &priv->sk_pollwork, ivshmnet_poll_work, priv, 0);
}

/****************************************************************************
 * Name: ivshmnet_ifup
 *
 * Description:
 *   NuttX Callback: Bring up the Ethernet interface when an IP address is
 *   provided
 *
 * Input Parameters:
 *   dev - Reference to the NuttX driver state structure
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static int ivshmnet_ifup(FAR struct net_driver_s *dev)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)dev->d_private;

#ifdef CONFIG_NET_IPv4
  ninfo("Bringing up: %d.%d.%d.%d\n",
        dev->d_ipaddr & 0xff, (dev->d_ipaddr >> 8) & 0xff,
        (dev->d_ipaddr >> 16) & 0xff, dev->d_ipaddr >> 24);
#endif
#ifdef CONFIG_NET_IPv6
  ninfo("Bringing up: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
        dev->d_ipv6addr[0], dev->d_ipv6addr[1], dev->d_ipv6addr[2],
        dev->d_ipv6addr[3], dev->d_ipv6addr[4], dev->d_ipv6addr[5],
        dev->d_ipv6addr[6], dev->d_ipv6addr[7]);
#endif

  /* init states here */
  /* Changing the lstate will kick start the sequence of INIT in state machine */
  /* Initialize PHYs, the Ethernet interface, and setup up Ethernet interrupts */

  priv->rstate = priv->shm[IVSHM_NET_REGION_TX];

  /* First make sure that rstate writing is disabled. */
  (priv->ivshm_regs->rstate_write_lo) = 0;
  (priv->ivshm_regs->rstate_write_hi) = 0;

  (priv->ivshm_regs->rstate_write_lo) = 0x0 | IVSHMEM_RSTATE_WRITE_REGION1 | IVSHMEM_RSTATE_WRITE_ENABLE;

  (priv->ivshm_regs->lstate) = IVSHM_NET_STATE_RESET;

  ivshm_net_check_state(priv);

  /* Instantiate the MAC address from priv->sk_dev.d_mac.ether.ether_addr_octet */

#ifdef CONFIG_NET_ICMPv6
  /* Set up IPv6 multicast address filtering */

  ivshmnet_ipv6multicast(priv);
#endif

  /* Set and activate a timer process */

  (void)wd_start(priv->sk_txpoll, IVSHMEM_NET_WDDELAY, ivshmnet_poll_expiry, 1,
                 (wdparm_t)priv);

  /* Enable the Ethernet interrupt */

  /*up_enable_irq(CONFIG_IVSHMEM_NET_IRQ);*/
  return OK;
}

/****************************************************************************
 * Name: ivshmnet_ifdown
 *
 * Description:
 *   NuttX Callback: Stop the interface.
 *
 * Input Parameters:
 *   dev - Reference to the NuttX driver state structure
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static int ivshmnet_ifdown(FAR struct net_driver_s *dev)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)dev->d_private;
  irqstate_t flags;

  /* Disable the Ethernet interrupt */

  flags = enter_critical_section();
  /*up_disable_irq(CONFIG_IVSHMEM_NET_IRQ);*/

  (priv->ivshm_regs->lstate) = IVSHM_NET_STATE_RESET;

  /* Cancel the TX poll timer and TX timeout timers */

  wd_cancel(priv->sk_txpoll);
  wd_cancel(priv->sk_txtimeout);

  /* Put the EMAC in its reset, non-operational state.  This should be
   * a known configuration that will guarantee the ivshmnet_ifup() always
   * successfully brings the interface back up.
   */

  /* Mark the device "down" */

  priv->sk_bifup = false;
  leave_critical_section(flags);
  return OK;
}

/****************************************************************************
 * Name: ivshmnet_txavail_work
 *
 * Description:
 *   Perform an out-of-cycle poll on the worker thread.
 *
 * Input Parameters:
 *   arg - Reference to the NuttX driver state structure (cast to void*)
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   Runs on a work queue thread.
 *
 ****************************************************************************/

static void ivshmnet_txavail_work(FAR void *arg)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)arg;

  /* Lock the network and serialize driver operations if necessary.
   * NOTE: Serialization is only required in the case where the driver work
   * is performed on an LP worker thread and where more than one LP worker
   * thread has been configured.
   */

  net_lock();

  /* Ignore the notification if the interface is not yet up */

  if (priv->sk_bifup)
    {
      /* Check if there is room in the hardware to hold another outgoing packet. */

      /* If so, then poll the network for new XMIT data */

      (void)devif_poll(&priv->sk_dev, ivshmnet_txpoll);
    }

  net_unlock();
}

/****************************************************************************
 * Name: ivshmnet_txavail
 *
 * Description:
 *   Driver callback invoked when new TX data is available.  This is a
 *   stimulus perform an out-of-cycle poll and, thereby, reduce the TX
 *   latency.
 *
 * Input Parameters:
 *   dev - Reference to the NuttX driver state structure
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static int ivshmnet_txavail(FAR struct net_driver_s *dev)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)dev->d_private;

  /* Is our single work structure available?  It may not be if there are
   * pending interrupt actions and we will have to ignore the Tx
   * availability action.
   */

  if (work_available(&priv->sk_pollwork))
    {
      /* Schedule to serialize the poll on the worker thread. */

      work_queue(ETHWORK, &priv->sk_pollwork, ivshmnet_txavail_work, priv, 0);
    }

  return OK;
}

/****************************************************************************
 * Name: ivshmnet_addmac
 *
 * Description:
 *   NuttX Callback: Add the specified MAC address to the hardware multicast
 *   address filtering
 *
 * Input Parameters:
 *   dev  - Reference to the NuttX driver state structure
 *   mac  - The MAC address to be added
 *
 * Returned Value:
 *   Zero (OK) on success; a negated errno value on failure.
 *
 ****************************************************************************/

#if defined(CONFIG_NET_IGMP) || defined(CONFIG_NET_ICMPv6)
static int ivshmnet_addmac(FAR struct net_driver_s *dev, FAR const uint8_t *mac)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)dev->d_private;

  /* Add the MAC address to the hardware multicast routing table */

  return OK;
}
#endif

/****************************************************************************
 * Name: ivshmnet_rmmac
 *
 * Description:
 *   NuttX Callback: Remove the specified MAC address from the hardware multicast
 *   address filtering
 *
 * Input Parameters:
 *   dev  - Reference to the NuttX driver state structure
 *   mac  - The MAC address to be removed
 *
 * Returned Value:
 *   Zero (OK) on success; a negated errno value on failure.
 *
 ****************************************************************************/

#ifdef CONFIG_NET_IGMP
static int ivshmnet_rmmac(FAR struct net_driver_s *dev, FAR const uint8_t *mac)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)dev->d_private;

  /* Add the MAC address to the hardware multicast routing table */

  return OK;
}
#endif

/****************************************************************************
 * Name: ivshmnet_ipv6multicast
 *
 * Description:
 *   Configure the IPv6 multicast MAC address.
 *
 * Input Parameters:
 *   priv - A reference to the private driver state structure
 *
 * Returned Value:
 *   Zero (OK) on success; a negated errno value on failure.
 *
 ****************************************************************************/

#ifdef CONFIG_NET_ICMPv6
static void ivshmnet_ipv6multicast(FAR struct ivshmnet_driver_s *priv)
{
  FAR struct net_driver_s *dev;
  uint16_t tmp16;
  uint8_t mac[6];

  /* For ICMPv6, we need to add the IPv6 multicast address
   *
   * For IPv6 multicast addresses, the Ethernet MAC is derived by
   * the four low-order octets OR'ed with the MAC 33:33:00:00:00:00,
   * so for example the IPv6 address FF02:DEAD:BEEF::1:3 would map
   * to the Ethernet MAC address 33:33:00:01:00:03.
   *
   * NOTES:  This appears correct for the ICMPv6 Router Solicitation
   * Message, but the ICMPv6 Neighbor Solicitation message seems to
   * use 33:33:ff:01:00:03.
   */

  mac[0] = 0x33;
  mac[1] = 0x33;

  dev    = &priv->dev;
  tmp16  = dev->d_ipv6addr[6];
  mac[2] = 0xff;
  mac[3] = tmp16 >> 8;

  tmp16  = dev->d_ipv6addr[7];
  mac[4] = tmp16 & 0xff;
  mac[5] = tmp16 >> 8;

  ninfo("IPv6 Multicast: %02x:%02x:%02x:%02x:%02x:%02x\n",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  (void)ivshmnet_addmac(dev, mac);

#ifdef CONFIG_NET_ICMPv6_AUTOCONF
  /* Add the IPv6 all link-local nodes Ethernet address.  This is the
   * address that we expect to receive ICMPv6 Router Advertisement
   * packets.
   */

  (void)ivshmnet_addmac(dev, g_ipv6_ethallnodes.ether_addr_octet);

#endif /* CONFIG_NET_ICMPv6_AUTOCONF */

#ifdef CONFIG_NET_ICMPv6_ROUTER
  /* Add the IPv6 all link-local routers Ethernet address.  This is the
   * address that we expect to receive ICMPv6 Router Solicitation
   * packets.
   */

  (void)ivshmnet_addmac(dev, g_ipv6_ethallrouters.ether_addr_octet);

#endif /* CONFIG_NET_ICMPv6_ROUTER */
}
#endif /* CONFIG_NET_ICMPv6 */

/****************************************************************************
 * Name: ivshmnet_ioctl
 *
 * Description:
 *   Handle network IOCTL commands directed to this device.
 *
 * Input Parameters:
 *   dev - Reference to the NuttX driver state structure
 *   cmd - The IOCTL command
 *   arg - The argument for the IOCTL command
 *
 * Returned Value:
 *   OK on success; Negated errno on failure.
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

#ifdef CONFIG_NETDEV_IOCTL
static int ivshmnet_ioctl(FAR struct net_driver_s *dev, int cmd,
                      unsigned long arg)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)dev->d_private;
  int ret;

  /* Decode and dispatch the driver-specific IOCTL command */

  switch (cmd)
    {
      /* Add cases here to support the IOCTL commands */

      default:
        nerr("ERROR: Unrecognized IOCTL command: %d\n", command);
        return -ENOTTY;  /* Special return value for this case */
    }

  return OK;
}
#endif

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: ivshmnet_initialize
 *
 * Description:
 *   Initialize the Ethernet controller and driver
 *
 * Input Parameters:
 *   intf - In the case where there are multiple EMACs, this value
 *          identifies which EMAC is to be initialized.
 *
 * Returned Value:
 *   OK on success; Negated errno on failure.
 *
 * Assumptions:
 *   Called early in initialization before multi-tasking is initiated.
 *
 ****************************************************************************/

int ivshmnet_initialize(int intf)
{
  FAR struct ivshmnet_driver_s *priv;
  int bdf = 0;

  /* Get the interface structure associated with this interface number. */

  DEBUGASSERT(intf < CONFIG_IVSHMEM_NET_NINTERFACES);
  priv = &g_ivshmnet[intf];

  /* Initialize the driver structure */
  memset(priv, 0, sizeof(struct ivshmnet_driver_s));

  /* Check if a Ethernet chip is recognized at its I/O base */
  while ((-1 != (bdf = pci_find_device(VENDORID, DEVICEID, bdf)))) {
    _info("Found %04x:%04x at %02x:%02x.%x\n",
           pci_read_config(bdf, PCI_CFG_VENDOR_ID, 2),
           pci_read_config(bdf, PCI_CFG_DEVICE_ID, 2),
           bdf >> 8, (bdf >> 3) & 0x1f, bdf & 0x3);

    int class_rev = pci_read_config(bdf, 0x8, 4);

    if (class_rev != (PCI_DEV_CLASS_OTHER << 24 |
        JAILHOUSE_SHMEM_PROTO_VETH << 16 | JAILHOUSE_IVSHMEM_REVERSION)) {
      _info("class/revision %08x, not supported "
            "skipping device\n", class_rev);
      bdf++;
      continue;
    }

    priv->bdf = bdf;
    map_veth_shmem_and_bars(priv);
    _info("mapped the bars got position %d\n", priv->ivshm_regs->id);

    //XXX: conflict with pre-existing x86 IRQ number?
    (void)irq_attach(IRQ10, (xcpt_t)ivshmnet_state_handler, priv);
    (void)irq_attach(IRQ11, (xcpt_t)ivshmnet_interrupt, priv);
    pci_msix_set_vector(bdf, IRQ10, 0);
    pci_msix_set_vector(bdf, IRQ11, 1);

    priv->peer_id = !priv->ivshm_regs->id;

    bdf++;
  }

  if (ivshm_net_calc_qsize(priv))
      return -EINVAL;

  /* fill in the rest of the structure */
  priv->sk_dev.d_buf     = g_pktbuf;          /* Single packet buffer */
  priv->sk_dev.d_ifup    = ivshmnet_ifup;     /* I/F up (new IP address) callback */
  priv->sk_dev.d_ifdown  = ivshmnet_ifdown;   /* I/F down callback */
  priv->sk_dev.d_txavail = ivshmnet_txavail;  /* New TX data callback */
#ifdef CONFIG_NET_IGMP
  priv->sk_dev.d_addmac  = ivshmnet_addmac;   /* Add multicast MAC address */
  priv->sk_dev.d_rmmac   = ivshmnet_rmmac;    /* Remove multicast MAC address */
#endif
#ifdef CONFIG_NETDEV_IOCTL
  priv->sk_dev.d_ioctl   = ivshmnet_ioctl;    /* Handle network IOCTL commands */
#endif
  priv->sk_dev.d_private = (void *)priv; /* Used to recover private state from dev */

  /* Create a watchdog for timing polling for and timing of transmissions */

  priv->sk_txpoll        = wd_create();   /* Create periodic poll timer */
  priv->sk_txtimeout     = wd_create();   /* Create TX timeout timer */

  DEBUGASSERT(priv->sk_txpoll != NULL && priv->sk_txtimeout != NULL);

  /* Put the interface in the down state.  This usually amounts to resetting
   * the device and/or calling ivshmnet_ifdown().
   */
  priv->sk_bifup = false;

  /* Read the MAC address from the hardware into priv->sk_dev.d_mac.ether.ether_addr_octet
   * Applies only if the Ethernet MAC has its own internal address.
   */
  uint64_t mac = CONFIG_IVSHMEM_NET_MAC_ADDR;
  memcpy(priv->sk_dev.d_mac.ether.ether_addr_octet, (void *)(&mac), 6);

  /* Register the device with the OS so that socket IOCTLs can be performed */

  (void)netdev_register(&priv->sk_dev, NET_LL_ETHERNET);
  return OK;
}

#endif /* CONFIG_NET_IVSHMEM_NET */
