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
#include <nuttx/pcie/pcie.h>

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <debug.h>

#include <nuttx/arch.h>
#include <nuttx/irq.h>
#include <nuttx/wdog.h>
#include <nuttx/wqueue.h>
#include <nuttx/net/arp.h>
#include <nuttx/net/netdev.h>

#include <arch/io.h>
#include <arch/irq.h>

#include "sched/sched.h"
#include <arch/board/jailhouse_ivshmem.h>
#include <arch/board/shadow.h>
#include <arch/board/virtio_ring.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define IVSHM_ALIGN(addr, align) (((addr) + (align - 1)) & ~(align - 1))

#define SMP_CACHE_BYTES 64

#define JAILHOUSE_SHMEM_PROTO_VETH 0x1

#define SHADOW_PROC_RSTATE_WRITE_ENABLE	(1ULL << 0)
#define SHADOW_PROC_RSTATE_WRITE_REGION1	(1ULL << 1)

#define SHADOW_PROC_MTU_MIN 256
#define SHADOW_PROC_MTU_DEF 512

#define SHADOW_PROC_FRAME_SIZE(s) IVSHM_ALIGN(18 + (s), SMP_CACHE_BYTES)

#define SHADOW_PROC_VQ_ALIGN 64

#define SHADOW_PROC_REGION_TX		0
#define SHADOW_PROC_REGION_RX		1

#define SHADOW_PROC_VECTOR_STATE		0
#define SHADOW_PROC_VECTOR_TX_RX		1
#define SHADOW_PROC_VECTOR_OK		2

#define SHADOW_PROC_NUM_VECTORS		2

/*struct shadow_proc_driver_s *aux_shadow = 0;*/

/*****************************************
 *  ivshmem-net vring support functions  *
 *****************************************/

void *shadow_proc_desc_data(
        struct shadow_proc_driver_s *in, struct shadow_proc_queue *q,
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

void shadow_proc_init_queue(
        struct shadow_proc_driver_s *in, struct shadow_proc_queue *q,
        void *mem, unsigned int len)
{
    memset(q, 0, sizeof(*q));

    vring_init(&q->vr, len, mem, SHADOW_PROC_VQ_ALIGN);
    q->data = mem + in->vrsize;
    q->end = q->data + in->qsize;
    q->size = in->qsize;
}

void shadow_proc_init_queues(struct shadow_proc_driver_s *in)
{
    void *tx;
    void *rx;
    int i;
    void* tmp;

    tx = in->shm[SHADOW_PROC_REGION_TX] + 4;
    rx = in->shm[SHADOW_PROC_REGION_RX] + 4;

    memset(tx, 0, in->shmlen - 4);

    shadow_proc_init_queue(in, &in->tx, tx, in->qlen);
    shadow_proc_init_queue(in, &in->rx, rx, in->qlen);

    tmp = in->rx.vr.used;
    in->rx.vr.used = in->tx.vr.used;
    in->tx.vr.used = tmp;

    in->tx.num_free = in->tx.vr.num;

    _info("TX free: %d\n", in->tx.num_free);

    for (i = 0; i < in->tx.vr.num - 1; i++)
        in->tx.vr.desc[i].next = i + 1;
}

int shadow_proc_calc_qsize(struct shadow_proc_driver_s *in)
{
    unsigned int vrsize;
    unsigned int qsize;
    unsigned int qlen;

    for (qlen = 4096; qlen > 32; qlen >>= 1) {
        vrsize = vring_size(qlen, SHADOW_PROC_VQ_ALIGN);
        vrsize = IVSHM_ALIGN(vrsize, SHADOW_PROC_VQ_ALIGN);
        if (vrsize < (in->shmlen - 4) / 8)
            break;
    }

    if (vrsize > in->shmlen - 4)
        return -EINVAL;

    qsize = in->shmlen - 4 - vrsize;

    if (qsize < 4 * SHADOW_PROC_MTU_DEF)
        return -EINVAL;

    in->vrsize = vrsize;
    in->qlen = qlen;
    in->qsize = qsize;

    return 0;
}

/*****************************************
 *  ivshmem-net IRQ support functions  *
 *****************************************/

void shadow_proc_notify_tx(struct shadow_proc_driver_s *in, unsigned int num)
{
    /*uint16_t evt, old, new;*/

    /*mb();*/

    /*evt = READ_ONCE(vring_avail_event(&in->tx.vr));*/
    /*old = in->tx.last_avail_idx - num;*/
    /*new = in->tx.last_avail_idx;*/

    /*if (vring_need_event(evt, new, old)) {*/
    in->ivshm_regs->doorbell = SHADOW_PROC_VECTOR_TX_RX;
    /*}*/
}

void shadow_proc_enable_rx_irq(struct shadow_proc_driver_s *in)
{
    vring_avail_event(&in->rx.vr) = in->rx.last_avail_idx;
    wmb();
}

void shadow_proc_notify_rx(struct shadow_proc_driver_s *in, unsigned int num)
{
    uint16_t evt, old, new;

    /*mb();*/

    /*evt = vring_used_event(&in->rx.vr);*/
    /*old = in->rx.last_used_idx - num;*/
    /*new = in->rx.last_used_idx;*/

    /*if (vring_need_event(evt, new, old)) {*/
    in->ivshm_regs->doorbell = SHADOW_PROC_VECTOR_TX_RX;
    mb();
    /*}*/
}

void shadow_proc_enable_tx_irq(struct shadow_proc_driver_s *in)
{
    vring_used_event(&in->tx.vr) = in->tx.last_used_idx;
    wmb();
}

void shadow_proc_set_prio(struct shadow_proc_driver_s *in, uint64_t prio)
{
    return;
  *((volatile uint64_t*)(in->shm[SHADOW_PROC_REGION_TX] + in->shmlen)) = prio;
  wmb();
}

/*************************************
 *  ivshmem-net vring syntax sugars  *
 *************************************/

struct vring_desc *shadow_proc_rx_desc(struct shadow_proc_driver_s *in)
{
    struct shadow_proc_queue *rx = &in->rx;
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

bool shadow_proc_rx_avail(struct shadow_proc_driver_s *in)
{
    mb();
    return READ_ONCE(in->rx.vr.avail->idx) != in->rx.last_avail_idx;
}

void shadow_proc_rx_finish(struct shadow_proc_driver_s *in, struct vring_desc *desc)
{
    struct shadow_proc_queue *rx = &in->rx;
    struct vring *vr = &rx->vr;
    unsigned int desc_id = desc - vr->desc;
    unsigned int used;

    used = rx->last_used_idx++ & (vr->num - 1);
    vr->used->ring[used].id = desc_id;
    vr->used->ring[used].len = 1;

    virt_store_release(&vr->used->idx, rx->last_used_idx);
}

size_t shadow_proc_tx_space(struct shadow_proc_driver_s *in)
{
    struct shadow_proc_queue *tx = &in->tx;
    uint32_t tail = tx->tail;
    uint32_t head = tx->head;
    uint32_t space;

    if (head < tail)
        space = tail - head;
    else
        space = (tx->size - head) > tail ? (tx->size - head) : tail;

    return space;
}

bool shadow_proc_tx_ok(struct shadow_proc_driver_s *in, unsigned int mtu)
{
    return in->tx.num_free >= 2 &&
        shadow_proc_tx_space(in) >= 2 * SHADOW_PROC_FRAME_SIZE(mtu);
}

uint32_t shadow_proc_tx_advance(struct shadow_proc_queue *q, uint32_t *pos, uint32_t len)
{
    uint32_t p = *pos;

    len = SHADOW_PROC_FRAME_SIZE(len);

    if (q->size - p < len)
        p = 0;
    *pos = p + len;

    return p;
}

int shadow_proc_tx_frame(struct shadow_proc_driver_s *in, void* data, int len)
{
    struct shadow_proc_queue *tx = &in->tx;
    struct vring *vr = &tx->vr;
    struct vring_desc *desc;
    unsigned int desc_idx;
    unsigned int avail;
    uint32_t head;
    void *buf;
    irqstate_t flags;


    shadow_proc_tx_clean(in);
    if(tx->num_free < 1) {
        _err("tx exhausted!\n");
        _err("%d %d %d\n", tx->num_free, vr->used->idx, tx->last_used_idx);
        ASSERT(0);
    }

    flags = enter_critical_section();

    desc_idx = tx->free_head;
    desc = &vr->desc[desc_idx];
    tx->free_head = desc->next;
    tx->num_free--;

    leave_critical_section(flags);

    head = shadow_proc_tx_advance(tx, &tx->head, len);

    buf = tx->data + head;
    memcpy(buf, data, len);

    desc->addr = buf - in->shm[SHADOW_PROC_REGION_TX];
    desc->len = len;
    desc->flags = 0;

    avail = tx->last_avail_idx++ & (vr->num - 1);
    vr->avail->ring[avail] = desc_idx;
    tx->num_added++;

    virt_store_release(&vr->avail->idx, tx->last_avail_idx);
    shadow_proc_notify_tx(in, tx->num_added);
    tx->num_added = 0;

    return 0;
}

void shadow_proc_tx_clean(struct shadow_proc_driver_s *in)
{
    struct shadow_proc_queue *tx = &in->tx;
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

    if(tx->num_free < 1) {
        _err("%d %d\n", vr->used->idx, tx->last_used_idx);
    }

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

        data = shadow_proc_desc_data(in, &in->tx, SHADOW_PROC_REGION_TX,
                       desc, &len);
        if (!data) {
            _err("bad tx descriptor, data == NULL\n");
            break;
        }

        tail = shadow_proc_tx_advance(tx, &tx->tail, len);
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

    if(tx->num_free < 512)
        _info("c\n");
}

/*****************************************
 *  ivshmem-net support functions  *
 *****************************************/

void shadow_proc_run(struct shadow_proc_driver_s *in)
{
  irqstate_t flags;

  if (in->lstate < SHADOW_PROC_STATE_READY)
    return;

  /* test_and_set_bit */
  flags = enter_critical_section();
  if(in->flags & SHADOW_PROC_FLAG_RUN){
    in->flags |= SHADOW_PROC_FLAG_RUN;
    leave_critical_section(flags);
    return;
  }

  in->flags |= SHADOW_PROC_FLAG_RUN;
  leave_critical_section(flags);

  shadow_proc_set_state(in, SHADOW_PROC_STATE_RUN);

  /* Enable rx interrupts */
  shadow_proc_enable_rx_irq(in);

  return;
}

void shadow_proc_do_stop(struct shadow_proc_driver_s *in)
{
  irqstate_t flags;

  shadow_proc_set_state(in, SHADOW_PROC_STATE_RESET);

  /* test_and_clear_bit */
  flags = enter_critical_section();
  if(!(in->flags & SHADOW_PROC_FLAG_RUN)){
    in->flags &= ~SHADOW_PROC_FLAG_RUN;
    leave_critical_section(flags);
    return;
  }

  in->flags &= ~SHADOW_PROC_FLAG_RUN;
  leave_critical_section(flags);

  return;
}

/****************************************************************************
 * State Machine
 ****************************************************************************/

void shadow_proc_state_change(void *arg)
{
  struct shadow_proc_driver_s *in = (struct shadow_proc_driver_s*)arg;
  uint32_t rstate = READ_ONCE(*in->rstate);

  _info("R State: %d\n", rstate);

  switch (in->lstate) {
  case SHADOW_PROC_STATE_RESET:
    if (rstate < SHADOW_PROC_STATE_READY)
        shadow_proc_set_state(in, SHADOW_PROC_STATE_INIT);
    break;

  case SHADOW_PROC_STATE_INIT:
    if (rstate > SHADOW_PROC_STATE_RESET) {
        shadow_proc_init_queues(in);
        shadow_proc_set_state(in, SHADOW_PROC_STATE_READY);
    }
    break;

  case SHADOW_PROC_STATE_READY:
  case SHADOW_PROC_STATE_RUN:
    if (rstate >= SHADOW_PROC_STATE_READY) {
        shadow_proc_run(in);
        /*aux_shadow = in;*/
    } else {
        /*aux_shadow = 0;*/
        shadow_proc_do_stop(in);
    }
    break;
  }

  wmb();
  WRITE_ONCE(in->last_rstate, rstate);
}

void shadow_proc_set_state(struct shadow_proc_driver_s *in, uint32_t state)
{
  wmb();
  WRITE_ONCE(in->lstate, state);
  WRITE_ONCE(in->ivshm_regs->lstate,  state);
}

void shadow_proc_check_state(struct shadow_proc_driver_s *in)
{
  irqstate_t flags;

  /* test_bit */
  flags = enter_critical_section();

  if (*in->rstate != in->last_rstate || !(SHADOW_PROC_FLAG_RUN & in->flags)){
    work_queue(LPWORK, &in->sk_statework, shadow_proc_state_change, in, 0);
  }

  leave_critical_section(flags);
}

void shadow_proc_write_curr_prio(void *in, uint64_t prio)
{
  struct shadow_proc_driver_s *priv = in;
  irqstate_t flags;

  /* test_bit */
  flags = enter_critical_section();

  *(volatile uint64_t*)(priv->shm[SHADOW_PROC_REGION_TX] + priv->shmlen) = prio;

  wmb();

  leave_critical_section(flags);
}

/****************************************************************************
 * State IRQ Handlers
 ****************************************************************************/

int shadow_proc_state_handler(int irq, uint32_t *regs, void *arg)
{
  struct shadow_proc_driver_s *priv = arg;

  shadow_proc_check_state(priv);

  return 0;
}

/****************************************************************************
 * Name: shadow_proc_transmit
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

uint64_t shadow_proc_transmit(FAR struct shadow_proc_driver_s *priv, uint64_t *data)
{
  /* Verify that the hardware is ready to send another packet.  If we get
   * here, then we are committed to sending a packet; Higher level logic
   * must have assured that there is no transmission in progress.
   */
  uint64_t buf[10];
  struct tcb_s *rtcb = (struct tcb_s *)this_task();
  long ret;
  irqstate_t flags;

  memcpy(buf, data, sizeof(uint64_t) * 7);
  buf[7] = (uint64_t)rtcb;
  buf[8] = rtcb->sched_priority;
  buf[9] = rtcb->xcp.linux_tcb;

  shadow_proc_tx_frame(priv, buf, sizeof(buf));

  flags = enter_critical_section();

  do {
    ret = nxsem_wait(&rtcb->xcp.syscall_lock);
  }while(ret);

  ret = rtcb->xcp.syscall_ret;
  leave_critical_section(flags);

  return ret;
}

/****************************************************************************
 * Name: shadow_proc_receive
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

void shadow_proc_receive(FAR struct shadow_proc_driver_s *priv, uint64_t *buf)
{
  struct vring_desc *desc;
  void *data;
  uint32_t len;

  desc = shadow_proc_rx_desc(priv); /* get next avail rx descriptor from avail ring */
  if (!desc)
    return;

  data = shadow_proc_desc_data(priv, &priv->rx, SHADOW_PROC_REGION_RX,
               desc, &len); /* Unpack descriptor and get the physical address in SHMEM and fill in len */
  if (!data) {
    _err("bad rx descriptor\n");
    return;
  }

  memcpy(buf, data, sizeof(uint64_t) * 3);

  shadow_proc_rx_finish(priv, desc); /* Release the read descriptor in to the used ring */
  return;
}

/****************************************************************************
 * Name: shadow_proc_interrupt
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

int shadow_proc_interrupt(int irq, FAR void *context, FAR void *arg)
{
  FAR struct shadow_proc_driver_s *priv = (FAR struct shadow_proc_driver_s *)arg;
  uint64_t buf[3];
  struct tcb_s *rtcb;

  DEBUGASSERT(priv != NULL);

  memset(buf, 0, sizeof(buf));
  shadow_proc_receive(priv, buf);

  rtcb = (struct tcb_s *)buf[2];

  if(rtcb){
    rtcb->xcp.syscall_ret = buf[0];
    nxsem_post(&rtcb->xcp.syscall_lock);
  }

  shadow_proc_enable_rx_irq(priv);

  return OK;
}

int shadow_proc_ok(int irq, FAR void *context, FAR void *arg)
{
  _info("RECV OK\n");
  return OK;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: shadow_proc_initialize
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

typedef FAR struct file        file_t;

static int shadow_proc_open(file_t *filep)
{
    return OK;
}

static int shadow_proc_close(file_t *filep)
{

    return OK;
}

static int shadow_proc_ioctl(file_t *filep, int cmd, unsigned long arg)
{
    struct inode              *inode;
    struct shadow_proc_driver_s   *priv;
    int                        size;
    uint64_t ret;

    if(cmd != 0) return -1;

    DEBUGASSERT(filep);
    inode = filep->f_inode;

    DEBUGASSERT(inode && inode->i_private);
    priv  = (struct shadow_proc_driver_s *)inode->i_private;

    shadow_proc_write_curr_prio(priv, arg);

    return 0;

}

static off_t shadow_proc_seek(file_t *filep, off_t offset, int whence)
{
    return 0;
}

static ssize_t shadow_proc_read(file_t *filep, FAR char *buf, size_t buflen)
{
    return 0;
}

static ssize_t shadow_proc_write(file_t *filep, FAR const char *buf, size_t buflen)
{
    struct inode              *inode;
    struct shadow_proc_driver_s   *priv;
    int                        size;
    uint64_t ret;

    DEBUGASSERT(filep);
    inode = filep->f_inode;

    DEBUGASSERT(inode && inode->i_private);
    priv  = (struct shadow_proc_driver_s *)inode->i_private;

    ret = shadow_proc_transmit(priv, buf);
    ((uint64_t*)buf)[0] = ret;

    return ret;
}

static const struct file_operations shadow_proc_ops = {
    shadow_proc_open,      /* open */
    shadow_proc_close,     /* close */
    shadow_proc_read,      /* read */
    shadow_proc_write,     /* write */
    shadow_proc_seek,      /* seek */
    shadow_proc_ioctl,     /* ioctl */
};

int shadow_proc_probe(uint16_t bdf)
{
  static int inited = 0;
  FAR struct shadow_proc_driver_s *priv;
  uint64_t shmlen[2];
  uint64_t cap_pos;
  void* bar2mem;

  if (pci_find_cap(bdf, PCI_CAP_MSIX) < 0)
    {
      _err("device is not MSI-X capable\n");
      return -EINVAL;
    }

  if(inited == 1) return -EINVAL;
  inited = 1;

  /* Get the interface structure associated with this interface number. */

  DEBUGASSERT(intf < CONFIG_shadow_proc_NINTERFACES);
  priv = &g_shadow_proc[0];

  /* Initialize the driver structure */
  memset(priv, 0, sizeof(struct shadow_proc_driver_s));

  priv->bdf = bdf;

  for (int region = 0; region < 2; region++)
    {
      cap_pos = IVSHMEM_CFG_SHMEM_ADDR + (region + 1) * 16;
      priv->shm[region] = (void*)pci_cfg_read64(priv->bdf, cap_pos);

      cap_pos = IVSHMEM_CFG_SHMEM_SIZE + (region + 1) * 16;
      shmlen[region] = pci_cfg_read64(priv->bdf, cap_pos);

      up_map_region(priv->shm[region], shmlen[region], 0x10);

      _info("%s memory at %016llp, size %08llx\n",
           region == SHADOW_PROC_REGION_TX ? "TX" : "RX",
           priv->shm[region], shmlen[region]);
    }

  priv->shmlen = shmlen[0] < shmlen[1] ? shmlen[0] : shmlen[1];
  priv->shmlen -= PAGE_SIZE;

  priv->ivshm_regs = (struct ivshmem_regs *)pci_alloc_mem_region(PAGE_SIZE);
  bar2mem = pci_alloc_mem_region(PAGE_SIZE);

  pci_set_bar64(bdf, 0, (uint64_t)priv->ivshm_regs);
  pci_set_bar64(bdf, 2, (uint64_t)bar2mem);

  pci_enable_device(priv->bdf, (PCI_CMD_MEM | PCI_CMD_MASTER));

  _info("mapped the bars got position %d\n", priv->ivshm_regs->id);

  (void)irq_attach(IRQ11, (xcpt_t)shadow_proc_state_handler, priv);
  (void)irq_attach(IRQ12, (xcpt_t)shadow_proc_interrupt, priv);
  (void)irq_attach(IRQ13, (xcpt_t)shadow_proc_ok, priv);
  pci_msix_set_vector(bdf, IRQ11, 0);
  pci_msix_set_vector(bdf, IRQ12, 1);
  pci_msix_set_vector(bdf, IRQ13, 2);
  priv->peer_id = !priv->ivshm_regs->id;

  if (shadow_proc_calc_qsize(priv))
      return -EINVAL;

  /* init states here */
  /* Changing the lstate will kick start the sequence of INIT in state machine */
  /* Initialize PHYs, the Ethernet interface, and setup up Ethernet interrupts */

  priv->rstate = priv->shm[SHADOW_PROC_REGION_TX];

  /* First make sure that rstate writing is disabled. */
  (priv->ivshm_regs->rstate_write_lo) = 0;
  (priv->ivshm_regs->rstate_write_hi) = 0;

  (priv->ivshm_regs->rstate_write_lo) = 0x0 | SHADOW_PROC_RSTATE_WRITE_REGION1 | SHADOW_PROC_RSTATE_WRITE_ENABLE;

  (priv->ivshm_regs->lstate) = SHADOW_PROC_STATE_RESET;

  shadow_proc_check_state(priv);

  char buf[64];
  sprintf(buf, "/dev/shadow%d", 0);
  int ret = register_driver(buf, &shadow_proc_ops, 0444, priv);
  if(ret){
    _info("SHADOW %s register failed with errno=%d\n", buf, ret);
    PANIC();
  };

  gshadow = priv;
  shadow_proc_set_prio(priv, this_task()->sched_priority);

  return OK;
}

struct pcie_dev_t pci_shadow_proc = {
    .vendor = VENDORID,
    .device = DEVICEID,
    .class_rev = (PCI_DEV_CLASS_OTHER << 24 |
          0xff00 << 8 | JAILHOUSE_IVSHMEM_REVERSION),
    .probe = shadow_proc_probe
};

void up_shadow_proc(void)
{
  pci_register(&pci_shadow_proc);
}
