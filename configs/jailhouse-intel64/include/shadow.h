#ifndef __JAILHOUSE_INCLUDE_SHADOW_H
#define __JAILHOUSE_INCLUDE_SHADOW_H


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
#include <arch/board/virtio_ring.h>

#define SHADOW_PROC_FLAG_RUN	1

#define SHADOW_PROC_STATE_RESET		0
#define SHADOW_PROC_STATE_INIT		1
#define SHADOW_PROC_STATE_READY		2
#define SHADOW_PROC_STATE_RUN		3

/* Abstracted vring structure */

struct shadow_proc_queue {
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

/* The shadow_proc_driver_s encapsulates all state information for a single hardware
 * interface
 */

struct shadow_proc_driver_s
{
  /* Nuttx stuff */
  struct work_s sk_irqwork;    /* For deferring interrupt work to the work queue */

  /* driver specific */
  struct work_s sk_statework;    /* For deferring interrupt work to the work queue */

  uint32_t bdf;

  struct shadow_proc_queue rx;
  struct shadow_proc_queue tx;

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
};

/****************************************************************************
 * Private Data
 ****************************************************************************/

/* Driver state structure */

static struct shadow_proc_driver_s g_shadow_proc[1];

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

/* ivshm-net */

void shadow_proc_state_change(void *in);
void shadow_proc_set_state(struct shadow_proc_driver_s *in, uint32_t state);
void shadow_proc_check_state(struct shadow_proc_driver_s *in);

/* Common TX logic */

uint64_t  shadow_proc_transmit(FAR struct shadow_proc_driver_s *priv, uint64_t *buf);
int  shadow_proc_txpoll(FAR struct net_driver_s *dev);

/* Interrupt handling */

void shadow_proc_reply(struct shadow_proc_driver_s *priv);
void shadow_proc_receive(FAR struct shadow_proc_driver_s *priv, uint64_t *buf);
void shadow_proc_txdone(FAR struct shadow_proc_driver_s *priv);

int  shadow_proc_interrupt(int irq, FAR void *context, FAR void *arg);
int  shadow_proc_ok(int irq, FAR void *context, FAR void *arg);

bool shadow_proc_rx_avail(struct shadow_proc_driver_s *in);
void shadow_proc_enable_rx_irq(struct shadow_proc_driver_s *in);

/* Watchdog timer expirations */

void shadow_proc_txtimeout_work(FAR void *arg);
void shadow_proc_txtimeout_expiry(int argc, wdparm_t arg, ...);

void shadow_proc_poll_work(FAR void *arg);
void shadow_proc_poll_expiry(int argc, wdparm_t arg, ...);

/* NuttX callback functions */

int  shadow_proc_ifup(FAR struct net_driver_s *dev);
int  shadow_proc_ifdown(FAR struct net_driver_s *dev);

void shadow_proc_txavail_work(FAR void *arg);

void shadow_proc_set_prio(struct shadow_proc_driver_s *in, uint64_t prio);

struct shadow_proc_driver_s *gshadow;

#endif /* __JAILHOUSE_INCLUDE_SHADOW_H */
