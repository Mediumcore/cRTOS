/************************************************************************************
 * configs/jailhouse-amd64/src/jailhouse_boot.c
 *
 *   Copyright (C) 2011, 2014-2015 Gregory Nutt. All rights reserved.
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
 ************************************************************************************/

/************************************************************************************
 * Included Files
 ************************************************************************************/

#include <nuttx/config.h>
#include <nuttx/pcie/pcie.h>

#include <debug.h>

#include <nuttx/board.h>
#include <arch/arch.h>
#include <arch/board/board.h>

#include "up_arch.h"
#include "up_internal.h"

#include "broadwell.h"

#include "jailhouse_ivshmem.h"

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <nuttx/net/arp.h>
#include <nuttx/net/netdev.h>

/************************************************************************************
 * Pre-processor Definitions
 ************************************************************************************/

/************************************************************************************
 * Private Functions
 ************************************************************************************/

void up_netinitialize(void){

#ifdef CONFIG_NET_IVSHMEM_NET
  up_ivshmem_net();
#endif

  return;
}

/************************************************************************************
 * Public Functions
 ************************************************************************************/

/************************************************************************************
 * Name: x86_64_boardinitialize
 *
 * Description:
 *   All x86 architectures must provide the following entry point.  This entry point
 *   is called early in the initialization -- after all memory has been configured
 *   and mapped but before any devices have been initialized.
 *
 ************************************************************************************/

void x86_64_boardinitialize(void)
{

  int bdf1;
  int bdf2;
  void *ptr;
  int cap;
  int pmcsr;
  int old_cmd, cmd;
  /* Configure on-board LEDs if LED support has been selected. */

#ifdef CONFIG_ARCH_LEDS
  board_autoled_initialize();
#endif

  up_map_region((void*)COMM_REGION_BASE, HUGE_PAGE_SIZE, 0x10);

  up_mcs99xx();

  return;
}

/************************************************************************************
 * Name: board_initialize
 *
 * Description:
 *   By enabling BOARD_INITIALIZE, this function will be call late during os starting.
 *   Allow board specified drivers to register themself.
 *
 ************************************************************************************/

struct net_driver_s *netdev_findbyname(FAR const char *ifname);
void netdev_ifup(FAR struct net_driver_s *dev);

void board_initialize(void)
{
  struct net_driver_s *dev;

  up_ivshmem();
  up_shadow_proc();

#ifdef CONFIG_NET_IVSHMEM_NET
  /* Set up our host address */
  dev = netdev_findbyname("eth0");
  if(dev)
    {
      dev->d_ipaddr = HTONL(CONFIG_IVSHMEM_NET_IPADDR);
      dev->d_netmask = HTONL(CONFIG_IVSHMEM_NET_NETMASK);
      dev->d_draddr = HTONL(CONFIG_IVSHMEM_NET_DRIPADDR);

      netdev_ifup(dev);
    }
#endif

  return;
}
