#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <nuttx/fs/fs.h>

#include <nuttx/arch.h>
#include <nuttx/sched.h>
#include <nuttx/board.h>
#include <nuttx/irq.h>
#include <arch/io.h>
#include <syscall.h>
#include <semaphore.h>
#include <errno.h>

#include "up_internal.h"
#include "sched/sched.h"

#include "tux.h"

uint64_t tux_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  struct tcb_s *rtcb = this_task();
  uint64_t params[7];
  uint64_t syscall_ret;
  svcinfo("Delegating syscall %d to linux\n", nbr);

  if(rtcb->xcp.is_linux && rtcb->xcp.linux_sock)
  {
    params[0] = nbr;
    params[1] = parm1;
    params[2] = parm2;
    params[3] = parm3;
    params[4] = parm4;
    params[5] = parm5;
    params[6] = parm6;

    write(rtcb->xcp.linux_sock, params, sizeof(params));
    read(rtcb->xcp.linux_sock, &syscall_ret, sizeof(syscall_ret));

  } else {
    _err("Non-linux process calling linux syscall or invalid sock fd %d, %d\n", rtcb->xcp.is_linux, rtcb->xcp.linux_sock);
    PANIC();
  }
  return syscall_ret;
}

