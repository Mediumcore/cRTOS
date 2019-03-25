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
#include "tux_syscall_table.h"

int tux_local(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  svcinfo("Local syscall %d, %d\n", nbr, linux_syscall_number_table[nbr]);

  if(linux_syscall_number_table[nbr] == (uint64_t)-1){
    _alert("Not implemented Local syscall %d\n", nbr);
    PANIC();
  }

  return ((syscall_t) \
         (g_stublookup[linux_syscall_number_table[nbr] - CONFIG_SYS_RESERVED])) \
         (linux_syscall_number_table[nbr] - CONFIG_SYS_RESERVED, parm1, parm2, parm3, parm4, parm5, parm6);
}

int tux_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
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

    syscall_ret = write(rtcb->xcp.linux_sock, params, sizeof(params));

  } else {
    _err("Non-linux process calling linux syscall or invalid sock fd %d, %d\n", rtcb->xcp.is_linux, rtcb->xcp.linux_sock);
    PANIC();
  }
  return params[0];
}

int tux_file_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  int ret;
  svcinfo("File related syscall %d, fd: %d\n", nbr, parm1);

  if(parm1 <= 2) { // stdin, stdout, stderr should be delegated
    ret = tux_delegate(nbr, parm1, parm2, parm3, parm4, parm5, parm6);
  }else{
    ret = -1;
    if(linux_syscall_number_table[nbr] != (uint64_t)-1){
      ret = tux_local(nbr, parm1, parm2, parm3, parm4, parm5, parm6);
    }
    if(ret < 0){
      svcinfo("%s\n", strerror(errno));
      ret = tux_delegate(nbr, parm1 - TUX_FD_OFFSET, parm2, parm3, parm4, parm5, parm6);
    }
  }

  return ret;
}

int tux_open_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  int ret;

  svcinfo("Open syscall %d, path: %s\n", nbr, (char*)parm1);

  ret = tux_local(nbr, parm1, parm2, parm3, parm4, parm5, parm6);
  if(ret < 0){
      svcinfo("%s\n", strerror(errno));
      ret = tux_delegate(nbr, parm1, parm2, parm3, parm4, parm5, parm6) + TUX_FD_OFFSET;
      svcinfo("Open fd: %d\n", ret - TUX_FD_OFFSET);
  }

  return ret;
}
