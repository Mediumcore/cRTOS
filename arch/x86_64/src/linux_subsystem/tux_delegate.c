#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <nuttx/fs/fs.h>

#include <sys/select.h>

#include <nuttx/arch.h>
#include <nuttx/sched.h>
#include <nuttx/board.h>
#include <nuttx/irq.h>
#include <arch/io.h>
#include <syscall.h>
#include <fcntl.h>
#include <semaphore.h>
#include <errno.h>
#include <poll.h>

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
  svcinfo("Multiplexed File related syscall %d, fd: %d\n", nbr, parm1);

  if(parm1 < CONFIG_TUX_FD_RESERVE) { // Lower parts should be delegated
    ret = tux_delegate(nbr, parm1, parm2, parm3, parm4, parm5, parm6);
  }else{
    ret = -1;
    if(linux_syscall_number_table[nbr] != (uint64_t)-1){
      ret = tux_local(nbr, parm1 - CONFIG_TUX_FD_RESERVE, parm2, parm3, parm4, parm5, parm6);
    }
  }

  return ret;
}

int tux_poll_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  int ret, i;
  svcinfo("Poll syscall %d, nfd: %d\n", nbr, parm2);

  for(i = 0; i < parm2; i++)
    {
      svcinfo("Poll fd #%d: %d\n", i, ((struct pollfd*)parm1)[i].fd);
      if(((struct pollfd*)parm1)[i].fd >= CONFIG_TUX_FD_RESERVE)
          return -1;
    }

  ret = tux_delegate(nbr, parm1, parm2, parm3, parm4, parm5, parm6);

  return ret;
}


int tux_open_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  int ret;
  uint64_t new_flags;

  svcinfo("Open/Socket syscall %d, path: %s, flag: %llx\n", nbr, (char*)parm1, parm2);
  if(nbr == 2){
      // Nuttx has different Bit pattern in flags, we have to decode them
      new_flags = 0;
      if(parm2 & TUX_O_ACCMODE)     new_flags |= O_ACCMODE;
      if(parm2 & TUX_O_RDONLY)      new_flags |= O_RDONLY;
      if(parm2 & TUX_O_WRONLY)      new_flags |= O_WRONLY;
      if(parm2 & TUX_O_RDWR)        new_flags |= O_RDWR;
      if(parm2 & TUX_O_CREAT)       new_flags |= O_CREAT;
      if(parm2 & TUX_O_EXCL)        new_flags |= O_EXCL;
      if(parm2 & TUX_O_NOCTTY)      new_flags |= O_NOCTTY;
      if(parm2 & TUX_O_TRUNC)       new_flags |= O_TRUNC;
      if(parm2 & TUX_O_APPEND)      new_flags |= O_APPEND;
      if(parm2 & TUX_O_NONBLOCK)    new_flags |= O_NONBLOCK;
      if(parm2 & TUX_O_DSYNC)       new_flags |= O_DSYNC;
      if(parm2 & TUX_O_SYNC == TUX_O_SYNC)        new_flags |= O_SYNC;
      if(parm2 & TUX_O_DIRECT)      new_flags |= O_DIRECT;
      /*if(parm2 & TUX_O_LARGEFILE)   new_flags |= O_LARGEFILE;*/
      /*if(parm2 & TUX_O_DIRECTORY)   new_flags |= O_DIRECTORY;*/
      /*if(parm2 & TUX_O_NOFOLLOW)    new_flags |= O_NOFOLLOW;*/
      /*if(parm2 & TUX_O_NOATIME)     new_flags |= O_NOATIME;*/
      /*if(parm2 & TUX_O_CLOEXEC)     new_flags |= O_CLOEXEC;*/
      if(parm2 & TUX_O_TMPFILE == TUX_O_TMPFILE)     return -1;
      if(parm2 & TUX_O_NDELAY)      new_flags |= O_NDELAY;
      ret = tux_local(nbr, parm1, new_flags, parm3, parm4, parm5, parm6);
      if(ret >= 0){
          return ret + CONFIG_TUX_FD_RESERVE;
      }

      svcinfo("%s\n", strerror(errno));
      ret = tux_delegate(nbr, parm1, parm2, parm3, parm4, parm5, parm6);
      svcinfo("Open/Socket fd: %d\n", ret);

      return ret;
  }else{

      ret = tux_delegate(nbr, parm1, parm2, parm3, parm4, parm5, parm6);
      svcinfo("Open/Socket fd: %d\n", ret);

      return ret;
  }

}
