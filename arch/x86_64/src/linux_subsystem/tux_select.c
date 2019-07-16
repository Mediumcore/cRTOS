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

int fd_set_tux_split(fd_set* out, struct tux_fd_set *in){
    int i, j;
    int ret = 0;

    if(!in || !out)
        return -1;

    for(i = 0; i < CONFIG_TUX_FD_RESERVE / TUX_NFDBITS; i++){
      if(in->__fds_bits[i]){
        ret = 1;
      }
    }

    for(j = 0; j < CONFIG_TUX_FD_RESERVE % TUX_NFDBITS; j++){
      if((in->__fds_bits[i] >> j) & 0x1){
          ret = 1;
      }
    }

    for(; j < TUX_NFDBITS; j++)
    {
      if((in->__fds_bits[i] >> j) & 0x1){

        in->__fds_bits[i] &=  ~(1 << j);

        FD_SET((TUX_NFDBITS * i + j) - CONFIG_TUX_FD_RESERVE, out);

        ret |= 2;
      }
    }

    for(i++; i < (CONFIG_TUX_FD_RESERVE + FD_SETSIZE) / TUX_NFDBITS; i++)
    {
      for(j = 0; j < TUX_NFDBITS; j++){
        if((in->__fds_bits[i] >> j) & 0x1){

          in->__fds_bits[i] &=  ~(1 << j);

          FD_SET((TUX_NFDBITS * i + j) - CONFIG_TUX_FD_RESERVE, out);

          ret |= 2;
        }
      }
    }

    for(j = 0; j < (CONFIG_TUX_FD_RESERVE + FD_SETSIZE) % TUX_NFDBITS; j++)
    {
      if((in->__fds_bits[i] >> j) & 0x1){

        in->__fds_bits[i] &=  ~(1 << j);

        FD_SET((TUX_NFDBITS * i + j) - CONFIG_TUX_FD_RESERVE, out);

        ret |= 2;
      }
    }

    return ret;
}

int fd_set_tux_merge(struct tux_fd_set* out, fd_set *in){
    int i, j;

    if(!in || !out)
        return -1;

    for(i = 0; i < __SELECT_NUINT32; i++){
        for(j = 0; j < 32; j++){
            if((in->arr[i] >> j) & 0x1){
                out->__fds_bits[((i * 32 + j) + CONFIG_TUX_FD_RESERVE) / TUX_NFDBITS] |=  1 << ((i * 32 + j) + CONFIG_TUX_FD_RESERVE) % TUX_NFDBITS;
            }
        }
    }

    return 0;
}

long tux_select (unsigned long nbr, int fd, struct tux_fd_set *r, struct tux_fd_set *w, struct tux_fd_set *e, struct timeval *timeout)
{
  int ret;
  int rr, wr, er;

  fd_set lr;
  fd_set lw;
  fd_set le;

  svcinfo("Select syscall %d, fd: %d\n", nbr, fd);

  FD_ZERO(&lr);
  FD_ZERO(&lw);
  FD_ZERO(&le);

  rr = fd_set_tux_split(&lr, r);
  wr = fd_set_tux_split(&lw, w);
  er = fd_set_tux_split(&le, e);

  if((rr | wr | er) == 3) return -1; // Not support mixing fds from 2 realms

  if((rr | wr | er) == 1){
    ret = tux_delegate(nbr, fd, (uintptr_t)r, (uintptr_t)w, (uintptr_t)e, (uintptr_t)timeout, 0);
  }else{
    ret = select(fd - CONFIG_TUX_FD_RESERVE, &lr, &lw, &le, timeout);
  }

  fd_set_tux_merge(r, &lr);
  fd_set_tux_merge(w, &lw);
  fd_set_tux_merge(e, &le);

  return ret;
}
