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

#include <nuttx/kmalloc.h>

#include "up_internal.h"
#include "sched/sched.h"

#include "tux.h"

int pollfd_translate2local(struct pollfd* out, struct tux_pollfd* in, tux_nfds_t nfds){
    int i;

    if(!in || !out)
        return -1;


    for(i = 0; i < nfds; i++){
        // Copy FD
        out[i].fd = in[i].fd - CONFIG_TUX_FD_RESERVE;

        // Copy events
        short int events = in[i].events;
        if(events & TUX_POLLIN) {

            out[i].events |= POLLIN;

            events &= ~TUX_POLLIN;
        }

        if(events & TUX_POLLPRI) {

            out[i].events |= POLLIN;

            events &= ~TUX_POLLPRI;
        }

        if(events & TUX_POLLRDNORM) {

            out[i].events |= POLLRDNORM;

            events &= ~TUX_POLLRDNORM;
        }

        if(events & TUX_POLLRDBAND) {

            out[i].events |= POLLRDBAND;

            events &= ~TUX_POLLRDBAND;
        }

        if(events & TUX_POLLOUT) {

            out[i].events |= POLLOUT;

            events &= ~TUX_POLLOUT;
        }

        if(events & TUX_POLLWRNORM) {

            out[i].events |= POLLWRNORM;

            events &= ~TUX_POLLWRNORM;
        }

        if(events & TUX_POLLWRBAND) {

            out[i].events |= POLLWRBAND;

            events &= ~TUX_POLLWRBAND;
        }

        events &= ~TUX_POLLERR;
        events &= ~TUX_POLLHUP;
        events &= ~TUX_POLLNVAL;

        if(events){
            svcerr("Polling #%d with some ambiguous flags 0x%x -> 0x%x\n", i, in[i].events, events);
            return -1;
        }

        out[i].events |= POLLFD;

        svcerr("Polling #%d fd: %d with flags 0x%x\n", i, out[i].fd, out[i].events);
    }

    return 0;
}

int pollfd_translate2tux(struct tux_pollfd* out, struct pollfd* in, tux_nfds_t nfds){
    int i;

    if(!in || !out)
        return -1;


    for(i = 0; i < nfds; i++){

        // Decode events
        uint8_t revents = out[i].revents;
        if(revents & POLLIN) {

            out[i].revents |= TUX_POLLIN;

            revents &= ~POLLIN;
        }

        if(revents & POLLOUT) {

            out[i].revents |= TUX_POLLOUT;

            revents &= ~POLLOUT;
        }

        if(revents & POLLERR) {

            out[i].revents |= TUX_POLLERR;

            revents &= ~POLLERR;
        }

        if(revents & POLLHUP) {

            out[i].revents |= TUX_POLLHUP;

            revents &= ~POLLHUP;
        }

        if(revents & POLLNVAL) {

            out[i].revents |= TUX_POLLNVAL;

            revents &= ~POLLNVAL;
        }

        if(revents) {
            svcerr("Poll #%d returned with some ambiguous flags 0x%x -> 0x%x\n", i, in[i].revents, revents);
            return -1;
        }

        svcerr("Polled #%d with flags 0x%x\n", i, in[i].events);
    }

    return 0;
}

long tux_poll(unsigned long nbr, struct tux_pollfd *fds, tux_nfds_t nfds, int timeout) {
  int ret;
  int i;

  int flag = 0;
  for(i = 0; i < nfds; i++)
    {
        if(fds[i].fd >= CONFIG_TUX_FD_RESERVE) {
          flag = 1;
        }
    }

  for(i = 0; i < nfds; i++)
    {
        // If user is mixing the fds
        if(flag == 1 && fds[i].fd < CONFIG_TUX_FD_RESERVE) {
          svcerr("FATAL: Poll mixing fd: %d, #%d of %d\n", fds[i].fd, i, nfds);
          PANIC();
        }
    }

  svcinfo("Poll syscall\n");

  if(!flag) {
    // Pure Linux poll
    // Delegate it
    return tux_delegate(nbr, (uintptr_t)fds, (uintptr_t)nfds, (uintptr_t)timeout, 0, 0, 0);
  } else {
    // Pure Nuttx poll
    // Translate it and decode result back

    struct pollfd* local = (struct pollfd*)kmm_malloc(sizeof(struct pollfd) * nfds);
    memset(local, 0, sizeof(struct pollfd) * nfds);
    if(pollfd_translate2local(local, fds, nfds)) {
        kmm_free(local);
        return -1;
    }

    ret = tux_local(nbr, (uintptr_t)local, (uintptr_t)nfds, (uintptr_t)timeout, 0, 0, 0);
    if(ret != -1) {
        if(pollfd_translate2tux(fds, local, nfds)) {
            ret = -1;
        }
    }

    kmm_free(local);

    return ret;
  }

  return 0;
}
