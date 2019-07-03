#include <nuttx/arch.h>
#include <nuttx/kmalloc.h>
#include <nuttx/sched.h>

#include <errno.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

#include <arch/irq.h>
#include <sys/mman.h>

static inline void translate_from_tux_sigaction(struct sigaction *out, const struct tux_sigaction *in){
    memcpy(out, in, sizeof(struct sigaction)); // Copy the function pointer.
    out->sa_flags = in->sa_flags;
    out->sa_mask = in->sa_mask;
}

static inline void translate_to_tux_sigaction(struct tux_sigaction *out, const struct sigaction *in){
    int i;
    memcpy(out, in, sizeof(struct sigaction)); // Copy the function pointer.
    out->sa_flags = in->sa_flags;
    out->sa_mask = in->sa_mask;
}

int tux_alarm(unsigned long nbr, unsigned int second){
    int ret;
    struct itimerspec ti;
    struct itimerspec tip;
    ti.it_interval.tv_sec = 0;
    ti.it_interval.tv_nsec = 0;

    ti.it_value.tv_sec = second;
    ti.it_value.tv_nsec = 0;
    _info("ALARM IN\n");

    if(second == 0){
        ti.it_value.tv_sec = 0;
        ret = timer_settime(this_task()->xcp.alarm_timer, 0, &ti, &tip);
        if(!ret)
            ret = tip.it_value.tv_sec;
    }else{
        if(!(this_task()->xcp.alarm_timer))
            ret = timer_create(CLOCK_REALTIME, NULL, &(this_task()->xcp.alarm_timer));
        if(!ret)
            ret = timer_settime(this_task()->xcp.alarm_timer, 0, &ti, NULL);
        else
            _info("Timer Create Failed\n");
        if(!ret)
            ret = tip.it_value.tv_sec;
        else
            _info("Timer set Failed\n");
    }

    if(ret < 0) ret = -errno;
    return ret;
};

int tux_rt_sigaction(unsigned long nbr, int sig, const struct tux_sigaction* act, struct tux_sigaction* old_act, uint64_t set_size){
    int ret;

    struct sigaction lact;
    struct sigaction lold_act;

    if(set_size != sizeof(((struct tux_sigaction*)0)->sa_mask)) return -EINVAL;

    translate_from_tux_sigaction(&lact, act);

    ret = sigaction(sig, &lact, &lold_act);

    if(!ret)
        translate_to_tux_sigaction(old_act, &lold_act);

    if(ret < 0) ret = -errno;
    return ret;
};


