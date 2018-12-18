#include <sys/time.h>
#include <nuttx/arch.h>
#include <nuttx/sched.h>

#include <time.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

int tux_nanosleep(unsigned long nbr, const struct timespec *rqtp, struct timespec *rmtp){
  return nanosleep(rqtp, rmtp);
}

int tux_gettimeofday(unsigned long nbr, struct timeval *tv, struct timeval *tz){
  return gettimeofday(tv, tz);
}
