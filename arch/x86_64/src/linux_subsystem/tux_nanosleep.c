#include <nuttx/arch.h>
#include <nuttx/sched.h>

#include <time.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

int tux_nanosleep(const struct timespec *rqtp, struct timespec *rmtp){
  return nanosleep(rqtp, rmtp);
}

