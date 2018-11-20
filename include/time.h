/********************************************************************************
 * include/time.h
 *
 *   Copyright (C) 2007-2011, 2013-2015, 2017 Gregory Nutt. All rights reserved.
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
 ********************************************************************************/

#ifndef __INCLUDE_TIME_H
#define __INCLUDE_TIME_H

/********************************************************************************
 * Included Files
 ********************************************************************************/

#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <sys/types.h>
#include <stdint.h>

/********************************************************************************
 * Pre-processor Definitions
 ********************************************************************************/

/* Clock tick of the system (frequency Hz).
 *
 * NOTE: This symbolic name CLK_TCK has been removed from the standard.  It is
 * replaced with CLOCKS_PER_SEC.  Both are defined here.
 *
 * The default value is 100Hz, but this default setting can be overridden by
 * defining the clock interval in microseconds as CONFIG_USEC_PER_TICK in the
 * board configuration file.
 */

#ifdef CONFIG_NSEC_PER_TICK
# define CLK_TCK           (1000000000/CONFIG_NSEC_PER_TICK)
# define CLOCKS_PER_SEC    (1000000000/CONFIG_NSEC_PER_TICK)
#else
# define CLK_TCK           (100)
# define CLOCKS_PER_SEC    (100)
#endif

/* CLOCK_REALTIME refers to the standard time source.  For most
 * implementations, the standard time source is the system timer interrupt.
 * However, if the platform supports an RTC, then the standard time source
 * will be the RTC for the clock_gettime() and clock_settime() interfaces
 * (the system timer is still the time source for all of the interfaces).
 *
 * CLOCK_REALTIME represents the machine's best-guess as to the current
 * wall-clock, time-of-day time. This means that CLOCK_REALTIME can jump
 * forward and backward as the system time-of-day clock is changed.
 */

#define CLOCK_REALTIME     0

/* Clock that cannot be set and represents monotonic time since some
 * unspecified starting point. It is not affected by changes in the
 * system time-of-day clock.
 */

#ifdef CONFIG_CLOCK_MONOTONIC
#  define CLOCK_MONOTONIC  1
#endif

/* This is a flag that may be passed to the timer_settime() and
 * clock_nanosleep() functions.
 */

#define TIMER_ABSTIME      1

#ifndef CONFIG_LIBC_LOCALTIME
/* Local time is the same as gmtime in this implementation */

#  define localtime(c)     gmtime(c)
#  define localtime_r(c,r) gmtime_r(c,r)
#endif

/********************************************************************************
 * Public Types
 ********************************************************************************/

/* Scalar types */

typedef uint32_t  time_t;         /* Holds time in seconds */
typedef uint8_t   clockid_t;      /* Identifies one time base source */
typedef FAR void *timer_t;        /* Represents one POSIX timer */

/* struct timespec is the standard representation of time as seconds and
 * nanoseconds.
 */

struct timespec
{
  time_t tv_sec;                   /* Seconds */
  long   tv_nsec;                  /* Nanoseconds */
};

/* struct tm is the standard representation for "broken out" time.
 *
 * REVISIT: This structure could be packed better using uint8_t's and
 * uint16_t's.  The standard definition does, however, call out type int for
 * all of the members.  NOTE: Any changes to this structure must be also be
 * reflected in struct rtc_time defined in include/nuttx/timers/rtc.h; these
 * two structures must be cast compatible.
 */

struct tm
{
  int tm_sec;     /* Seconds (0-61, allows for leap seconds) */
  int tm_min;     /* Minutes (0-59) */
  int tm_hour;    /* Hours (0-23) */
  int tm_mday;    /* Day of the month (1-31) */
  int tm_mon;     /* Month (0-11) */
  int tm_year;    /* Years since 1900 */
#if defined(CONFIG_LIBC_LOCALTIME) || defined(CONFIG_TIME_EXTENDED)
  int tm_wday;    /* Day of the week (0-6) */
  int tm_yday;    /* Day of the year (0-365) */
  int tm_isdst;   /* Non-0 if daylight savings time is in effect */
#endif
};

/* Struct itimerspec is used to define settings for an interval timer */

struct itimerspec
{
  struct timespec it_value;    /* First time */
  struct timespec it_interval; /* and thereafter */
};

/* forward reference (defined in signal.h) */

struct sigevent;

/********************************************************************************
 * Public Data
 ********************************************************************************/

#undef EXTERN
#if defined(__cplusplus)
#define EXTERN extern "C"
extern "C"
{
#else
#define EXTERN extern
#endif

#ifdef CONFIG_LIBC_LOCALTIME

/* daylight - Daylight savings time flag */
/* EXTERN int daylight; not supported */

/* timezone - Difference from UTC and local standard time */
/* EXTERN long int timezone; not supported */

/* tzname[] - Timezone strings
 * Setup by tzset()
 */

EXTERN FAR char *tzname[2];
#endif

/********************************************************************************
 * Public Function Prototypes
 ********************************************************************************/

clock_t clock(void);

int clock_settime(clockid_t clockid, FAR const struct timespec *tp);
int clock_gettime(clockid_t clockid, FAR struct timespec *tp);
int clock_getres(clockid_t clockid, FAR struct timespec *res);

time_t mktime(FAR struct tm *tp);
FAR struct tm *gmtime(FAR const time_t *timep);
FAR struct tm *gmtime_r(FAR const time_t *timep, FAR struct tm *result);

#ifdef CONFIG_LIBC_LOCALTIME
FAR struct tm *localtime(FAR const time_t *timep);
FAR struct tm *localtime_r(FAR const time_t *timep, FAR struct tm *result);
#endif

size_t strftime(FAR char *s, size_t max, FAR const char *format,
                FAR const struct tm *tm);

#if defined(CONFIG_LIBC_LOCALTIME) || defined(CONFIG_TIME_EXTENDED)
FAR char *asctime(FAR const struct tm *tp);
FAR char *asctime_r(FAR const struct tm *tp, FAR char *buf);
FAR char *ctime(FAR const time_t *timep);
FAR char *ctime_r(FAR const time_t *timep, FAR char *buf);
#endif

time_t time(FAR time_t *timep);

#ifdef CONFIG_HAVE_DOUBLE
double difftime(time_t time1, time_t time0);
#else
float difftime(time_t time1, time_t time0);
#endif

int timer_create(clockid_t clockid, FAR struct sigevent *evp,
                 FAR timer_t *timerid);
int timer_delete(timer_t timerid);
int timer_settime(timer_t timerid, int flags,
                  FAR const struct itimerspec *value,
                  FAR struct itimerspec *ovalue);
int timer_gettime(timer_t timerid, FAR struct itimerspec *value);
int timer_getoverrun(timer_t timerid);

int clock_nanosleep(clockid_t clockid, int flags,
                    FAR const struct timespec *rqtp,
                    FAR struct timespec *rmtp);
int nanosleep(FAR const struct timespec *rqtp, FAR struct timespec *rmtp);

#ifdef CONFIG_LIBC_LOCALTIME
void tzset(void);
#endif

#undef EXTERN
#if defined(__cplusplus)
}
#endif

#endif  /* __INCLUDE_TIME_H */
