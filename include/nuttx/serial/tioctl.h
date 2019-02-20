/********************************************************************************************
 * include/nuttx/serial/tioctl.h
 *
 *   Copyright (C) 2011-2013 Gregory Nutt. All rights reserved.
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
 ********************************************************************************************/
/* This function should not be included directly.  Rather, it should be included indirectly
 * via include/nuttx/fs/ioctl.h.
 */

#ifndef __INCLUDE_NUTTX_SERIAL_TIOCTL_H
#define __INCLUDE_NUTTX_SERIAL_TIOCTL_H

/********************************************************************************************
 * Included Files
 ********************************************************************************************/

#include <stdint.h>

/********************************************************************************************
 * Pre-processor Definitions
 ********************************************************************************************/

/* Get and Set Terminal Attributes (see termios.h) */
/* This list has been modified to be compatiable with Linux */

#define TCGETS          _TIOC(0x0001)  /* Get serial port settings: FAR struct termios* */
#define TCSETS          _TIOC(0x0002)  /* Set serial port settings: FAR const struct termios* */
#define TCSETSW         _TIOC(0x0003)  /* Drain output and set serial port settings: FAR const struct termios* */
#define TCSETSF         _TIOC(0x0004)  /* Drain output, discard intput, and set serial port settings: FAR const struct termios* */
#define TCGETA          _TIOC(0x0005)  /* See TCGETS: FAR struct termio* */
#define TCSETA          _TIOC(0x0006)  /* See TCSETS: FAR const struct termio* */
#define TCSETAW         _TIOC(0x0007)  /* See TCSETSF: FAR const struct termio* */
#define TCSETAF         _TIOC(0x0008)  /* See TCSETSF: FAR const struct termio* */
#define TCSBRK          _TIOC(0x0009)  /* Send a break: int */
#define TCXONC          _TIOC(0x000A)  /* Control flow control: int */
#define TCFLSH          _TIOC(0x000B)  /* Flush: int */

#define TIOCNXCL        _TIOC(0x000D)  /* Disable exclusive mode: void */
#define TIOCSCTTY       _TIOC(0x000E)  /* Make controlling TTY: int */


#define TIOCOUTQ        _TIOC(0x0011)  /* Bytes in output buffer: int */
#define TIOCSTI         _TIOC(0x0012)  /* Insert into input: const char */
#define TIOCGWINSZ      _TIOC(0x0013) /* Get window size: FAR struct winsize */
#define TIOCSWINSZ      _TIOC(0x0014) /* Set window size: FAR const struct winsize */
#define TIOCMGET        _TIOC(0x0015)  /* Get modem status bits: FAR int */
#define TIOCMBIS        _TIOC(0x0016)  /* Set modem bits: FAR const int */
#define TIOCMBIC        _TIOC(0x0017)  /* Clear modem bits: FAR const int */
#define TIOCMSET        _TIOC(0x0018)  /* Set modem status bits: FAR const int */
#  define TIOCM_LE      (1 << 0)       /* DSR (data set ready/line enable) */
#  define TIOCM_DTR     (1 << 1)       /* DTR (data terminal ready) */
#  define TIOCM_RTS     (1 << 2)       /* RTS (request to send) */
#  define TIOCM_ST      (1 << 3)       /* Secondary TXD (transmit) */
#  define TIOCM_SR      (1 << 4)       /* Secondary RXD (receive) */
#  define TIOCM_CTS     (1 << 5)       /* CTS (clear to send) */
#  define TIOCM_CAR     (1 << 6)       /* DCD (data carrier detect) */
#  define TIOCM_CD      TIOCM_CAR
#  define TIOCM_RNG     (1 << 7)       /* RNG (ring) */
#  define TIOCM_RI      TIOCM_RNG
#  define TIOCM_DSR     (1 << 8)       /* DSR (data set ready) */

#define TIOCGSOFTCAR    _TIOC(0x0019)  /* Get software carrier flag: FAR int* */
#define TIOCSSOFTCAR    _TIOC(0x001A)  /* Set software carrier flag: FAR const int */
#define TIOCINQ         _TIOC(0x001B)  /* Bytes in input buffer: int */

#define TIOCCONS        _TIOC(0x001D)  /* Re-direct console output to device: void */
#define TIOCGSERIAL     _TIOC(0x001E)  /* Get serial line info: FAR struct serial_struct */
#define TIOCSSERIAL     _TIOC(0x001F)  /* Set serial line info: FAR const struct serial_struct */
#define TIOCPKT         _TIOC(0x0020)  /* Control packet mode: FAR const int */
#  define TIOCPKT_DATA       (0)
#  define TIOCPKT_FLUSHREAD  (1 << 0)  /* The read queue for the terminal is flushed */
#  define TIOCPKT_FLUSHWRITE (1 << 1)  /* The write queue for the terminal is flushed */
#  define TIOCPKT_STOP       (1 << 2)  /* Output to the terminal is stopped */
#  define TIOCPKT_START      (1 << 3)  /* Output to the terminal is restarted */
#  define TIOCPKT_DOSTOP     (1 << 4)  /* t_stopc is '^S' and t_startc is '^Q' */
#  define TIOCPKT_NOSTOP     (1 << 5)  /* The start and stop characters are not '^S/^Q' */
#  define TIOCPKT_IOCTL      (1 << 6)


#define TIOCNOTTY       _TIOC(0x0022)  /* Give up controllinog TTY: void */
#define TIOCSETD        _TIOC(0x0023)  /* Set line discipline: FAR const int */
#define TIOCGETD        _TIOC(0x0024)  /* Get line discipline: FAR int */
#define TCSBRKP         _TIOC(0x0025)  /* Send a POSIX break: int */
#define TIOCSBRK        _TIOC(0x0027)  /* Turn break on: void */
#define TIOCCBRK        _TIOC(0x0028)  /* Turn break off: void */





#define TIOCSRS485      _TIOC(0x002E)  /* Set RS485 mode, arg: pointer to struct serial_rs485 */
#define TIOCGRS485      _TIOC(0x002F)  /* Get RS485 mode, arg: pointer to struct serial_rs485 */
#  define SER_RS485_ENABLED        (1 << 0) /* Enable/disble RS-485 support */
#  define SER_RS485_RTS_ON_SEND    (1 << 1) /* Logic level for RTS pin when sending */
#  define SER_RS485_RTS_AFTER_SEND (1 << 2) /* Logic level for RTS pin after sent */
#  define SER_RS485_RX_DURING_TX   (1 << 4)

#define TIOCGPTN        _TIOC(0x0030)  /* Get Pty Number (of pty-mux device): FAR int* XXX:size*/
#define TIOCSPTLCK      _TIOC(0x0031)  /* Lock/unlock Pty: int XXX: size*/





#define TIOCVHANGUP     _TIOC(0x0037)  /* Shutdown TTY: void */
#define TIOCEXCL        _TIOC(0x0038)  /* Put TTY in exclusive mode: void XXX:size*/
#define TIOCGPTLCK      _TIOC(0x0039)  /* Get Pty lock state: FAR int* XXX: size*/

#define TIOCGLCKTRMIOS  _TIOC(0x0056) /* Get termios lock status: FAR struct termios* */
#define TIOCSLCKTRMIOS  _TIOC(0x0057) /* Set termios lock status: FAR const struct termios* */
#define TIOCSERGSTRUCT  _TIOC(0x0058) /* Get device TTY structure */
#define TIOCSERGETLSR   _TIOC(0x0059)  /* Get line status register: FAR int */
#define TIOCMIWAIT      _TIOC(0x005C)  /* Wait for a change on serial input line(s): void */
#define TIOCGICOUNT     _TIOC(0x005D)  /* Read serial port interrupt count: FAR  struct serial_icounter_struct */

#define TCDRN           _TIOC(0x0070)  /* Drain: void XXX: Non exist*/
#define TIOCSSINGLEWIRE _TIOC(0x0071)  /* Set single-wire mode XXX:nonexist*/
#define TIOCGSINGLEWIRE _TIOC(0x0072)  /* Get single-wire mode XXX:nonexist*/
#  define SER_SINGLEWIRE_ENABLED   (1 << 0) /* Enable/disable single-wire support */


/********************************************************************************************
 * Public Type Definitions
 ********************************************************************************************/

/* Used with TTY ioctls */

struct winsize
{
  uint16_t ws_row;
  uint16_t ws_col;
/* uint16_t ws_xpixel;    unused */
/* uint16_t ws_ypixel;    unused */
};

/* Structure used with TIOCSRS485 and TIOCGRS485 (Linux compatible) */

struct serial_rs485
{
  uint32_t flags;                  /* See SER_RS485_* definitions */
  uint32_t delay_rts_before_send;  /* Delay before send (milliseconds) */
  uint32_t delay_rts_after_send;   /* Delay after send (milliseconds) */
};

/********************************************************************************************
 * Public Function Prototypes
 ********************************************************************************************/

#ifdef __cplusplus
#define EXTERN extern "C"
extern "C"
{
#else
#define EXTERN extern
#endif

#undef EXTERN
#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_NUTTX_SERIAL_TIOCTL_H */
