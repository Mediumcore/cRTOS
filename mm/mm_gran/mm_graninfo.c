/****************************************************************************
 * mm/mm_gran/mm_graninfo.c
 *
 *   Copyright (C) 2017 Gregory Nutt. All rights reserved.
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
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <assert.h>

#include <nuttx/mm/gran.h>

#include "mm_gran/mm_gran.h"

#ifdef CONFIG_GRAN

/****************************************************************************
 * Private Data
 ****************************************************************************/

struct nibble_info_s
{
  uint16_t nfree   : 4; /* Total bits free in a nibble */
  uint16_t nlsfree : 4; /* Total contiguous LS bits free */
  uint16_t nmsfree : 4; /* Total contiguous MS bits free */
  uint16_t mxfree : 4; /* Largest internal contiguous bits free */
};

struct valinfo_s
{
  uint8_t nfree;        /* Total bits free in the byte/hword */
  uint8_t nlsfree;      /* Total contiguous LS bits free */
  uint8_t nmsfree;      /* Total contiguous MS bits free */
  uint8_t mxfree;      /* Largest internal contiguous bits free */
};

/****************************************************************************
 * Private Data
 ****************************************************************************/

static const struct nibble_info_s g_0bit_info[1] =
{
  { 0, 0, 0, 0}   /*  0 xxxx */
};

static const struct nibble_info_s g_1bit_info[2] =
{
  { 1, 1, 0, 1},  /*  0 xxx0 */
  { 0, 0, 0, 0}   /*  1 xxx1 */
};

static const struct nibble_info_s g_2bit_info[4] =
{
  { 2, 2, 0, 0},  /*  0 xx00 */
  { 1, 0, 1, 0},  /*  1 xx01 */
  { 1, 1, 0, 0},  /*  2 xx10 */
  { 0, 0, 0, 0}   /*  3 xx11 */
};

static const struct nibble_info_s g_3bit_info[8] =
{
  { 3, 3, 0, 0},  /*  0 x000 */
  { 2, 0, 2, 0},  /*  1 x001 */
  { 2, 1, 1, 0},  /*  2 x010 */
  { 1, 0, 1, 0},  /*  3 x011 */
  { 2, 2, 0, 0},  /*  4 x100 */
  { 1, 0, 0, 1},  /*  5 x101 */
  { 1, 1, 0, 0},  /*  6 x110 */
  { 0, 0, 0, 0}   /*  7 x111 */
};

static const struct nibble_info_s g_4bit_info[16] =
{
  { 4, 4, 0, 0},  /*  0 0000 */
  { 3, 0, 3, 0},  /*  1 0001 */
  { 3, 1, 2, 0},  /*  2 0010 */
  { 2, 0, 2, 0},  /*  3 0011 */
  { 3, 2, 1, 0},  /*  4 0100 */
  { 2, 0, 1, 1},  /*  5 0101 */
  { 2, 1, 1, 0},  /*  6 0110 */
  { 1, 0, 1, 0},  /*  7 0111 */
  { 3, 3, 0, 0},  /*  8 1000 */
  { 2, 0, 0, 2},  /*  9 1001 */
  { 2, 1, 0, 1},  /* 10 1010 */
  { 1, 0, 0, 1},  /* 11 1011 */
  { 2, 2, 0, 0},  /* 12 1100 */
  { 1, 0, 0, 1},  /* 13 1101 */
  { 1, 1, 0, 0},  /* 14 1110 */
  { 0, 0, 0, 0}   /* 15 1111 */
};

static FAR const struct nibble_info_s *g_info_table[4] =
{
   g_0bit_info,
   g_1bit_info,
   g_2bit_info,
   g_3bit_info
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: gran_nibble_info
 *
 * Description:
 *   Return information a 4-bit value from the GAT.
 *
 * Input Parameters:
 *   value - The 4-bit value
 *   info  - The location to return the hword info
 *   nbits - Number of valid bits in value
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void gran_nibble_info(uint8_t value, FAR struct valinfo_s *info,
                      unsigned int nbits)
{
  FAR const struct nibble_info_s *table = g_info_table[nbits];
  FAR const struct nibble_info_s *nibinfo;
  uint8_t mask;

  /* Look up the table entry */

  mask          = ((1 << nbits) - 1);
  value        &= mask;
  nibinfo       = &table[value];

  /* Return expanded values */

  info->nfree   = nibinfo->nfree;
  info->nlsfree = nibinfo->nlsfree;
  info->nmsfree = nibinfo->nmsfree;
  info->mxfree  = nibinfo->mxfree;
}

/****************************************************************************
 * Name: gran_byte_info
 *
 * Description:
 *   Return information a 8-bit value from the GAT.
 *
 * Input Parameters:
 *   value - The 16-bit value
 *   info  - The location to return the hword info
 *   nbits - Number of valid bits in value
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void gran_byte_info(uint8_t value, FAR struct valinfo_s *info,
                    unsigned int nbits)
{
  uint16_t mask;

  if (nbits < 8)
    {
      mask   = ((1 << nbits) - 1);
      value &= mask;
    }
  else
    {
      mask = 0xff;
    }

  /* Handle special cases */

   if (value == 0)
    {
      /* All free */

      info->nfree   = nbits;
      info->nlsfree = nbits;
      info->nmsfree = 0;
      info->mxfree  = 0;
    }
  else if (value == mask)
    {
      info->nfree   = 0;
      info->nlsfree = 0;
      info->nmsfree = 0;
      info->mxfree  = 0;
    }
  else
    {
      /* Some allocated */

      gran_nibble_info(value & 0x0f, info, nbits > 4 ? 4 : nbits);
      if (nbits > 4)
        {
          struct valinfo_s nibinfo;
          unsigned int msbits = nbits - 4;
          unsigned int midfree;

          gran_nibble_info(value >> 4, &nibinfo, msbits);

          midfree = info->nmsfree + nibinfo.nlsfree;

          info->nfree += nibinfo.nfree;

          if (nibinfo.nlsfree == msbits)
            {
              if (info->nlsfree == 8)
                {
                  info->nmsfree = 0;
                }
              else
                {
                  info->nmsfree += msbits;
                }
            }
          else
            {
              info->nmsfree = nibinfo.nmsfree;
            }

          if (info->nlsfree == 8)
            {
              info->nlsfree += nibinfo.nlsfree;
            }

          if (midfree > info->mxfree)
            {
              info->mxfree = midfree;
            }

          if (nibinfo.mxfree > info->mxfree)
            {
              info->mxfree = nibinfo.mxfree;
            }
        }
    }
}

/****************************************************************************
 * Name: gran_hword_info
 *
 * Description:
 *   Return information a 16-bit value from the GAT.
 *
 * Input Parameters:
 *   value - The 16-bit value
 *   info  - The location to return the hword info
 *   nbits - Number of valid bits in value
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void gran_hword_info(uint16_t value, FAR struct valinfo_s *info,
                     unsigned int nbits)
{
  uint16_t mask;

  if (nbits < 16)
    {
      mask   = ((1 << nbits) - 1);
      value &= mask;
    }
  else
    {
      mask = 0xffff;
    }

  /* Handle special cases */

   if (value == 0)
    {
      /* All free */

      info->nfree   = nbits;
      info->nlsfree = nbits;
      info->nmsfree = 0;
      info->mxfree  = 0;
    }
  else if (value == mask)
    {
      info->nfree   = 0;
      info->nlsfree = 0;
      info->nmsfree = 0;
      info->mxfree  = 0;
    }
  else
    {
      /* Some allocated */

      gran_hword_info((uint8_t)(value & 0xff), info, nbits > 8 ? 8 : nbits);
      if (nbits > 8)
        {
          struct valinfo_s byteinfo;
          unsigned int msbits = nbits - 8;
          unsigned int midfree;

          gran_hword_info((uint8_t)(value >> 8), &byteinfo, msbits);

          midfree = info->nmsfree + byteinfo.nlsfree;

          info->nfree += byteinfo.nfree;

          if (byteinfo.nlsfree == msbits)
            {
              if (info->nlsfree == 8)
                {
                  info->nmsfree = 0;
                }
              else
                {
                  info->nmsfree += msbits;
                }
            }
          else
            {
              info->nmsfree = byteinfo.nmsfree;
            }

          if (info->nlsfree == 8)
            {
              info->nlsfree += byteinfo.nlsfree;
            }

          if (midfree > info->mxfree)
            {
              info->mxfree = midfree;
            }

          if (byteinfo.mxfree > info->mxfree)
            {
              info->mxfree = byteinfo.mxfree;
            }
        }
    }
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: gran_info
 *
 * Description:
 *   Return information about the granule heap.
 *
 * Input Parameters:
 *   handle - The handle previously returned by gran_initialize
 *   info   - Memory location to return the gran allocator info.
 *
 * Returned Value:
 *   Zero (OK) is returned on success; a negated errno value is return on
 *   any failure.
 *
 ****************************************************************************/

void gran_info(GRAN_HANDLE handle, FAR struct graninfo_s *info)
{
  FAR struct gran_s *priv = (FAR struct gran_s *)handle;
  uint32_t mask;
  uint32_t value;
  uint16_t mxfree;
  unsigned int nbits;
  unsigned int granidx;
  unsigned int gatidx;

  DEBUGASSERT(priv != NULL && info != NULL);

  info->log2gran   = priv->log2gran;
  info->ngranules  = priv->ngranules;
  info->nfree      = 0;
  info->mxfree     = 0;
  mxfree           = 0;

  /* Get exclusive access to the GAT */

  gran_enter_critical(priv);

  /* Travere the granule allocation  */

  for (granidx = 0; granidx < priv->ngranules; granidx += 32)
    {
      /* Get the GAT index associated with the granule table entry */

      gatidx = granidx >> 5;
      value  = priv->gat[gatidx];

      /* The final entry is a special case */

      if ((granidx + 32) >= priv->ngranules)
        {
          nbits  = priv->ngranules - granidx;
          mask   = ((1ul << nbits) - 1);
          value  &= mask;
        }
      else
        {
          nbits  = 32;
          mask   = 0xffffffff;
        }

      /* Handle the 32-bit cases */

      if (value == mask)
        {
          /* All allocated.  This will terminate any sequence of free
           * granules.
           */

          if (mxfree > info->mxfree)
            {
              info->mxfree = mxfree;
            }

          mxfree = 0;
        }
      else if (value == 0x00000000)
        {
          /* All free */

          info->nfree += nbits;
          mxfree      += nbits;
        }
      else
        {
          struct valinfo_s hwinfo;

          /* Some allocated */

          gran_hword_info((uint16_t)(value & 0xffff), &hwinfo,
                          nbits > 16 ? 16 : nbits);
          if (nbits > 16)
            {
              struct valinfo_s msinfo;
              unsigned int msbits = nbits - 16;
              unsigned int midfree;

              gran_hword_info((uint16_t)(value >> 16), &msinfo, msbits);

              midfree = hwinfo.nmsfree + msinfo.nlsfree;

              hwinfo.nfree += msinfo.nfree;

              if (msinfo.nlsfree == msbits)
                {
                  if (hwinfo.nlsfree == 8)
                    {
                      hwinfo.nmsfree = 0;
                    }
                  else
                    {
                      hwinfo.nmsfree += msbits;
                   }
                }
              else
                {
                  hwinfo.nmsfree = msinfo.nmsfree;
                }

              if (hwinfo.nlsfree == 8)
                {
                  hwinfo.nlsfree += msinfo.nlsfree;
                }

              if (midfree > hwinfo.mxfree)
                {
                  hwinfo.mxfree = midfree;
                }

              if (msinfo.mxfree > hwinfo.mxfree)
                {
                  hwinfo.mxfree = msinfo.mxfree;
                }
            }

          /* Update the running free sequence of granules */

          if (hwinfo.nlsfree > 0)
            {
              mxfree += hwinfo.nlsfree;
            }

          /* If the entire word is not free, then update the maxfree free
           * sequence.
           */

          if (hwinfo.nlsfree < nbits)
            {
              /* Is the sequence internally free bits in the 32-bit value
               * longer than the running free sequence?
               */

              if (hwinfo.mxfree > mxfree)
                {
                  mxfree = hwinfo.mxfree;
                }

              /* Is the running free sequence long than the last sequence
               * that we saw?
               */

              if (mxfree > info->mxfree)
                {
                  info->mxfree = mxfree;
                }

              /* Then restart with the free MS granules */

              mxfree = hwinfo.nmsfree;
            }

          /* Update the total number of free granules */

          info->nfree += hwinfo.nfree;
        }
    }

  gran_leave_critical(priv);
}

#endif /* CONFIG_GRAN */