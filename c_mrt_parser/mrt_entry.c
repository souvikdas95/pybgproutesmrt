/*
 * SPDX-FileCopyrightText: 2025 Thomas Alfroy
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "mrt_entry.h"
#include "bgp_macros.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define MAX_BUFF_LEN 32768

static inline void u64_to_be(uint64_t v, uint8_t out[8])
{
    out[0] = (uint8_t)((v >> 56) & 0xFF);
    out[1] = (uint8_t)((v >> 48) & 0xFF);
    out[2] = (uint8_t)((v >> 40) & 0xFF);
    out[3] = (uint8_t)((v >> 32) & 0xFF);
    out[4] = (uint8_t)((v >> 24) & 0xFF);
    out[5] = (uint8_t)((v >> 16) & 0xFF);
    out[6] = (uint8_t)((v >> 8)  & 0xFF);
    out[7] = (uint8_t)(v & 0xFF);
}

static void addr_to_str(uint64_t a1, uint64_t a0, char* out, size_t outlen)
{
    if (outlen == 0) return;
    out[0] = '\0';

    if (a1 == 0)
    {
        /* IPv4 stored in low 32 bits of a0 (network order packed) */
        uint32_t v4 = (uint32_t)(a0 & 0xFFFFFFFFu);
        uint8_t b4[4];
        b4[0] = (uint8_t)((v4 >> 24) & 0xFF);
        b4[1] = (uint8_t)((v4 >> 16) & 0xFF);
        b4[2] = (uint8_t)((v4 >> 8) & 0xFF);
        b4[3] = (uint8_t)(v4 & 0xFF);

        if (inet_ntop(AF_INET, b4, out, (socklen_t)outlen) == NULL)
        {
            snprintf(out, outlen, "-");
        }
    }
    else
    {
        uint8_t b16[16];
        u64_to_be(a1, b16);
        u64_to_be(a0, b16 + 8);

        if (inet_ntop(AF_INET6, b16, out, (socklen_t)outlen) == NULL)
        {
            snprintf(out, outlen, "-");
        }
    }
}

static void prefix_to_str(uint64_t a1, uint64_t a0, uint8_t plen, char* out, size_t outlen)
{
    char tmp[INET6_ADDRSTRLEN];
    addr_to_str(a1, a0, tmp, sizeof(tmp));
    snprintf(out, outlen, "%s/%u", tmp, (unsigned)plen);
}

static int buf_append(char* buf, int* off, int max, const char* fmt, ...)
{
    if (*off >= max) return 0;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *off, (size_t)(max - *off), fmt, ap);
    va_end(ap);
    if (n < 0) return 0;
    if (n >= (max - *off)) { *off = max; return 0; }
    *off += n;
    return 1;
}

static void origin_to_str(uint8_t origin, uint8_t present, char* out, size_t outlen)
{
    if (!present)
    {
        snprintf(out, outlen, "-");
        return;
    }
    switch (origin)
    {
    case BGP_UPDATE_ORIGIN_IGP:
        snprintf(out, outlen, "IGP");
        break;
    case BGP_UPDATE_ORIGIN_EGP:
        snprintf(out, outlen, "EGP");
        break;
    case BGP_UPDATE_ORIGIN_INCOMPLETE:
        snprintf(out, outlen, "INCOMPLETE");
        break;
    default:
        snprintf(out, outlen, "%u", (unsigned)origin);
        break;
    }
}

static void aspath_to_str(const MRTentry* e, char* out, size_t outlen)
{
    int off = 0;
    out[0] = '\0';

    /* If we have segment metadata, use it. Otherwise fall back to flat list. */
    if (e->asPathSegCount > 0)
    {
        for (uint8_t s = 0; s < e->asPathSegCount; s++)
        {
            uint8_t stype = e->asPathSegType[s];
            uint8_t slen  = e->asPathSegLen[s];
            uint8_t base = e->asPathSegOffset[s];

            if (s > 0) buf_append(out, &off, (int)outlen, " ");

            if (stype == BGP_UPDATE_AS_PATH_SET)
            {
                buf_append(out, &off, (int)outlen, "{");
                for (uint8_t i = 0; i < slen; i++)
                {
                    if (i > 0) buf_append(out, &off, (int)outlen, ",");
                    uint8_t idx = (uint8_t)(base + i);
                    if (idx < e->asPathLen) buf_append(out, &off, (int)outlen, "%" PRIu32, e->asPath[idx]);
                }
                buf_append(out, &off, (int)outlen, "}");
            }
            else
            {
                for (uint8_t i = 0; i < slen; i++)
                {
                    if (i > 0) buf_append(out, &off, (int)outlen, " ");
                    uint8_t idx = (uint8_t)(base + i);
                    if (idx < e->asPathLen) buf_append(out, &off, (int)outlen, "%" PRIu32, e->asPath[idx]);
                }
            }
        }
    }
    else
    {
        for (uint8_t i = 0; i < e->asPathLen; i++)
        {
            if (i > 0) buf_append(out, &off, (int)outlen, " ");
            buf_append(out, &off, (int)outlen, "%" PRIu32, e->asPath[i]);
        }
    }
}

static void communities_to_str(const MRTentry* e, char* out, size_t outlen)
{
    int off = 0;
    out[0] = '\0';

    for (uint16_t i = 0; i < e->communities_count; i++)
    {
        if (i > 0) buf_append(out, &off, (int)outlen, " ");

        uint8_t len = e->communities_value_len[i];
        uint64_t hi = e->communities1[i];
        uint64_t lo = e->communities0[i];

        if (len == 4)
        {
            uint32_t v = (uint32_t)(lo & 0xFFFFFFFFu);
            uint16_t asn = (uint16_t)((v >> 16) & 0xFFFFu);
            uint16_t val = (uint16_t)(v & 0xFFFFu);
            buf_append(out, &off, (int)outlen, "%u:%u", (unsigned)asn, (unsigned)val);
        }
        else
        {
            /* Render as hex for non-4-byte communities */
            if (hi == 0)
                buf_append(out, &off, (int)outlen, "0x%016" PRIx64, lo);
            else
                buf_append(out, &off, (int)outlen, "0x%016" PRIx64 "%016" PRIx64, hi, lo);
        }
    }
}


MRTentry* MRTentry_new(void)
{
    MRTentry* entry = (MRTentry*)calloc(1, sizeof(MRTentry));
    return entry;
}

MRTentry* MRTentry_copy_for_ribs(MRTentry* entry)
{
    MRTentry* newEntry = MRTentry_new();

    if (newEntry == NULL)
    {
        return NULL;
    }

    /* Copy generic meta */
    newEntry->entryType    = entry->entryType;
    newEntry->entrySubType = entry->entrySubType;
    newEntry->entryLength  = entry->entryLength;

    newEntry->bgpType   = entry->bgpType;
    newEntry->afi       = entry->afi;
    newEntry->time      = entry->time;
    newEntry->time_ms   = entry->time_ms;
    newEntry->dumper    = entry->dumper;

    /* Copy prefixes only (RIB header is shared) */
    newEntry->nbNLRI = entry->nbNLRI;
    for (u_int16_t i = 0; i < entry->nbNLRI; i++)
    {
        newEntry->nlri_address1[i]  = entry->nlri_address1[i];
        newEntry->nlri_address0[i]  = entry->nlri_address0[i];
        newEntry->nlri_prefix_len[i]= entry->nlri_prefix_len[i];
    }

    return newEntry;
}

void MRTentry_free_one(MRTentry* entry)
{
    if (entry != NULL)
    {
        free(entry);
    }
}

void MRTentry_free(MRTentry* entry)
{
    MRTentry* currentEntry = entry;
    MRTentry* tmp;

    while (currentEntry != NULL)
    {
        tmp = currentEntry;
        currentEntry = currentEntry->next;
        MRTentry_free_one(tmp);
    }
}

void MRTentry_print(MRTentry* entry)
{
    if (entry == NULL)
    {
        return;
    }

    char buffer[MAX_BUFF_LEN];
    int actOff = 0;

    /* Prefix for the BGP message type */
    char type_prefix = '?';
    if (entry->entryType == MRT_TYPE_BGP4MP || entry->entryType == MRT_TYPE_BGP4MP_ET)
    {  
        switch (entry->bgpType)
        {
            case BGP_TYPE_OPEN: type_prefix = 'O'; break;
            case BGP_TYPE_UPDATE: type_prefix = 'U'; break;
            case BGP_TYPE_NOTIFICATION: type_prefix = 'N'; break;
            case BGP_TYPE_KEEPALIVE: type_prefix = 'K'; break;
            case BGP_TYPE_STATE_CHANGE: type_prefix = 'S'; break;
        }
    }
    else
        type_prefix = 'R';

    buf_append(buffer, &actOff, MAX_BUFF_LEN, "%c|%u.%06u|", type_prefix, entry->time, entry->time_ms);

    /* NLRI list */
    for (u_int16_t i = 0; i < entry->nbNLRI; i++)
    {
        if (i > 0) buf_append(buffer, &actOff, MAX_BUFF_LEN, ",");
        char pbuf[INET6_ADDRSTRLEN + 8];
        prefix_to_str(entry->nlri_address1[i], entry->nlri_address0[i], entry->nlri_prefix_len[i], pbuf, sizeof(pbuf));
        buf_append(buffer, &actOff, MAX_BUFF_LEN, "%s", pbuf);
    }

    buf_append(buffer, &actOff, MAX_BUFF_LEN, "|");

    /* Withdraw list */
    for (u_int16_t i = 0; i < entry->nbWithdraw; i++)
    {
        if (i > 0) buf_append(buffer, &actOff, MAX_BUFF_LEN, ",");
        char pbuf[INET6_ADDRSTRLEN + 8];
        prefix_to_str(entry->withdraw_address1[i], entry->withdraw_address0[i], entry->withdraw_prefix_len[i], pbuf, sizeof(pbuf));
        buf_append(buffer, &actOff, MAX_BUFF_LEN, "%s", pbuf);
    }

    buf_append(buffer, &actOff, MAX_BUFF_LEN, "|");

    /* Origin */
    char origin_str[32];
    origin_to_str(entry->origin, entry->origin_present, origin_str, sizeof(origin_str));
    buf_append(buffer, &actOff, MAX_BUFF_LEN, "%s|", origin_str);

    /* Next-hop */
    char nh_str[INET6_ADDRSTRLEN];
    addr_to_str(entry->nextHop_address1, entry->nextHop_address0, nh_str, sizeof(nh_str));
    buf_append(buffer, &actOff, MAX_BUFF_LEN, "%s|", nh_str);

    /* AS-PATH */
    char asp_str[MAX_ASPATH_ASNS * 8];
    aspath_to_str(entry, asp_str, sizeof(asp_str));
    buf_append(buffer, &actOff, MAX_BUFF_LEN, "%s|", asp_str);

    /* Communities */
    char com_str[MAX_COMMUNITIES * 8];
    communities_to_str(entry, com_str, sizeof(com_str));
    buf_append(buffer, &actOff, MAX_BUFF_LEN, "%s|", com_str);

    /* Peer */
    char peer_str[INET6_ADDRSTRLEN];
    addr_to_str(entry->peer_address1, entry->peer_address0, peer_str, sizeof(peer_str));
    buf_append(buffer, &actOff, MAX_BUFF_LEN, "%u|%s\n", entry->peer_asn, peer_str);

    printf("%s", buffer);
}
