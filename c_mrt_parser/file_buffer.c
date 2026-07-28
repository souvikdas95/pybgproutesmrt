/*
 * SPDX-FileCopyrightText: 2025 Thomas Alfroy
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "file_buffer.h"
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* ========= Binary address helpers ========= */
static inline uint64_t pack_u64_be(const uint8_t* p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) | ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static inline void pack_ipv4_from_bytes(const uint8_t* p, uint64_t* a1, uint64_t* a0)
{
    uint32_t v4 = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | ((uint32_t)p[3]);
    *a1 = 0;
    *a0 = (uint64_t)v4;
}

static inline void pack_ipv6_from_bytes(const uint8_t* p, uint64_t* a1, uint64_t* a0)
{
    *a1 = pack_u64_be(p);
    *a0 = pack_u64_be(p + 8);
}

static inline void pack_128_from_bytes_be(const uint8_t* p, uint8_t n, uint64_t* hi, uint64_t* lo)
{
    /* Pack up to 16 bytes into (hi, lo).
     *
     * The input bytes are interpreted as one big-endian integer of length n
     * and right-aligned inside the 128-bit lane:
     *
     *   (hi, lo) = zero_pad_left(p[0..n-1])
     *
     * Example for n = 12:
     *   hi = 0x00000000 || p[0..3]
     *   lo = p[4..7]   || p[8..11]
     *
     * This makes a large community:
     *   global_admin -> low 32 bits of hi
     *   local_data1  -> high 32 bits of lo
     *   local_data2  -> low 32 bits of lo
     */
    uint8_t tmp[16];
    memset(tmp, 0, 16);
    if (n > 16) n = 16;
    if (n > 0) memcpy(tmp + (16 - n), p, n);    // memcpy(tmp, p, n);
    *hi = pack_u64_be(tmp);
    *lo = pack_u64_be(tmp + 8);
}

void print_raw_bgp_message(u_char* buffer, int len, uint16_t type, uint16_t subType)
{   
    if (subType != BGP_SUBTYPE_RIB_IPV6_UNICAST)
    {
        return;
    }

    char tmp[1024];
    memset(tmp, 0, 1024);
    printf("\n########## New BGP message ############\n");
    printf("%d | %d\n", type, subType);

    for (int i = 0 ; i < len ; i++)
    {
        printf("%d ", buffer[i]);

        if ((i+1)%16 == 0 && i < len-1)
        {
            printf("\n");
        }
    }
    printf("\n######### End of BGP message ############\n");
}


uint8_t get_buf_char(u_char* buf)
{
    uint8_t ch = buf[0];
    return ch;
}


uint16_t get_buf_short(u_char* buf)
{
    uint16_t ch = 256 * buf[0] + buf[1];

    return ch;
}


uint32_t get_buf_int(u_char* buf)
{
    uint32_t ch = 256 * 256 * 256 * buf[0] + 256 * 256 * buf[1] + 256 * buf[2] + buf[3];
    return ch;
}


void get_buf_n(u_char* buf, char* dest, int n)
{
    for (int i = 0 ; i < n ; i++)
    {
        dest[i] = buf[i];
    }
}

static inline int socket_afi_from_bgp_afi(uint16_t bgp_afi)
{
    if (bgp_afi == BGP_IPV4_AFI)
    {
        return AF_INET;
    }
    else if (bgp_afi == BGP_IPV6_AFI)
    {
        return AF_INET6;
    }

    return -1;
}


int process_prefix(u_char* buffer, uint64_t* address1, uint64_t* address0, uint8_t* prefix_len, int afi)
{
    /* Prefix length is in bits */
    int pfxLen = get_buf_char(buffer);

    if ((afi == AF_INET && pfxLen > 32) || (afi == AF_INET6 && pfxLen > 128))
    {
        return -1;
    }

    int nbBytesPfx = (pfxLen + 7) / 8;

    if (prefix_len) *prefix_len = (uint8_t)pfxLen;

    if (afi == AF_INET)
    {
        uint8_t tmp4[4];
        memset(tmp4, 0, 4);
        get_buf_n(buffer + 1, (char*)tmp4, nbBytesPfx > 4 ? 4 : nbBytesPfx);
        pack_ipv4_from_bytes(tmp4, address1, address0);
        return 1 + nbBytesPfx;
    }
    else if (afi == AF_INET6)
    {
        uint8_t tmp16[16];
        memset(tmp16, 0, 16);
        get_buf_n(buffer + 1, (char*)tmp16, nbBytesPfx > 16 ? 16 : nbBytesPfx);
        pack_ipv6_from_bytes(tmp16, address1, address0);
        return 1 + nbBytesPfx;
    }

    return -1;
}



typedef struct
{
    uint8_t  present;
    uint8_t  asn_count;
    uint8_t  seg_count;
    uint32_t asn[MAX_ASPATH_ASNS];
    uint8_t  seg_type[MAX_ASPATH_SEGS];
    uint8_t  seg_len[MAX_ASPATH_SEGS];
    uint8_t  seg_off[MAX_ASPATH_SEGS];
} Parsed_aspath_t;

static inline void parsed_aspath_reset(Parsed_aspath_t* p)
{
    memset(p, 0, sizeof(*p));
}

static inline int is_confed_seg(uint8_t t)
{
    return (t == BGP_AS_PATH_SEG_CONFED_SEQUENCE) || (t == BGP_AS_PATH_SEG_CONFED_SET);
}

/* "Number of AS numbers" per RFC 6793: use the path length calculation from
 * RFC 4271 9.1.2.2 (AS_SEQUENCE counts all ASNs, AS_SET counts as 1, confed segments ignored). */
static int aspath_metric(const Parsed_aspath_t* p)
{
    int m = 0;
    for (uint8_t s = 0; s < p->seg_count; s++)
    {
        uint8_t t = p->seg_type[s];
        uint8_t l = p->seg_len[s];

        if (t == BGP_UPDATE_AS_PATH_SEQ)
        {
            m += (int)l;
        }
        else if (t == BGP_UPDATE_AS_PATH_SET)
        {
            if (l > 0) m += 1;
        }
        else
        {
            /* AS_CONFED_*: ignored */
        }
    }
    return m;
}

static inline void aspath_append_segment(Parsed_aspath_t* dst, uint8_t segType, const uint32_t* asns, uint8_t segLen)
{
    if (segLen == 0) return;

    /* record segment metadata (best-effort) */
    if (dst->seg_count < MAX_ASPATH_SEGS)
    {
        dst->seg_type[dst->seg_count] = segType;
        dst->seg_len[dst->seg_count]  = segLen;
        dst->seg_off[dst->seg_count]  = dst->asn_count;
        dst->seg_count++;
    }

    /* append ASNs (best-effort) */
    for (uint8_t i = 0; i < segLen; i++)
    {
        if (dst->asn_count < MAX_ASPATH_ASNS)
        {
            dst->asn[dst->asn_count++] = asns[i];
        }
    }
}

static inline void aspath_append_path(Parsed_aspath_t* dst, const Parsed_aspath_t* src)
{
    for (uint8_t s = 0; s < src->seg_count; s++)
    {
        uint8_t t = src->seg_type[s];
        uint8_t l = src->seg_len[s];
        uint8_t o = src->seg_off[s];
        if (o + l <= src->asn_count)
        {
            aspath_append_segment(dst, t, &src->asn[o], l);
        }
        else if (o < src->asn_count)
        {
            /* defensive clamp on malformed metadata */
            uint8_t clamp = (uint8_t)(src->asn_count - o);
            aspath_append_segment(dst, t, &src->asn[o], clamp);
        }
    }
}

/* Parse AS_PATH / AS4_PATH payload into a local representation.
 * Returns:
 *   1  success
 *   0  hard bounds error (caller should abort)
 *  -1  malformed attribute (caller should discard this attribute and continue)
 */
static int parse_aspath_attr_payload(const u_char* buffer,
                                    uint32_t* actOff,
                                    uint32_t limit,
                                    uint16_t attrLen,
                                    int asnBytes,
                                    int drop_confed,
                                    Parsed_aspath_t* out)
{
    uint32_t off = *actOff;
    uint16_t parsed = 0;

    parsed_aspath_reset(out);
    out->present = 1;

    while (parsed < attrLen)
    {
        if (parsed + 2 > attrLen)
        {
            /* Malformed: header truncated */
            off += (uint32_t)(attrLen - parsed);
            if (off > limit) return 0;
            *actOff = off;
            return -1;
        }

        uint8_t segType = buffer[off++];
        if (off > limit) return 0;
        uint8_t segLen  = buffer[off++];
        if (off > limit) return 0;
        parsed += 2;

        if (segLen == 0)
        {
            /* Malformed per RFC 6793 */
            off += (uint32_t)(attrLen - parsed);
            if (off > limit) return 0;
            *actOff = off;
            return -1;
        }

        uint32_t needBytes = (uint32_t)segLen * (uint32_t)asnBytes;
        if ((uint32_t)parsed + needBytes > (uint32_t)attrLen)
        {
            /* Malformed length */
            off += (uint32_t)(attrLen - parsed);
            if (off > limit) return 0;
            *actOff = off;
            return -1;
        }

        /* Drop confed segments from AS4_PATH (RFC 6793, Section 4.2.2/6) */
        if (drop_confed && is_confed_seg(segType))
        {
            off += needBytes;
            if (off > limit) return 0;
            parsed = (uint16_t)(parsed + needBytes);
            continue;
        }

        /* Accept only known segment types */
        if (!(segType == BGP_UPDATE_AS_PATH_SET ||
              segType == BGP_UPDATE_AS_PATH_SEQ ||
              segType == BGP_AS_PATH_SEG_CONFED_SEQUENCE ||
              segType == BGP_AS_PATH_SEG_CONFED_SET))
        {
            off += (uint32_t)(attrLen - parsed);
            if (off > limit) return 0;
            *actOff = off;
            return -1;
        }

        if (out->seg_count < MAX_ASPATH_SEGS)
        {
            out->seg_type[out->seg_count] = segType;
            out->seg_len[out->seg_count]  = segLen;
            out->seg_off[out->seg_count]  = out->asn_count;
            out->seg_count++;
        }

        for (uint8_t i = 0; i < segLen; i++)
        {
            uint32_t asn_val = 0;

            if (asnBytes == 2)
            {
                asn_val = (uint32_t)get_buf_short((u_char*)(buffer + off));
                off += 2;
                if (off > limit) return 0;
                parsed += 2;
            }
            else
            {
                asn_val = (uint32_t)get_buf_int((u_char*)(buffer + off));
                off += 4;
                if (off > limit) return 0;
                parsed += 4;
            }

            if (out->asn_count < MAX_ASPATH_ASNS)
            {
                out->asn[out->asn_count++] = asn_val;
            }
        }
    }

    *actOff = off;
    return 1;
}

/* Build the RFC6793-reconstructed AS path from AS_PATH and AS4_PATH. */
static void reconstruct_aspath(Parsed_aspath_t* out,
                              const Parsed_aspath_t* as_path,
                              const Parsed_aspath_t* as4_path)
{
    Parsed_aspath_t prefix;
    parsed_aspath_reset(out);
    parsed_aspath_reset(&prefix);

    if (as_path && as_path->present && (!as4_path || !as4_path->present))
    {
        aspath_append_path(out, as_path);
        return;
    }
    if (as4_path && as4_path->present && (!as_path || !as_path->present))
    {
        aspath_append_path(out, as4_path);
        return;
    }
    if (!as_path || !as4_path || !as_path->present || !as4_path->present)
    {
        return;
    }

    int m2 = aspath_metric(as_path);
    int m4 = aspath_metric(as4_path);

    /* If AS_PATH "length" < AS4_PATH "length", ignore AS4_PATH (RFC 6793 4.2.3). */
    if (m2 < m4)
    {
        aspath_append_path(out, as_path);
        return;
    }

    int need = m2 - m4;

    /* Always keep leading confed segments from AS_PATH (excluded from AS4_PATH). */
    uint8_t s = 0;
    while (s < as_path->seg_count && is_confed_seg(as_path->seg_type[s]))
    {
        uint8_t o = as_path->seg_off[s];
        uint8_t l = as_path->seg_len[s];
        if (o < as_path->asn_count)
        {
            uint8_t clamp = (uint8_t)((o + l <= as_path->asn_count) ? l : (as_path->asn_count - o));
            aspath_append_segment(&prefix, as_path->seg_type[s], &as_path->asn[o], clamp);
        }
        s++;
    }

    int remaining = need;
    int ended_mid_segment = 0;

    /* Take as many leading segments / ASNs as necessary from AS_PATH to reach "need". */
    while (remaining > 0 && s < as_path->seg_count)
    {
        uint8_t t = as_path->seg_type[s];
        uint8_t o = as_path->seg_off[s];
        uint8_t l = as_path->seg_len[s];

        if (o >= as_path->asn_count) break;

        uint8_t clamp = (uint8_t)((o + l <= as_path->asn_count) ? l : (as_path->asn_count - o));
        const uint32_t* asns = &as_path->asn[o];

        if (is_confed_seg(t))
        {
            /* Adjacent confed segment */
            aspath_append_segment(&prefix, t, asns, clamp);
            s++;
            continue;
        }

        if (t == BGP_UPDATE_AS_PATH_SET)
        {
            /* AS_SET counts as 1 in metric */
            aspath_append_segment(&prefix, t, asns, clamp);
            remaining -= 1;
            s++;
            continue;
        }

        /* Treat everything else as AS_SEQUENCE-like for reconstruction */
        uint8_t take = (clamp <= (uint8_t)remaining) ? clamp : (uint8_t)remaining;
        aspath_append_segment(&prefix, t, asns, take);
        remaining -= (int)take;

        if (take < clamp)
        {
            ended_mid_segment = 1;
            break;
        }

        s++;
    }

    /* If we ended exactly on a segment boundary, also prepend immediately-adjacent confed segments. */
    if (!ended_mid_segment)
    {
        while (s < as_path->seg_count && is_confed_seg(as_path->seg_type[s]))
        {
            uint8_t o = as_path->seg_off[s];
            uint8_t l = as_path->seg_len[s];
            if (o < as_path->asn_count)
            {
                uint8_t clamp = (uint8_t)((o + l <= as_path->asn_count) ? l : (as_path->asn_count - o));
                aspath_append_segment(&prefix, as_path->seg_type[s], &as_path->asn[o], clamp);
            }
            s++;
        }
    }

    aspath_append_path(out, &prefix);
    aspath_append_path(out, as4_path);
}

static void commit_aspath_to_entry(MRTentry* entry, const Parsed_aspath_t* p)
{
    entry->asPathLen      = p->asn_count;
    entry->asPathSegCount = p->seg_count;

    /* Copy flattened ASNs */
    for (uint8_t i = 0; i < p->asn_count; i++)
    {
        entry->asPath[i] = p->asn[i];
    }

    /* Copy segment metadata */
    for (uint8_t s = 0; s < p->seg_count; s++)
    {
        entry->asPathSegType[s]   = p->seg_type[s];
        entry->asPathSegLen[s]    = p->seg_len[s];
        entry->asPathSegOffset[s] = p->seg_off[s];
    }
}


File_buf_t* File_buf_create(const char *filename)
{
    File_buf_t* dumper = calloc(1, sizeof(File_buf_t));
    dumper->f = cfr_open(filename);

    if (!dumper->f)
    {
        free(dumper);
        return NULL;
    }

    dumper->eof=0;
    dumper->parsed = 0;
    dumper->parsed_ok = 0;

    return dumper;
}


void File_buf_close_dump(File_buf_t *dump)
{
    if(dump == NULL) {
        return;
    }

    if (dump->actEntry)
    {
        MRTentry_free(dump->actEntry);
    }

	cfr_close(dump->f);
    free(dump);
}



MRTentry* Read_next_mrt_entry(File_buf_t *dump)
{
    MRTentry* tmp;

    /* If we still have an already-parsed chain, stream through it */
    if (dump->actEntry)
    {
        /* If there is still a next entry that has not been already returned */
        if (dump->actEntry->next)
        {
            MRTentry* old = dump->actEntry;
            tmp = old->next;

            /* Advance cursor first */
            dump->actEntry = tmp;

            /* Detach and free the previous node to prevent memory growth */
            old->next = NULL;
            old->prev = NULL;
            MRTentry_free_one(old);

            return tmp;
        }
        /* No more linked entries: free the last node and parse a new MRT record */
        else
        {
            MRTentry_free_one(dump->actEntry);
            dump->actEntry = NULL;
        }
    }

    /* Allocate a new entry for the next MRT record */
    MRTentry* entry = MRTentry_new();
    if (!entry)
    {
        printf("Unable to allocate any memory\n");
        dump->actEntry = NULL;
        return NULL;
    }

    /* Defensive init in case MRTentry_new() uses malloc instead of calloc */
    entry->next = NULL;
    entry->prev = NULL;
    entry->dumper = dump;

    u_int32_t bytes_read;
    u_int8_t ok = 0;
    u_int8_t* bgpMsgBuffer;

    bytes_read = cfr_read_n(dump->f, &entry->time, 4);
    bytes_read += cfr_read_n(dump->f, &(entry->entryType), 2);
    bytes_read += cfr_read_n(dump->f, &(entry->entrySubType), 2);
    bytes_read += cfr_read_n(dump->f, &(entry->entryLength), 4);

    if (bytes_read == 12)
    {
        /* Intel byte ordering stuff ... */
        entry->entryType = ntohs(entry->entryType);
        entry->entrySubType = ntohs(entry->entrySubType);
        entry->time = (time_t)ntohl(entry->time);
        entry->entryLength = ntohl(entry->entryLength);

        /* If Extended Header format, then reading the microseconds attribute */
        if (entry->entryType == MRT_TYPE_BGP4MP_ET)
        {
            bytes_read += cfr_read_n(dump->f, &(entry->time_ms), 4);
            if (bytes_read == 16)
            {
                entry->time_ms = ntohl(entry->time_ms);
                /* "The Microsecond Timestamp is included in the computation of
                 * the Length field value." (RFC6396 2011) */
                entry->entryLength -= 4;
                ok = 1;
            }
        }
        else
        {
            entry->time_ms = 0;
            ok = 1;
        }
    }

    if (!ok)
    {
        if (bytes_read > 0)
        {
            printf("Incomplete MRT header (%d bytes read, expecting 12 or 16)\n", bytes_read);
        }
        MRTentry_free(entry);
        dump->eof = 1;
        dump->actEntry = NULL;
        return NULL;
    }

    dump->parsed++;

    if (entry->entryLength == 0)
    {
        printf("Invalid entry length: 0\n");
        MRTentry_free(entry);
        dump->eof = 1;
        dump->actEntry = NULL;
        return NULL;
    }

    bgpMsgBuffer = (u_int8_t*)malloc(entry->entryLength);
    if (!bgpMsgBuffer)
    {
        printf("Out of memory\n");
        MRTentry_free(entry);
        dump->eof = 1;
        dump->actEntry = NULL;
        return NULL;
    }

    bytes_read = cfr_read_n(dump->f, bgpMsgBuffer, entry->entryLength);
    if (bytes_read != entry->entryLength)
    {
        printf("Incomplete dump record (%d bytes read, expecting %d)\n", bytes_read, entry->entryLength);
        MRTentry_free(entry);
        free(bgpMsgBuffer);
        dump->eof = 1;
        dump->actEntry = NULL;
        return NULL;
    }

    switch (entry->entryType)
    {
        case MRT_TYPE_BGP4MP:
        case MRT_TYPE_BGP4MP_ET:
            ok = process_classic_message(bgpMsgBuffer, entry, entry->entryLength);
            break;

        case MRT_TYPE_TABLE_DUMP_V2:
            ok = process_bgp_rib(bgpMsgBuffer, entry, entry->entryLength);
            break;

        default:
            printf("Sorry MRT type not handled\n");
            ok = 0;
            break;
    }

    free(bgpMsgBuffer);

    if (ok)
    {
        dump->parsed_ok++;
    }
    else
    {
        MRTentry_free(entry);
        dump->actEntry = NULL;
        return NULL;
    }

    /* Set current cursor to the head of the returned chain */
    dump->actEntry = entry;
    return entry;
}




int process_classic_message(u_char* buffer, MRTentry* entry, int max_len)
{
    if (!entry || !buffer)
    {
        return 0;
    }

    u_char marker[16]; /* BGP marker */
    int actOff = 0;
    u_char peer_ip[16];
    uint16_t msgSize;
    u_char msgType;

    /* In case we have an ASN 2-bytes peer */
    if (entry->entrySubType == MRT_SUBTYPE_BGP4MP_MESSAGE || 
        entry->entrySubType == MRT_SUBTYPE_BGP4MP_MESSAGE_LOCAL || 
        entry->entrySubType == MRT_SUBTYPE_BGP4MP_STATE_CHANGE)
    {
        /* Get the peer ASN */
        entry->peer_asn = get_buf_short(buffer + actOff);
        UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0) 

        /* Skip dest ASN */
        UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0) 
    }
    /* In case we have an ASN 4-bytes peer */
    else if (entry->entrySubType == MRT_SUBTYPE_BGP4MP_MESSAGE_AS4 || 
             entry->entrySubType == MRT_SUBTYPE_BGP4MP_MESSAGE_AS4_LOCAL ||
             entry->entrySubType == MRT_SUBTYPE_BGP4MP_STATE_CHANGE_AS4)
    {
        /* Get the peer ASN */
        entry->peer_asn = get_buf_int(buffer + actOff);
        UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0) 

        /* Skip dest ASN */
        UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0) 
    }
    else
    {
        return 0;
    }

    /* Skip interface ID */
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0) 
    
    /* Get the peer AFI */
    entry->afi = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0) 

    /* Set the number of prefixes to 0 */
    entry->nbNLRI = 0;
    entry->nbWithdraw = 0;

    /* Parsing source peer IP */
    if (entry->afi == BGP_IPV4_AFI)
    {
        get_buf_n(buffer+actOff, (char*)peer_ip, 4);
        UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0) 

        /* Skip destination IP */
        UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)

        pack_ipv4_from_bytes((const uint8_t*)peer_ip, &entry->peer_address1, &entry->peer_address0);
    }
    else if (entry->afi == BGP_IPV6_AFI)
    {
        get_buf_n(buffer+actOff, (char*)peer_ip, 16);
        UPDATE_AND_CHECK_LEN(actOff, 16, max_len, 0) 

        /* Skip destination IP */
        UPDATE_AND_CHECK_LEN(actOff, 16, max_len, 0) 

        pack_ipv6_from_bytes((const uint8_t*)peer_ip, &entry->peer_address1, &entry->peer_address0);
    }
    else
    {
        return 0;
    }

    if (entry->entrySubType == MRT_SUBTYPE_BGP4MP_STATE_CHANGE ||
        entry->entrySubType == MRT_SUBTYPE_BGP4MP_STATE_CHANGE_AS4)
    {
        entry->bgpType = BGP_TYPE_STATE_CHANGE;

        /* Skipp old state */
        UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

        /* skipp new state */
        UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

        return 1;
    }

    /* Get BGP marker */
    get_buf_n(buffer+actOff, (char*)marker, 16);
    UPDATE_AND_CHECK_LEN(actOff, 16, max_len, 0)

    /* If BGP marker is not correct, return */
    if(memcmp(marker, "\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377", 16) != 0)
    {
        return 0;
    }

    /* Get BGP message Length */
    msgSize = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

    /* Check for message length inconsistency */
    if (msgSize + actOff - 18 !=max_len)
    {
        printf("BGP message inconsistency %d vs %d\n", msgSize + actOff - 18, max_len);
        return 0;
    }

    /* Get Message type */
    msgType = get_buf_char(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 1, max_len, 0)

    switch (msgType)
    {
        case BGP_TYPE_UPDATE:
            entry->bgpType = BGP_TYPE_UPDATE;
            return process_bgp_update(buffer+actOff, entry, msgSize - 19);

        default:
            entry->bgpType = msgType;
            return 1;
    }

    return 1;
}


int process_bgp_update(u_char* buffer, MRTentry* entry, int max_len)
{
    int actOff = 0;
    int ret;
    int parsedLen = 0;

    /* Get the withdraw length */
    uint16_t withdrawLen = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

    uint16_t actWithLen = 0;


    /* parsing withdraw section */
    while (actWithLen < withdrawLen)
    {   
        /* If already too much prefixes in the packet, just skip */
        if (entry->nbWithdraw >= MAX_NB_PREFIXES)
        {
            parsedLen = get_buf_char(buffer+actOff);
            if (parsedLen > 128)
            {
                return 0;
            }
            parsedLen = (parsedLen+7)/8;

            UPDATE_AND_CHECK_LEN(actOff, parsedLen+1, max_len, 0)
        }
        else
        {
            /* Get te prefix length */
            parsedLen = process_prefix(buffer+actOff, &entry->withdraw_address1[entry->nbWithdraw], &entry->withdraw_address0[entry->nbWithdraw], &entry->withdraw_prefix_len[entry->nbWithdraw], AF_INET);
            if (parsedLen == -1)
            {
                return 0;
            }

            UPDATE_AND_CHECK_LEN(actOff, parsedLen, max_len, 0)
            actWithLen += parsedLen;
            
            entry->nbWithdraw++;
        }
        
    }

    /* Get all attribute length */
    uint16_t allAttrLen = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

    ret = process_bgp_attributes(buffer+actOff, entry, allAttrLen);
    if (ret != allAttrLen)
    {
        return 0;
    }

    actOff += allAttrLen;

    /* Parse IPv4 NLRI */
    while (actOff < max_len)
    {
        /* If already too much prefixes in the packet, just skip them */
        if (entry->nbNLRI >= MAX_NB_PREFIXES)
        {
            parsedLen = get_buf_char(buffer+actOff);
            if (parsedLen > 128)
            {
                return 0;
            }
            parsedLen = (parsedLen+7)/8;

            UPDATE_AND_CHECK_LEN(actOff, parsedLen+1, max_len, 0)
        }
        else
        {
            ret = process_prefix(buffer+actOff, &entry->nlri_address1[entry->nbNLRI], &entry->nlri_address0[entry->nbNLRI], &entry->nlri_prefix_len[entry->nbNLRI], AF_INET);
            if (ret == -1)
            {
                return 0;
            }

            UPDATE_AND_CHECK_LEN(actOff, ret, max_len, 0)
            entry->nbNLRI++;
        }
    }

    return 1;
}



int process_bgp_rib(u_char* buffer, MRTentry* entry, int max_len)
{
    
    switch (entry->entrySubType)
    {
        case BGP_SUBTYPE_PEER_INDEX_TABLE:
            return process_bgp_rib_index(buffer, entry, max_len);

        case BGP_SUBTYPE_RIB_IPV4_UNICAST:
        case BGP_SUBTYPE_RIB_IPV6_UNICAST:
            return process_bgp_rib_entry(buffer, entry, max_len);
        default:
            return 0;
    }
}






int process_bgp_rib_index(u_char *buffer, MRTentry* entry, int max_len)
{
    int actOff = 0;
    uint16_t viewLen;
    uint16_t peerCount;
    uint8_t peerType;
    uint32_t peerIdx;

    /* Collector ID */
    UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0) 

    /* Get the view length */
    viewLen = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

    /* Skip View name if exists */
    UPDATE_AND_CHECK_LEN(actOff, viewLen, max_len, 0)

    /* Get the peer count */
    peerCount = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

    for (int i = 0 ; i < peerCount ; i++)
    {
        /* Get peer Type */
        peerType = get_buf_char(buffer+actOff);
        UPDATE_AND_CHECK_LEN(actOff, 1, max_len, 0)
        
        /* Skip peer ID */
        UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)
        peerIdx = entry->dumper->actPeerIdx;
        entry->dumper->actPeerIdx++;

        if (peerIdx < 256)
        {
            entry->dumper->index[peerIdx].afi = peerType;
            entry->dumper->index[peerIdx].idx = peerIdx;

            if (peerType & 0x01) /* Case IPv6 peer */
            {
                /* Get peer IP address */
                pack_ipv6_from_bytes((const uint8_t*)(buffer+actOff), &entry->dumper->index[peerIdx].addr1, &entry->dumper->index[peerIdx].addr0);
                UPDATE_AND_CHECK_LEN(actOff, 16, max_len, 0)
            }
            else /* Case IPv4 peer */
            {
                /* Get peer IP address */
                pack_ipv4_from_bytes((const uint8_t*)(buffer+actOff), &entry->dumper->index[peerIdx].addr1, &entry->dumper->index[peerIdx].addr0);
                UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)
            }

            if (peerType & 0x02) /* Case ASN-32 peer */
            {
                /* Get peer ASN */
                entry->dumper->index[peerIdx].asn = get_buf_int(buffer+actOff);
                UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)
            }
            else /* Case ASN-16 peer */
            {
                /* Get peer ASN */
                entry->dumper->index[peerIdx].asn = get_buf_short(buffer+actOff);
                UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)
            }

        }
        /* Just skip if to much IDs */
        else
        {
            if (peerType & 0x01) /* Case IPv6 peer */
            {
                /* Skipp peer IP address */
                UPDATE_AND_CHECK_LEN(actOff, 16, max_len, 0)
            }
            else /* Case IPv4 peer */
            {
                /* Skipp peer IP address */
                UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)
            }

            if (peerType & 0x02) /* Case ASN-32 peer */
            {
                /* Skipp peer ASN */
                UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)
            }
            else /* Case ASN-16 peer */
            {
                /* Skipp peer ASN */
                UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)
            }
        }
    }

    return 1;
}

int process_bgp_rib_entry(u_char *buffer, MRTentry* entry, int max_len)
{
    int actOff = 0;
    int ret;
    uint16_t nbEntries;
    uint16_t peerIdx;
    uint16_t attrLen;

    /* Skip sequence number */
    UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)

    /* Process prefix */
    if (entry->entrySubType == BGP_SUBTYPE_RIB_IPV4_UNICAST)
    {
        ret = process_prefix(buffer+actOff, &entry->nlri_address1[entry->nbNLRI], &entry->nlri_address0[entry->nbNLRI], &entry->nlri_prefix_len[entry->nbNLRI], AF_INET);
        if (ret != -1) entry->nbNLRI++;
    }
    else
    {
        ret = process_prefix(buffer+actOff, &entry->nlri_address1[entry->nbNLRI], &entry->nlri_address0[entry->nbNLRI], &entry->nlri_prefix_len[entry->nbNLRI], AF_INET6);
        if (ret != -1) entry->nbNLRI++;
    }

    if (ret == -1)
    {
        return 0;
    }
    UPDATE_AND_CHECK_LEN(actOff, ret, max_len, 0)

    /* Get the number of entries */
    nbEntries = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

    /* Process only the first RIB entry, skip other if exists */
    peerIdx = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)


    /* If peer Index is too long, skip */
    if (peerIdx >= 256)
    {
        return 0;
    }

    /* Setup the peer infos according to index */
    entry->peer_asn      = entry->dumper->index[peerIdx].asn;
    entry->peer_address1  = entry->dumper->index[peerIdx].addr1;
    entry->peer_address0  = entry->dumper->index[peerIdx].addr0;

    /* Skip timestamp (already in MRT header) */
    UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)

    /* Get attribute length */
    attrLen = get_buf_short(buffer+actOff);
    UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0);

    /* Process attributes */
    ret = process_bgp_attributes(buffer+actOff, entry, attrLen);
    if (ret != attrLen)
    {
        return 0;
    }

    UPDATE_AND_CHECK_LEN(actOff, attrLen, max_len, 0);
    MRTentry* tmpEntry;
    MRTentry* prevEntry = entry;

    /* Skip other entries */
    for (int i = 1 ; i < nbEntries ; i++)
    {
        tmpEntry = MRTentry_copy_for_ribs(entry);
        tmpEntry->prev = prevEntry;
        prevEntry->next = tmpEntry;

        /* Process only the first RIB entry, skip other if exists */
        peerIdx = get_buf_short(buffer+actOff);
        UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)


        /* If peer Index is too long, skip */
        if (peerIdx >= 256)
        {
            return 0;
        }

        /* Setup the peer infos according to index */
        tmpEntry->peer_asn      = entry->dumper->index[peerIdx].asn;
        tmpEntry->peer_address1  = entry->dumper->index[peerIdx].addr1;
        tmpEntry->peer_address0  = entry->dumper->index[peerIdx].addr0;

        /* Skip timestamp */
        UPDATE_AND_CHECK_LEN(actOff, 4, max_len, 0)

        /* Get Attribute length */
        attrLen = get_buf_short(buffer+actOff);
        UPDATE_AND_CHECK_LEN(actOff, 2, max_len, 0)

        /* Process attributes */
        ret = process_bgp_attributes(buffer+actOff, tmpEntry, attrLen);
        if (ret != attrLen)
        {
            return 0;
        }

        UPDATE_AND_CHECK_LEN(actOff, attrLen, max_len, 0)

        prevEntry = tmpEntry;
    }

    return 1;
}



int process_bgp_attributes(u_char* buffer, MRTentry* entry, int allAttrLen)
{
    uint32_t actOff = 0;
    uint16_t actAllAttrLen = 0;
    uint8_t attrFlags, attrType;
    uint16_t attrLen;
    int parsedLen;
    uint8_t val;
    // uint8_t segType;
    // uint8_t segLen;
    uint8_t nextHopLen;
    uint8_t isMRTcompressed;

    /* Delay AS_PATH/AS4_PATH resolution until we've seen both attributes. */
    Parsed_aspath_t parsed_as_path;
    Parsed_aspath_t parsed_as4_path;
    Parsed_aspath_t final_as_path;
    parsed_aspath_reset(&parsed_as_path);
    parsed_aspath_reset(&parsed_as4_path);
    parsed_aspath_reset(&final_as_path);


    while (actAllAttrLen < allAttrLen)
    {   
        /* Get attribute flags */
        attrFlags = get_buf_char(buffer+actOff);
        UPDATE_AND_CHECK_LEN(actOff, 1, allAttrLen, 0);
        actAllAttrLen += 1;

        /* Get attribute type */
        attrType = get_buf_char(buffer+actOff);
        UPDATE_AND_CHECK_LEN(actOff, 1, allAttrLen, 0);
        actAllAttrLen += 1;

        /* Retrieve attribute Length */
        if (attrFlags & 0x10)
        {
            /* If extended lenth is set */
            attrLen = get_buf_short(buffer+actOff);
            UPDATE_AND_CHECK_LEN(actOff, 2, allAttrLen, 0);
            actAllAttrLen += 2;
        }
        else
        {
            /* If extended length is not set */
            attrLen = get_buf_char(buffer+actOff);
            UPDATE_AND_CHECK_LEN(actOff, 1, allAttrLen, 0)
            actAllAttrLen += 1;
        }

        /* Check attribute length */
        if (attrLen > 4096)
        {
            return 0;
        }

        /* Switch attribute type */
        switch (attrType)
        {
            case BGP_UPDATE_ATTR_ORIGIN:
            {
                /* Get origin value */
                val = get_buf_char(buffer+actOff);
                entry->origin = (uint8_t)val;
                entry->origin_present = 1;
                UPDATE_AND_CHECK_LEN(actOff, attrLen, allAttrLen, 0)
                break;
            }

            /* Parsing AS_PATH / AS4_PATH (RFC 6793 reconstruction) */
            case BGP_UPDATE_ATTR_AS_PATH:
            case BGP_UPDATE_ATTR_AS4_PATH:
            {
                Parsed_aspath_t* dst = (attrType == BGP_UPDATE_ATTR_AS4_PATH) ? &parsed_as4_path : &parsed_as_path;

                /* Determine ASN width */
                int asnBytes = 4;
                if (attrType == BGP_UPDATE_ATTR_AS_PATH)
                {
                    if (entry->entrySubType == MRT_SUBTYPE_BGP4MP_MESSAGE ||
                        entry->entrySubType == MRT_SUBTYPE_BGP4MP_MESSAGE_LOCAL)
                    {
                        asnBytes = 2;
                    }
                    else
                    {
                        asnBytes = 4;
                    }
                }

                /* If a duplicate attribute is seen, skip it (best-effort). */
                if (dst->present)
                {
                    UPDATE_AND_CHECK_LEN(actOff, attrLen, allAttrLen, 0)
                    break;
                }

                int drop_confed = (attrType == BGP_UPDATE_ATTR_AS4_PATH) ? 1 : 0;
                int st = parse_aspath_attr_payload(buffer, &actOff, (uint32_t)allAttrLen, attrLen, asnBytes, drop_confed, dst);

                if (st == 0)
                {
                    return 0; /* bounds error */
                }
                if (st < 0)
                {
                    /* Malformed attribute: discard AS4_PATH per RFC 6793; for AS_PATH keep empty. */
                    dst->present = 0;
                }

                break;
            }

            /* Parse the BGP communities */
            case BGP_UPDATE_NLRI_COMMUNITIES:
            {
                parsedLen = 0;

                while (parsedLen + 4 <= attrLen)
                {
                    /* Classic community: 4 bytes */
                    uint16_t c_asn = get_buf_short(buffer+actOff);
                    UPDATE_AND_CHECK_LEN(actOff, 2, allAttrLen, 0)
                    uint16_t c_val = get_buf_short(buffer+actOff);
                    UPDATE_AND_CHECK_LEN(actOff, 2, allAttrLen, 0)
                    parsedLen += 4;

                    if (entry->communities_count < MAX_COMMUNITIES)
                    {
                        uint32_t packed = ((uint32_t)c_asn << 16) | (uint32_t)c_val;
                        entry->communities_attr_type[entry->communities_count]  = (uint8_t)attrType; /* usually 8 */
                        entry->communities_value_len[entry->communities_count]  = 4;
                        entry->communities1[entry->communities_count]           = 0;
                        entry->communities0[entry->communities_count]           = (uint64_t)packed;
                        entry->communities_count++;
                    }
                }

                /* Skip any remaining odd bytes */
                if (parsedLen < attrLen)
                {
                    UPDATE_AND_CHECK_LEN(actOff, attrLen - parsedLen, allAttrLen, 0)
                }

                break;
            }

            case BGP_UPDATE_ATTR_EXT_COMMUNITIES:
            {
                parsedLen = 0;
                while (parsedLen + 8 <= attrLen)
                {
                    if (entry->communities_count >= MAX_COMMUNITIES)
                    {
                        UPDATE_AND_CHECK_LEN(actOff, attrLen - parsedLen, allAttrLen, 0)
                        parsedLen = attrLen;
                        break;
                    }

                    entry->communities_attr_type[entry->communities_count] = (uint8_t)attrType; /* 16 */
                    entry->communities_value_len[entry->communities_count] = 8;
                    entry->communities1[entry->communities_count] = 0;
                    entry->communities0[entry->communities_count] = pack_u64_be((const uint8_t*)(buffer+actOff));
                    entry->communities_count++;

                    UPDATE_AND_CHECK_LEN(actOff, 8, allAttrLen, 0)
                    parsedLen += 8;
                }

                if (parsedLen < attrLen)
                {
                    UPDATE_AND_CHECK_LEN(actOff, attrLen - parsedLen, allAttrLen, 0)
                }
                break;
            }

            case BGP_UPDATE_ATTR_LARGE_COMMUNITIES:
            {
                parsedLen = 0;
                while (parsedLen + 12 <= attrLen)
                {
                    if (entry->communities_count >= MAX_COMMUNITIES)
                    {
                        UPDATE_AND_CHECK_LEN(actOff, attrLen - parsedLen, allAttrLen, 0)
                        parsedLen = attrLen;
                        break;
                    }

                    /* Pack 12 bytes into 128-bit (hi, lo) */
                    pack_128_from_bytes_be((const uint8_t*)(buffer+actOff), 12,
                                           &entry->communities1[entry->communities_count],
                                           &entry->communities0[entry->communities_count]);
                    entry->communities_attr_type[entry->communities_count] = (uint8_t)attrType; /* 32 */
                    entry->communities_value_len[entry->communities_count] = 12;
                    entry->communities_count++;

                    UPDATE_AND_CHECK_LEN(actOff, 12, allAttrLen, 0)
                    parsedLen += 12;
                }

                if (parsedLen < attrLen)
                {
                    UPDATE_AND_CHECK_LEN(actOff, attrLen - parsedLen, allAttrLen, 0)
                }
                break;
            }

            /* Parse the nexthop attribute */
            case BGP_UPDATE_ATTR_NEXT_HOP:
            {
                /* Check that the Next-hop is 4-bytes long, return otherwise */
                if (attrLen != 4)
                {
                    UPDATE_AND_CHECK_LEN(actOff, attrLen, allAttrLen, 0)
                    return 0;
                }

                pack_ipv4_from_bytes((const uint8_t*)(buffer+actOff),
                                     &entry->nextHop_address1, &entry->nextHop_address0);
                UPDATE_AND_CHECK_LEN(actOff, attrLen, allAttrLen, 0)

                break;
            }

            /* Parse MP NRLI REACH, i.e., parse IPv6 nexthop and prefixes */
            case BGP_UPDATE_ATTR_NLRI:
            {
                uint16_t mp_afi = 0;
                int p_afi = -1;

                parsedLen = 0;

                /* 
                 * Handle truncated MP_REACH in some MRT encodings (no AFI/SAFI fields).
                 * If first byte is non-zero, treat as "compressed" and skip AFI/SAFI parsing.
                 */
                isMRTcompressed = false;
                if (buffer[actOff] != 0)
                {
                    isMRTcompressed = true;
                }

                /* Parse AFI + SAFI if present and use that AFI for NLRI decoding. */
                if (!isMRTcompressed)
                {
                    mp_afi = get_buf_short(buffer+actOff);
                    p_afi = socket_afi_from_bgp_afi(mp_afi);
                    if (p_afi == -1)
                    {
                        return 0;
                    }

                    UPDATE_AND_CHECK_LEN(actOff, 3, allAttrLen, 0)
                    parsedLen += 3;
                }

                /* Next-hop length */
                nextHopLen = get_buf_char(buffer+actOff);
                UPDATE_AND_CHECK_LEN(actOff, 1, allAttrLen, 0)
                parsedLen += 1;

                if (isMRTcompressed)
                {
                    if (nextHopLen == 4)
                    {
                        p_afi = AF_INET;
                    }
                    else if (nextHopLen == 16 || nextHopLen == 32)
                    {
                        p_afi = AF_INET6;
                    }
                    else
                    {
                        return 0;
                    }
                }

                /* Parse next-hop (we keep the first address if 32 bytes are present) */
                if (nextHopLen == 16 || nextHopLen == 32)
                {
                    pack_ipv6_from_bytes((const uint8_t*)(buffer+actOff),
                                         &entry->nextHop_address1, &entry->nextHop_address0);
                }
                else if (nextHopLen == 4)
                {
                    pack_ipv4_from_bytes((const uint8_t*)(buffer+actOff),
                                         &entry->nextHop_address1, &entry->nextHop_address0);
                }
                else
                {
                    /* Unknown next-hop length, just skip it */
                }

                UPDATE_AND_CHECK_LEN(actOff, nextHopLen, allAttrLen, 0)
                parsedLen += nextHopLen;

                /* Skip reserved byte */
                UPDATE_AND_CHECK_LEN(actOff, 1, allAttrLen, 0)
                parsedLen += 1;

                /* Parse NLRI prefixes */
                while (parsedLen < attrLen)
                {
                    if (entry->nbNLRI >= MAX_NB_PREFIXES)
                    {
                        /* Skip prefix */
                        int pfxLen = get_buf_char(buffer+actOff);
                        if ((p_afi == AF_INET && pfxLen > 32) || (p_afi == AF_INET6 && pfxLen > 128)) return 0;
                        int nbBytes = (pfxLen + 7) / 8;
                        UPDATE_AND_CHECK_LEN(actOff, nbBytes + 1, allAttrLen, 0)
                        parsedLen += nbBytes + 1;
                        continue;
                    }

                    int consumed = process_prefix(buffer+actOff,
                                                  &entry->nlri_address1[entry->nbNLRI],
                                                  &entry->nlri_address0[entry->nbNLRI],
                                                  &entry->nlri_prefix_len[entry->nbNLRI],
                                                  p_afi);
                    if (consumed == -1) return 0;

                    UPDATE_AND_CHECK_LEN(actOff, consumed, allAttrLen, 0)
                    parsedLen += consumed;
                    entry->nbNLRI++;
                }

                break;
            }

            /* Case of IPv6 withdraw */
            case BGP_UPDATE_NLRI_UNREACH:
            {
                uint16_t mp_afi = 0;
                int p_afi = -1;

                parsedLen = 0;

                mp_afi = get_buf_short(buffer+actOff);
                p_afi = socket_afi_from_bgp_afi(mp_afi);
                if (p_afi == -1)
                {
                    return 0;
                }

                /* Skip AFI + SAFI */
                UPDATE_AND_CHECK_LEN(actOff, 3, allAttrLen, 0)
                parsedLen += 3;

                /* Parse withdrawn NLRIs */
                while (parsedLen < attrLen)
                {
                    if (entry->nbWithdraw >= MAX_NB_PREFIXES)
                    {
                        int pfxLen = get_buf_char(buffer+actOff);
                        if ((p_afi == AF_INET && pfxLen > 32) || (p_afi == AF_INET6 && pfxLen > 128)) return 0;
                        int nbBytes = (pfxLen + 7) / 8;
                        UPDATE_AND_CHECK_LEN(actOff, nbBytes + 1, allAttrLen, 0)
                        parsedLen += nbBytes + 1;
                        continue;
                    }

                    int consumed = process_prefix(buffer+actOff,
                                                  &entry->withdraw_address1[entry->nbWithdraw],
                                                  &entry->withdraw_address0[entry->nbWithdraw],
                                                  &entry->withdraw_prefix_len[entry->nbWithdraw],
                                                  p_afi);
                    if (consumed == -1) return 0;

                    UPDATE_AND_CHECK_LEN(actOff, consumed, allAttrLen, 0)
                    parsedLen += consumed;
                    entry->nbWithdraw++;
                }

                break;
            }

            /* Default case for unknown or OSEF attribute */
            default:
                UPDATE_AND_CHECK_LEN(actOff, attrLen, allAttrLen, 0);
        }

        actAllAttrLen += attrLen;
    }

    /* Finalize AS_PATH reconstruction once all attributes are parsed (order-independent). */
    if (parsed_as_path.present || parsed_as4_path.present)
    {
        reconstruct_aspath(&final_as_path, &parsed_as_path, &parsed_as4_path);
        commit_aspath_to_entry(entry, &final_as_path);
        // fprintf(stderr, "DBG segCount=%u segType0=%u segOff0=%u segLen0=%u asLen=%u\n",
        //     entry->asPathSegCount,
        //     entry->asPathSegCount ? entry->asPathSegType[0] : 0,
        //     entry->asPathSegCount ? entry->asPathSegOffset[0] : 0,
        //     entry->asPathSegCount ? entry->asPathSegLen[0] : 0,
        //     entry->asPathLen
        // );
    }
    else
    {
        entry->asPathLen = 0;
        entry->asPathSegCount = 0;
    }

    return actOff;
}
