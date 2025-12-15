/*
 * SPDX-FileCopyrightText: 2025 Thomas Alfroy
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __MRT_ENTRY_H__
#define __MRT_ENTRY_H__

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#define MAX_NB_PREFIXES 2048

/* Maximum number of bytes for optional debug buffers */
#define MAX_ATTR 4096

/* ===== Binary (non-string) storage limits ===== */
#define MAX_ASPATH_ASNS 256
#define MAX_ASPATH_SEGS 64

/* Up to 4096 bytes of community payload:
 *  - classic communities (4B): 1024 values
 *  - ext communities (8B): 512 values
 *  - large communities (12B): 341 values
 *
 * We cap at 1024 entries and store each value in a 128-bit lane (communities1, communities0),
 * plus per-value metadata (attr type + value length).
 */
#define MAX_COMMUNITIES 1024


/**
 * @brief Structure containing an IP prefix.
 *
 * NOTE: kept for backward compatibility, but MRTentry now stores prefixes in split 128-bit form:
 *   address1 (upper 64 bits), address0 (lower 64 bits), prefix_len.
 */
typedef struct
{
    /**
     * @brief Address family of the IP prefix.
     */
    u_int8_t afi;

    /**
     * @brief Length of the prefix mask.
     */
    u_int8_t pfxLen;

    /**
     * @brief Array of bytes composing the prefix (4 for IPv4, 16 for IPv6).
     */
    u_int8_t pfx[16];
} Prefix_t;


struct FileBuffer;

/**
 * @brief Structure representing a MRT entry (only for BGP-related records.).
 *
 * This version stores key values in base datatypes (no persistent string fields).
 * Any string rendering is performed on-the-fly in MRTentry_print().
 *
 * IPv4/IPv6 representation for addresses:
 *   - IPv4: address1 == 0, address0 holds IPv4 in the LOW 32 bits (network order packed into u32)
 *   - IPv6: address1/address0 are the upper/lower 64 bits of the 128-bit address (big-endian packed)
 *
 * (Per your requirement, address1==0 is treated as IPv4.)
 */
typedef struct mrt_entry_t
{
    /**
     * @brief Entry type of the MRT entry, as defined in the RFC.
     */
    u_int16_t entryType;

    /**
     * @brief Entry subtype of the MRT entry, as defined in the RFC.
     */
    u_int16_t entrySubType;

    /**
     * @brief Length of the MRT entry (in number of bytes).
     */
    u_int32_t entryLength;


    /**
     * @brief Type of BGP message (e.g., UPDATE, KEEPALIVE,...). We also added the
     * BGP STATE CHANGE message, in case we have an MRT state change message.
     */
    u_int16_t bgpType;


    /**
     * @brief AS number of the BGP peer from which we collected the BGP message
     */
    u_int32_t peer_asn;

    /**
     * @brief Address family of the BGP peer from which we collected the BGP message
     */
    u_int16_t afi;

    /**
     * @brief IP address of the BGP peer (split 128-bit).
     */
    uint64_t peer_address1;
    uint64_t peer_address0;


    /**
     * @brief UNIX timestamp at which the BGP message has been received (seconds).
     */
    u_int32_t time;

    /**
     * @brief Sub-second timestamp component (microseconds for BGP4MP_ET, else 0).
     */
    u_int32_t time_ms;


    /**
     * @brief Number of prefixes that are withdrawn in this BGP message (if any).
     */
    u_int16_t nbWithdraw;

    /**
     * @brief Number of prefixes that are announced in this BGP message (if any).
     */
    u_int16_t nbNLRI;


    /**
     * @brief Withdrawn prefixes (split 128-bit + prefix length).
     */
    uint64_t withdraw_address1[MAX_NB_PREFIXES];
    uint64_t withdraw_address0[MAX_NB_PREFIXES];
    uint8_t  withdraw_prefix_len[MAX_NB_PREFIXES];

    /**
     * @brief Announced prefixes (split 128-bit + prefix length).
     */
    uint64_t nlri_address1[MAX_NB_PREFIXES];
    uint64_t nlri_address0[MAX_NB_PREFIXES];
    uint8_t  nlri_prefix_len[MAX_NB_PREFIXES];


    /**
     * @brief Next-hop attribute (split 128-bit).
     */
    uint64_t nextHop_address1;
    uint64_t nextHop_address0;


    /**
     * @brief AS-PATH attribute, stored as:
     *   - asPath[]: flattened list of ASNs
     *   - segment metadata to preserve AS_SEQUENCE vs AS_SET, etc.
     */
    uint8_t asPathLen;          /* number of ASNs in asPath[] */
    uint8_t asPathSegCount;     /* number of segments */
    uint32_t asPath[MAX_ASPATH_ASNS];

    uint8_t asPathSegOffset[MAX_ASPATH_SEGS]; /* offset into asPath[] */
    uint8_t asPathSegType[MAX_ASPATH_SEGS];   /* segment type */
    uint8_t asPathSegLen[MAX_ASPATH_SEGS];    /* segment ASN count (as in BGP) */


    /**
     * @brief Communities (classic/extended/large), stored as 128-bit lanes.
     * - communities_attr_type: the attribute code that carried the value (8/16/32)
     * - communities_value_len: the value length in bytes (4/8/12/16, etc.)
     * - communities1/communities0: raw value bytes packed in big-endian order into 128 bits
     */
    uint16_t communities_count;
    uint8_t  communities_attr_type[MAX_COMMUNITIES];
    uint8_t  communities_value_len[MAX_COMMUNITIES];
    uint64_t communities1[MAX_COMMUNITIES];
    uint64_t communities0[MAX_COMMUNITIES];


    /**
     * @brief Origin attribute (raw origin code).
     * Values are usually: 0=IGP, 1=EGP, 2=INCOMPLETE
     */
    uint8_t origin;
    uint8_t origin_present;


    /**
     * @brief Related File buffer structure.
     */
    struct FileBuffer* dumper;

    struct mrt_entry_t *next;
    struct mrt_entry_t *prev;

} MRTentry;


/**
 * @brief Function that creates a new, empty pointer to an allocated MRT entry
 * structure. In case no memory can be allocated, NULL is returned.
 *
 * @return MRTentry*    Returns the pointer to the allocated new MRT entry structure.
 */
MRTentry* MRTentry_new(void);


/**
 * @brief Function that copy an MRT entry for RIB processing. Takes an input MRT entry,
 * creates a new pointer to an allocated empty MRT structure, and copies only the
 * fields that should be inherited across per-peer RIB route entries (e.g., time + prefix).
 *
 * @param entry     Pointer to the MRT entry structure that we want to copy.
 *
 * @return MRTentry*    Returns a pointer to the copied MRT entry.
 */
MRTentry* MRTentry_copy_for_ribs(MRTentry* entry);


/**
 * @brief Function that frees the current MRT entry. Does not touch anything to the MRT entry
 * structures that are linked to the current one.
 *
 * @param entry     Pointer to the MRT entry structure that we want to free.
 */
void MRTentry_free_one(MRTentry* entry);


/**
 * @brief Function that frees the current MRT entry structure, as well as all the other MRT entries
 * that are linked to the current one.
 *
 * @param entry     Pointer to the MRT entry structure that we want to free.
 */
void MRTentry_free(MRTentry* entry);


/**
 * @brief Function that prints (on standard output) the corresponding full MRT entry.
 *
 * @param entry     Pointer to the MRT entry that we want to print.
 */
void MRTentry_print(MRTentry* entry);

#endif
