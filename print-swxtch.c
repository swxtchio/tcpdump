/*
 * Copyright (c) 2022 swXtch.io, LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. The names of the authors may not be used to endorse or promote
 *     products derived from this software without specific prior
 *     written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* \summary: swXtch Protocol printer */
/* specification: https://www.swxtch.io/protocol */

// clang-format off
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"
#include "netdissect-alloc.h"
#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"
#include <stdbool.h>


typedef enum CmdType_e
{
    CMD_TYPE_UNKNOWN = 0,
    CMD_TYPE_ECHO = 1,
    CMD_TYPE_IGMP = 2,
    CMD_TYPE_MCA_MC = 3,
    CMD_TYPE_REPL_CONFIG_FRAGMENT = 4,
    CMD_TYPE_CFG = 5,
    CMD_TYPE_MCA_STATS = 6,
    CMD_TYPE_SHUTDOWN = 7,
    CMD_TYPE_REPL_STATS = 8,
    CMD_TYPE_REPL_MC = 9,
    CMD_TYPE_MCC_STATS = 10,
    CMD_TYPE_MCA_ANNOUNCEMENT = 11,
    CMD_TYPE_RETRAN_REQUEST = 12,
    CMD_TYPE_BRIDGE_MC = 13,
    CMD_TYPE_UNICAST_UDP = 14,
    CMD_TYPE_HA_PATH_ID_SETTINGS = 15,
    CMD_TYPE_ARP_REQUEST = 16,
    CMD_TYPE_CAPTURE_FILTER = 17,
    CMD_TYPE_UNICAST_SRT_CALLER = 18,
    CMD_TYPE_UNICAST_SRT_LISTENER = 19,
    CMD_TYPE_MCA_MC_FRAG = 20,
    CMD_TYPE_UNICAST_RIST_CALLER = 21,
    CMD_TYPE_UNICAST_RIST_LISTENER = 22,
    CMD_TYPE_LOSSLESS_CTRL = 23,
} CmdType_t;

static const struct tok cmd_type_str[] = {
	{0, "Invalid"},
	{CMD_TYPE_ECHO, "Echo"},
	{CMD_TYPE_IGMP, "IGMP"},
	{CMD_TYPE_MCA_MC, "xNIC->SWXTCH"},
	{CMD_TYPE_REPL_CONFIG_FRAGMENT, "ReplConfigFragment"},
	{CMD_TYPE_CFG, "Config"},
	{CMD_TYPE_MCA_STATS, "xNIC_stats"},
	{CMD_TYPE_SHUTDOWN, "Shutdown"},
	{CMD_TYPE_REPL_STATS, "ReplStats"},
	{CMD_TYPE_REPL_MC, "SWXTCH->xNIC"},
	{CMD_TYPE_MCC_STATS, "MCCStats"},
	{CMD_TYPE_MCA_ANNOUNCEMENT, "MCAAnnouncement"},
	{CMD_TYPE_RETRAN_REQUEST, "RetranRequest"},
	{CMD_TYPE_BRIDGE_MC, "BridgeMc"},
	{CMD_TYPE_UNICAST_UDP, "UnicastUDP"},
	{CMD_TYPE_HA_PATH_ID_SETTINGS, "HaPathIdSettings"},
	{CMD_TYPE_ARP_REQUEST, "ArpRequest"},
	{CMD_TYPE_CAPTURE_FILTER, "CaptureFilter"},
	{CMD_TYPE_UNICAST_SRT_CALLER, "UnicastSrtCaller"},
	{CMD_TYPE_UNICAST_SRT_LISTENER, "UnicastSrtListener"},
	{CMD_TYPE_MCA_MC_FRAG, "McaMcFrag"},
	{CMD_TYPE_UNICAST_RIST_CALLER, "UnicastRistCaller"},
	{CMD_TYPE_UNICAST_RIST_LISTENER, "UnicastRistListener"},
	{CMD_TYPE_LOSSLESS_CTRL, "LosslessXtrl"},
};

// clang-format on

// Masks and values for the Tag field
// We are now out of bits for the Tag Field
// 8          7          6         3         0
// | Fragment | Lossless | Path ID | Version |
#define VERSION_MASK 0x7
#define PATH_ID_OFFSET 3
#define PATH_ID_MASK (0x7 << PATH_ID_OFFSET)
#define PACKET_TYPE_LOSSLESS (1 << 6)
#define PACKET_TYPE_FRAGMENT (1 << 7)

// Metadata appended to a swx packet if it needs to be fragmented.
struct SwxtchFragMetaData_t {
    uint8_t FragmentIndex;
    uint8_t TotalFragments;
    uint32_t Sequence;
};

typedef struct SwxtchMetaData_s {
    uint16_t Token;
    uint8_t CmdType;
    uint8_t Tag;
    uint64_t Seq;
    uint64_t Timestamp;
    uint32_t SrcIP;
    uint32_t DstIP;
    uint16_t SrcPort;
    uint16_t DstPort;
} SwxtchMetaData_t;

// SwxtchMetaData_t - SrcIP - DstIP - SrcPort - DstPort
const size_t SWXTCH_METADATA_SIZE = sizeof(SwxtchMetaData_t) - sizeof(uint16_t) - sizeof(uint8_t) - sizeof(uint8_t) - sizeof(uint64_t) - sizeof(uint64_t);

#define EXPECTED_TOKEN (0x01EA)

static void hexprint(netdissect_options* ndo, const uint8_t* cp, size_t len) {
    size_t i;

    for (i = 0; i < len; i++)
        ND_PRINT("%02x", cp[i]);
}

/* Returns 1 if the first two octets looks like a swXtch packet. */
int swxtch_detect(netdissect_options* ndo, const u_char* p, const u_int len) {
    uint16_t ExtractedToken;

    if (len < sizeof(SwxtchMetaData_t))
        return 0;
    ExtractedToken = GET_LE_U_2(p);
    /* All swXtch packets must have the following token value */
    if (ExtractedToken == EXPECTED_TOKEN)
        return 1;
    else
        return 0;
}

static const u_char* swxtch_print_packet(netdissect_options* ndo,
                                         const u_char* bp,
                                         const u_char* end) {
    static int Cached_Xflag = 0;
    static int Cached_xflag = 0;
    const u_char* sp = bp;
    uint8_t cmdType = 0;
    uint8_t tag = 0;
    uint8_t path_id = 0;
    uint8_t version = 0;
    uint64_t sequence = 0;
    uint64_t timestamp = 0;
    const u_char* SrcIP;
    const u_char* DstIP;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    bool isLossless = false;
    bool isFragmented = false;

    if ((end - bp) < sizeof(SwxtchMetaData_t)) {
        ND_PRINT(" (invalid Swxtch header length");
        return end;
    }

    // Skip TOKEN
    bp += 2;

    // CmdType
    cmdType = GET_U_1(bp);
    bp += 1;

    // Tag
    tag = GET_U_1(bp);
    version = tag & VERSION_MASK;
    path_id = (tag & PATH_ID_MASK) >> PATH_ID_OFFSET;
    isLossless = (tag & PACKET_TYPE_LOSSLESS) != 0;
    isFragmented = (tag & PACKET_TYPE_FRAGMENT) != 0;
    bp += 1;

    // Seq;
    sequence = GET_LE_U_8(bp);
    bp += 8;

    // Timestamp;
    timestamp = GET_LE_U_8(bp);
    bp += 8;

    ND_PRINT("%s", tok2str(cmd_type_str, "[swxtch:%u]", cmdType));
    if (version > 0) {
        ND_PRINT("(v%i)", version);
    }
     ND_PRINT(", Version: %u, Path ID: %u, Lossless: %s, Fragmented: %s",
             version, path_id, isLossless ? "true" : "false",
             isFragmented ? "true" : "false");

    if ((cmdType == CMD_TYPE_MCA_MC) || (cmdType == CMD_TYPE_REPL_MC)
        || (cmdType == CMD_TYPE_BRIDGE_MC)) {
        if ((end - bp) < SWXTCH_METADATA_SIZE) {
            ND_PRINT(" (invalid MC header length");
            return end;
        }
        SrcIP = bp;
        bp += 4;
        DstIP = bp;
        bp += 4;
        srcPort = GET_BE_U_2(bp);
        bp += 2;
        dstPort = GET_BE_U_2(bp);
        bp += 2;

        ND_PRINT(", %s.%s > %s.%s", GET_IPADDR_STRING(SrcIP), udpport_string(ndo, srcPort),
                 GET_IPADDR_STRING(DstIP), udpport_string(ndo, dstPort));

        if (ndo->ndo_vflag > 0) {
            ND_PRINT(")\n        ");
            ND_PRINT("mc_off %" PRIu64, (bp - sp));
            ND_PRINT(", mc_len %" PRIu64, (end - bp));
            ND_PRINT(", seq %" PRIu64, sequence);
            ND_PRINT(", ts %" PRIu64, timestamp);
        }
    } else {
        if (ndo->ndo_vflag > 0) {
            ND_PRINT(", seq %" PRIu64, sequence);
            ND_PRINT(", ts %" PRIu64, timestamp);
        }
    }

    if (Cached_Xflag || (ndo->ndo_Xflag > 2)) {
        Cached_Xflag |= ndo->ndo_Xflag;
        ndo->ndo_Xflag = 0;
        hex_and_ascii_print(ndo, "\n\t", bp, (end - bp));
    } else {
        if (Cached_xflag || (ndo->ndo_xflag > 2)) {
            Cached_xflag |= ndo->ndo_xflag;
            ndo->ndo_xflag = 0;
            hex_print(ndo, "\n\t", bp, (end - bp));
        }
    }

    return end;
}

void swxtch_print(netdissect_options* ndo, const u_char* bp, const u_int len) {
    const uint8_t* end = bp + len;

    ndo->ndo_protocol = "swxtch.io";
    // nd_print_protocol(ndo);

    while (bp < end) {
        bp = swxtch_print_packet(ndo, bp, end);
        /*
         * Skip all zero bytes which are
         * considered padding.
         */
        while (ND_TTEST_1(bp) && GET_U_1(bp) == 0)
            bp++;
    }
}
