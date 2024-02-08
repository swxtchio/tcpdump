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

typedef enum CmdType_e
{
	CMD_TYPE_ECHO = 1,
	CMD_TYPE_IGMP = 2,
	CMD_TYPE_MCA_MC = 3,
	CMD_TYPE_REPL_CONFIG = 4,
	CMD_TYPE_CFG = 5,
	CMD_TYPE_MCA_STATS = 6,
	CMD_TYPE_SHUTDOWN = 7,
	CMD_TYPE_REPL_STATS = 8,
	CMD_TYPE_REPL_MC = 9,
	CMD_TYPE_MCC_STATS = 10,
	CMD_TYPE_MCA_ANNOUNCEMENT = 11,
	CMD_TYPE_RETRAN_REQUEST = 12,
	CMD_TYPE_BRIDGE_MC = 13,
	CMD_TYPE_UNICAST_PKT = 14,
} CmdType_t;

static const struct tok cmd_type_str[] = {
	{0, "Invalid"},
	{CMD_TYPE_ECHO, "Echo"},
	{CMD_TYPE_IGMP, "IGMP"},
	{CMD_TYPE_MCA_MC, "xNIC->SWXTCH"},
	{CMD_TYPE_REPL_CONFIG, "REPL_CFG"},
	{CMD_TYPE_CFG, "Config"},
	{CMD_TYPE_MCA_STATS, "xNIC_stats"},
	{CMD_TYPE_SHUTDOWN, "Shutdown"},
	{CMD_TYPE_REPL_STATS, "REPL_STATS"},
	{CMD_TYPE_REPL_MC, "SWXTCH->xNIC"},
	{CMD_TYPE_MCC_STATS, "MCC_STATS"},
	{CMD_TYPE_MCA_ANNOUNCEMENT, "xNIC_Announce"},
	{CMD_TYPE_RETRAN_REQUEST, "Retran_Request"},
	{CMD_TYPE_BRIDGE_MC, "BRIDGE-MC"},
	{CMD_TYPE_UNICAST_PKT, "Unicast"},
	{0, NULL}};

// clang-format on

typedef struct SwxtchHeader_s {
    nd_uint16_t Token;
    nd_uint8_t CmdType;
    nd_uint8_t rsvd;
    nd_uint64_t Seq;
    nd_uint64_t Timestamp;
} SwxtchHeader_t;

typedef struct MCTunHeader_s {
    nd_uint32_t SrcIP;
    nd_uint32_t DstIP;
    nd_uint16_t SrcPort;
    nd_uint16_t DstPort;
} MCTunHeader_t;

#define EXPECTED_TOKEN (0x01EA)

static void hexprint(netdissect_options* ndo, const uint8_t* cp, size_t len) {
    size_t i;

    for (i = 0; i < len; i++)
        ND_PRINT("%02x", cp[i]);
}

/* Returns 1 if the first two octets looks like a swXtch packet. */
int swxtch_detect(netdissect_options* ndo, const u_char* p, const u_int len) {
    uint16_t ExtractedToken;

    if (len < sizeof(SwxtchHeader_t))
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
    uint8_t CmdType = 0;
    uint8_t xNICVersion = 0;
    uint64_t Sequence = 0;
    uint64_t Timestamp = 0;
    const u_char* SrcIP;
    const u_char* DstIP;
    uint16_t SrcPort = 0;
    uint16_t DstPort = 0;

    if ((end - bp) < sizeof(SwxtchHeader_t)) {
        ND_PRINT(" (invalid Swxtch header length");
        return end;
    }

    // Skip TOKEN
    bp += 2;
    // CmdType
    CmdType = GET_U_1(bp);
    bp += 1;
    // xNIC version
    xNICVersion = GET_U_1(bp);
    bp += 1;
    // Seq;
    Sequence = GET_LE_U_8(bp);
    bp += 8;
    // Timestamp;
    Timestamp = GET_LE_U_8(bp);
    bp += 8;

    ND_PRINT("%s", tok2str(cmd_type_str, "[swxtch:%u]", CmdType));
    if (xNICVersion > 0) {
        ND_PRINT("(v%i)", xNICVersion);
    }
    if ((CmdType == CMD_TYPE_MCA_MC) || (CmdType == CMD_TYPE_REPL_MC)
        || (CmdType == CMD_TYPE_BRIDGE_MC)) {
        if ((end - bp) < sizeof(MCTunHeader_t)) {
            ND_PRINT(" (invalid MC header length");
            return end;
        }
        SrcIP = bp;
        bp += 4;
        DstIP = bp;
        bp += 4;
        SrcPort = GET_BE_U_2(bp);
        bp += 2;
        DstPort = GET_BE_U_2(bp);
        bp += 2;
        ND_PRINT(", %s.%s > %s.%s", GET_IPADDR_STRING(SrcIP), udpport_string(ndo, SrcPort),
                 GET_IPADDR_STRING(DstIP), udpport_string(ndo, DstPort));
        if (ndo->ndo_vflag > 0) {
            ND_PRINT(")\n        ");
            ND_PRINT("mc_off %" PRIu64, (bp - sp));
            ND_PRINT(", mc_len %" PRIu64, (end - bp));
            ND_PRINT(", seq %" PRIu64, Sequence);
            ND_PRINT(", ts %" PRIu64, Timestamp);
        }
    } else {
        if (ndo->ndo_vflag > 0) {
            ND_PRINT(", seq %" PRIu64, Sequence);
            ND_PRINT(", ts %" PRIu64, Timestamp);
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
