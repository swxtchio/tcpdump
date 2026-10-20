/*
 * Copyright (c) 2022-2026 swXtch.io, LLC
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

/* \summary: swXtch overlay (tunnel, SLP, probe) printer */

/*
 * Wire contract: swxtch-core common/swxtch-definitions/src/SwxtchOverlay.hpp (SwxtchMetaData_t) and
 * common/swx-lossless-protocol/src/slp/networkHeaders.hpp (SLP trailer and control payloads).
 *
 * Every swXtch packet is UDP whose payload starts with a 32-byte overlay header:
 *
 *   0  Magic       EA 01
 *   2  Kind        low 5 bits: 1 Data, 2 SlpControl, 3 Probe, 4 TestData
 *   3  Flags       0x01 time valid, 0x02 clock synchronized, 0x18 HA path, 0x20 sequence synchronized,
 *                  0x40 lossless (20-byte SLP trailer at the end), 0x80 fragment (6-byte trailer at the end)
 *   4  SequenceId  BE: top 8 bits producer epoch, low 56 bits per-flow counter
 *  12  OriginTime  BE ns since the Unix epoch, valid with flag 0x01
 *  20  inner source IP, destination IP, source port, destination port (network order)
 *
 * The overlay header and its fragment, probe and test structures are big-endian; the SLP trailer and SLP
 * control payloads are host-native little-endian, except the trailer's original source port.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"
#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"

#define SWX_HEADER_LEN       32
#define SWX_MAGIC_0          0xEA
#define SWX_MAGIC_1          0x01
#define SWX_KIND_MASK        0x1F

#define SWX_FLAG_TIME_VALID  0x01
#define SWX_FLAG_CLOCK_SYNC  0x02
#define SWX_FLAG_HA_MASK     0x18
#define SWX_FLAG_HA_SHIFT    3
#define SWX_FLAG_SEQ_SYNC    0x20
#define SWX_FLAG_LOSSLESS    0x40
#define SWX_FLAG_FRAGMENT    0x80

#define SWX_SLP_TRAILER_LEN  20
#define SWX_FRAG_TRAILER_LEN 6
#define SWX_TEST_LEN         24

enum swx_kind {
    SWX_KIND_DATA = 1,
    SWX_KIND_SLP_CONTROL = 2,
    SWX_KIND_PROBE = 3,
    SWX_KIND_TEST_DATA = 4
};

static const struct tok swx_kind_str[] = {
    { SWX_KIND_DATA,        "Data" },
    { SWX_KIND_SLP_CONTROL, "SLP" },
    { SWX_KIND_PROBE,       "Probe" },
    { SWX_KIND_TEST_DATA,   "TestData" },
    { 0, NULL }
};

enum swx_probe_type {
    SWX_PING_REQUEST = 1,
    SWX_PING_RESPONSE = 2,
    SWX_PMTU_REQUEST = 3,
    SWX_PMTU_RESPONSE = 4
};

static const struct tok swx_probe_str[] = {
    { SWX_PING_REQUEST,  "ping request" },
    { SWX_PING_RESPONSE, "ping response" },
    { SWX_PMTU_REQUEST,  "pmtu request" },
    { SWX_PMTU_RESPONSE, "pmtu response" },
    { 0, NULL }
};

enum slp_type {
    SLP_ODATA = 0,
    SLP_RDATA = 1,
    SLP_FDATA = 2,
    SLP_ACK2 = 3,
    SLP_HANDSHAKE = 4,
    SLP_EOB_MARKER = 7,
    SLP_CLOSE = 8,
    SLP_NACK = 128,
    SLP_ACK = 129,
    SLP_HANDSHAKE_RESPONSE = 130
};

static const struct tok slp_type_str[] = {
    { SLP_ODATA,              "ODATA" },
    { SLP_RDATA,              "RDATA" },
    { SLP_FDATA,              "FDATA" },
    { SLP_ACK2,               "ACK2" },
    { SLP_HANDSHAKE,          "HANDSHAKE" },
    { SLP_EOB_MARKER,         "EOB" },
    { SLP_CLOSE,              "CLOSE" },
    { SLP_NACK,               "NACK" },
    { SLP_ACK,                "ACK" },
    { SLP_HANDSHAKE_RESPONSE, "HANDSHAKE-RESPONSE" },
    { 0, NULL }
};

/* NACK ranges printed on one line before the rest is summarized. */
#define SLP_NACK_RANGES_SHOWN 8

/* Returns 1 when the UDP payload starts with a swXtch overlay header. */
int
swxtch_detect(netdissect_options *ndo, const u_char *bp, const u_int len)
{
    u_int kind;

    if (len < SWX_HEADER_LEN || !ND_TTEST_3(bp))
        return 0;
    if (GET_U_1(bp) != SWX_MAGIC_0 || GET_U_1(bp + 1) != SWX_MAGIC_1)
        return 0;
    kind = GET_U_1(bp + 2) & SWX_KIND_MASK;
    return kind >= SWX_KIND_DATA && kind <= SWX_KIND_TEST_DATA;
}

static void
swxtch_print_flags(netdissect_options *ndo, u_int flags)
{
    const char *sep = "";
    u_int ha = (flags & SWX_FLAG_HA_MASK) >> SWX_FLAG_HA_SHIFT;

    if ((flags & ~SWX_FLAG_CLOCK_SYNC) == 0 && !(flags & SWX_FLAG_TIME_VALID))
        return;
    ND_PRINT(" [");
    if (flags & SWX_FLAG_TIME_VALID) {
        ND_PRINT("%stime%s", sep, (flags & SWX_FLAG_CLOCK_SYNC) ? "+sync" : "");
        sep = ",";
    }
    if (ha != 0) {
        ND_PRINT("%sha path %u", sep, ha);
        sep = ",";
    }
    if (flags & SWX_FLAG_SEQ_SYNC) {
        ND_PRINT("%sseq-sync", sep);
        sep = ",";
    }
    if (flags & SWX_FLAG_LOSSLESS) {
        ND_PRINT("%slossless", sep);
        sep = ",";
    }
    if (flags & SWX_FLAG_FRAGMENT)
        ND_PRINT("%sfragment", sep);
    ND_PRINT("]");
}

static void
slp_print_handshake(netdissect_options *ndo, const u_char *p, u_int avail)
{
    if (avail < 61) {
        ND_PRINT(" (handshake payload %u bytes)", avail);
        return;
    }
    ND_PRINT(" v%u.%u%s epoch %u mtu %u start-seq %" PRIu64,
             GET_U_1(p), GET_U_1(p + 21), GET_U_1(p + 1) ? " acknowledged" : "",
             GET_U_1(p + 2), GET_LE_U_2(p + 3), GET_LE_U_8(p + 5));
    if (ndo->ndo_vflag > 1) {
        ND_PRINT(", ack-interval %" PRIu64 "ns, rtt-before-drop x%u, ack-timeout x%u",
                 GET_LE_U_8(p + 13), GET_LE_U_4(p + 22), GET_LE_U_4(p + 26));
        ND_PRINT(", first-nack min %" PRIu64 "ns +%" PRIu64 "ns/arrival, static %u, ewma %u, adaptive %u x%u",
                 GET_LE_U_8(p + 30), GET_LE_U_8(p + 38), GET_U_1(p + 46), GET_LE_U_2(p + 47),
                 GET_U_1(p + 49), GET_LE_U_2(p + 50));
        ND_PRINT(", min-drop %" PRIu64 "ns, cc %u", GET_LE_U_8(p + 52), GET_U_1(p + 60));
    }
}

static void
slp_print_ack(netdissect_options *ndo, const u_char *p, u_int avail)
{
    if (avail < 40) {
        ND_PRINT(" (ack payload %u bytes)", avail);
        return;
    }
    ND_PRINT(" expected %" PRIu64 ", max-received %" PRIu64 ", window-end %" PRIu64,
             GET_LE_U_8(p + 16), GET_LE_U_8(p + 24), GET_LE_U_8(p + 32));
    if (ndo->ndo_vflag > 0)
        ND_PRINT(", rtt %" PRId64 "ns, rtt-var %" PRId64 "ns", GET_LE_S_8(p), GET_LE_S_8(p + 8));
}

static void
slp_print_nack(netdissect_options *ndo, const u_char *p, u_int avail)
{
    u_int total, ranges, i, shown;

    if (avail < 8) {
        ND_PRINT(" (nack payload %u bytes)", avail);
        return;
    }
    total = GET_LE_U_4(p);
    ranges = GET_LE_U_4(p + 4);
    ND_PRINT(" %u missing in %u range%s", total, ranges, ranges == 1 ? "" : "s");
    p += 8;
    avail -= 8;
    if ((uint64_t)ranges * 16 > avail)
        ND_PRINT(" (invalid: %u range%s present)", avail / 16, avail / 16 == 1 ? "" : "s");
    shown = ndo->ndo_vflag > 1 ? ranges : SLP_NACK_RANGES_SHOWN;
    for (i = 0; i < ranges && avail >= 16; i++, p += 16, avail -= 16) {
        if (i == shown) {
            ND_PRINT(" ...");
            break;
        }
        ND_PRINT("%s%" PRIu64 "-%" PRIu64, i == 0 ? " " : ",", GET_LE_U_8(p), GET_LE_U_8(p + 8));
    }
}

/*
 * The SLP trailer is the last 20 bytes of the UDP payload. Its type says what the bytes between the overlay
 * header and the trailer are: user data for ODATA/RDATA, a control payload otherwise.
 */
static void
slp_print(netdissect_options *ndo, u_int kind, const u_char *payload, u_int payload_len, const u_char *trailer)
{
    u_int type = GET_U_1(trailer + 19);

    ND_PRINT(" slp %s", tok2str(slp_type_str, "type %u", type));
    ND_PRINT(" epoch %u", GET_U_1(trailer + 18));
    if (type == SLP_ODATA || type == SLP_RDATA || type == SLP_EOB_MARKER || type == SLP_ACK2)
        ND_PRINT(" seq %" PRIu64, GET_LE_U_8(trailer + 8));
    if (ndo->ndo_vflag > 0) {
        ND_PRINT(" ts %" PRIu64, GET_LE_U_8(trailer));
        if (kind == SWX_KIND_DATA)
            ND_PRINT(" orig-sport %u", GET_BE_U_2(trailer + 16));
    }
    if (kind != SWX_KIND_SLP_CONTROL)
        return;
    switch (type) {
    case SLP_HANDSHAKE:
        ND_PRINT(":");
        slp_print_handshake(ndo, payload, payload_len);
        break;
    case SLP_ACK:
    case SLP_ACK2:
        ND_PRINT(":");
        slp_print_ack(ndo, payload, payload_len);
        break;
    case SLP_NACK:
        ND_PRINT(":");
        slp_print_nack(ndo, payload, payload_len);
        break;
    default:
        if (payload_len > 0)
            ND_PRINT(": %u bytes", payload_len);
        break;
    }
}

static void
swxtch_print_probe(netdissect_options *ndo, const u_char *p, u_int avail)
{
    u_int type;

    if (avail < 9) {
        ND_PRINT(" (probe payload %u bytes)", avail);
        return;
    }
    type = GET_U_1(p);
    ND_PRINT(" %s id 0x%" PRIx64, tok2str(swx_probe_str, "type %u", type), GET_BE_U_8(p + 1));
    if ((type == SWX_PMTU_REQUEST || type == SWX_PMTU_RESPONSE) && avail >= 11)
        ND_PRINT(" tested-mtu %u", GET_BE_U_2(p + 9));
}

static void
swxtch_print_test(netdissect_options *ndo, const u_char *p, u_int avail)
{
    u_int flags;

    if (avail < SWX_TEST_LEN) {
        ND_PRINT(" (test metadata %u bytes)", avail);
        return;
    }
    flags = GET_U_1(p + 6);
    ND_PRINT(" adjacent %s.%u", GET_IPADDR_STRING(p), GET_BE_U_2(p + 4));
    if (flags & 0x02)
        ND_PRINT(" switch-ingress %" PRIu64 "ns residence %" PRIu64 "ns",
                 GET_BE_U_8(p + 8), GET_BE_U_8(p + 16));
    else if (flags & 0x01)
        ND_PRINT(" switch-latency requested");
}

/*
 * -XXX / -xxx dump only the tunneled application payload, after the overlay header and before any trailer.
 * print.c dumps the whole frame for any -X/-x count above one, so the flag is taken over here on its first
 * use and kept for the rest of the run.
 */
static int payload_only_ascii;
static int payload_only_hex;

static void
swxtch_take_payload_dump(netdissect_options *ndo)
{
    if (ndo->ndo_Xflag > 2) {
        payload_only_ascii = 1;
        ndo->ndo_Xflag = 0;
    } else if (ndo->ndo_xflag > 2) {
        payload_only_hex = 1;
        ndo->ndo_xflag = 0;
    }
}

static void
swxtch_dump_payload(netdissect_options *ndo, const u_char *payload, u_int payload_len)
{
    if (payload_only_ascii)
        hex_and_ascii_print(ndo, "\n\t", payload, payload_len);
    else if (payload_only_hex)
        hex_print(ndo, "\n\t", payload, payload_len);
}

/*
 * len is what this packet holds of the UDP payload; datagram_len is the whole payload. They differ in an IP
 * fragment, whose end is not the datagram's end, so the trailers are not there to read.
 */
void
swxtch_print(netdissect_options *ndo, const u_char *bp, const u_int len, const u_int datagram_len)
{
    const u_char *payload = bp + SWX_HEADER_LEN;
    const u_char *app;
    const u_char *slp_trailer = NULL;
    const u_char *frag_trailer = NULL;
    u_int payload_len = len - SWX_HEADER_LEN;
    u_int kind, flags;
    uint64_t sequence;

    ndo->ndo_protocol = "swxtch";
    swxtch_take_payload_dump(ndo);
    kind = GET_U_1(bp + 2) & SWX_KIND_MASK;
    flags = GET_U_1(bp + 3);
    sequence = GET_BE_U_8(bp + 4);

    ND_PRINT("swXtch %s", tok2str(swx_kind_str, "kind %u", kind));
    if (kind != SWX_KIND_SLP_CONTROL)
        ND_PRINT(" %s.%u > %s.%u", GET_IPADDR_STRING(bp + 20), GET_BE_U_2(bp + 28),
                 GET_IPADDR_STRING(bp + 24), GET_BE_U_2(bp + 30));
    if (sequence != 0)
        ND_PRINT(", seq %u:%" PRIu64, (u_int)(sequence >> 56), (uint64_t)(sequence & 0x00FFFFFFFFFFFFFFULL));
    if (ndo->ndo_vflag > 0 && (flags & SWX_FLAG_TIME_VALID))
        ND_PRINT(", origin %" PRIu64 "ns", GET_BE_U_8(bp + 12));
    swxtch_print_flags(ndo, flags);

    /* Trailers sit at the end, the SLP one outermost, so a short snapshot drops them first. */
    if ((flags & (SWX_FLAG_LOSSLESS | SWX_FLAG_FRAGMENT)) && len < datagram_len) {
        ND_PRINT(" (IP fragment, trailer in a later fragment), length %u", datagram_len - SWX_HEADER_LEN);
        return;
    }
    if ((flags & (SWX_FLAG_LOSSLESS | SWX_FLAG_FRAGMENT)) && !ND_TTEST_LEN(bp, len)) {
        ND_PRINT(" (trailer not captured, use -s 0), length %u", len - SWX_HEADER_LEN);
        return;
    }
    if (payload_len < ((flags & SWX_FLAG_LOSSLESS) ? SWX_SLP_TRAILER_LEN : 0) +
                      ((flags & SWX_FLAG_FRAGMENT) ? SWX_FRAG_TRAILER_LEN : 0)) {
        ND_PRINT(" (%u bytes after the header cannot hold the flagged trailers)", payload_len);
        nd_print_invalid(ndo);
        return;
    }
    if ((flags & SWX_FLAG_LOSSLESS) && payload_len >= SWX_SLP_TRAILER_LEN) {
        slp_trailer = bp + len - SWX_SLP_TRAILER_LEN;
        payload_len -= SWX_SLP_TRAILER_LEN;
    }
    if ((flags & SWX_FLAG_FRAGMENT) && payload_len >= SWX_FRAG_TRAILER_LEN) {
        frag_trailer = payload + payload_len - SWX_FRAG_TRAILER_LEN;
        payload_len -= SWX_FRAG_TRAILER_LEN;
    }

    app = payload;
    switch (kind) {
    case SWX_KIND_PROBE:
        ND_PRINT(":");
        swxtch_print_probe(ndo, payload, payload_len);
        break;
    case SWX_KIND_TEST_DATA:
        /* The test metadata leads the payload, so only the first overlay fragment carries it. */
        if (frag_trailer != NULL && GET_U_1(frag_trailer) != 0)
            break;
        ND_PRINT(":");
        swxtch_print_test(ndo, payload, payload_len);
        app = payload + SWX_TEST_LEN;
        payload_len = payload_len >= SWX_TEST_LEN ? payload_len - SWX_TEST_LEN : 0;
        break;
    default:
        break;
    }
    if (frag_trailer != NULL)
        ND_PRINT(", fragment %u/%u fseq %u", GET_U_1(frag_trailer) + 1, GET_U_1(frag_trailer + 1),
                 GET_BE_U_4(frag_trailer + 2));
    if (slp_trailer != NULL)
        slp_print(ndo, kind, payload, payload_len, slp_trailer);
    else if (kind == SWX_KIND_SLP_CONTROL)
        ND_PRINT(" (no SLP trailer)");
    if (kind == SWX_KIND_DATA || kind == SWX_KIND_TEST_DATA) {
        ND_PRINT(", length %u", payload_len);
        swxtch_dump_payload(ndo, app, payload_len);
    }
}
