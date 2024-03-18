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
#include <stdint.h>
#include <inttypes.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h> 

#define PRINT_IP_PORT(description, ip, port) \
    printf("%s:%d", inet_ntoa(*(struct in_addr*)&ip), ntohs(port))
typedef enum CmdType_e {
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

typedef enum PktType_e {
    ODATA,
    RDATA,
    FDATA,
    ACK2,
    HANDSHAKE,
    NACK = 128,
    ACK = 129,
    HANDSHAKE_RESPONSE = 130,
    UNKNOWN,
}PktType_t;

static const struct tok lossless_cmd_type_str[] = {
	{0, "Invalid"},
	{ODATA, "ODATA"},
	{RDATA, "RDATA"},
	{FDATA, "FDATA"},
	{ACK2, "ACK2"},
	{HANDSHAKE, "HANDSHAKE"},
	{NACK, "NACK"},
	{ACK, "ACK"},
	{HANDSHAKE_RESPONSE, "HANDSHAKE_RESPONSE"},
	{UNKNOWN, "UNKNOWN"},
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

#define EXPECTED_SWXTCH_MDATA_TOKEN 0x01EA
#define EXPECTED_PERF_TOKEN 0x01EA

#define BUFFER_SIZE 20
#define LE 1 //LITTLE_ENDIAN
#define BE 0 //BIG_ENDIAN

// #define DEBUG_FLAG 1

// Metadata appended to a swx packet if it needs to be fragmented.
#pragma pack(1)

struct SwxtchMetaData_t {
    uint16_t token;
    uint8_t cmdType;
    uint8_t tag;
    uint64_t seq;
    uint64_t timestamp;
    uint32_t srcIP;
    uint32_t dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
};

struct SwxtchFragMetaData_t {
    uint8_t fragmentIndex;
    uint8_t totalFragments;
    uint32_t sequence;
};

struct Lossless_t {
    uint64_t timestamp;
    uint64_t seq;
    uint16_t srcPortBe;  // To tunnel original src port (used for channel bonding)
    uint8_t type;
};

struct PerfMetaData_t {
    uint16_t token;
    uint64_t seq;
    uint64_t timestamp;
};

struct AckPayload {
    int64_t rtt;
    int64_t rttVar;
    uint64_t expectedSeq;
    uint64_t maxReceivedSeq;
    uint64_t maxSeq;
};

typedef struct Range_t {
    uint64_t m_From;
    uint64_t m_To;
} Range_t;
struct NackPayload {
    uint32_t totalPackets;
    uint32_t rangeCount;
    Range_t ranges[];
};
struct HandShakePayload {
    uint8_t slpVer;
    uint8_t acked;
    uint16_t mtu;
    uint64_t startSeq;
    uint64_t ackPeriodUs;
    // everything below is added by v 2
    uint8_t slpMinorVer;
    // The number of rtts to wait before considering a packet dropped
    uint32_t lostPacketRTTs;
    // The number of rtts to wait for control packets before considering a connection lost
    uint32_t connectionDroppedRTTs;
};

#pragma pack()

#define EXPECTED_TOKEN (0x01EA)

uint64_t bigEndianToLittleEndian64(uint64_t value) {
    return (((value) & 0xff00000000000000ull) >> 56) |
           (((value) & 0x00ff000000000000ull) >> 40) |
           (((value) & 0x0000ff0000000000ull) >> 24) |
           (((value) & 0x000000ff00000000ull) >> 8) |
           (((value) & 0x00000000ff000000ull) << 8) |
           (((value) & 0x0000000000ff0000ull) << 24) |
           (((value) & 0x000000000000ff00ull) << 40) |
           (((value) & 0x00000000000000ffull) << 56);
}

const char *convertUnixTimeToString(const uint64_t unixTime, int isLittleEndian) {

    if (unixTime == 0) {
        return "Emty Date";
    }
    
    time_t seconds;
    struct tm *timeinfo;
    uint64_t timeToUse;
    static char buffer[BUFFER_SIZE];

    timeToUse = isLittleEndian ? le64toh(unixTime) : unixTime;
    
    seconds = timeToUse / 1000000000;

    timeinfo = localtime(&seconds);
    strftime(buffer, 20, "%Y-%m-%d %H:%M:%S", timeinfo);
    return buffer;
}

/* Returns 1 if the first two octets looks like a swXtch packet. */
int swxtch_detect(netdissect_options* ndo, const u_char* p, const u_int len) {
    uint16_t ExtractedToken;

    if (len < sizeof(struct SwxtchMetaData_t))
        return 0;
    ExtractedToken = GET_LE_U_2(p);

    /* All swXtch packets must have the following token value */
    if (ExtractedToken == EXPECTED_TOKEN) {
        ND_PRINT(" \nTOKEN OK\n");
        return 1;

    } else {
        ND_PRINT(" \nINVALID TOKEN %04x\n",ExtractedToken);

        return 0;
    }
}

static void print_all_bytes(netdissect_options* ndo, const u_char* start, const u_char* end) {
    size_t i;

    for (i = 0; start + i < end; i++) {
        ND_PRINT("%02x ", start[i]);
    }
        ND_PRINT("\n");
}

static void lossless_print_packet (netdissect_options* ndo,
                                         const u_char* bp,
                                         const u_char* end,
                                         uint8_t losslessType) {
    struct AckPayload *ackPayload;
    struct Range_t *range;
    struct NackPayload *nackPayload;
    struct HandShakePayload *handshakePayload;

    switch (losslessType) {
        case ODATA:
            // ODATA: No additional fields
            break;

        case RDATA:
            // Range
            range = (struct Range_t *)bp;
            ND_PRINT("\n\tRange Start: %lu, End: %lu\n", range->m_From, range->m_To);
            break;

        case FDATA:
            // FDATA: No additional fields
            break;

        case ACK2:
            // ACK2: No additional fields
            break;

        case HANDSHAKE:
            // HandShakePayload
            handshakePayload = (struct HandShakePayload *)bp;
            ND_PRINT("\n\tRTT: %" PRIu64 ", RTT Var: %" PRIu64 ", Expected Seq: %" PRIu64 ", Max Received Seq: %" PRIu64 ", Max Seq: %" PRIu64 "\n",
             le64toh(ackPayload->rtt),
             le64toh(ackPayload->rttVar),
             le64toh(ackPayload->expectedSeq),
             le64toh(ackPayload->maxReceivedSeq),
             le64toh(ackPayload->maxSeq));
            break;

        case NACK:
            // NackPayload
            nackPayload = (struct NackPayload *)bp;
            ND_PRINT("\n\tTotal Packets: %u, Range Count: %u\n", nackPayload->totalPackets, nackPayload->rangeCount);

            for (uint32_t i = 0; i < nackPayload->rangeCount; ++i) {
                range = &(nackPayload->ranges[i]);
                ND_PRINT("\t\tRange %u - Start: %lu, End: %lu\n", i + 1, range->m_From, range->m_To);
            }
            break;

        case ACK:
            // AckPayload
            ackPayload = (struct AckPayload *)bp;
            ND_PRINT("\n\tRTT: %lu, RTT Var: %lu, Expected Seq: %lu, Max Received Seq: %lu, Max Seq: %lu\n",
                ackPayload->rtt, ackPayload->rttVar, ackPayload->expectedSeq,  ackPayload->maxReceivedSeq,ackPayload->maxSeq);
            break;

        case HANDSHAKE_RESPONSE:
            // HANDSHAKE_RESPONSE: No additional fields
            break;

        default:
            // UNKNOWN: No additional fields
            break;
    }
}

void printBytes(uint64_t value) {

    unsigned char bytes[sizeof(uint64_t)];
    for (int i = 0; i < sizeof(uint64_t); i++) {
        bytes[i] = (value >> (i * 8)) & 0xFF;
    }
    printf("Bytes: ");
    for (int i = sizeof(uint64_t) - 1; i >= 0; i--) {
        printf("%02X ", bytes[i]);
    }
    printf("\n");
}

void processPerfMetaData(netdissect_options* ndo, const u_char* bp, const u_char* end) {
    struct PerfMetaData_t perfMetaData;
const char * convertedDate;

if (end - bp >= sizeof(struct PerfMetaData_t)) {
perfMetaData = *((struct PerfMetaData_t*)bp);
    if (perfMetaData.token == EXPECTED_PERF_TOKEN) {
        perfMetaData.seq = bigEndianToLittleEndian64(perfMetaData.seq);
        convertedDate = convertUnixTimeToString(perfMetaData.timestamp, LE);
            ND_PRINT("\nPerfMetaData: Token: 0x%x, Seq: %" PRIu64 ", Timestamp: %s",
        perfMetaData.token,
        perfMetaData.seq,
        convertedDate);
        bp += sizeof(struct PerfMetaData_t);
        }
    }
}

void processFragmentedData(netdissect_options* ndo, const u_char* end, bool isLossless) {
    
    const struct SwxtchFragMetaData_t* fragMetaData;

    if (isLossless) {
        const size_t total_size = sizeof(struct Lossless_t) + sizeof(struct SwxtchFragMetaData_t);
        fragMetaData = (const struct SwxtchFragMetaData_t*)((const char*)end - total_size);
    } else {
        fragMetaData = (const struct SwxtchFragMetaData_t*)(end - sizeof(struct SwxtchFragMetaData_t));
    }

    ND_PRINT("\nFragmented Data: FragmentIndex=%u, TotalFragments=%u, Sequence=%u",
        fragMetaData->fragmentIndex, fragMetaData->totalFragments, fragMetaData->sequence);
    
}

void processLosslessData(netdissect_options* ndo, const u_char* bp, const u_char* end) {

    struct Lossless_t* losslessData = (struct Lossless_t*)(end - sizeof(struct Lossless_t));

ND_PRINT("-->Timestamp: %" PRIu64, losslessData->timestamp);


    const char * convertedDate =convertUnixTimeToString(losslessData->timestamp, BE);
    ND_PRINT("\nLossless Data(%s): Seq=%lu, SrcPort=%u, --->Timestamp=%s",
        tok2str(lossless_cmd_type_str, "[type:%u]", losslessData->type),
        losslessData->seq,
        losslessData->srcPortBe,
        convertedDate);

    lossless_print_packet(ndo, bp, end, losslessData->type);
}

static const u_char* swxtch_print_packet(netdissect_options* ndo,
                                         const u_char* bp,
                                         const u_char* end) {
    const u_char* sp = bp;
    bool isLossless = false;
    bool isFragmented = false;
    uint8_t path_id = 0;
    uint8_t version = 0;
    static int Cached_xflag = 0;
    static int Cached_Xflag = 0;
    const char * convertedDate;
    struct PerfMetaData_t perfMetaData;
    struct SwxtchMetaData_t swxtchMetaData;

    // ND_PRINT("\n--------------------------- START -------------------------------- \n");

    if ((end - bp) < sizeof(struct SwxtchMetaData_t)) {
        ND_PRINT(" \n------------->(Invalid Swxtch header length)<-------------\n");
        return end;
    }

    memcpy(&swxtchMetaData, bp, sizeof(struct SwxtchMetaData_t));

    bp += sizeof(struct SwxtchMetaData_t);

    version = swxtchMetaData.tag & VERSION_MASK;
    path_id = (swxtchMetaData.tag & PATH_ID_MASK) >> PATH_ID_OFFSET;
    isLossless = (swxtchMetaData.tag & PACKET_TYPE_LOSSLESS) != 0;
    isFragmented = (swxtchMetaData.tag & PACKET_TYPE_FRAGMENT) != 0;

    #ifdef DEBUG_FLAG
        ND_PRINT("Tag: 0x%x\n", swxtchMetaData.tag);
        ND_PRINT("CmdType: 0x%x\n", swxtchMetaData.cmdType);
        ND_PRINT("Token: 0x%x\n", swxtchMetaData.token);
        ND_PRINT("Seq %" PRIu64, swxtchMetaData.seq);
        ND_PRINT("\n");
        ND_PRINT("Ts %" PRIu64, swxtchMetaData.timestamp);
        ND_PRINT("\n");
        ND_PRINT("Version:%d\n", version);
        ND_PRINT("path_id:%d\n", path_id);
        ND_PRINT("isLossless:%d\n", isLossless);
        ND_PRINT("isFragmented:%d\n", isFragmented);
    #endif

    ND_PRINT("\n-----------------------\n");
    ND_PRINT("%s", tok2str(cmd_type_str, "[swxtch:%u]", swxtchMetaData.cmdType));
    ND_PRINT("\n-----------------------\n");
    if (version > 0) {
        ND_PRINT("(v%i): ", version);
    }
  
    if ((swxtchMetaData.cmdType == CMD_TYPE_MCA_MC) || (swxtchMetaData.cmdType == CMD_TYPE_REPL_MC)
        || (swxtchMetaData.cmdType == CMD_TYPE_BRIDGE_MC)) {

        ND_PRINT("Tag: 0x%x, Token: 0x%x, Version: %u, Path ID: %u, Lossless: %s, Fragmented: %s",
                swxtchMetaData.tag, swxtchMetaData.token, version, path_id, isLossless ? "true" : "false",
                isFragmented ? "true" : "false");
        
        if (end - bp >= sizeof(struct PerfMetaData_t)) {
            processPerfMetaData(ndo, bp, end);
        }

        ND_PRINT(", SrcIP:"); 
        PRINT_IP_PORT("SrcIP", swxtchMetaData.srcIP, swxtchMetaData.srcPort); 
        ND_PRINT(" > DestIP:"); 
        PRINT_IP_PORT("DstIP", swxtchMetaData.dstIP, swxtchMetaData.dstPort); 
        ND_PRINT("\n");

        if (ndo->ndo_vflag > 0) {
            ND_PRINT("mc_off %" PRIu64, (bp - sp));
            ND_PRINT(", mc_len %" PRIu64, (end - bp));
            ND_PRINT(", seq %" PRIu64, swxtchMetaData.seq);
            convertedDate = convertUnixTimeToString(swxtchMetaData.timestamp, LE);
            ND_PRINT(", ----> ts %s", convertedDate);
        }
        if (isFragmented){
            processFragmentedData(ndo, end, isLossless);
        }
        
        if (isLossless) {
            processLosslessData(ndo, bp, end);
        }
    } else if (swxtchMetaData.cmdType == CMD_TYPE_LOSSLESS_CTRL) {

        ND_PRINT("Lossless: %s, Fragmented: %s", isLossless ? "true" : "false", isFragmented ? "true" : "false");

        if (end - bp >= sizeof(struct PerfMetaData_t)) {
            processPerfMetaData(ndo, bp, end);
        }
        if (isFragmented){
            processFragmentedData(ndo, end, isLossless);
        }
        
        if (isLossless) {
            processLosslessData(ndo, bp, end);
        }
    } else {
        if (ndo->ndo_vflag > 0) {
            ND_PRINT("-----------------------");
            ND_PRINT(", seq %" PRIu64, swxtchMetaData.seq);
            convertedDate = convertUnixTimeToString(swxtchMetaData.timestamp, LE);
            ND_PRINT(", ts %s", convertedDate);
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
    // ND_PRINT("\n--------------------------- END -------------------------------- \n");

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
