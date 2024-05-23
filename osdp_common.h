

#ifndef _OSDP_COMMON_H_
#define _OSDP_COMMON_H_
#define SCS_11 0x11 /* CP -> PD -- CMD_CHLNG */
#define SCS_12 0x12 /* PD -> CP -- REPLY_CCRYPT */
#define SCS_13 0x13 /* CP -> PD -- CMD_SCRYPT */
#define SCS_14 0x14 /* PD -> CP -- REPLY_RMAC_I */

#define SCS_15 0x15 /* CP -> PD -- packets w MAC w/o ENC */
#define SCS_16 0x16 /* PD -> CP -- packets w MAC w/o ENC */
#define SCS_17 0x17 /* CP -> PD -- packets w MAC w ENC*/
#define SCS_18 0x18 /* PD -> CP -- packets w MAC w ENC*/
#define CMD_POLL 0x60
#define CMD_ID 0x61
#define CMD_CAP 0x62
#define CMD_LSTAT 0x64
#define CMD_ISTAT 0x65
#define CMD_OSTAT 0x66
#define CMD_RSTAT 0x67
#define CMD_OUT 0x68
#define CMD_LED 0x69
#define CMD_BUZ 0x6A
#define CMD_TEXT 0x6B
#define CMD_RMODE 0x6C
#define CMD_TDSET 0x6D
#define CMD_COMSET 0x6E
#define CMD_BIOREAD 0x73
#define CMD_BIOMATCH 0x74
#define CMD_KEYSET 0x75
#define CMD_CHLNG 0x76
#define CMD_SCRYPT 0x77
#define CMD_ACURXSIZE 0x7B
#define CMD_FILETRANSFER 0x7C
#define CMD_MFG 0x80
#define CMD_XWR 0xA1
#define CMD_ABORT 0xA2
#define CMD_PIVDATA 0xA3
#define CMD_GENAUTH 0xA4
#define CMD_CRAUTH 0xA5
#define CMD_KEEPACTIVE 0xA7

/**
 * @brief OSDP reserved responses
 */
#define REPLY_ACK 0x40
#define REPLY_NAK 0x41
#define REPLY_PDID 0x45
#define REPLY_PDCAP 0x46
#define REPLY_LSTATR 0x48
#define REPLY_ISTATR 0x49
#define REPLY_OSTATR 0x4A
#define REPLY_RSTATR 0x4B
#define REPLY_RAW 0x50
#define REPLY_FMT 0x51
#define REPLY_KEYPPAD 0x53
#define REPLY_COM 0x54
#define REPLY_BIOREADR 0x57
#define REPLY_BIOMATCHR 0x58
#define REPLY_CCRYPT 0x76
#define REPLY_BUSY 0x79
#define REPLY_RMAC_I 0x78
#define REPLY_FTSTAT 0x7A
#define REPLY_PIVDATAR 0x80
#define REPLY_GENAUTHR 0x81
#define REPLY_CRAUTHR 0x82
#define REPLY_MFGSTATR 0x83
#define REPLY_MFGERRR 0x84
#define REPLY_MFGREP 0x90
#define REPLY_XRD 0xB1
#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <osdp.h>
#include <queue.h>
#include <slab.h>
#include<logger.h>
#include "osdp_config.h"			  /* generated */
#define PD_FLAG_SC_CAPABLE BIT(0)	  /* PD secure channel capable */
#define PD_FLAG_TAMPER BIT(1)		  /* local tamper status */
#define PD_FLAG_POWER BIT(2)		  /* local power status */
#define PD_FLAG_R_TAMPER BIT(3)		  /* remote tamper status */
#define PD_FLAG_AWAIT_RESP BIT(4)	  /* set after command is sent */
#define PD_FLAG_SKIP_SEQ_CHECK BIT(5) /* disable seq checks (debug) */
#define PD_FLAG_SC_USE_SCBKD BIT(6)	  /* in this SC attempt, use SCBKD */
#define PD_FLAG_SC_ACTIVE BIT(7)	  /* secure channel is active */
#define PD_FLAG_PD_MODE BIT(8)		  /* device is setup as PD */
#define PD_FLAG_CHN_SHARED BIT(9)	  /* PD's channel is shared */
#define PD_FLAG_PKT_SKIP_MARK BIT(10) /* CONFIG_OSDP_SKIP_MARK_BYTE */
#define PD_FLAG_PKT_HAS_MARK BIT(11)  /* Packet has mark byte */
#define PD_FLAG_HAS_SCBK BIT(12)	  /* PD has a dedicated SCBK */
#define PD_FLAG_SC_DISABLED BIT(13)	  /* master_key=NULL && scbk=NULL */
#define PD_FLAG_PKT_BROADCAST BIT(14) /* this packet was addressed to 0x7F */

#define BYTE_0(x) (uint8_t)(((x) >> 0) & 0xFF)
#define BYTE_1(x) (uint8_t)(((x) >> 8) & 0xFF)
#define BYTE_2(x) (uint8_t)(((x) >> 16) & 0xFF)
#define BYTE_3(x) (uint8_t)(((x) >> 24) & 0xFF)

/* casting helpers */


#define USE_CUSTOM_LOGGER
#ifndef NULL
#define NULL ((void *)0)
#endif

enum osdp_cp_phy_state_e
{
	OSDP_CP_PHY_STATE_IDLE,
	OSDP_CP_PHY_STATE_SEND_CMD,
	OSDP_CP_PHY_STATE_REPLY_WAIT,
	OSDP_CP_PHY_STATE_WAIT,
	OSDP_CP_PHY_STATE_ERR,
};

enum osdp_cp_state_e
{
	OSDP_CP_STATE_INIT,
	OSDP_CP_STATE_IDREQ,
	OSDP_CP_STATE_CAPDET,
	OSDP_CP_STATE_SC_INIT,
	OSDP_CP_STATE_SC_CHLNG,
	OSDP_CP_STATE_SC_SCRYPT,
	OSDP_CP_STATE_SET_SCBK,
	OSDP_CP_STATE_ONLINE,
	OSDP_CP_STATE_OFFLINE
};

enum osdp_pkt_errors_e
{
	OSDP_ERR_PKT_NONE = 0,
	/**
	 * Fatal packet formatting issues. The phy layer was unable to find a
	 * valid OSDP packet or the length of the packet was too long/incorrect.
	 */
	OSDP_ERR_PKT_FMT = -1,
	/**
	 * Not enough data in buffer (but we have some); wait for more.
	 */
	OSDP_ERR_PKT_WAIT = -2,
	/**
	 * Message to/from an foreign device that can be safely ignored
	 * without altering the state of this PD.
	 */
	OSDP_ERR_PKT_SKIP = -3,
	/**
	 * Packet was valid but does not match some conditions. ie., only this
	 * packet is faulty, rest of the buffer may still be intact.
	 */
	OSDP_ERR_PKT_CHECK = -4,
	/**
	 * Discovered a busy packet. In CP mode, it should retry this command
	 * after some time.
	 */
	OSDP_ERR_PKT_BUSY = -5,
	/**
	 * Phy layer found a reason to send NACK to the CP that produced
	 * this packet; pd->reply_id is set REPLY_NAK and the reason code is
	 * also filled.
	 */
	OSDP_ERR_PKT_NACK = -6,
	/**
	 * Packet build errors
	 */
	OSDP_ERR_PKT_BUILD = -7,
	/**
	 * No data received (do not confuse with OSDP_ERR_PKT_WAIT)
	 */
	OSDP_ERR_PKT_NO_DATA = -8,
};

struct osdp_slab
{
	int block_size;
	int num_blocks;
	int free_blocks;
	uint8_t *blob;
};

struct osdp_secure_channel
{
	uint8_t scbk[16];
	uint8_t s_enc[16];
	uint8_t s_mac1[16];
	uint8_t s_mac2[16];
	uint8_t r_mac[16];
	uint8_t c_mac[16];
	uint8_t cp_random[8];
	uint8_t pd_random[8];
	uint8_t pd_client_uid[8];
	uint8_t cp_cryptogram[16];
	uint8_t pd_cryptogram[16];
};

struct osdp_rb
{
	size_t head;
	size_t tail;
	uint8_t buffer[OSDP_RX_RB_SIZE];
};

#define OSDP_QUEUE_SLAB_SIZE                                                   \
	(OSDP_CP_CMD_POOL_SIZE *                                               \
	 (sizeof(union osdp_ephemeral_data) + sizeof(queue_node_t)))

#define safe_free(p)                                                           \
	if (p)                                                                 \
		free(p)

#define osdp_dump hexdump // for zephyr compatibility.

/* Unused type only to estimate ephemeral_data size */
union osdp_ephemeral_data {
	struct osdp_cmd cmd;
	struct osdp_event event;
};
#define OSDP_EPHEMERAL_DATA_MAX_LEN sizeof(union osdp_ephemeral_data)

struct osdp_queue
{
	queue_t queue;
	slab_t slab;
	uint8_t slab_blob[OSDP_QUEUE_SLAB_SIZE];
};

struct osdp_pd
{
	const char *name;
	struct osdp *osdp_ctx; /* Ref to osdp * to access shared resources */
	int idx;			   /* Offset into osdp->pd[] for this PD */
	uint32_t flags;		   /* Used with: ISSET_FLAG, SET_FLAG, CLEAR_FLAG */

	int baud_rate;		  /* Serial baud/bit rate */
	int address;		  /* PD address */
	int seq_number;		  /* Current packet sequence number */
	struct osdp_pd_id id; /* PD ID information (as received from app) */

	/* PD Capability; Those received from app + implicit capabilities */
	struct osdp_pd_cap cap[OSDP_PD_CAP_SENTINEL];

	int state;			/* FSM state (CP mode only) */
	int phy_state;		/* phy layer FSM state (CP mode only) */
	uint32_t wait_ms;	/* wait time in MS to retry communication */
	int64_t tstamp;		/* Last POLL command issued time in ticks */
	int64_t sc_tstamp;	/* Last received secure reply time in ticks */
	int64_t phy_tstamp; /* Time in ticks since command was sent */

	uint16_t peer_rx_size; /* Receive buffer size of the peer PD/CP */

	/* Raw bytes received from the serial line for this PD */
	struct osdp_rb rx_rb;
	uint8_t packet_buf[OSDP_PACKET_BUF_SIZE];
	int packet_len;
	int packet_buf_len;

	int cmd_id;	  /* Currently processing command ID */
	int reply_id; /* Currently processing reply ID */

	/* Data bytes of the current command/reply ID */
	uint8_t ephemeral_data[OSDP_EPHEMERAL_DATA_MAX_LEN];
    
	union
	{
		struct osdp_queue cmd;	 /* Command queue (CP Mode only) */
		struct osdp_queue event; /* Command queue (PD Mode only) */
	};

	struct osdp_channel channel;   /* PD's serial channel */
	struct osdp_secure_channel sc; /* Secure Channel session context */
	struct osdp_file *file;		   /* File transfer context */

	/* PD command callback to app with opaque arg pointer as passed by app */
	void *command_callback_arg;
	pd_command_callback_t command_callback;

	logger_t logger; /* logger context (from utils/logger.h) */
};
#endif /* _OSDP_COMMON_H_ */