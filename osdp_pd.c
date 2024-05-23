#include<stdint.h>
#include "osdp_common.h"
#include "osdp_file.h"
#include<utils.h>
#ifndef CONFIG_OSDP_STATIC_PD
#include <stdlib.h>
#endif

#define CMD_POLL_DATA_LEN              0
#define CMD_LSTAT_DATA_LEN             0
#define CMD_ISTAT_DATA_LEN             0
#define CMD_OSTAT_DATA_LEN             0
#define CMD_RSTAT_DATA_LEN             0
#define CMD_ID_DATA_LEN                1
#define CMD_CAP_DATA_LEN               1
#define CMD_OUT_DATA_LEN               4
#define CMD_LED_DATA_LEN               14
#define CMD_BUZ_DATA_LEN               5
#define CMD_TEXT_DATA_LEN              6   /* variable length command */
#define CMD_COMSET_DATA_LEN            5
#define CMD_KEYSET_DATA_LEN            18
#define CMD_CHLNG_DATA_LEN             8
#define CMD_SCRYPT_DATA_LEN            16
#define CMD_ABORT_DATA_LEN             0
#define CMD_ACURXSIZE_DATA_LEN         2
#define CMD_KEEPACTIVE_DATA_LEN        2
#define CMD_MFG_DATA_LEN               4 /* variable length command */

#define REPLY_ACK_LEN                  1
#define REPLY_PDID_LEN                 13
#define REPLY_PDCAP_LEN                1   /* variable length command */
#define REPLY_PDCAP_ENTITY_LEN         3
#define REPLY_LSTATR_LEN               3
#define REPLY_RSTATR_LEN               2
#define REPLY_COM_LEN                  6
#define REPLY_NAK_LEN                  2
#define REPLY_CCRYPT_LEN               33
#define REPLY_RMAC_I_LEN               17
#define REPLY_KEYPAD_LEN               2
#define REPLY_RAW_LEN                  4
#define REPLY_FMT_LEN                  3
#define REPLY_MFGREP_LEN               4 /* variable length command */

enum osdp_pd_error_e {
	OSDP_PD_ERR_NONE = 0,
	OSDP_PD_ERR_WAIT = -1,
	OSDP_PD_ERR_GENERIC = -2,
	OSDP_PD_ERR_REPLY = -3,
	OSDP_PD_ERR_IGNORE = -4,
	OSDP_PD_ERR_NO_DATA = -5,
};
static struct osdp_pd_cap osdp_pd_cap[] = {
	{
		OSDP_PD_CAP_CHECK_CHARACTER_SUPPORT,
		1, /* The PD supports the 16-bit CRC-16 mode */
		0, /* N/A */
	},
	{
		OSDP_PD_CAP_COMMUNICATION_SECURITY,
		1, /* (Bit-0) AES128 support */
		0, /* N/A */
	},
	{
		OSDP_PD_CAP_RECEIVE_BUFFERSIZE,
		BYTE_0(OSDP_PACKET_BUF_SIZE),
		BYTE_1(OSDP_PACKET_BUF_SIZE),
	},
	{ -1, 0, 0 } /* Sentinel */
};


static int pd_build_reply(struct osdp_pd *pd, uint8_t *buf, int max_len)
{
	int ret = OSDP_PD_ERR_GENERIC;
	int i, len = 0;
	struct osdp_cmd *cmd;
	struct osdp_event *event;
	int data_off = osdp_phy_packet_get_data_offset(pd, buf);
	uint8_t *smb = osdp_phy_packet_get_smb(pd, buf);

	buf += data_off;
	max_len -= data_off;

	switch (pd->reply_id) {
	case REPLY_ACK:
		assert_buf_len(REPLY_ACK_LEN, max_len);
		buf[len++] = pd->reply_id;
		ret = OSDP_PD_ERR_NONE;
		break;
	case REPLY_PDID:
		assert_buf_len(REPLY_PDID_LEN, max_len);
		buf[len++] = pd->reply_id;

		buf[len++] = BYTE_0(pd->id.vendor_code);
		buf[len++] = BYTE_1(pd->id.vendor_code);
		buf[len++] = BYTE_2(pd->id.vendor_code);

		buf[len++] = pd->id.model;
		buf[len++] = pd->id.version;

		buf[len++] = BYTE_0(pd->id.serial_number);
		buf[len++] = BYTE_1(pd->id.serial_number);
		buf[len++] = BYTE_2(pd->id.serial_number);
		buf[len++] = BYTE_3(pd->id.serial_number);

		buf[len++] = BYTE_3(pd->id.firmware_version);
		buf[len++] = BYTE_2(pd->id.firmware_version);
		buf[len++] = BYTE_1(pd->id.firmware_version);
		ret = OSDP_PD_ERR_NONE;
		break;
	case REPLY_PDCAP:
		assert_buf_len(REPLY_PDCAP_LEN, max_len);
		buf[len++] = pd->reply_id;
		for (i = 1; i < OSDP_PD_CAP_SENTINEL; i++) {
			if (pd->cap[i].function_code != i) {
				continue;
			}
			if (max_len < REPLY_PDCAP_ENTITY_LEN) {
				LOG_ERR("Out of buffer space!");
				break;
			}
			buf[len++] = i;
			buf[len++] = pd->cap[i].compliance_level;
			buf[len++] = pd->cap[i].num_items;
			max_len -= REPLY_PDCAP_ENTITY_LEN;
		}
		ret = OSDP_PD_ERR_NONE;
		break;
	case REPLY_OSTATR: {
		int n = pd->cap[OSDP_PD_CAP_OUTPUT_CONTROL].num_items;

		assert_buf_len(n + 1, max_len);
		event = (struct osdp_event *)pd->ephemeral_data;
		buf[len++] = pd->reply_id;
		for (i = 0; i < n; i++) {
			buf[len++] = !!(event->io.status & (1 << i));
		}
		ret = OSDP_PD_ERR_NONE;
		break;
	}
	case REPLY_ISTATR: {
		int n = pd->cap[OSDP_PD_CAP_CONTACT_STATUS_MONITORING].num_items;

		assert_buf_len(n + 1, max_len);
		event = (struct osdp_event *)pd->ephemeral_data;
		buf[len++] = pd->reply_id;
		for (i = 0; i < n; i++) {
			buf[len++] = !!(event->io.status & (1 << i));
		}
		ret = OSDP_PD_ERR_NONE;
		break;
	}
	case REPLY_LSTATR:
		assert_buf_len(REPLY_LSTATR_LEN, max_len);
		buf[len++] = pd->reply_id;
		buf[len++] = ISSET_FLAG(pd, PD_FLAG_TAMPER);
		buf[len++] = ISSET_FLAG(pd, PD_FLAG_POWER);
		ret = OSDP_PD_ERR_NONE;
		break;
	case REPLY_RSTATR:
		assert_buf_len(REPLY_RSTATR_LEN, max_len);
		buf[len++] = pd->reply_id;
		buf[len++] = ISSET_FLAG(pd, PD_FLAG_R_TAMPER);
		ret = OSDP_PD_ERR_NONE;
		break;
	case REPLY_KEYPPAD:
		event = (struct osdp_event *)pd->ephemeral_data;
		assert_buf_len(REPLY_KEYPAD_LEN + event->keypress.length, max_len);
		buf[len++] = pd->reply_id;
		buf[len++] = (uint8_t)event->keypress.reader_no;
		buf[len++] = (uint8_t)event->keypress.length;
		memcpy(buf + len, event->keypress.data, event->keypress.length);
		len += event->keypress.length;
		ret = OSDP_PD_ERR_NONE;
		break;
	case REPLY_RAW: {
		int len_bytes;

		event = (struct osdp_event *)pd->ephemeral_data;
		len_bytes = (event->cardread.length + 7) / 8;
		assert_buf_len(REPLY_RAW_LEN + len_bytes, max_len);
		buf[len++] = pd->reply_id;
		buf[len++] = (uint8_t)event->cardread.reader_no;
		buf[len++] = (uint8_t)event->cardread.format;
		buf[len++] = BYTE_0(event->cardread.length);
		buf[len++] = BYTE_1(event->cardread.length);
		memcpy(buf + len, event->cardread.data, len_bytes);
		len += len_bytes;
		ret = OSDP_PD_ERR_NONE;
		break;
	}
	case REPLY_FMT:
		event = (struct osdp_event *)pd->ephemeral_data;
		assert_buf_len(REPLY_FMT_LEN + event->cardread.length, max_len);
		buf[len++] = pd->reply_id;
		buf[len++] = (uint8_t)event->cardread.reader_no;
		buf[len++] = (uint8_t)event->cardread.direction;
		buf[len++] = (uint8_t)event->cardread.length;
		memcpy(buf + len, event->cardread.data, event->cardread.length);
		len += event->cardread.length;
		ret = OSDP_PD_ERR_NONE;
		break;
	case REPLY_COM:
		assert_buf_len(REPLY_COM_LEN, max_len);
		/**
		 * If COMSET succeeds, the PD must reply with the old params and
		 * then switch to the new params from then then on. We have the
		 * new params in the commands struct that we just enqueued so
		 * we can peek at tail of command queue and set that to
		 * pd->addr/pd->baud_rate.
		 */
		cmd = (struct osdp_cmd *)pd->ephemeral_data;
		buf[len++] = pd->reply_id;
		buf[len++] = cmd->comset.address;
		buf[len++] = BYTE_0(cmd->comset.baud_rate);
		buf[len++] = BYTE_1(cmd->comset.baud_rate);
		buf[len++] = BYTE_2(cmd->comset.baud_rate);
		buf[len++] = BYTE_3(cmd->comset.baud_rate);

		pd->address = (int)cmd->comset.address;
		pd->baud_rate = (int)cmd->comset.baud_rate;
		LOG_INF("COMSET Succeeded! New PD-Addr: %d; Baud: %d",
			pd->address, pd->baud_rate);
		ret = OSDP_PD_ERR_NONE;
		break;
	case REPLY_NAK:
		assert_buf_len(REPLY_NAK_LEN, max_len);
		buf[len++] = pd->reply_id;
		buf[len++] = pd->ephemeral_data[0];
		ret = OSDP_PD_ERR_NONE;
		break;
	case REPLY_MFGREP:
		cmd = (struct osdp_cmd *)pd->ephemeral_data;
		assert_buf_len(REPLY_MFGREP_LEN + cmd->mfg.length, max_len);
		buf[len++] = pd->reply_id;
		buf[len++] = BYTE_0(cmd->mfg.vendor_code);
		buf[len++] = BYTE_1(cmd->mfg.vendor_code);
		buf[len++] = BYTE_2(cmd->mfg.vendor_code);
		buf[len++] = cmd->mfg.command;
		memcpy(buf + len, cmd->mfg.data, cmd->mfg.length);
		len += cmd->mfg.length;
		ret = OSDP_PD_ERR_NONE;
		break;
	case REPLY_FTSTAT:
		buf[len++] = pd->reply_id;
		ret = osdp_file_cmd_stat_build(pd, buf + len, max_len);
		if (ret <= 0) {
			break;
		}
		len += ret;
		ret = OSDP_PD_ERR_NONE;
		break;
	case REPLY_CCRYPT:
		if (smb == NULL) {
			break;
		}
		assert_buf_len(REPLY_CCRYPT_LEN, max_len);
		osdp_fill_random(pd->sc.pd_random, 8);
		osdp_compute_session_keys(pd);
		osdp_compute_pd_cryptogram(pd);
		buf[len++] = pd->reply_id;
		memcpy(buf + len, pd->sc.pd_client_uid, 8);
		memcpy(buf + len + 8, pd->sc.pd_random, 8);
		memcpy(buf + len + 16, pd->sc.pd_cryptogram, 16);
		len += 32;
		smb[0] = 3;      /* length */
		smb[1] = SCS_12; /* type */
		smb[2] = ISSET_FLAG(pd, PD_FLAG_SC_USE_SCBKD) ? 0 : 1;
		ret = OSDP_PD_ERR_NONE;
		break;
	case REPLY_RMAC_I:
		if (smb == NULL) {
			break;
		}
		assert_buf_len(REPLY_RMAC_I_LEN, max_len);
		osdp_compute_rmac_i(pd);
		buf[len++] = pd->reply_id;
		memcpy(buf + len, pd->sc.r_mac, 16);
		len += 16;
		smb[0] = 3;       /* length */
		smb[1] = SCS_14;  /* type */
		if (osdp_verify_cp_cryptogram(pd) == 0) {
			smb[2] = 1;  /* CP auth succeeded */
			sc_activate(pd);
			pd->sc_tstamp = osdp_millis_now();
			if (ISSET_FLAG(pd, PD_FLAG_SC_USE_SCBKD)) {
				LOG_WRN("SC Active with SCBK-D");
			} else {
				LOG_INF("SC Active");
			}
		} else {
			smb[2] = 0;  /* CP auth failed */
			LOG_WRN("failed to verify CP_crypt");
		}
		ret = OSDP_PD_ERR_NONE;
		break;
	}

	if (smb && (smb[1] > SCS_14) && sc_is_active(pd)) {
		smb[0] = 2; /* length */
		smb[1] = (len > 1) ? SCS_18 : SCS_16;
	}

	if (ret != 0) {
		/* catch all errors and report it as a RECORD error to CP */
		LOG_ERR("Failed to build REPLY: %s(%02x); Sending NAK instead!",
			osdp_reply_name(pd->reply_id), pd->reply_id);
		assert_buf_len(REPLY_NAK_LEN, max_len);
		buf[0] = REPLY_NAK;
		buf[1] = OSDP_PD_NAK_RECORD;
		len = 2;
	}

	if (IS_ENABLED(CONFIG_OSDP_DATA_TRACE)) {
		if (pd->cmd_id != CMD_POLL) {
			osdp_dump(buf + 1, len - 1, "OSDP: REPLY: %s(%02x)",
				  osdp_reply_name(buf[0]), buf[0]);
		}
	}

	return len;
}

static int pd_send_reply(struct osdp_pd *pd)
{
	int ret, packet_buf_size = get_tx_buf_size(pd);

	/* init packet buf with header */
	ret = osdp_phy_packet_init(pd, pd->packet_buf, packet_buf_size);
	if (ret < 0) {
		return OSDP_PD_ERR_GENERIC;
	}
	pd->packet_buf_len = ret;

	/* fill reply data */
	ret = pd_build_reply(pd, pd->packet_buf, packet_buf_size);
	if (ret <= 0) {
		return OSDP_PD_ERR_GENERIC;
	}
	pd->packet_buf_len += ret;

	ret = osdp_phy_send_packet(pd, pd->packet_buf, pd->packet_buf_len,
				   packet_buf_size);
	if (ret < 0) {
		return OSDP_PD_ERR_GENERIC;
	}

	return OSDP_PD_ERR_NONE;
}