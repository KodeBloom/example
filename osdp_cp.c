#include <stdlib.h>
#include<stdio.h>
#include<utils.h>

#include "osdp_common.h"
#include "osdp_file.h"
#define CMD_POLL_LEN                   1
#define CMD_LSTAT_LEN                  1
#define CMD_ISTAT_LEN                  1
#define CMD_OSTAT_LEN                  1
#define CMD_RSTAT_LEN                  1
#define CMD_ID_LEN                     2
#define CMD_CAP_LEN                    2
#define CMD_DIAG_LEN                   2
#define CMD_OUT_LEN                    5
#define CMD_LED_LEN                    15
#define CMD_BUZ_LEN                    6
#define CMD_TEXT_LEN                   7   /* variable length command */
#define CMD_COMSET_LEN                 6
#define CMD_KEYSET_LEN                 19
#define CMD_CHLNG_LEN                  9
#define CMD_SCRYPT_LEN                 17
#define CMD_MFG_LEN                    4 /* variable length command */

#define REPLY_ACK_DATA_LEN             0
#define REPLY_PDID_DATA_LEN            12
#define REPLY_PDCAP_ENTITY_LEN         3
#define REPLY_LSTATR_DATA_LEN          2
#define REPLY_RSTATR_DATA_LEN          1
#define REPLY_COM_DATA_LEN             5
#define REPLY_NAK_DATA_LEN             1
#define REPLY_CCRYPT_DATA_LEN          32
#define REPLY_RMAC_I_DATA_LEN          16
#define REPLY_KEYPPAD_DATA_LEN         2   /* variable length command */
#define REPLY_RAW_DATA_LEN             4   /* variable length command */
#define REPLY_FMT_DATA_LEN             3   /* variable length command */
#define REPLY_BUSY_DATA_LEN            0
#define REPLY_MFGREP_LEN               4 /* variable length command */

enum osdp_cp_error_e {
	OSDP_CP_ERR_NONE = 0,
	OSDP_CP_ERR_GENERIC = -1,
	OSDP_CP_ERR_NO_DATA = -2,
	OSDP_CP_ERR_RETRY_CMD = -3,
	OSDP_CP_ERR_CAN_YIELD = -4,
	OSDP_CP_ERR_INPROG = -5,
	OSDP_CP_ERR_UNKNOWN = -6,
};

static int cp_build_command(struct osdp_pd *pd, uint8_t *buf, int max_len)
{
	struct osdp_cmd *cmd = NULL;
	int ret, len = 0;
	int data_off = osdp_phy_packet_get_data_offset(pd, buf);
	uint8_t *smb = osdp_phy_packet_get_smb(pd, buf);

	buf += data_off;
	max_len -= data_off;
	if (max_len <= 0) {
		return OSDP_CP_ERR_GENERIC;
	}

	switch (pd->cmd_id) {
	case CMD_POLL:
		assert_buf_len(CMD_POLL_LEN, max_len);
		buf[len++] = pd->cmd_id;
		break;
	case CMD_LSTAT:
		assert_buf_len(CMD_LSTAT_LEN, max_len);
		buf[len++] = pd->cmd_id;
		break;
	case CMD_ISTAT:
		assert_buf_len(CMD_ISTAT_LEN, max_len);
		buf[len++] = pd->cmd_id;
		break;
	case CMD_OSTAT:
		assert_buf_len(CMD_OSTAT_LEN, max_len);
		buf[len++] = pd->cmd_id;
		break;
	case CMD_RSTAT:
		assert_buf_len(CMD_RSTAT_LEN, max_len);
		buf[len++] = pd->cmd_id;
		break;
	case CMD_ID:
		assert_buf_len(CMD_ID_LEN, max_len);
		buf[len++] = pd->cmd_id;
		buf[len++] = 0x00;
		break;
	case CMD_CAP:
		assert_buf_len(CMD_CAP_LEN, max_len);
		buf[len++] = pd->cmd_id;
		buf[len++] = 0x00;
		break;
	case CMD_OUT:
		assert_buf_len(CMD_OUT_LEN, max_len);
		cmd = (struct osdp_cmd *)pd->ephemeral_data;
		buf[len++] = pd->cmd_id;
		buf[len++] = cmd->output.output_no;
		buf[len++] = cmd->output.control_code;
		buf[len++] = BYTE_0(cmd->output.timer_count);
		buf[len++] = BYTE_1(cmd->output.timer_count);
		break;
	case CMD_LED:
		assert_buf_len(CMD_LED_LEN, max_len);
		cmd = (struct osdp_cmd *)pd->ephemeral_data;
		buf[len++] = pd->cmd_id;
		buf[len++] = cmd->led.reader;
		buf[len++] = cmd->led.led_number;

		buf[len++] = cmd->led.temporary.control_code;
		buf[len++] = cmd->led.temporary.on_count;
		buf[len++] = cmd->led.temporary.off_count;
		buf[len++] = cmd->led.temporary.on_color;
		buf[len++] = cmd->led.temporary.off_color;
		buf[len++] = BYTE_0(cmd->led.temporary.timer_count);
		buf[len++] = BYTE_1(cmd->led.temporary.timer_count);

		buf[len++] = cmd->led.permanent.control_code;
		buf[len++] = cmd->led.permanent.on_count;
		buf[len++] = cmd->led.permanent.off_count;
		buf[len++] = cmd->led.permanent.on_color;
		buf[len++] = cmd->led.permanent.off_color;
		break;
	case CMD_BUZ:
		assert_buf_len(CMD_BUZ_LEN, max_len);
		cmd = (struct osdp_cmd *)pd->ephemeral_data;
		buf[len++] = pd->cmd_id;
		buf[len++] = cmd->buzzer.reader;
		buf[len++] = cmd->buzzer.control_code;
		buf[len++] = cmd->buzzer.on_count;
		buf[len++] = cmd->buzzer.off_count;
		buf[len++] = cmd->buzzer.rep_count;
		break;
	case CMD_TEXT:
		cmd = (struct osdp_cmd *)pd->ephemeral_data;
		assert_buf_len(CMD_TEXT_LEN + cmd->text.length, max_len);
		buf[len++] = pd->cmd_id;
		buf[len++] = cmd->text.reader;
		buf[len++] = cmd->text.control_code;
		buf[len++] = cmd->text.temp_time;
		buf[len++] = cmd->text.offset_row;
		buf[len++] = cmd->text.offset_col;
		buf[len++] = cmd->text.length;
		memcpy(buf + len, cmd->text.data, cmd->text.length);
		len += cmd->text.length;
		break;
	case CMD_COMSET:
		assert_buf_len(CMD_COMSET_LEN, max_len);
		cmd = (struct osdp_cmd *)pd->ephemeral_data;
		buf[len++] = pd->cmd_id;
		buf[len++] = cmd->comset.address;
		buf[len++] = BYTE_0(cmd->comset.baud_rate);
		buf[len++] = BYTE_1(cmd->comset.baud_rate);
		buf[len++] = BYTE_2(cmd->comset.baud_rate);
		buf[len++] = BYTE_3(cmd->comset.baud_rate);
		break;
	case CMD_MFG:
		cmd = (struct osdp_cmd *)pd->ephemeral_data;
		assert_buf_len(CMD_MFG_LEN + cmd->mfg.length, max_len);
		if (cmd->mfg.length > OSDP_CMD_MFG_MAX_DATALEN) {
			LOG_ERR("Invalid MFG data length (%d)", cmd->mfg.length);
			return OSDP_CP_ERR_GENERIC;
		}
		buf[len++] = pd->cmd_id;
		buf[len++] = BYTE_0(cmd->mfg.vendor_code);
		buf[len++] = BYTE_1(cmd->mfg.vendor_code);
		buf[len++] = BYTE_2(cmd->mfg.vendor_code);
		buf[len++] = cmd->mfg.command;
		memcpy(buf + len, cmd->mfg.data, cmd->mfg.length);
		len += cmd->mfg.length;
		break;
	case CMD_ACURXSIZE:
		buf[len++] = pd->cmd_id;
		buf[len++] = BYTE_0(OSDP_PACKET_BUF_SIZE);
		buf[len++] = BYTE_1(OSDP_PACKET_BUF_SIZE);
		break;
	case CMD_KEEPACTIVE:
		buf[len++] = pd->cmd_id;
		buf[len++] = BYTE_0(0); // keepalive in ms time LSB
		buf[len++] = BYTE_1(0); // keepalive in ms time MSB
		break;
	case CMD_ABORT:
		buf[len++] = pd->cmd_id;
		break;
	case CMD_FILETRANSFER:
		buf[len++] = pd->cmd_id;
		ret = osdp_file_cmd_tx_build(pd, buf + len, max_len);
		if (ret <= 0) {
			return OSDP_CP_ERR_GENERIC;
		}
		len += ret;
		break;
	case CMD_KEYSET:
		if (!sc_is_active(pd)) {
			LOG_ERR("Cannot perform KEYSET without SC!");
			return OSDP_CP_ERR_GENERIC;
		}
		cmd = (struct osdp_cmd *)pd->ephemeral_data;
		assert_buf_len(CMD_KEYSET_LEN, max_len);
		if (cmd->keyset.length != 16) {
			LOG_ERR("Invalid key length");
			return OSDP_CP_ERR_GENERIC;
		}
		buf[len++] = pd->cmd_id;
		buf[len++] = 1;  /* key type (1: SCBK) */
		buf[len++] = 16; /* key length in bytes */
		if (cmd->keyset.type == 1) { /* SCBK */
			memcpy(buf + len, cmd->keyset.data, 16);
		} else if (cmd->keyset.type == 0) {  /* master_key */
			osdp_compute_scbk(pd, cmd->keyset.data, buf + len);
		} else {
			LOG_ERR("Unknown key type (%d)", cmd->keyset.type);
			return -1;
		}
		len += 16;
		break;
	case CMD_CHLNG:
		assert_buf_len(CMD_CHLNG_LEN, max_len);
		if (smb == NULL) {
			LOG_ERR("Invalid secure message block!");
			return OSDP_CP_ERR_GENERIC;
		}
		smb[0] = 3;       /* length */
		smb[1] = SCS_11;  /* type */
		smb[2] = ISSET_FLAG(pd, PD_FLAG_SC_USE_SCBKD) ? 0 : 1;
		buf[len++] = pd->cmd_id;
		memcpy(buf + len, pd->sc.cp_random, 8);
		len += 8;
		break;
	case CMD_SCRYPT:
		assert_buf_len(CMD_SCRYPT_LEN, max_len);
		if (smb == NULL) {
			LOG_ERR("Invalid secure message block!");
			return OSDP_CP_ERR_GENERIC;
		}
		osdp_compute_cp_cryptogram(pd);
		smb[0] = 3;       /* length */
		smb[1] = SCS_13;  /* type */
		smb[2] = ISSET_FLAG(pd, PD_FLAG_SC_USE_SCBKD) ? 0 : 1;
		buf[len++] = pd->cmd_id;
		memcpy(buf + len, pd->sc.cp_cryptogram, 16);
		len += 16;
		break;
	default:
		LOG_ERR("Unknown/Unsupported CMD(%02x)", pd->cmd_id);
		return OSDP_CP_ERR_GENERIC;
	}

	if (smb && (smb[1] > SCS_14) && sc_is_active(pd)) {
		/**
		 * When SC active and current cmd is not a handshake (<= SCS_14)
		 * then we must set SCS type to 17 if this message has data
		 * bytes and 15 otherwise.
		 */
		smb[0] = 2;
		smb[1] = (len > 1) ? SCS_17 : SCS_15;
	}

	if (IS_ENABLED(CONFIG_OSDP_DATA_TRACE)) {
		if (pd->cmd_id != CMD_POLL) {
			hexdump(buf + 1, len - 1, "OSDP: CMD: %s(%02x)",
				osdp_cmd_name(pd->cmd_id), pd->cmd_id);
		}
	}

	return len;
}
