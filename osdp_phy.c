#include "osdp_common.h"

#define OSDP_PKT_MARK                  0xFF
#define OSDP_PKT_SOM                   0x53
#define PKT_CONTROL_SQN                0x03
#define PKT_CONTROL_CRC                0x04
#define PKT_CONTROL_SCB                0x08
struct osdp_packet_header {
	uint8_t som;
	uint8_t pd_address;
	uint8_t len_lsb;
	uint8_t len_msb;
	uint8_t control;
	uint8_t data[];
} __packed;

uint8_t osdp_compute_checksum(uint8_t *msg, int length)
{
	uint8_t checksum = 0;
	int i, whole_checksum;

	whole_checksum = 0;
	for (i = 0; i < length; i++) {
		whole_checksum += msg[i];
		checksum = ~(0xff & whole_checksum) + 1;
	}
	return checksum;
}

int osdp_phy_decode_packet(struct osdp_pd *pd, uint8_t **pkt_start)
{
	uint8_t *data, *mac, *buf = pd->packet_buf;
	int mac_offset, is_cmd, len = pd->packet_buf_len;
	struct osdp_packet_header *pkt;

	pkt = (struct osdp_packet_header *)buf;
	len -= pkt->control & PKT_CONTROL_CRC ? 2 : 1;
	mac_offset = len - 4;
	data = pkt->data;
	len -= sizeof(struct osdp_packet_header);

	if (pkt->control & PKT_CONTROL_SCB) {
		if (is_pd_mode(pd) && !sc_is_capable(pd)) {
			LOG_ERR("PD is not SC capable");
			pd->reply_id = REPLY_NAK;
			pd->ephemeral_data[0] = OSDP_PD_NAK_SC_UNSUP;
			return OSDP_ERR_PKT_NACK;
		}
		if (pkt->data[1] < SCS_11 || pkt->data[1] > SCS_18) {
			LOG_ERR("Invalid SB Type");
			pd->reply_id = REPLY_NAK;
			pd->ephemeral_data[0] = OSDP_PD_NAK_SC_COND;
			return OSDP_ERR_PKT_NACK;
		}
		if (!sc_is_active(pd) && pkt->data[1] > SCS_14) {
			LOG_ERR("Received invalid secure message!");
			pd->reply_id = REPLY_NAK;
			pd->ephemeral_data[0] = OSDP_PD_NAK_SC_COND;
			return OSDP_ERR_PKT_NACK;
		}
		if (pkt->data[1] == SCS_11 || pkt->data[1] == SCS_13) {
			/**
			 * CP signals PD to use SCBKD by setting SB data byte
			 * to 0. In CP, PD_FLAG_SC_USE_SCBKD comes from FSM; on
			 * PD we extract it from the command itself. But this
			 * usage of SCBKD is allowed only when the PD is in
			 * install mode (indicated by OSDP_FLAG_INSTALL_MODE).
			 */
			if (ISSET_FLAG(pd, OSDP_FLAG_INSTALL_MODE) &&
			    pkt->data[2] == 0) {
				SET_FLAG(pd, PD_FLAG_SC_USE_SCBKD);
			}
		}
		data = pkt->data + pkt->data[0];
		len -= pkt->data[0]; /* consume security block */
	} else {
		/**
		 * If the current packet is an ACK for a KEYSET, the PD might
		 * have discarded the secure channel session keys in favour of
		 * the new key we sent and hence this packet may reach us in
		 * plain text. To work with such PDs, we must also discard our
		 * secure session.
		 *
		 * The way we do this is by calling osdp_keyset_complete() which
		 * copies the key in ephemeral_data to the current SCBK.
		 */
		if (is_cp_mode(pd) && pd->cmd_id == CMD_KEYSET &&
		    pkt->data[0] == REPLY_ACK) {
			osdp_keyset_complete(pd);
		}

		if (sc_is_active(pd)) {
			LOG_ERR("Received plain-text message in SC");
			pd->reply_id = REPLY_NAK;
			pd->ephemeral_data[0] = OSDP_PD_NAK_SC_COND;
			return OSDP_ERR_PKT_NACK;
		}
	}

	if (sc_is_active(pd) &&
	    pkt->control & PKT_CONTROL_SCB && pkt->data[1] >= SCS_15) {
		/* validate MAC */
		is_cmd = is_pd_mode(pd);
		osdp_compute_mac(pd, is_cmd, buf, mac_offset);
		mac = is_cmd ? pd->sc.c_mac : pd->sc.r_mac;
		if (memcmp(buf + mac_offset, mac, 4) != 0) {
			LOG_ERR("Invalid MAC; discarding SC");
			sc_deactivate(pd);
			pd->reply_id = REPLY_NAK;
			pd->ephemeral_data[0] = OSDP_PD_NAK_SC_COND;
			return OSDP_ERR_PKT_NACK;
		}
		len -= 4; /* consume MAC */

		/* decrypt data block */
		if (pkt->data[1] == SCS_17 || pkt->data[1] == SCS_18) {
			/**
			 * Only the data portion of message (after id byte)
			 * is encrypted. While (en/de)crypting, we must skip
			 * header (6), security block (2) and cmd/reply id (1)
			 * bytes if cmd/reply has no data, use SCS_15/SCS_16.
			 *
			 * At this point, the header and security block is
			 * already consumed. So we can just skip the cmd/reply
			 * ID (data[0])  when calling osdp_decrypt_data().
			 */
			len = osdp_decrypt_data(pd, is_cmd, data + 1, len - 1);
			if (len < 0) {
				LOG_ERR("Failed at decrypt; discarding SC");
				sc_deactivate(pd);
				pd->reply_id = REPLY_NAK;
				pd->ephemeral_data[0] = OSDP_PD_NAK_SC_COND;
				return OSDP_ERR_PKT_NACK;
			}
			if (len == 0) {
				/**
				 * If cmd/reply has no data, PD "should" have
				 * used SCS_15/SCS_16 but we will be tolerant
				 * towards those faulty implementations.
				 */
				LOG_INF("Received encrypted data block with 0 "
					"length; tolerating non-conformance!");
			}
			len += 1; /* put back cmd/reply ID */
		}
	}

	*pkt_start = data;
	return len;
}
