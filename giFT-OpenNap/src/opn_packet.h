/* giFT OpenNap
 *
 * $Id: opn_packet.h,v 1.10 2003/08/14 20:19:51 tsauerbeck Exp $
 * 
 * Copyright (C) 2003 Tilman Sauerbeck <tilman@code-monkey.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __OPN_PACKET_H
#define __OPN_PACKET_H

/* Each message to/from the server is in the form of
 * <length><type><data>
 * where <length> and <type> are 2 bytes each.
 * <length> specifies the length in bytes of the <data> portion of the message.
 *
 * Be aware that <length> and <type> are in little-endian format.
 * 
 * The <data> portion of the message is a plain ASCII string.
 */

/* length of the header: sizeof(length) + sizeof(type) */
#define OPN_PACKET_HEADER_LEN 4

#ifdef WORDS_BIGENDIAN
# define BSWAP16(x) (((x) & 0x00ff) << 8 | ((x) & 0xff00) >> 8)
# define BSWAP32(x) \
	((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >> 8) | \
	(((x) & 0x0000ff00) << 8) | (((x) & 0x000000ff) << 24))
#else /* !WORDS_BIGENDIAN */
# define BSWAP16(x) (x)
# define BSWAP32(x) (x)
#endif /* WORDS_BIGENDIAN */
	
typedef struct _OpnPacket {
	OpnCommand cmd; /**< command */

	String *data; /**< payload of the OpnPacket */
	
	uint8_t *serialized; /**< serialized data */

	char *read;
} OpnPacket;

OpnPacket *opn_packet_new();
void opn_packet_free(OpnPacket *packet);

void opn_packet_set_cmd(OpnPacket *packet, OpnCommand cmd);

void opn_packet_put_str(OpnPacket *packet, char *str, BOOL quoted);
void opn_packet_put_ustr(OpnPacket *packet, uint8_t *str, int len,
                         BOOL quoted);
void opn_packet_put_uint32(OpnPacket *packet, uint32_t val);
void opn_packet_put_ip(OpnPacket *packet, in_addr_t ip);

char *opn_packet_get_str(OpnPacket *packet, BOOL quoted);
uint32_t opn_packet_get_uint32(OpnPacket *packet);
in_addr_t opn_packet_get_ip(OpnPacket *packet);

OpnPacket *opn_packet_unserialize(uint8_t *data, uint16_t size);

BOOL opn_packet_send(OpnPacket *packet, OpnSession *session);

#endif

