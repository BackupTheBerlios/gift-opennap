/* giFT OpenNap
 *
 * $Id: opn_packet.c,v 1.10 2003/08/07 20:17:37 tsauerbeck Exp $
 * 
 * Copyright (C) 2003 Tilman Sauerbeck <tilman@code-monkey.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 */

#include "opn_opennap.h"

#ifdef WORDS_BIGENDIAN
# define BSWAP16(x) (((x) & 0x00ff) << 8 | ((x) & 0xff00) >> 8)
# define BSWAP32(x) \
	((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >> 8) | \
	(((x) & 0x0000ff00) << 8) | (((x) & 0x000000ff) << 24))
#else /* !WORDS_BIGENDIAN */
# define BSWAP16(x) (x)
# define BSWAP32(x) (x)
#endif /* WORDS_BIGENDIAN */

/* length of the header: sizeof(length) + sizeof(type) */
#define OPN_PACKET_HEADER_LEN 4

/**
 * Creates a new OpnPacket
 * 
 * @return The newly created OpnPacket
 */
OpnPacket *opn_packet_new()
{
	OpnPacket *packet;

	if (!(packet = malloc(sizeof(OpnPacket))))
		return NULL;

	memset(packet, 0, sizeof(OpnPacket));

	packet->cmd = OPN_CMD_NONE;
	packet->data = string_new(NULL, 0, 0, TRUE);

	return packet;
}

/**
 * Frees a OpnPacket
 * 
 * @param packet The OpnPacket which should be freed
 */
void opn_packet_free(OpnPacket *packet)
{
	if (!packet)
		return;

	string_free(packet->data);
	free(packet->serialized);
	free(packet);
}

void opn_packet_set_cmd(OpnPacket *packet, OpnCommand cmd)
{
	assert(packet);
	assert(cmd != OPN_CMD_NONE);

	packet->cmd = cmd;
}

static void packet_append(OpnPacket *packet, char *str)
{
	if (!packet->data->len)
		string_appendf(packet->data, str);
	else
		string_appendf(packet->data, " %s", str);
}

void opn_packet_put_str(OpnPacket *packet, char *str, BOOL quoted)
{
	char buf[PATH_MAX + 1];
	
	assert(packet);
	assert(str);

	if (quoted) {
		snprintf(buf, sizeof(buf), "\"%s\"", str);
		packet_append(packet, buf);
	} else
		packet_append(packet, str);
}

void opn_packet_put_uint32(OpnPacket *packet, uint32_t val)
{
	char buf[16];
	
	assert(packet);

	snprintf(buf, sizeof(buf), "%u", val);
	packet_append(packet, buf);
}

void opn_packet_put_ip(OpnPacket *packet, in_addr_t ip)
{
	opn_packet_put_uint32(packet, BSWAP32(ip));
}

char *opn_packet_get_str(OpnPacket *packet, BOOL quoted)
{
	char *start, *end;
	
	assert(packet);
	assert(packet->read);

	if (quoted) {
		/* string is delimited by quotes */
		if (!(start = strchr(packet->read, '"')))
			return NULL;
		
		if (!(end = strchr(++start, '"')))
			return NULL;
	} else {
		/* string is delimited by spaces */
		start = packet->read;
		
		if (!(end = strchr(start, ' ')))
			end = strchr(start, 0);
	}

	packet->read = end;
	packet->read += (quoted) ? 2 : 1;
	
	return STRDUP_N(start, end - start);
}

uint32_t opn_packet_get_uint32(OpnPacket *packet)
{
	char *ptr = opn_packet_get_str(packet, FALSE);
	uint32_t val = ATOUL(ptr);
	
	free(ptr);

	return val;
}

in_addr_t opn_packet_get_ip(OpnPacket *packet)
{
	return BSWAP32(opn_packet_get_uint32(packet));
}

/**
 * Serializes a OpnPacket
 * 
 * @param packet The OpnPacket which should be serialized
 * @return A pointer to the serialized data,
 *         which must not not be freed!
 */
static uint8_t *packet_serialize(OpnPacket *packet)
{
	uint16_t foo;
	
	assert(packet);

	free(packet->serialized);
	
	/* payload of the message + type and size fields */
	if (!(packet->serialized = malloc(packet->data->len +
	                                  OPN_PACKET_HEADER_LEN)))
		return NULL;

	/* size and type are always in little-endian format */
	foo = BSWAP16(packet->data->len);
	memcpy(packet->serialized, &foo, 2);

	foo = BSWAP16(packet->cmd);
	memcpy(&packet->serialized[2], &foo, 2);

	if (packet->data->len)
		memcpy(&packet->serialized[OPN_PACKET_HEADER_LEN],
		       packet->data->str, packet->data->len);
	
	return packet->serialized;
}

/**
 * Unserializes a buffer into a OpnPacket.
 *
 * @param data Data stream which is to be unserialized
 * @param size Amount of bytes to unserialize
 * @return The newly created OpnPacket
 */
OpnPacket *opn_packet_unserialize(uint8_t *data, uint16_t size)
{
	OpnPacket *packet;
	uint16_t cmd;

	assert(data);
	assert(size >= OPN_PACKET_HEADER_LEN);

	if (!(packet = opn_packet_new()))
		return NULL;
	
	memcpy(&cmd, &data[2], 2);
	packet->cmd = BSWAP16(cmd);
	
	if ((size -= OPN_PACKET_HEADER_LEN)) {
		string_appendu(packet->data, &data[OPN_PACKET_HEADER_LEN], size);
		packet->read = packet->data->str;
	}

	return packet;
}

/**
 * Sends a OpnPacket using a TCPC
 * 
 * @param packet The packet to send
 * @param con The connection the packet is sent over
 * @return TRUE on success, FALSE on failure
 */
BOOL opn_packet_send(OpnPacket *packet, TCPC *con)
{
	uint8_t *data;
	int bytes;

	assert(packet);
	assert(packet->cmd != OPN_CMD_NONE);
	assert(con);
	
	if (!(data = packet_serialize(packet)))
		return FALSE;
	
	bytes = packet->data->len + OPN_PACKET_HEADER_LEN;
	return (tcp_send(con, data, bytes) == bytes);
}

/**
 * Reads a packet and handles it.
 * 
 * @param session The session to read the packet from
 * @return TRUE if a packet has been read, else FALSE.
 */
BOOL opn_packet_recv(OpnSession *session)
{
	OpnPacket *packet;
	uint8_t buf[2048];
	int bytes;
	uint16_t len;

	assert(session);

	/* get the length field of the message:
	 * always in little-endian format
	 */
	if (tcp_peek(session->con, (uint8_t *) &len, 2) < 2)
		return FALSE;
	
	len = MIN(BSWAP16(len) + OPN_PACKET_HEADER_LEN, sizeof(buf));
	bytes = tcp_recv(session->con, buf, len);
	
	if (bytes < OPN_PACKET_HEADER_LEN)
		return FALSE;
	
	packet = opn_packet_unserialize(buf, bytes);
	
	if (packet->cmd != OPN_CMD_NONE)
		opn_protocol_handle(packet, session);
	
	opn_packet_free(packet);

	return TRUE;
}

