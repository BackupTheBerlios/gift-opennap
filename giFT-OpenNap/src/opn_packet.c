/* giFT OpenNap
 *
 * $Id: opn_packet.c,v 1.15 2003/08/12 14:49:03 tsauerbeck Exp $
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

	if (!(packet->data = string_new(NULL, 0, 0, TRUE)))
		return NULL;
	
	packet->cmd = OPN_CMD_NONE;

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

void opn_packet_put_str(OpnPacket *packet, char *str, BOOL quoted)
{
	char *fmt;
	BOOL first = (!packet->data->len);
	
	assert(packet);
	assert(str);

	fmt = stringf("%s%s", first ? "" : " ", quoted ? "\"%s\"" : "%s");
	string_appendf(packet->data, fmt, str);
}

void opn_packet_put_uint32(OpnPacket *packet, uint32_t val)
{
	assert(packet);

	if (!packet->data->len)
		string_appendf(packet->data, "%lu", val);
	else
		string_appendf(packet->data, " %lu", val);
}

void opn_packet_put_ip(OpnPacket *packet, in_addr_t ip)
{
	opn_packet_put_uint32(packet, BSWAP32(ip));
}

char *opn_packet_get_str(OpnPacket *packet, BOOL quoted)
{
	char *start, *end;
	
	assert(packet);

	if (!packet->read)
		return NULL;

	if (quoted) {
		/* string is delimited by quotes */
		if (!(start = strchr(packet->read, '"')))
			return NULL;
		
		if (!(end = strchr(++start, '"')))
			return NULL;
	} else {
		/* string is delimited by spaces */
		start = packet->read;
		end = strchr(start, ' ');
	}

	if ((packet->read = end)) {
		packet->read += quoted ? 2 : 1;
		return STRDUP_N(start, end - start);
	} else
		return STRDUP(start);
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

	if (!(packet = opn_packet_new()))
		return NULL;
	
	memcpy(&cmd, &data[2], 2);
	packet->cmd = BSWAP16(cmd);
	
	if (size) {
		string_appendu(packet->data, &data[OPN_PACKET_HEADER_LEN], size);
		packet->read = packet->data->str;
	}

	return packet;
}

/**
 * Sends a OpnPacket using a TCPC
 * 
 * @param packet The packet to send
 * @param session The session the packet is sent over
 * @return TRUE on success, FALSE on failure
 */
BOOL opn_packet_send(OpnPacket *packet, OpnSession *session)
{
	uint8_t *data;
	int bytes;

	assert(packet);
	assert(packet->cmd != OPN_CMD_NONE);
	assert(session);
	
	if (!(data = packet_serialize(packet)))
		return FALSE;
	
	bytes = packet->data->len + OPN_PACKET_HEADER_LEN;
	return (tcp_write(session->con, data, bytes) == bytes);
}

