/* giFT OpenNap
 *
 * $Id: opn_session.c,v 1.20 2003/08/21 19:00:44 tsauerbeck Exp $
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

#include "opn_opennap.h"
#include "opn_node.h"
#include "opn_protocol.h"

static void on_session_read(int fd, input_id input, OpnSession *session)
{
	OpnPacket *packet;
	FDBuf *buf;
	uint16_t len;
	uint8_t *data;
	int n;

	if (fd == -1 || !input || net_sock_error(fd)) {
		opn_session_disconnect(session);
		return;
	}

	buf = tcp_readbuf(session->con);
	len = buf->flag + OPN_PACKET_HEADER_LEN;

	if ((n = fdbuf_fill(buf, len)) < 0) {
		opn_session_disconnect(session);
		return;
	} else if (n > 0)
		return;

	data = fdbuf_data(buf, NULL);

	/* get the payload's length */
	memcpy(&len, data, 2);
	len = BSWAP16(len);

	if (buf->flag || !len) {
		buf->flag = 0;
		fdbuf_release(buf);

		if ((packet = opn_packet_unserialize(data, len))) {
			assert(packet->cmd != OPN_CMD_NONE);

			opn_protocol_handle(packet, session);
			opn_packet_free(packet);
		}
	} else if (!buf->flag)
		buf->flag = len;
}

static void session_login(OpnSession *session)
{
	OpnPacket *packet;

	assert(session);

	if (!(packet = opn_packet_new()))
		return;

	opn_packet_set_cmd(packet, OPN_CMD_LOGIN);

	opn_packet_put_str(packet, OPN_ALIAS, FALSE);
	opn_packet_put_str(packet, OPN_PASSWORD, FALSE);
	opn_packet_put_uint32(packet, OPN_DATAPORT);
	opn_packet_put_str(packet, OPN_CLIENTNAME " " VERSION, TRUE);
	opn_packet_put_uint32(packet, 0);
	
	opn_packet_send(packet, session);
	opn_packet_free(packet);
}

static void on_session_connect(int fd, input_id input, OpnSession *session)
{
	if (fd == -1 || !input || net_sock_error(fd)) {
		opn_session_disconnect(session);
		return;
	}
	
	session_login(session);

	input_remove(input);
	input_add(fd, session, INPUT_READ,
	          (InputCallback) on_session_read, 30 * SECONDS);
}

BOOL opn_session_connect(OpnSession *session, OpnNode *node)
{
	assert(session);
	assert(node);
	
	if (!(session->con = tcp_open(node->ip, node->port, FALSE)))
		return FALSE;

	session->node = node;
	session->node->state = OPN_NODE_STATE_CONNECTING;

	input_add(session->con->fd, session, INPUT_WRITE,
	          (InputCallback) on_session_connect, 30 * SECONDS);
	
	return TRUE;
}

void opn_session_disconnect(OpnSession *session)
{
	assert(session);
	
	OPENNAP->sessions = list_remove(OPENNAP->sessions, session);
	opn_session_free(session);
}

OpnSession *opn_session_new()
{
	OpnSession *session;

	if (!(session = malloc(sizeof(OpnSession))))
		return NULL;

	memset(session, 0, sizeof(OpnSession));

	return session;
}

void opn_session_free(OpnSession *session)
{
	if (!session)
		return;

	tcp_close(session->con);

	if (session->node)
		session->node->state = OPN_NODE_STATE_DISCONNECTED;

	free(session);
}

OpnSession *opn_session_find(OpnUrl *url)
{
	OpnSession *session;
	List *l;

	assert(url);
	
	for (l = OPENNAP->sessions; l; l = l->next) {
		session = l->data;

		if (session->node->ip == url->server.ip
		    && session->node->port == url->server.port)
			return session;
	}

	return NULL;
}

static int foreach_session_free(OpnSession *session, void *udata)
{
	opn_session_free(session);

	return 1;
}

void opn_sessions_free(List *sessions)
{
	if (!sessions)
		return;

	list_foreach_remove(sessions,
	                    (ListForeachFunc) foreach_session_free, NULL);
}

