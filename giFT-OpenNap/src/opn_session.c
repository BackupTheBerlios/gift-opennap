/* giFT OpenNap
 *
 * $Id: opn_session.c,v 1.16 2003/08/10 14:10:28 tsauerbeck Exp $
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

static void on_session_read(int fd, input_id input, void *udata)
{
	OpnSession *session = (OpnSession *) udata;
	
	if (!opn_packet_recv(session)) {
		OPENNAP->sessions = list_remove(OPENNAP->sessions, session);
		opn_session_free(session);
	}
}

static void session_login(OpnSession *session)
{
	OpnPacket *packet;

	assert(session);

	if (!(packet = opn_packet_new()))
		return;

	opn_packet_set_cmd(packet, OPN_CMD_LOGIN);

	opn_packet_put_str(packet, OPN_ALIAS, FALSE);
	opn_packet_put_str(packet, "none", FALSE);
	opn_packet_put_uint32(packet, OPN_DATAPORT);
	opn_packet_put_str(packet, OPN_CLIENTNAME " " VERSION, TRUE);
	opn_packet_put_uint32(packet, 0);
	
	opn_packet_send(packet, session);
	opn_packet_free(packet);
}

static void on_session_connect(int fd, input_id input, void *udata)
{
	OpnSession *session = (OpnSession *) udata;
	
	input_remove(input);
	
	session_login(session);

	input_add(fd, session, INPUT_READ, on_session_read, TIMEOUT_DEF);
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
	          on_session_connect, TIMEOUT_DEF);
	
	return TRUE;
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

	if (session->con)
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
		session = (OpnSession *) l->data;

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
	assert(sessions);
	
	list_foreach_remove(sessions,
	                    (ListForeachFunc) foreach_session_free, NULL);
}

