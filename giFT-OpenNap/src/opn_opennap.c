/* giFT OpenNap
 *
 * $Id: opn_opennap.c,v 1.22 2003/08/07 20:17:37 tsauerbeck Exp $
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

#define __OPN_OPENNAP_C
#include "opn_opennap.h"
#include <libgift/proto/share.h>
#include "opn_share.h"
#include "opn_search.h"
#include "opn_download.h"
#include "opn_upload.h"
#include "opn_hash.h"

Protocol *OPN = NULL;

BOOL opn_is_connected()
{
	OpnSession *session;
	List *l;
	
	for (l = OPENNAP->sessions; l; l = l->next) {
		session = (OpnSession *) l->data;

		if (session->node->connected)
			return TRUE;
	}

	return FALSE;
}

static BOOL opn_connect(void *udata)
{
	OpnSession *session;
	OpnNode *node;
	List *l;

	if (list_length(OPENNAP->sessions) >= OPN_MAX_CONNECTIONS)
		return TRUE;
	
	for (l = OPENNAP->nodelist->nodes; l; l = l->next) {
		node = (OpnNode *) l->data;
	
		/* Check whether we are already connected to that node */
		if (node->connected)
			continue;

		if (!(session = opn_session_new()))
			return TRUE;

		OPENNAP->sessions = list_prepend(OPENNAP->sessions, session);

		if (!opn_session_connect(session, node)) {
			OPENNAP->sessions = list_remove(OPENNAP->sessions, session);
			opn_session_free(session);
		}
	}

	return TRUE;
}

void main_timer()
{
#ifdef OPENNAP_DEBUG
	OPN->DBGFN(OPN, "Got %i nodes - connecting...\n",
	           list_length(OPENNAP->nodelist->nodes));
#endif

	opn_connect(NULL);

	OPENNAP->timer_connect = timer_add(30 * SECONDS, opn_connect,
	                                   NULL);
}

static int opennap_stats(Protocol *p, unsigned long *users,
                         unsigned long *files, double *size,
                         Dataset **extra)
{
	OpnSession *session;
	List *l;
	int i;

	*users = *files = *size = 0;

	for (l = OPENNAP->sessions, i = 0; l; l = l->next, i++) {
		session = (OpnSession *) l->data;

		*users += session->stats.users;
		*files += session->stats.files;
		*size += session->stats.size;
	}

	return i;
}

/**
 * Creates a random username
 *
 * @param buf String the username is stored in
 */
static void set_username(char buf[16])
{
	int i, x;

	srand(time(NULL));

	for (i = 0; i < 15; i++) {
		x = 1 + (int) (26.0 * rand() / (RAND_MAX + 1.0));

		if (1 + (int) (2.0 * rand() / (RAND_MAX + 1.0)) == 2)
			x += 32;

		buf[i] = x + 64;
	}

	buf[i] = 0;
}

static BOOL opennap_start(Protocol *p)
{
	char alias[16];
	
	if (!(OPENNAP->cfg = gift_config_new("OpenNap"))) {
		OPN->err(OPN, "Can't load OpenNap configuration!");
		return FALSE;
	}

	if (!(OPENNAP->con = tcp_bind(OPN_DATAPORT, FALSE)))
		return FALSE;
	
	input_add(OPENNAP->con->fd, OPENNAP->con, INPUT_READ,
	          opn_upload_connect, TIMEOUT_DEF);

	if (OPN_RANDOM_USERNAME) {
		set_username(alias);
		config_set_str(OPENNAP->cfg, "main/alias", alias);
	}

	OPENNAP->nodelist = opn_nodelist_new();
	opn_nodelist_load(OPENNAP->nodelist, OPN_USE_NAPIGATOR);

	return TRUE;
}

static void opennap_destroy(Protocol *p)
{
	if (!OPENNAP)
		return;

	if (OPENNAP->timer_connect)
		timer_remove(OPENNAP->timer_connect);

	config_free(OPENNAP->cfg);

	tcp_close(OPENNAP->con);

	if (OPENNAP->searches)
		opn_searches_free(OPENNAP->searches);

	if (OPENNAP->sessions)
		opn_sessions_free(OPENNAP->sessions);
	
	opn_nodelist_free(OPENNAP->nodelist);
	free(OPENNAP);
}

static void setup_callbacks(Protocol *p)
{
	p->hash_handler(p, OPN_HASH, HASH_PRIMARY,
	                (HashFn) opn_hash, (HashDspFn) STRDUP);
	
	p->start = opennap_start;
	p->destroy = opennap_destroy;

	p->search = opennap_search;

	p->download_start = opennap_download_start;
	p->download_stop = opennap_download_stop;
	p->source_remove = opennap_source_remove;
	p->chunk_suspend = opennap_chunk_suspend;
	p->chunk_resume = opennap_chunk_resume;
	
	p->upload_stop = opennap_upload_stop;

	p->share_sync = opennap_share_sync;
	p->share_add = opennap_share_add;
	p->share_remove = opennap_share_remove;
	p->share_show = opennap_share_show;
	p->share_hide = opennap_share_hide;

	p->stats = opennap_stats;
}

BOOL OpenNap_init(Protocol *p)
{
	OpnPlugin *plugin;
	
	if (protocol_compat(p, LIBGIFTPROTO_VERSION))
		return FALSE;

	OPN = p;

	if (!(plugin = malloc(sizeof(OpnPlugin))))
		return FALSE;

	memset(plugin, 0, sizeof(OpnPlugin));

	p->udata = plugin;

	setup_callbacks(p);
	
	return TRUE;
}


