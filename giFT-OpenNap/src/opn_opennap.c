/* giFT OpenNap
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

	if (list_length(OPENNAP->sessions) >= OPENNAP_MAX_CONNECTIONS)
		return TRUE;
	
	for (l = OPENNAP->nodelist->nodes; l; l = l->next) {
		node = (OpnNode *) l->data;
		
		if (!node->connected) {
			if (!(session = opn_session_new()))
				return TRUE;

			OPENNAP->sessions = list_prepend(OPENNAP->sessions, session);
			
			if (!opn_session_connect(session, node)) {
				OPENNAP->sessions = list_remove(OPENNAP->sessions, session);
				opn_session_free(session);
			}
		}
	}

	return TRUE;
}

void main_timer()
{
	opn_connect(NULL);

	OPENNAP->timer_connect = timer_add(30 * SECONDS, opn_connect,
	                                   NULL);
}

static int gift_cb_stats(Protocol *p, unsigned long *users,
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

static Config *config_load()
{
	Config *cfg;
	char *src, dst[PATH_MAX + 1];
	
	src = gift_conf_path("OpenNap/OpenNap.conf");

	if (!(cfg = gift_config_new("OpenNap"))) {
		snprintf(dst, sizeof(dst), DATADIR "/OpenNap/OpenNap.conf");
		file_cp(src, dst);

		cfg = gift_config_new("OpenNap");
	}

	return cfg;
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

static BOOL gift_cb_start(Protocol *p)
{
	char alias[16];
	
	if (!(OPENNAP->cfg = config_load())) {
		GIFT_ERROR(("Can't load OpenNap configuration!"));
		return FALSE;
	}

#if 0
	if (!(OPENNAP->con = tcp_bind(OPENNAP_DATAPORT, FALSE)))
		return FALSE;
	
	input_add(OPENNAP->con->fd, NULL, INPUT_READ, opn_upload_connect,
	          TIMEOUT_DEF);
#endif

	if (OPENNAP_RANDOM_USERNAME) {
		set_username(alias);
		config_set_str(OPENNAP->cfg, "main/alias", alias);
	}

	if (OPENNAP_LOCAL_MODE)
		config_set_int(OPENNAP->cfg, "main/max_connections", 1);

	OPENNAP->nodelist = opn_nodelist_new();

#if 0
	opn_nodelist_load(OPENNAP->nodelist);
#endif

	opn_nodelist_refresh(OPENNAP->nodelist);

	return TRUE;
}

static void gift_cb_destroy(Protocol *p)
{
	if (!OPENNAP)
		return;

	if (OPENNAP->timer_connect)
		timer_remove(OPENNAP->timer_connect);

#if 0
	opn_nodelist_save(OPENNAP->nodelist);
#endif

	config_free(OPENNAP->cfg);

#if 0
	tcp_close(OPENNAP->con);
#endif

	if (OPENNAP->searches)
		opn_searches_free(OPENNAP->searches);

	if (OPENNAP->sessions)
		opn_sessions_free(OPENNAP->sessions);
	
	opn_nodelist_free(OPENNAP->nodelist);
	free(OPENNAP);
}

static void setup_callbacks(Protocol *p)
{
	p->hash_handler(p, OPENNAP_HASH, HASH_PRIMARY,
	                (HashFn) opn_hash, (HashDspFn) strdup);
	
	p->start = gift_cb_start;
	p->destroy = gift_cb_destroy;

	p->search = gift_cb_search;

	p->download_start = gift_cb_download_start;
	p->download_stop = gift_cb_download_stop;
	p->source_remove = gift_cb_source_remove;

	p->share_sync = gift_cb_share_sync;
	p->share_add = gift_cb_share_add;
	p->share_remove = gift_cb_share_remove;
	p->share_hide = gift_cb_share_hide;

	p->stats = gift_cb_stats;
}

BOOL OpenNap_init(Protocol *p)
{
	OpnPlugin *plugin;
	
	if (protocol_compat(LIBGIFTPROTO_VERSION))
		return FALSE;

	/* tell our debugger to insert a breakpoint here
	 * this only works on x86 and GLibC 2
	 */
#if defined OPENNAP_DEBUG \
	&& defined (__i386__) && defined (__GNUC__) && __GNUC__ >= 2
	__asm__ __volatile__ ("int $03");
#endif
	 
	OPN = p;

	if (!(plugin = malloc(sizeof(OpnPlugin))))
		return FALSE;

	memset(plugin, 0, sizeof(OpnPlugin));

	p->udata = plugin;

	setup_callbacks(p);
	
	return TRUE;
}


