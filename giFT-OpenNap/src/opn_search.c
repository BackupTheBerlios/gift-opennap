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

#include "opn_opennap.h"
#include <libgift/proto/share.h>
#include "opn_search.h"
#include "opn_utils.h"

#define OPN_MAX_SEARCH_RESULTS 512
#define OPN_SEARCH_TIMEOUT 120 * SECONDS

static BOOL search_remove(OpnSearch *search)
{
	OPENNAP->searches = list_remove(OPENNAP->searches, search);
	opn_search_free(search);

	return FALSE;
}

OpnSearch *opn_search_new()
{
	OpnSearch *search;

	if (!(search = malloc(sizeof(OpnSearch))))
		return NULL;

	memset(search, 0, sizeof(OpnSearch));

	opn_search_ref(search);
	search->timer = timer_add(OPN_SEARCH_TIMEOUT,
	                          (TimerCallback) search_remove, search);

	return search;
}

void opn_search_free(OpnSearch *search)
{
	if (!search)
		return;

	opn_string_freev(search->query);
	opn_string_freev(search->exclude);
	timer_remove(search->timer);

	OPN->search_complete(OPN, search->event);
	free(search);
}

uint32_t opn_search_ref(OpnSearch *search)
{
	assert(search);

	return ++search->ref;
}

uint32_t opn_search_unref(OpnSearch *search)
{
	assert(search);

	if (!--search->ref) {
		OPENNAP->searches = list_remove(OPENNAP->searches, search);
		opn_search_free(search);
		return 0;
	} else
		return search->ref;
}

/* Checks whether a file matches a query string
 * @param file
 * @param query
 * @return TRUE if the file matches the query
 */
static BOOL file_cmp_query(char *file, char **query)
{
	char **ptr;

	assert(file);

	if (!query)
		return FALSE;

	for (ptr = query; *ptr; ptr++)
		if (opn_strcasestr(file, *ptr))
			return TRUE;

	return FALSE;
}

BOOL opn_search_reply_add(char *file, OpnUrl *url, Share *share)
{
	OpnSearch *search;
	List *l;
	BOOL match[2], added = FALSE;

	assert(file);
	assert(url);
	assert(share);

	for (l = OPENNAP->searches; l; l = l->next) {
		search = (OpnSearch *) l->data;

		match[0] = file_cmp_query(file, search->query);
		match[1] = file_cmp_query(file, search->exclude);
		
		if (match[0] && !match[1]) {
			OPN->search_result(OPN, search->event,
			                   url->user, NULL, opn_url_serialize(url),
			                   1, share);

			added = TRUE;
			timer_reset(search->timer);
		}
	}

	return added;
}

BOOL opennap_search(Protocol *p, IFEvent *event, char *query,
                    char *exclude, char *realm, Dataset *meta)
{
	OpnSearch *search;
	OpnPacket *packet;
	OpnSession *session;
	List *l;

	if (!opn_is_connected || !(search = opn_search_new()))
		return FALSE;

	OPENNAP->searches = list_prepend(OPENNAP->searches, search);

	search->query = opn_string_split(query, " ");
	search->exclude = opn_string_split(exclude, " ");
	search->event = event;
	
	for (l = OPENNAP->sessions; l; l = l->next) {
		session = (OpnSession *) l->data;
		
		if (!session->node->connected)
			continue;

		if (!(packet = opn_packet_new()))
			continue;

		opn_packet_set_cmd(packet, OPN_CMD_SEARCH);
		
		opn_packet_put_str(packet, "MAX_RESULTS", FALSE);
		opn_packet_put_uint32(packet, OPN_MAX_SEARCH_RESULTS);
		opn_packet_put_str(packet, "FILENAME CONTAINS", FALSE);
		opn_packet_put_str(packet, query, TRUE);

		opn_packet_send(packet, session->con);
		opn_packet_free(packet);

		opn_search_ref(search);
	}

#ifdef OPENNAP_DEBUG
	OPN->DBGFN(OPN, "sent out %i search packets\n", search->ref - 1);
#endif

	return (opn_search_unref(search) > 0);
}

static int foreach_search_free(OpnSearch *search, void *udata)
{
	opn_search_free(search);

	return 1;
}

void opn_searches_free(List *searches)
{
	assert(searches);

	list_foreach_remove(searches,
	                    (ListForeachFunc) foreach_search_free, NULL);
}

