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
#include "opn_search.h"

#define OPN_MAX_SEARCH_RESULTS 512

static BOOL search_remove(OpnSearch *search)
{
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
	search->timer = timer_add(90 * SECONDS,
	                          (TimerCallback) search_remove, search);

	OPENNAP->searches = list_prepend(OPENNAP->searches, search);

	return search;
}

void opn_search_free(OpnSearch *search)
{
	if (!search)
		return;

	timer_remove(search->timer);

	OPENNAP->searches = list_remove(OPENNAP->searches, search);
	opn_proto->search_complete(opn_proto, search->event);
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
static BOOL file_cmp_query(char *file, char *query)
{
	char *ptr, *tmp, *token;

	assert(query);
	assert(file);

	if (string_isempty(query))
		return FALSE;

	if (!strchr(query, ' '))
		return (strcasestr(file, query) != NULL);
	
	ptr = tmp = strdup(query);

	while ((token = string_sep(&tmp, " ")))
		if (strcasestr(file, token)) {
			free(ptr);
			return TRUE;
		}

	free(ptr);

	return FALSE;
}

/* Returns the OpnSearch object that belongs to a file
 * @param file
 * @return The OpnSearch object, if found, else NULL
 */
OpnSearch *opn_search_find(char *file)
{
	OpnSearch *search;
	List *l;
	BOOL match_query, match_excl;

	assert(file);

	for (l = OPENNAP->searches; l; l = l->next) {
		search = (OpnSearch *) l->data;

		match_query = file_cmp_query(file, search->query);
		match_excl = file_cmp_query(file, search->exclude);
		
		if (match_query && !match_excl)
			return search;
	}

	return NULL;
}

BOOL gift_cb_search(Protocol *p, IFEvent *event, char *query, char *exclude,
                    char *realm, Dataset *meta)
{
	OpnSearch *search;
	OpnPacket *packet;
	OpnSession *session;
	List *l;
	char buf[256];

	if (!opn_is_connected || !(search = opn_search_new()))
		return FALSE;

	snprintf(search->query, sizeof(search->query), query);
	snprintf(search->exclude, sizeof(search->exclude), exclude);
	search->event = event;
	
	for (l = OPENNAP->sessions; l; l = l->next) {
		session = (OpnSession *) l->data;
		
		if (session->state != OPN_SESSION_STATE_CONNECTED)
			continue;

		snprintf(buf, sizeof(buf),
		         "MAX_RESULTS %i FILENAME CONTAINS \"%s\"",
		         OPN_MAX_SEARCH_RESULTS, query);

		if (!(packet = opn_packet_new(OPN_CMD_SEARCH, buf, strlen(buf))))
			continue;

		opn_packet_send(packet, session->con);
		opn_packet_free(packet);

		opn_search_ref(search);
	}

	return (opn_search_unref(search) > 0);
}

