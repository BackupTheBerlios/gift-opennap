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

static char **string_split(char *str, char *delim)
{
	List *list = NULL, *l;
	char *tmp, *ptr, *token, **retval;
	int i = 1;

	if (!str || !delim)
		return NULL;

	ptr = tmp = strdup(str);

	/* Find the tokens and add them to the list */
	while ((token = string_sep(&tmp, delim)))
	{
		list = list_prepend(list, token);
		i++;
	}
	
	/* Now copy the tokens into the array */
	if (!(retval = malloc(sizeof(char *) * i)))
		return NULL;

	retval[--i] = NULL;
	
	for (l = list; l; l = l->next)
		retval[--i] = strdup(l->data);

	list_free(list);
	free(ptr);

	return retval;
}

/**
 * Frees a string array built by \em str_split
 *
 * @param str String array to free
 */
static void string_freev (char **str)
{
	char **ptr;

	if (!str)
		return;

	for (ptr = str; *ptr; ptr++)
		free(*ptr);

	free(str);
}

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
	search->timer = timer_add(90 * SECONDS,
	                          (TimerCallback) search_remove, search);

	return search;
}

void opn_search_free(OpnSearch *search)
{
	if (!search)
		return;

	string_freev(search->query);
	string_freev(search->exclude);
	timer_remove(search->timer);

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

	assert(query);
	assert(file);

	for (ptr = query; *ptr; ptr++)
		if (strcasestr(file, *ptr))
			return TRUE;

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

	assert(file);

	for (l = OPENNAP->searches; l; l = l->next) {
		search = (OpnSearch *) l->data;

		if (file_cmp_query(file, search->query)
		    && !file_cmp_query(file, search->exclude))
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

	OPENNAP->searches = list_prepend(OPENNAP->searches, search);

	search->query = string_split(query, " ");
	search->exclude = string_split(exclude, " ");
	search->event = event;
	
	for (l = OPENNAP->sessions; l; l = l->next) {
		session = (OpnSession *) l->data;
		
		if (!session->node->connected)
			continue;

		snprintf(buf, sizeof(buf),
		         "MAX_RESULTS %i FILENAME CONTAINS \"%s\"",
		         OPN_MAX_SEARCH_RESULTS, query);

		if (!(packet = opn_packet_new(OPN_CMD_SEARCH))
		    || !opn_packet_set_data(packet, buf))
			continue;

		opn_packet_send(packet, session->con);
		opn_packet_free(packet);

		opn_search_ref(search);
	}

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

