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
#include "opn_hash.h"

static BOOL share_syncing = FALSE;
static BOOL share_enabled = TRUE; /* TRUE if sharing is enabled */

/**
 * Returns the current share-syncing state.
 *
 * @return TRUE if giFT is currently syncing shares
 */
BOOL opn_share_syncing()
{
	return share_syncing;
}

/**
 * Returns the current sharing state.
 *
 * @return TRUE if sharing is enabled
 */
BOOL opn_share_enabled()
{
	return share_enabled;
}

/**
 * Updates the list of shared material
 * @param session The OpnSession to update shares for
 */
void opn_share_refresh(OpnSession *session)
{
	OpnPacket *packet;
	Share *share;
	Hash *hash;
	List *l;
	char buf[PATH_MAX + 128];

	assert(session);

	if (!session->node->connected)
		return;

	for (l = OPENNAP->shares; l; l = l->next) {
		share = (Share *) l->data;
		hash = share_get_hash(share, OPENNAP_HASH);

		if (!(packet = opn_packet_new(OPN_CMD_SHARE_ADD)))
			continue;

		snprintf(buf, sizeof(buf), "\"%s\" %s %lu %s %s %s",
				share->path, hash->data, share->size,
				STRING_NOTNULL(share_get_meta(share, "Bitrate")),
				STRING_NOTNULL(share_get_meta(share, "Frequency")),
				STRING_NOTNULL(share_get_meta(share, "Length")));

		opn_packet_set_data(packet, buf);
		opn_packet_send(packet, session->con);
		opn_packet_free(packet);
	}
}
	
/**
 * Tells each server we're connected to
 * we aren't sharing anything any more.
 */
void share_remove()
{
	OpnSession *session;
	OpnPacket *packet;
	List *l;
	
	for (l = OPENNAP->sessions; l; l = l->next) {
		session = (OpnSession *) l->data;

		if (!session->node->connected)
			continue;

		if ((packet = opn_packet_new(OPN_CMD_SHARE_REMOVE_ALL))) {
			opn_packet_send(packet, session->con);
			opn_packet_free(packet);
		}
	}
}

/**
 * Informs us about giFT's current share syncronizing state.
 *
 * @param p
 * @param begin TRUE if share's are currently synced.
 *              FALSE if syncing shares has been finished.
 */
void gift_cb_share_sync(Protocol *p, BOOL begin)
{
	List *l;

	share_syncing = begin;

	/* syncing has been finished, so tell the servers
	 * we are connected to about the changes
	 */
	if (!begin)
		for (l = OPENNAP->sessions; l; l = l->next) {
			share_remove((OpnSession *) l->data);
			opn_share_refresh((OpnSession *) l->data);
		}
}

/**
 * Adds a share.
 * 
 * @param p
 * @param share
 * @param udata Protocol-specific data associated with \em share
 */
BOOL gift_cb_share_add(Protocol *p, Share *share, void *udata)
{
	OPENNAP->shares = list_prepend(OPENNAP->shares, share);
	share_ref(share);

	return TRUE;
}

/**
 * Removes a share.
 * 
 * @param p
 * @param share
 * @param udata Protocol-specific data associated with \em share
 */
BOOL gift_cb_share_remove(Protocol *p, Share *share, void *udata)
{
	OPENNAP->shares = list_remove(OPENNAP->shares, share);
	share_unref(share);

	return TRUE;
}

/**
 * Unshares all files. 
 *
 * @param p
 */
void gift_cb_share_hide(Protocol *p)
{
	List *l;

	share_enabled = FALSE;

	for (l = OPENNAP->sessions; l; l = l->next)
		share_remove((OpnSession *) l->data);
}

/**
 * Sharing has been enabled again so refresh the list
 * of shares.
 *
 * @param p
 */
void gift_cb_share_show(Protocol *p)
{
	List *l;

	share_enabled = TRUE;

	for (l = OPENNAP->sessions; l; l = l->next)
		opn_share_refresh((OpnSession *) l->data);
}

