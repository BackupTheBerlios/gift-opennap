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
#include "opn_download.h"
#include "opn_search.h"
#include "opn_share.h"
#include "opn_utils.h"

OPN_HANDLER(login_error)
{
	assert(udata);

#ifdef OPENNAP_DEBUG
	OPN->DBGFN(OPN, "login error: %s\n", packet->read);
#endif

	OPENNAP->sessions = list_remove(OPENNAP->sessions, udata);
	opn_session_free((OpnSession *) udata);
}

OPN_HANDLER(login_ack)
{
	OpnSession *session = (OpnSession *) udata;

	assert(session);
	
	session->node->connected = TRUE;
	
	if (opn_share_enabled() && !opn_share_syncing())
		opn_share_refresh(session);
}

OPN_HANDLER(stats)
{
	OpnSession *session = (OpnSession *) udata;

	assert(session);

	session->stats.users = opn_packet_get_uint32(packet);
	session->stats.files = opn_packet_get_uint32(packet);
	session->stats.size = (double) opn_packet_get_uint32(packet);
}

OPN_HANDLER(error)
{
#ifdef OPENNAP_DEBUG
	OPN->DBGFN(OPN, "error: %s\n", packet->read);
#endif
}

OPN_HANDLER(ping)
{
	OpnSession *session = (OpnSession *) udata;
	OpnPacket *pong;

	assert(session);

	if (!(pong = opn_packet_new()))
		return;

	opn_packet_set_cmd(pong, OPN_CMD_PONG);
	opn_packet_put_str(pong, packet->read, FALSE);

	opn_packet_send(pong, session->con);
	opn_packet_free(pong);
}

OPN_HANDLER(search_result)
{
	OpnSession *session = (OpnSession *) udata;
	OpnUrl *url;
	Share share;
	char *md5, *user, *bitrate, *freq, *duration, *root;
	char *path_orig, *path_nix;
	uint32_t ip, filesize;

	assert(session);
	assert(packet->data);
	assert(packet->data->str);

	if (!(url = opn_url_new()))
		return;

	if (!(path_orig = opn_packet_get_str(packet, TRUE))) {
		opn_url_free(url);
		return;
	}
	
	md5 = opn_packet_get_str(packet, FALSE);
	filesize = opn_packet_get_uint32(packet);
	bitrate = opn_packet_get_str(packet, FALSE);
	freq = opn_packet_get_str(packet, FALSE);
	duration = opn_packet_get_str(packet, FALSE);
	
	if (!(user = opn_packet_get_str(packet, FALSE))) {
		free(path_orig);
		free(md5);
		free(bitrate);
		free(freq);
		free(duration);
		free(md5);
		opn_url_free(url);
		
		return;
	}
	
	ip = opn_packet_get_ip(packet);
	path_nix = opn_unix_path(path_orig);
	root = file_dirname(path_nix);

	share_init(&share, path_nix);
	share_set_root(&share, root, strlen(root));
	share.size = filesize;
	share_set_meta(&share, "Bitrate", bitrate);
	share_set_meta(&share, "Frequency", freq);
	share_set_meta(&share, "Duration", duration);

	opn_url_set_file(url, path_orig, filesize);
	opn_url_set_client(url, user, ip, 0);
	opn_url_set_server(url, session->node->ip, session->node->port);

	opn_search_reply_add(path_nix, url, &share);
	
	share_finish(&share);
	opn_url_free(url);

	free(path_orig);
	free(path_nix);
	free(md5);
	free(bitrate);
	free(freq);
	free(duration);
	free(user);
}

OPN_HANDLER(search_finished)
{
	if (!OPENNAP->searches)
		return;

	if (list_length(OPENNAP->searches) == 1)
		opn_search_unref((OpnSearch *) OPENNAP->searches->data);
	else {
		/* those will be handled by search->timer :) */
	}
}

OPN_HANDLER(download_ack)
{
	OpnDownload *download;
	OpnUrl *url;
	char *user, *file;
	in_addr_t ip;
	in_port_t port;
	
	user = opn_packet_get_str(packet, FALSE);
	ip = opn_packet_get_ip(packet);
	port = opn_packet_get_uint32(packet);
	file = opn_packet_get_str(packet, TRUE);

	if (!(url = opn_url_new()))
		return;
	
	opn_url_set_file(url, file, 0);
	opn_url_set_client(url, user, ip, port);

	free(user);
	free(file);

	/* if port is 0 => user is firewalled
	 * currently not supported
	 * FIXME implement me!
	 */
	if (!(download = opn_download_find_by_client(url)) || !port) {
		opn_url_free(url);
		return;
	}

	opn_url_free(url);

	download->url->client.port = port;
	opn_download_start(download);
}

OPN_HANDLER(download_error)
{
	/* FIXME */
}

OPN_HANDLER(queue_limit)
{
	OpnDownload *download;
	OpnUrl *url;
	char *user, *file;
	uint32_t size;

	if (!(url = opn_url_new()))
		return;

	user = opn_packet_get_str(packet, FALSE);
	file = opn_packet_get_str(packet, TRUE);
	size = opn_packet_get_uint32(packet);

	opn_url_set_client(url, user, 0, 0);
	opn_url_set_file(url, file, size);

	free(user);
	free(file);
	
	if (!(download = opn_download_find_by_user(url)))
		return;

	opn_url_free(url);

	OPN->source_status(OPN, download->chunk->source,
	                   SOURCE_QUEUED_REMOTE, "Queued");
}

