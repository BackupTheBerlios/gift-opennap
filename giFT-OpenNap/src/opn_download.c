/* giFT OpenNap
 *
 * $Id: opn_download.c,v 1.17 2003/08/09 09:56:34 tsauerbeck Exp $
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
#include <ctype.h>
#include "opn_download.h"

static BOOL find_by_chunk(OpnDownload *dl, void *udata)
{
	return (dl->chunk == udata);
}

static BOOL find_by_client(OpnDownload *dl, void *udata)
{
	OpnUrl *url = (OpnUrl *) udata;

	return (!strcasecmp(url->file, dl->url->file)
	        && !strcasecmp(url->user, dl->url->user)
	        && url->client.ip == dl->url->client.ip);
}

static BOOL find_by_user(OpnDownload *dl, void *udata)
{
	OpnUrl *url = (OpnUrl *) udata;

	return (!strcasecmp(url->file, dl->url->file)
	        && !strcasecmp(url->user, dl->url->user)
	        && url->size == dl->url->size);
}

static OpnDownload *opn_download_find(OpnDownloadFindCb cb, void *udata)
{
	OpnDownload *download;
	List *l;

	assert(cb);
	assert(udata);

	for (l = OPENNAP->downloads; l; l = l->next) {
		download = (OpnDownload *) l->data;

		if ((*cb)((OpnDownload *) l->data, udata))
			return download;
	}

	return NULL;
}

OpnDownload *opn_download_find_by_user(OpnUrl *url)
{
	return opn_download_find(find_by_user, url);
}

OpnDownload *opn_download_find_by_client(OpnUrl *url)
{
	return opn_download_find(find_by_client, url);
}

OpnDownload *opn_download_find_by_chunk(Chunk *c)
{
	return opn_download_find(find_by_chunk, c);
}

BOOL opennap_download_start(Protocol *p, Transfer *transfer,
                            Chunk *chunk, Source *source)
{
	OpnDownload *download;
	OpnSession *session;
	OpnPacket *packet;
	BOOL ret;

	if (!(download = opn_download_new()))
		return FALSE;

	download->chunk = chunk;
	download->url = opn_url_unserialize(source->url);

	if (!(session = opn_session_find(download->url))
	   || !(packet = opn_packet_new())) {
		opn_download_free(download);
		return FALSE;
	}
	
	opn_packet_set_cmd(packet, OPN_CMD_DOWNLOAD_REQUEST);
	
	opn_packet_put_str(packet, download->url->user, FALSE);
	opn_packet_put_str(packet, download->url->file, TRUE);

	ret = opn_packet_send(packet, session);
	opn_packet_free(packet);
	
	return ret;
}

void opennap_source_remove(Protocol *p, Transfer *t, Source *s)
{
	/* FIXME */
}

void opennap_download_stop(Protocol *p, Transfer *transfer,
                           Chunk *chunk, Source *source, int complete)
{
	opn_download_free(opn_download_find_by_chunk(chunk));
}

BOOL opennap_chunk_suspend(Protocol *p, Transfer *transfer,
                           Chunk *chunk, Source *source)
{
	OpnDownload *download;

	if (!(download = opn_download_find_by_chunk(chunk)))
		return FALSE;
	else {
		assert(download->con);
		input_suspend_all(download->con->fd);

		return TRUE;
	}
}

BOOL opennap_chunk_resume(Protocol *p, Transfer *transfer,
                          Chunk *chunk, Source *source)
{
	OpnDownload *download;

	if (!(download = opn_download_find_by_chunk(chunk)))
		return FALSE;
	else {
		assert(download->con);
		input_resume_all(download->con->fd);
		
		return TRUE;
	}
}

OpnDownload *opn_download_new()
{
	OpnDownload *dl;

	if (!(dl = malloc(sizeof(OpnDownload))))
		return NULL;

	memset(dl, 0, sizeof(OpnDownload));

	OPENNAP->downloads = list_prepend(OPENNAP->downloads, dl);

	return dl;
}

void opn_download_free(OpnDownload *dl)
{
	if (!dl)
		return;

	OPENNAP->downloads = list_remove(OPENNAP->downloads, dl);

	if (dl->con)
		tcp_close(dl->con);

	opn_url_free(dl->url);
	free(dl);
}

static void on_download_read_data(int fd, input_id input, void *udata)
{
	OpnDownload *download = (OpnDownload *) udata;
	uint8_t buf[RW_BUFFER];
	size_t size;
	int recvd;

	/* Ask giFT for the max size we should read.  If this returns 0, the
	 * download was suspended.
	 */
	if (!(size = download_throttle(download->chunk, sizeof(buf))))
		return;

	if ((recvd = tcp_recv(download->con, buf, size)) <= 0) {
		OPN->source_status(OPN, download->chunk->source,
		                   SOURCE_CANCELLED, "Error");
		opn_download_free(download);
		return;
	}

	OPN->chunk_write(OPN, download->chunk->transfer,
	                 download->chunk, download->chunk->source,
	                 buf, recvd);
}

static void on_download_read_filesize(int fd, input_id input, void *udata)
{
	OpnDownload *download = (OpnDownload *) udata;
	uint8_t buf[128];
	int recvd, i;
	uint32_t size = 0;

	input_remove(input);

	/* get the filesize */
	if ((recvd = tcp_peek(download->con, buf, sizeof(buf))) <= 0) {
		opn_download_free(download);
		return;
	}

	buf[recvd] = 0;

	for (i = 0; isdigit(buf[i]) && size < download->url->size; i++)
		size = (size * 10) + (buf[i] - '0');

	tcp_recv(download->con, buf, i);

	input_add(fd, download, INPUT_READ, on_download_read_data,
	          TIMEOUT_DEF);
}

static void on_download_write(int fd, input_id input, void *udata)
{
	OpnDownload *download = (OpnDownload *) udata;
	char buf[PATH_MAX + 256];

	input_remove(input);

	tcp_writestr(download->con, "GET");

	snprintf(buf, sizeof(buf), "%s \"%s\" %lu",
	         OPN_ALIAS, download->url->file,
	         download->chunk->start + download->chunk->transmit);

	tcp_writestr(download->con, buf);

	input_add(fd, download, INPUT_READ, on_download_read_filesize,
	          TIMEOUT_DEF);
}

static void on_download_connect(int fd, input_id input, void *udata)
{
	OpnDownload *download = (OpnDownload *) udata;
	char c;

	input_remove(input);

	if (tcp_recv(download->con, (uint8_t *) &c, 1) <= 0 || c != '1') {
		opn_download_free(download);
		return;
	}

	input_add(fd, download, INPUT_WRITE, on_download_write,
	          TIMEOUT_DEF);
}

void opn_download_start(OpnDownload *download)
{
	assert(download);
	
	if (!(download->con = tcp_open(download->url->client.ip,
	                               download->url->client.port, FALSE)))
		return;
	
	input_add(download->con->fd, download, INPUT_READ,
	          on_download_connect, TIMEOUT_DEF);
}

