/* giFT OpenNap
 *
 * $Id: opn_download.c,v 1.20 2003/08/14 20:57:02 tsauerbeck Exp $
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
	List *l;

	assert(cb);
	assert(udata);

	for (l = OPENNAP->downloads; l; l = l->next)
		if ((*cb)(l->data, udata))
			return l->data;

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

	tcp_close(dl->con);
	timer_remove(dl->retry_timer);
	opn_url_free(dl->url);

	free(dl);
}

static void on_download_read_data(int fd, input_id input, OpnDownload *dl)
{
	uint8_t buf[RW_BUFFER];
	size_t size;
	int recvd;

	if (fd == -1 || !input || net_sock_error(fd)) {
		opn_download_free(dl);
		return;
	}

	/* Ask giFT for the max size we should read.  If this returns 0, the
	 * download was suspended.
	 */
	if (!(size = download_throttle(dl->chunk, sizeof(buf))))
		return;

	if ((recvd = tcp_recv(dl->con, buf, size)) <= 0) {
		OPN->source_status(OPN, dl->chunk->source,
		                   SOURCE_CANCELLED, "Error");
		opn_download_free(dl);
		return;
	}

	OPN->chunk_write(OPN, dl->chunk->transfer, dl->chunk,
	                 dl->chunk->source, buf, recvd);
}

static void on_download_read_filesize(int fd, input_id input, OpnDownload *dl)
{
	uint8_t buf[128];
	int recvd, i;
	uint32_t size = 0;

	if (fd == -1 || !input || net_sock_error(fd)) {
		opn_download_free(dl);
		return;
	}

	/* get the filesize */
	if ((recvd = tcp_peek(dl->con, buf, sizeof(buf))) <= 0) {
		opn_download_free(dl);
		return;
	}

	buf[recvd] = 0;

	for (i = 0; isdigit(buf[i]) && size < dl->url->size; i++)
		size = (size * 10) + (buf[i] - '0');

	tcp_recv(dl->con, buf, i);

	input_remove(input);
	input_add(fd, dl, INPUT_READ,
	          (InputCallback) on_download_read_data, 5 * SECONDS);
}

static void on_download_write(int fd, input_id input, OpnDownload *dl)
{
	char buf[PATH_MAX + 256];

	if (fd == -1 || !input || net_sock_error(fd)) {
		opn_download_free(dl);
		return;
	}

	tcp_writestr(dl->con, "GET");

	snprintf(buf, sizeof(buf), "%s \"%s\" %lu",
	         OPN_ALIAS, dl->url->file,
	         dl->chunk->start + dl->chunk->transmit);

	tcp_writestr(dl->con, buf);

	input_remove(input);
	input_add(fd, dl, INPUT_READ,
	          (InputCallback) on_download_read_filesize, 30 * SECONDS);
}

static void on_download_connect(int fd, input_id input, OpnDownload *dl)
{
	char c;

	if (fd == -1 || !input || net_sock_error(fd)
	   || tcp_recv(dl->con, (uint8_t *) &c, 1) <= 0 || c != '1') {
		opn_download_free(dl);
		return;
	}

	input_remove(input);
	input_add(fd, dl, INPUT_WRITE, (InputCallback) on_download_write,
	          5 * SECONDS);
}

void opn_download_start(OpnDownload *download)
{
	assert(download);
	
	if (!(download->con = tcp_open(download->url->client.ip,
	                               download->url->client.port, FALSE)))
		return;
	
	input_add(download->con->fd, download, INPUT_READ,
	          (InputCallback) on_download_connect, 30 * SECONDS);
}

