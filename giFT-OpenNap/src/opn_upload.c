/* giFT OpenNap
 *
 * $Id: opn_upload.c,v 1.15 2003/08/13 09:20:13 tsauerbeck Exp $
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
#include <libgift/proto/share.h>
#include "opn_upload.h"

OpnUpload *opn_upload_new()
{
	OpnUpload *upload;

	if (!(upload = malloc(sizeof(OpnUpload))))
		return NULL;

	memset(upload, 0, sizeof(OpnUpload));

	return upload;
}

void opn_upload_free(OpnUpload *upload)
{
	if (!upload)
		return;

	tcp_close(upload->con);

	if (upload->fp)
		fclose(upload->fp);

	free(upload);
}

void opennap_upload_stop(Protocol *p, Transfer *t, Chunk *c, Source *s)
{
	assert(c);
	
	opn_upload_free((OpnUpload *) c->udata);
	c->udata = NULL;
}

static void on_upload_write(int fd, input_id input, OpnUpload *upload)
{
	uint8_t buf[RW_BUFFER];
	size_t size, read, sent;

	if (fd == -1 || !input || net_sock_error(fd)) {
		opn_upload_free(upload);
		return;
	}

	if (!(size = upload_throttle(upload->chunk, sizeof(buf))))
		return;

	if (!(read = fread(buf, 1, size, upload->fp))
	   || (sent = tcp_write(upload->con, buf, read)) <= 0) {
		opn_upload_free(upload);
		return;
	}
	
	OPN->chunk_write(OPN, upload->transfer, upload->chunk,
	                 upload->chunk->source, buf, sent);
}

static void on_upload_send_filesize(int fd, input_id input,
                                    OpnUpload *upload)
{
	if (fd == -1 || !input || net_sock_error(fd)) {
		opn_upload_free(upload);
		return;
	}
	
	tcp_writestr(upload->con, stringf("%lu",
	             upload->chunk->stop - upload->chunk->start));
	
	input_remove(input);
	input_add(fd, upload, INPUT_WRITE,
	          (InputCallback) on_upload_write, 30 * SECONDS);
}

static void opn_upload_start(char *user, Share *share, uint32_t offset,
                             TCPC *con)
{
	OpnUpload *upload;
	char *path = file_host_path(share->path);

	if (!(upload = opn_upload_new()))
		return;
	
	upload->transfer = OPN->upload_start(OPN, &upload->chunk,
	                                     user, share, offset,
	                                     share->size);

	upload->chunk->udata = upload;
	upload->con = con;
	upload->fp = fopen(path, "rb");
	fseek(upload->fp, offset, SEEK_SET);
	
	input_add(con->fd, upload, INPUT_WRITE,
	          (InputCallback) on_upload_send_filesize, 30 * SECONDS);
	free(path);
}

static void on_upload_read(int fd, input_id input, TCPC *con)
{
	Share *share;
	char buf[PATH_MAX + 256], file[PATH_MAX + 1] = {0}, user[64] = {0};
	int bytes;
	uint32_t offset = 0;

	if (fd == -1 || !input || net_sock_error(fd)) {
		tcp_close(con);
		return;
	}
	
	if ((bytes = tcp_recv(con, (uint8_t *) buf, sizeof(buf) - 1)) <= 0)
		return;

	buf[bytes] = 0;

	if (!strcmp(buf, "GET"))
		return;

	input_remove(input);

	sscanf(&buf[3], stringf("%%%is \"%%%i[^\"]\" %%lu",
	       sizeof(user) - 1, PATH_MAX), user, file, &offset);
	
	if (!(share = OPN->share_lookup(OPN, SHARE_LOOKUP_HPATH, file))) {
		tcp_close(con);
		return;
	}

	switch (OPN->upload_auth(OPN, net_ip_str(con->host), share, NULL)) {
		case UPLOAD_AUTH_ALLOW:
			opn_upload_start(user, share, offset, con);
			return;
		case UPLOAD_AUTH_NOTSHARED:
			tcp_writestr(con, OPN_MSG_FILENOTSHARED);
			break;
		case UPLOAD_AUTH_STALE:
			tcp_writestr(con, OPN_MSG_INVALIDREQUEST);
		default:
			break;
	}

	tcp_close(con);
}

void opn_upload_connect(int fd, input_id input, TCPC *listen)
{
	TCPC *con;

	if (!(con = tcp_accept(listen, FALSE)))
		return;
	
	tcp_writestr(con, "1");

	input_add(con->fd, con, INPUT_READ, (InputCallback) on_upload_read,
	          30 * SECONDS);
}

