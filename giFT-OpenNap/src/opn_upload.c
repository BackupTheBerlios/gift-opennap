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

	if (upload->con)
		tcp_close(upload->con);

	if (upload->fp)
		fclose(upload->fp);

	free(upload);
}

static void on_upload_write(int fd, input_id input, void *udata)
{
	OpnUpload *upload = (OpnUpload *) udata;
	uint8_t buf[RW_BUFFER];
	size_t size = sizeof(buf), read, sent;
	off_t remains;

#if 0
	if (!(size = upload_throttle(transfer->chunk, sizeof(buf))))
		return;
#endif

	remains = upload->chunk->stop -
	          (upload->chunk->start + upload->chunk->transmit);

	if (remains <= 0) {
		tcp_close(upload->con);
		OPN->chunk_write(OPN, upload->transfer, upload->chunk,
		                 upload->chunk->source, NULL, 0);
		return;
	}

	if (!(read = fread(buf, 1, size, upload->fp))) {
		tcp_close(upload->con);
		return;
	}

	sent = tcp_send(upload->con, buf, MIN(remains, read));

	if (sent <= 0) {
		tcp_close(upload->con);
		return;
	}

	OPN->chunk_write(OPN, upload->transfer, upload->chunk,
	                 upload->chunk->source, buf, sent);
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
	                                     share->size - offset);

	upload->con = con;
	upload->fp = fopen(path, "rb");
	
	input_add(con->fd, upload, INPUT_WRITE,
	          on_upload_write, TIMEOUT_DEF);
	free(path);
}

static void on_upload_read(int fd, input_id input, void *udata)
{
	TCPC *con = (TCPC *) udata;
	Share *share;
	uint8_t buf[PATH_MAX + 256];
	int bytes;
	uint32_t offset;
	char file[PATH_MAX + 1], user[64], fmt[32];
	
	if (net_sock_error(fd)) {
		tcp_close(con);
		return;
	}

	if ((bytes = tcp_recv(con, buf, sizeof(buf) - 1)) <= 0)
		return;

	buf[bytes] = 0;

	if (!strcmp(buf, "GET"))
		return;

	input_remove(input);

	snprintf(fmt, sizeof(fmt), "%%%is \"%%%is[^\"]\" %%lu",
	         sizeof(user) - 1, PATH_MAX);
	sscanf(buf, fmt, user, file, &offset);
	
	if (!(share = OPN->share_lookup(OPN, SHARE_LOOKUP_PATH, file))) {
		tcp_close(con);
		return;
	}

	switch (OPN->upload_auth(OPN, net_ip_str(con->host), share, NULL)) {
		case UPLOAD_AUTH_ALLOW:
			opn_upload_start(user, share, offset, con);
			break;
		case UPLOAD_AUTH_NOTSHARED:
			tcp_send(con, OPN_MSG_FILENOTSHARED,
			         strlen(OPN_MSG_FILENOTSHARED));
			tcp_close(con);
			break;
		case UPLOAD_AUTH_STALE:
			tcp_send(con, OPN_MSG_INVALIDREQUEST,
			         strlen(OPN_MSG_INVALIDREQUEST));
			tcp_close(con);
		case UPLOAD_AUTH_MAX:
		case UPLOAD_AUTH_MAX_PERUSER:
			/* ... */
			break;
		default:
			tcp_close(con);
			break;
	}
}

void opn_upload_connect(int fd, input_id input, void *udata)
{
	TCPC *con;
	
	if (!(con = tcp_accept(OPENNAP->con, FALSE)))
		return;
	
	tcp_send(con, "1", 1);

	input_add(fd, con, INPUT_READ, on_upload_read, TIMEOUT_DEF);
}

