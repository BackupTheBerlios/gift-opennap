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

	free(upload);
}

#if 0
static void on_upload_write(int fd, input_id input, void *udata)
{
	OpnUpload *upload = (OpnUpload *) udata;
	uint8_t buf[RW_BUFFER];
	size_t size;

	/*
	 * if (!(size = upload_throttle(transfer->chunk, sizeof(buf))))
	 * return;
	 */

}

static void opn_upload_start(char *user, Share *share, uint32_t offset,
                             TCPC *con)
{
	OpnUpload *upload;
	Transfer *transfer;

	if (!(upload = opn_upload_new()))
		return;

	upload->transfer = upload_new(opn_proto, user, OPENNAP_HASH, NULL,
	                              file_basename(share->path),
	                              share->path, (off_t) offset,
	                              (off_t) share->size - offset, TRUE, TRUE);

	upload->con = con;
	
	input_add(con->fd, upload, INPUT_WRITE,
	          on_upload_write, TIMEOUT_DEF);
}

static void on_upload_read(int fd, input_id input, void *udata)
{
	TCPC *con = (TCPC *) udata;
	Share *share;
	uint8_t buf[PATH_MAX + 256];
	int bytes;
	uint32_t offset;
	char file[PATH_MAX + 1], user[64];
	
	if (net_sock_error(fd)) {
		tcp_close(con);
		return;
	}

	if (bytes = tcp_recv(con, buf, sizeof(buf) - 1) <= 0)
		return;

	buf[bytes] = 0;

	if (!strcmp(buf, "GET"))
		return;

	input_remove(input);

	sscanf(buf, "%64s \"%PATH_MAXs\" %lu", user, file, &offset);
	
	if (!(share = share_find_file(file))) {
		tcp_close(con);
		return;
	}

	opn_download_start(user, share, offset, con);
}

void opn_upload_connect(int fd, input_id input, void *udata)
{
	TCPC *con;
	
	if (!(con = tcp_accept(OPENNAP->con, FALSE)))
		return;
	
	tcp_send(con, "1", 1);

	input_add(fd, con, INPUT_READ, on_upload_read, TIMEOUT_DEF);
}
#endif

