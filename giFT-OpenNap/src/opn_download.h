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

#ifndef __OPN_DOWNLOAD_H
#define __OPN_DOWNLOAD_H

typedef struct {
	OpnUrl *url;
	TCPC *con;
	Chunk *chunk;
} OpnDownload;

typedef BOOL (*OpnDownloadFindCb)(OpnDownload *dl, void *udata);

BOOL opennap_download_start(Protocol *p, Transfer *transfer,
                            Chunk *chunk, Source *source);
void opennap_download_stop(Protocol *p, Transfer *transfer,
                           Chunk *chunk, Source *source, int complete);
int opennap_source_remove(Protocol *p, Transfer *transfer,
                          Source *source);
BOOL opennap_chunk_suspend(Protocol *p, Transfer *transfer,
                           Chunk *chunk, Source *source);
BOOL opennap_chunk_resume(Protocol *p, Transfer *transfer,
                          Chunk *chunk, Source *source);

OpnDownload *opn_download_new();

OpnDownload *opn_download_find_by_chunk(Chunk *c);
OpnDownload *opn_download_find_by_client(OpnUrl *url);
OpnDownload *opn_download_find_by_user(OpnUrl *url);

void opn_download_free(OpnDownload *download);
void opn_download_start(OpnDownload *download);

#endif

