/* giFT OpenNap
 *
 * $Id: opn_upload.h,v 1.4 2003/08/07 20:17:37 tsauerbeck Exp $
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

#ifndef __OPN_UPLOAD_H
#define __OPN_UPLOAD_H

typedef struct {
	FILE *fp;
	TCPC *con;
	Transfer *transfer;
	Chunk *chunk;
} OpnUpload;

OpnUpload *opn_upload_new();
void opn_upload_free(OpnUpload *upload);

void opennap_upload_stop(Protocol *p, Transfer *t, Chunk *c, Source *s);
	
void opn_upload_connect(int fd, input_id input, void *udata);

#endif

