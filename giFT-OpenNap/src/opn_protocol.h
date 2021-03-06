/* giFT OpenNap
 *
 * $Id: opn_protocol.h,v 1.9 2003/08/08 11:01:41 tsauerbeck Exp $
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

#ifndef __OPN_PROTOCOL_H
#define __OPN_PROTOCOL_H

struct _OpnPacket;

typedef enum {
	OPN_CMD_NONE = -1,
	OPN_CMD_LOGIN_ERROR = 0,
	OPN_CMD_LOGIN = 2,
	OPN_CMD_LOGIN_ACK = 3,
	OPN_CMD_SHARE_ADD = 100,
	OPN_CMD_SHARE_REMOVE = 102,
	OPN_CMD_SHARE_REMOVE_ALL = 110,
	OPN_CMD_SEARCH = 200,
	OPN_CMD_SEARCH_RESULT = 201,
	OPN_CMD_SEARCH_FINISHED = 202,
	OPN_CMD_DOWNLOAD_REQUEST = 203,
	OPN_CMD_DOWNLOAD_ACK = 204,
	OPN_CMD_DOWNLOAD_ERROR = 206,
	OPN_CMD_STATS = 214,
	OPN_CMD_DOWNLOAD_START = 218,
	OPN_CMD_DOWNLOAD_FINISH = 219,
	OPN_CMD_UPLOAD_START = 220,
	OPN_CMD_UPLOAD_FINISH = 221,
	OPN_CMD_CLIENT_DISCONNECT = 316,
	OPN_CMD_ERROR = 404,
	OPN_CMD_UPLOAD_REQUEST = 607,
	OPN_CMD_UPLOAD_ACK = 608,
	OPN_CMD_QUEUE_LIMIT_CL = 619,
	OPN_CMD_QUEUE_LIMIT_SV = 620,
	OPN_CMD_PING = 751,
	OPN_CMD_PONG = 752,
	OPN_CMD_NUM
} OpnCommand;

#define OPN_HANDLER_FUNC(func) opn_proto_handler_##func
#define OPN_HANDLER_PARAMS struct _OpnPacket *packet, OpnSession *session
#define OPN_HANDLER(func) void OPN_HANDLER_FUNC(func)(OPN_HANDLER_PARAMS)

typedef void (*HandlerFn)(OPN_HANDLER_PARAMS);

typedef struct {
	OpnCommand cmd;
	HandlerFn func;
} Handler;

BOOL opn_protocol_handle(struct _OpnPacket *packet, OpnSession *session);

#endif

