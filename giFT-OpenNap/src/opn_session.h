/* giFT OpenNap
 *
 * $Id: opn_session.h,v 1.6 2003/08/05 07:51:37 tsauerbeck Exp $
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

#ifndef __OPN_SESSION_H
#define __OPN_SESSION_H

typedef struct {
	uint32_t users; /**< Number of users online */
	uint32_t files; /**< Number of files shared */
	double size; /**< Amount of shares (GB) */
} OpnStats;

typedef struct {
	TCPC *con; /**< Connection */
	OpnNode *node; /**< Pointer to the node this sessions is based on */
	OpnStats stats; /** Stats */
} OpnSession;

OpnSession *opn_session_new();
void opn_session_free(OpnSession *session);
OpnSession *opn_session_find(OpnUrl *url);
int opn_session_connect(OpnSession *session, OpnNode *node);
void opn_sessions_free(List *sessions);

#endif

