/* giFT OpenNap
 *
 * $Id: opn_share.h,v 1.5 2003/08/07 20:17:37 tsauerbeck Exp $
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

#ifndef __OPN_SHARE_H
#define __OPN_SHARE_H

void opennap_share_sync(Protocol *p, BOOL begin);
BOOL opennap_share_add(Protocol *p, Share *file, void *udata);
BOOL opennap_share_remove(Protocol *p, Share *file, void *udata);
void opennap_share_show(Protocol *p);
void opennap_share_hide(Protocol *p);

BOOL opn_share_syncing();
BOOL opn_share_enabled();
void opn_share_refresh(OpnSession *session);

#endif

