/* giFT OpenNap
 *
 * $Id: opn_hash.h,v 1.3 2003/08/14 20:19:51 tsauerbeck Exp $
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

#ifndef __OPN_HASH_H
#define __OPN_HASH_H

#define OPN_HASH "MD5_300K"
#define OPN_HASH_LEN 32

uint8_t *opn_hash(const char *file, size_t *len);
char *opn_hash_human(uint8_t *hash, size_t len);

BOOL opn_hash_is_valid(char *hash);

#endif

