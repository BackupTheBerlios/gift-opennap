/* giFT OpenNap
 *
 * $Id: opn_utils.h,v 1.4 2003/08/05 07:51:37 tsauerbeck Exp $
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

#ifndef __OPN_UTILS_H
#define __OPN_UTILS_H

char *opn_unix_path(char *path);

char **opn_string_split(char *str, char *delim);
void opn_string_freev(char **str);

char *opn_url_encode(char *decoded);
char *opn_url_decode(char *encoded);

#ifdef HAVE_STRCASESTR
# define opn_strcasestr strcasestr
#else
char *opn_strcasestr(const char *haystack, const char *needle);
#endif

#endif

