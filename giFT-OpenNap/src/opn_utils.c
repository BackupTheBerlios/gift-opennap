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
#include <ctype.h>

char *opn_unix_path(char *path)
{
	char *unix_path;
	char *ptr;

	assert(path);

	if (!(unix_path = strdup(path)))
		return NULL;

	if (path[1] == ':') {
		/* C:\dir\file -> /C\dir\file */
		unix_path[0] = '/';
		unix_path[1] = path[0];
	}

	for (ptr = unix_path; *ptr; ptr++)
		if (*ptr == '\\')
			*ptr = '/';

	return unix_path;
}

char **opn_string_split(char *str, char *delim)
{
	List *list = NULL, *l;
	char *tmp, *ptr, *token, **retval;
	int i = 1;

	if (!str || !delim)
		return NULL;

	ptr = tmp = strdup(str);

	/* Find the tokens and add them to the list */
	while ((token = string_sep(&tmp, delim))) {
		list = list_prepend(list, token);
		i++;
	}
	
	/* Now copy the tokens into the array */
	if (!(retval = malloc(sizeof(char *) * i)))
		return NULL;

	retval[--i] = NULL;
	
	for (l = list; l; l = l->next)
		retval[--i] = strdup(l->data);

	list_free(list);
	free(ptr);

	return retval;
}

/**
 * Frees a string array built by \em str_split
 *
 * @param str String array to free
 */
void opn_string_freev(char **str)
{
	char **ptr;

	if (!str)
		return;

	for (ptr = str; *ptr; ptr++)
		free(*ptr);

	free(str);
}

/* stolen from OpenFT ;) */
static int oct_value_from_hex(char hex_char)
{
	if (!isxdigit(hex_char))
		return 0;

	if (hex_char >= '0' && hex_char <= '9')
		return (hex_char - '0');

	hex_char = toupper(hex_char);

	return ((hex_char - 'A') + 10);
}

/* stolen from OpenFT ;) */
char *opn_url_decode(char *encoded)
{
	char *decoded, *ptr;
	int oct_val;

	assert(encoded);

	/* make sure we are using our own memory here ... */
	ptr = strdup(encoded);

	/* save the head */
	decoded = ptr;

	/* convert '+' -> ' ' and %2x -> char value */
	while (*ptr) {
		switch (*ptr) {
			case '+':
				*ptr = ' ';
				break;
			case '%':
				if (isxdigit (ptr[1]) && isxdigit (ptr[2])) {
					oct_val = oct_value_from_hex(ptr[1]) * 16;
					oct_val += oct_value_from_hex(ptr[2]);

					*ptr = (char) oct_val;
					string_move(ptr + 1, ptr + 3);
				}

				break;
			default:
				break;
		}

		ptr++;
	}

	return decoded;
}

/* stolen from OpenFT ;) */
static char *url_encode_char(char *stream, uint8_t c)
{
	*stream++ = '%';

	sprintf(stream, "%02x", (uint32_t) c);

	return stream + 2;
}

/* stolen from OpenFT ;) */
char *opn_url_encode(char *decoded)
{
	char *encoded, *ptr;

	assert(decoded);

	/* allocate a large enough buffer for all cases */
	encoded = ptr = malloc((strlen(decoded) * 3) + 1);

	while (*decoded) {
		/* we can rule out non-printable and whitespace characters */
		if (!isprint(*decoded) || isspace(*decoded))
			ptr = url_encode_char(ptr, *decoded);
		else
			/* check for anything special */
			switch (*decoded) {
				case '?':
				case '@':
				case '+':
				case '%':
				case '&':
				case ':':
				case '=':
				case '(':
				case ')':
				case '[':
				case ']':
				case '\"':
				case '\\':
				case '\'':
						ptr = url_encode_char(ptr, *decoded);
						break;
				default: /* regular character, just copy */
						*ptr++ = *decoded;
						break;
			}

		decoded++;
	}

	*ptr = 0;

	return encoded;
}

