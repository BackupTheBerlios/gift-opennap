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

OpnUrl *opn_url_new()
{
	OpnUrl *url;

	if (!(url = malloc(sizeof(OpnUrl))))
		return NULL;

	memset(url, 0, sizeof(OpnUrl));

	return url;
}

void opn_url_free(OpnUrl *url)
{
	if (!url)
		return;

	free(url->user);
	free(url->file);
	free(url->serialized);
	free(url);
}

void opn_url_set_client(OpnUrl *url, char *user, in_addr_t ip,
                        in_port_t port)
{
	assert(url);

	url->client.ip = ip;
	url->client.port = port;
	url->user = STRDUP(user);
}

void opn_url_set_server(OpnUrl *url, in_addr_t ip, in_port_t port)
{
	assert(url);

	url->server.ip = ip;
	url->server.port = port;
}

void opn_url_set_file(OpnUrl *url, char *file, uint32_t size)
{
	assert(url);

	url->size = size;
	url->file = STRDUP(file);
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
static char *url_decode(char *encoded)
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
static char *url_encode(char *decoded)
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

OpnUrl *opn_url_unserialize(char *data)
{
	OpnUrl *url;
	char *ptr, *ptr2, buf[PATH_MAX + 1];

	assert(data);

	if (!(url = opn_url_new()))
		return NULL;

	sscanf(data, "OpenNap://%u:%hu@%u:%hu",
			&url->client.ip, &url->client.port,
			&url->server.ip, &url->server.port);

	assert((ptr = strstr(data, "user=")));
	assert((ptr2 = strstr(data, "&size=")));
	ptr += 5;
	ptr2++;

	snprintf(buf, MIN(ptr2 - ptr, sizeof(buf)), "%s", ptr);
	url->user = url_decode(buf);
	
	url->size = strtoul(ptr2 + 5, NULL, 10);

	assert((ptr = strstr(data, "&file=")));
	ptr += 6;
	
	snprintf(buf, sizeof(buf), "%s", ptr);
	url->file = url_decode(buf);
	
	return url;
}

char *opn_url_serialize(OpnUrl *url)
{
	char *user, *file;
	
	assert(url);

	user = url_encode(url->user);
	file = url_encode(url->file);

	url->serialized = stringf_dup("OpenNap://%u:%hu@%u:%hu?user=%s"
	                              "&size=%u&file=%s",
	                              url->client.ip, url->client.port,
	                              url->server.ip, url->server.port,
	                              user, url->size, file);

	free(user);
	free(file);

	return url->serialized;
}

