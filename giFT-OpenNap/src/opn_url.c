/* giFT OpenNap
 *
 * $Id: opn_url.c,v 1.10 2003/08/08 14:35:07 tsauerbeck Exp $
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

#include "opn_opennap.h"
#include "opn_utils.h"

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


OpnUrl *opn_url_unserialize(char *data)
{
	OpnUrl *url;
	char *ptr, *ptr2, buf[PATH_MAX + 1];

	assert(data);

	if (!(url = opn_url_new()))
		return NULL;

	sscanf(data, "OpenNap://%*[^:]:%hu@%*[^:]:%hu",
	       &url->client.port, &url->server.port);

	/* get the client's ip */
	assert((ptr = strstr(data, "OpenNap://")));
	ptr += 10;
	assert((ptr2 = strchr(ptr, ':')));
	ptr2++;

	snprintf(buf, MIN(ptr2 - ptr, sizeof(buf)), "%s", ptr);
	url->client.ip = net_ip(buf);

	/* get the server's ip */
	assert((ptr = strchr(data, '@')));
	ptr++;;
	assert((ptr2 = strchr(ptr, ':')));
	ptr2++;

	snprintf(buf, MIN(ptr2 - ptr, sizeof(buf)), "%s", ptr);
	url->server.ip = net_ip(buf);

	/* get file data */
	assert((ptr = strstr(data, "user=")));
	assert((ptr2 = strstr(data, "&size=")));
	ptr += 5;
	ptr2++;

	snprintf(buf, MIN(ptr2 - ptr, sizeof(buf)), "%s", ptr);
	url->user = opn_url_decode(buf);
	
	url->size = strtoul(ptr2 + 5, NULL, 10);

	assert((ptr = strstr(data, "&file=")));
	ptr += 6;
	
	snprintf(buf, sizeof(buf), "%s", ptr);
	url->file = opn_url_decode(buf);
	
	return url;
}

char *opn_url_serialize(OpnUrl *url)
{
	char *user, *file, client[16];
	
	assert(url);

	user = opn_url_encode(url->user);
	file = opn_url_encode(url->file);
	snprintf(client, sizeof(client), "%s", net_ip_str(url->client.ip));

	url->serialized = stringf_dup("OpenNap://%s:%hu@%s:%hu?user=%s"
	                              "&size=%u&file=%s",
	                              client, url->client.port,
	                              net_ip_str(url->server.ip), url->server.port,
	                              user, url->size, file);

	free(user);
	free(file);

	return url->serialized;
}

