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

OpnNode *opn_node_new(in_addr_t ip, in_port_t port)
{
	OpnNode *node;

	if (!(node = malloc(sizeof(OpnNode))))
		return NULL;

	memset(node, 0, sizeof(OpnNode));

	node->ip = ip;
	node->port = port;
	
	return node;
}

void opn_node_free(OpnNode *node)
{
	free(node);
}

static int foreach_node_free(OpnNode *node, void *udata)
{
	opn_node_free(node);

	return 1;
}

static void nodelist_nodes_remove(OpnNodeList *nodelist)
{
	if (!nodelist || !nodelist->nodes)
		return;

	nodelist->nodes = list_foreach_remove(nodelist->nodes,
						(ListForeachFunc) foreach_node_free, NULL);
}

OpnNodeList *opn_nodelist_new()
{
	OpnNodeList *nodelist;

	if (!(nodelist = malloc(sizeof(OpnNodeList))))
		return NULL;

	memset(nodelist, 0, sizeof(OpnNodeList));

	return nodelist;
}

void opn_nodelist_free(OpnNodeList *nodelist)
{
	if (!nodelist)
		return;

	if (nodelist->con)
		tcp_close(nodelist->con);
	
	nodelist_nodes_remove(nodelist);
	free(nodelist);
}

void opn_nodelist_node_add(OpnNodeList *nodelist, OpnNode *node)
{
	if (!nodelist || !node)
		return;

	nodelist->nodes = list_prepend(nodelist->nodes, node);
}

void opn_nodelist_node_remove(OpnNodeList *nodelist, OpnNode *node)
{
	if (!nodelist || !node)
		return;

	nodelist->nodes = list_remove(nodelist->nodes, node);

	opn_node_free(node);
}

static void on_napigator_read(int fd, input_id input, void *udata)
{
	OpnNodeList *nodelist = (OpnNodeList *) udata;
	char buf[RW_BUFFER], ip[16], *ptr = buf;
	int bytes;
	in_port_t port;

	if (net_sock_error(fd)) {
		tcp_close(nodelist->con);
		nodelist->con = NULL;
		return;
	}
	
	if ((bytes = tcp_recv(nodelist->con, buf, sizeof(buf) - 1)) <= 0) {
		/* so now we got our serverlist... connect! */
		tcp_close(nodelist->con);
		nodelist->con = NULL;
		main_timer();
	}
	
	buf[bytes] = 0;

	if (!strncmp(ptr, "HTTP", 4)) {
		/* position the pointer behind the HTTP header */
		if (!(ptr = strstr(ptr, "\r\n\r\n")) || !(ptr += 4))
			return;
	}
	
	while (sscanf(ptr, "%15s %hu %*[^\n]", ip, &port) == 2) {
		if (port)
			opn_nodelist_node_add(nodelist, opn_node_new(net_ip(ip), port));
		
		if (!(ptr = strchr(ptr, '\n')) || !(++ptr) || !strlen(ptr))
			break;
	}
}

static void on_napigator_connect(int fd, input_id input, void *udata)
{
	OpnNodeList *nodelist = (OpnNodeList *) udata;
	char buf[] = "GET /servers.php?version=107&client=" OPENNAP_CLIENTNAME " HTTP/1.0\n\n";

	if (net_sock_error(fd)) {
		tcp_close(nodelist->con);
		nodelist->con = NULL;
		return;
	}
	
	input_remove(input);

	/* remove old nodes
	 * FIXME we could also use a Hashtable to store the nodes to make
	 * sure there are dupes
	 */
	nodelist_nodes_remove(nodelist);
	
	tcp_send(nodelist->con, buf, strlen(buf));

	input_add(fd, nodelist, INPUT_READ, on_napigator_read,
	          TIMEOUT_DEF);
}

static void nodelist_load_napigator(OpnNodeList *nodelist)
{
	assert(nodelist);

	/* only query napigator if we aren't running in local mode */
	if (OPENNAP_LOCAL_MODE)
		return;

	if (nodelist->con)
		tcp_close(nodelist->con);

	/* FIXME lookup the ip of www.napigator.com here ;) */
	if (!(nodelist->con = tcp_open(net_ip("216.116.119.192"), 80, FALSE)))
		return;
	
	input_add(nodelist->con->fd, nodelist, INPUT_WRITE,
	          on_napigator_connect, TIMEOUT_DEF);
}

static void nodelist_load_local(OpnNodeList *nodelist)
{
	FILE *fp;
	char *file = gift_conf_path("OpenNap/nodelist");
	char ip[16], *buf = NULL;
	in_port_t port;

	assert(nodelist);
	
	if (!(fp = fopen(file, "r")))
		return;

	while (file_read_line(fp, &buf))
		if (sscanf(buf, "%15[^:]:%hu", ip, &port) == 2)
			opn_nodelist_node_add(nodelist, opn_node_new(net_ip(ip), port));

	return;
}

void opn_nodelist_load(OpnNodeList *nodelist, BOOL local_mode)
{
	if (local_mode) {
		nodelist_load_local(nodelist);
		main_timer();
	} else
		nodelist_load_napigator(nodelist);
}



