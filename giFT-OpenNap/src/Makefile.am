# $Id: Makefile.am,v 1.6 2003/08/05 07:51:37 tsauerbeck Exp $

AM_CFLAGS = $(GIFT_OPENNAP_CFLAGS)

plugin_LTLIBRARIES = libOpenNap.la

libOpenNap_la_SOURCES = \
	opn_opennap.c opn_opennap.h \
	opn_packet.c opn_packet.h \
	opn_session.c opn_session.h \
	opn_node.c opn_node.h \
	opn_protocol.c opn_protocol.h \
	opn_protocol_handlers.c opn_protocol_handlers.h \
	opn_search.c opn_search.h \
	opn_download.c opn_download.h \
	opn_upload.c opn_upload.h \
	opn_url.c opn_url.h \
	opn_share.c opn_share.h \
	opn_hash.c opn_hash.h \
	opn_utils.c opn_utils.h

libOpenNap_la_LIBADD = $(GIFT_OPENNAP_LIBS)
libOpenNap_la_LDFLAGS = -module -avoid-version

