dnl $Id: configure.ac,v 1.6 2003/08/18 09:29:14 tsauerbeck Exp $

AC_PREREQ(2.53)

AC_INIT(giFT-OpenNap, 0.0.1, gift-opennap-devel@lists.berlios.de, giFT-OpenNap)
AC_CONFIG_SRCDIR([src/opn_opennap.c])

AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

AH_TEMPLATE([OPENNAP_DEBUG], [Define to 1 if you want debugging output])
AH_VERBATIM([_GNU_SOURCE], [/* Enable GNU extensions on systems that have them. */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
])

AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL
AC_HEADER_STDC
AC_C_BIGENDIAN
AM_DISABLE_STATIC
AC_PROG_LIBTOOL
 
AC_ARG_ENABLE(debug,
		[  --enable-debug          debug build (default: no)], [
			AC_DEFINE(OPENNAP_DEBUG)
			CFLAGS=`echo "$CFLAGS -g -Wall -Werror" | sed s/" -s"//`
		])

GIFT_PLUGIN_PREFIX
GIFT_PLUGIN_PKGCONFIG(GIFT_OPENNAP, 0.11.3, 0.12.0)

AC_CHECK_FUNCS(strcasestr)

GIFT_PLUGIN_INSTALL_PATH

AC_CONFIG_FILES([
Makefile
data/Makefile
m4/Makefile
src/Makefile
])

AC_OUTPUT

