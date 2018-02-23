AM_MAKEFLAGS = --no-print-directory

modules_sources =
modules_ldadd =
modules_cflags =

AM_CFLAGS = $(WARNING_CFLAGS) $(BUILD_CFLAGS) @GLIB_CFLAGS@
AM_LDFLAGS = $(BUILD_LDFLAGS)

bin_PROGRAMS = src/knotd inetbr/inetbrd
noinst_PROGRAMS = tools/ktool unit/ktest unit/inettest

dbusdir = @DBUS_CONFDIR@/dbus-1/system.d
dbus_DATA = src/knot.conf

include Makefile.modules

src_knotd_SOURCES = src/main.c \
			src/settings.c src/settings.h \
			src/session.c src/session.h \
			src/manager.h src/manager.c \
			src/msg.c src/msg.h \
			src/proto.c src/proto.h \
			src/node.c src/node.h \
			src/dbus.c src/dbus.h \
			$(modules_sources)

src_knotd_LDADD = @GLIB_LIBS@ $(modules_ldadd) @ELL_LIBS@ @WEBSOCKETS_LIBS@ -lm
src_knotd_LDFLAGS = $(AM_LDFLAGS)
src_knotd_CFLAGS = $(AM_CFLAGS) $(modules_cflags) @ELL_CFLAGS@ @WEBSOCKETS_CFLAGS@

inetbr_inetbrd_SOURCES = inetbr/main.c \
			inetbr/manager.c inetbr/manager.h \
			inetbr/inet4.c inetbr/inet4.h \
			inetbr/inet6.c inetbr/inet6.h unix.h

inetbr_inetbrd_LDADD = @GLIB_LIBS@ $(modules_ldadd) -lm
inetbr_inetbrd_LDFLAGS = $(AM_LDFLAGS)
inetbr_inetbrd_CFLAGS = $(AM_CFLAGS) $(modules_cflags)

tools_ktool_SOURCES = tools/ktool.c
tools_ktool_LDADD = @GLIB_LIBS@ @JSON_LIBS@
tools_ktool_LDFLAGS = $(AM_LDFLAGS)
tools_ktool_CFLAGS = $(AM_CFLAGS) @JSON_CFLAGS@

unit_ktest_SOURCES = unit/ktest.c

unit_ktest_LDADD = @GLIB_LIBS@
unit_ktest_LDFLAGS = $(AM_LDFLAGS)
unit_ktest_CFLAGS = $(AM_CFLAGS) @GLIB_CFLAGS@

unit_inettest_SOURCES = unit/inettest.c

unit_inettest_LDADD = @GLIB_LIBS@
unit_inettest_LDFLAGS = $(AM_LDFLAGS)
unit_inettest_CFLAGS = $(AM_CFLAGS) @GLIB_CFLAGS@

DISTCLEANFILES =

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh

clean-local:
	$(RM) -r src/knotd inetbr/inetbrd tools/ktool unit/ktest
