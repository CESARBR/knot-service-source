AM_MAKEFLAGS = --no-print-directory

modules_sources =
modules_ldadd =
modules_cflags =

AM_CFLAGS = $(WARNING_CFLAGS) $(BUILD_CFLAGS)
AM_LDFLAGS = $(BUILD_LDFLAGS)

bin_PROGRAMS = src/knotd inetbr/inetbrd
noinst_PROGRAMS = tools/ktool unit/ktest unit/inettest

dbusdir = @DBUS_CONFDIR@/dbus-1/system.d
dbus_DATA = src/knot.conf

knotconfigdir = @KNOTCONFIGDIR@
knotconfig_DATA = src/knotd.conf

include Makefile.modules

src_knotd_SOURCES = src/main.c \
			src/storage.c src/storage.h \
			src/settings.c src/settings.h \
			src/manager.h src/manager.c \
			src/msg.c src/msg.h \
			src/node.c src/node.h \
			src/dbus.c src/dbus.h \
			src/device.c src/device.h \
			src/proxy.c src/proxy.h \
			src/parser.c src/parser.h \
			src/mq.c src/mq.h \
			src/cloud.c src/cloud.h \
			$(modules_sources)

src_knotd_LDADD = $(modules_ldadd) @ELL_LIBS@ @RABBITMQ_LIBS@ @KNOTPROTO_LIBS@ @KNOTHAL_LIBS@ @JSON_LIBS@ @KNOTCLOUDSDK_LIBS@ -lm
src_knotd_LDFLAGS = $(AM_LDFLAGS)
src_knotd_CFLAGS = $(AM_CFLAGS) $(modules_cflags) @ELL_CFLAGS@ @RABBITMQ_CFLAGS@ @KNOTPROTO_CFLAGS@ @KNOTHAL_CFLAGS@ @JSON_CFLAGS@ @KNOTCLOUDSDK_CFLAGS@

inetbr_inetbrd_SOURCES = inetbr/main.c \
			inetbr/settings.c inetbr/settings.h \
			inetbr/manager.c inetbr/manager.h \
			inetbr/udp4.c inetbr/udp4.h \
			inetbr/tcp4.c inetbr/tcp4.h \
			inetbr/udp6.c inetbr/udp6.h unix.h \
			inetbr/tcp6.c inetbr/tcp6.h

inetbr_inetbrd_LDADD = @ELL_LIBS@  @KNOTHAL_LIBS@ $(modules_ldadd) -lm
inetbr_inetbrd_LDFLAGS = $(AM_LDFLAGS)
inetbr_inetbrd_CFLAGS = $(AM_CFLAGS) $(modules_cflags) @ELL_CFLAGS@  @KNOTHAL_CFLAGS@

tools_ktool_SOURCES = tools/ktool.c
tools_ktool_LDADD = @ELL_LIBS@ @JSON_LIBS@ @KNOTPROTO_LIBS@ @KNOTHAL_LIBS@
tools_ktool_LDFLAGS = $(AM_LDFLAGS)
tools_ktool_CFLAGS = $(AM_CFLAGS) @ELL_CFLAGS@ @JSON_CFLAGS@ @KNOTPROTO_CFLAGS@ @KNOTHAL_CFLAGS@

unit_ktest_SOURCES = unit/ktest.c

unit_ktest_LDADD = @ELL_LIBS@ @KNOTPROTO_LIBS@ @KNOTHAL_LIBS@
unit_ktest_LDFLAGS = $(AM_LDFLAGS)
unit_ktest_CFLAGS = $(AM_CFLAGS) @ELL_CFLAGS@ @KNOTPROTO_CFLAGS@ @KNOTHAL_CFLAGS@

unit_inettest_SOURCES = unit/inettest.c

unit_inettest_LDADD = @ELL_LIBS@ @KNOTPROTO_LIBS@ @KNOTHAL_LIBS@
unit_inettest_LDFLAGS = $(AM_LDFLAGS)
unit_inettest_CFLAGS = $(AM_CFLAGS) @ELL_CFLAGS@ @KNOTPROTO_CFLAGS@ @KNOTHAL_CFLAGS@

DISTCLEANFILES =

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh

clean-local:
	$(RM) -r src/knotd inetbr/inetbrd tools/ktool unit/ktest
