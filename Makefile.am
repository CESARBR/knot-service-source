AM_MAKEFLAGS = --no-print-directory

include_HEADERS =
modules_sources =
modules_ldadd =
modules_cflags =

AM_CFLAGS = $(WARNING_CFLAGS) $(BUILD_CFLAGS) @GLIB_CFLAGS@
AM_LDFLAGS = $(BUILD_LDFLAGS)

bin_PROGRAMS = src/knotd inetbr/inetbrd
noinst_PROGRAMS = tools/ktool unit/ktest unit/inettest

include Makefile.modules

noinst_LTLIBRARIES = ell/libell-internal.la

ell_sources = ell/ell.h ell/private.h ell/missing.h \
			ell/util.h ell/util.c \
			ell/test.h ell/test.c \
			ell/queue.h ell/queue.c \
			ell/hashmap.h ell/hashmap.c \
			ell/ringbuf.h ell/ringbuf.c \
			ell/string.h ell/string.c \
			ell/settings.h ell/settings.c \
			ell/main.h ell/main.c \
			ell/idle.h ell/idle.c \
			ell/signal.h ell/signal.c \
			ell/timeout.h ell/timeout.c \
			ell/io.h ell/io.c \
			ell/log.h ell/log.c \
			ell/plugin.h ell/plugin.c \
			ell/checksum.h ell/checksum.c \
			ell/netlink-private.h \
			ell/netlink.h ell/netlink.c \
			ell/genl-private.h \
			ell/genl.h ell/genl.c \
			ell/dbus-private.h \
			ell/dbus.h ell/dbus.c \
			ell/dbus-util.c \
			ell/dbus-message.c \
			ell/dbus-service.h ell/dbus-service.c \
			ell/dbus-filter.c \
			ell/dbus-name-cache.c \
			ell/gvariant-private.h \
			ell/gvariant-util.c \
			ell/siphash-private.h \
			ell/siphash.c \
			ell/hwdb.h ell/hwdb.c \
			ell/cipher.h ell/cipher.c \
			ell/random.h ell/random.c \
			ell/uintset.h ell/uintset.c \
			ell/base64.h ell/base64.c \
			ell/pem.h ell/pem.c \
			ell/tls-private.h \
			ell/tls.h ell/tls.c \
			ell/tls-record.c \
			ell/uuid.h ell/uuid.c \
			ell/key.h ell/key.c \
			ell/asn1-private.h \
			ell/pkcs5.h ell/pkcs5.c \
			ell/pkcs5-private.h \
			ell/file.h ell/file.c \
			ell/dbus-client.h ell/dbus-client.c

ell_libell_internal_la_SOURCES = $(ell_sources)

src_knotd_SOURCES = src/main.c \
			src/filewatch.c src/filewatch.h \
			src/settings.c src/settings.h \
			src/session.c src/session.h \
			src/manager.h src/manager.c \
			src/msg.c src/msg.h \
			src/proto.c src/proto.h \
			src/node.c src/node.h \
			$(modules_sources)

src_knotd_LDADD = @GLIB_LIBS@ $(modules_ldadd) ell/libell-internal.la -lm
src_knotd_LDFLAGS = $(AM_LDFLAGS)
src_knotd_CFLAGS = $(AM_CFLAGS) $(modules_cflags)

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

BUILT_SOURCES = ell/internal

ell/internal: Makefile
	$(AM_V_at)$(MKDIR_P) ell
	$(AM_V_GEN)for f in $(ell_sources) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t ell -f $(abs_srcdir)/../ell.git/$$f ; \
		fi \
	done > $@
	$(AM_V_at)$(MKDIR_P) linux
	$(AM_V_GEN)for f in $(ell_linux_headers) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t linux -f $(abs_srcdir)/../ell.git/$$f ; \
		fi \
	done > $@

DISTCLEANFILES =

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh

maintainer-clean-local:
	$(RM) -rf ell

clean-local:
	$(RM) -r src/knotd inetbr/inetbrd tools/ktool unit/ktest
