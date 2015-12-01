AM_MAKEFLAGS = --no-print-directory

include_HEADERS =
modules_sources =
modules_ldadd =
modules_cflags =
INCLUDES =

AM_CFLAGS = $(WARNING_CFLAGS) $(BUILD_CFLAGS) @GLIB_CFLAGS@
AM_LDFLAGS = $(BUILD_LDFLAGS)

libexec_PROGRAMS = src/knotd tools/ktool unit/ktest

include Makefile.modules

src_knotd_SOURCES = src/main.c \
			src/manager.h src/manager.c \
			src/proto.h src/node.h \
			include/log.h \
			$(modules_sources)

src_knotd_LDADD = @GLIB_LIBS@ $(modules_ldadd)
src_knotd_LDFLAGS = $(AM_LDFLAGS)
src_knotd_CFLAGS = $(AM_CFLAGS) $(modules_cflags)

tools_ktool_SOURCES = tools/ktool.c
tools_ktool_LDADD = @GLIB_LIBS@
tools_ktool_LDFLAGS = $(AM_LDFLAGS)
tools_ktool_CFLAGS = $(AM_CFLAGS)

unit_ktest_SOURCES = unit/ktest.c
unit_ktest_LDADD = @GLIB_LIBS@
unit_ktest_LDFLAGS = $(AM_LDFLAGS)
unit_ktest_CFLAGS = $(AM_CFLAGS) @GLIB_CFLAGS@

DISTCLEANFILES =

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh

clean-local:
	$(RM) -r src/knotd tools/ktool unit/ktest
