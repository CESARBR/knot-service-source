AC_PREREQ(2.60)
AC_INIT(knot, 0.01)

AM_INIT_AUTOMAKE([silent-rules subdir-objects])

AC_CONFIG_HEADERS(config.h)

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

PKG_PROG_PKG_CONFIG

COMPILER_WARNING_CFLAGS
COMPILER_BUILD_CFLAGS

AC_LANG_C

AC_PROG_CC
AC_PROG_CC_PIE

m4_define([_LT_AC_TAGCONFIG], [])
m4_ifdef([AC_LIBTOOL_TAGS], [AC_LIBTOOL_TAGS([])])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.28, dummy=no,
				AC_MSG_ERROR(required glib >= 2.28))
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

AC_ARG_WITH([radioheaddir], AC_HELP_STRING([--with-radioheaddir=DIR],
				[path to Radio Head directory]),
					[path_radioheaddir=${withval}])
if (test "${path_radioheaddir}"); then
	AC_SUBST(RADIOHEADDIR, [${path_radioheaddir}])
	AC_DEFINE([HAVE_RADIOHEAD],[1],[Enable radio head])
fi

AM_CONDITIONAL(RADIOHEAD, test "${path_radioheaddir}")

AC_OUTPUT(Makefile)
