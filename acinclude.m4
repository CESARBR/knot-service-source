AC_DEFUN([AC_PROG_CC_PIE], [
	AC_CACHE_CHECK([whether ${CC-cc} accepts -fPIE], ac_cv_prog_cc_pie, [
		echo 'void f(){}' > conftest.c
		if test -z "`${CC-cc} -fPIE -pie -c conftest.c 2>&1`"; then
			ac_cv_prog_cc_pie=yes
		else
			ac_cv_prog_cc_pie=no
		fi
		rm -rf conftest*
	])
])

AC_DEFUN([COMPILER_WARNING_CFLAGS], [
	warn_cflags=""
	if (test "$USE_MAINTAINER_MODE" = "yes"); then
		warn_cflags="$warn_cflags -Wall -Werror -Wextra"
		warn_cflags="$warn_cflags -Wno-unused-parameter"
		warn_cflags="$warn_cflags -Wno-missing-field-initializers"
		warn_cflags="$warn_cflags -Wdeclaration-after-statement"
		warn_cflags="$warn_cflags -Wmissing-declarations"
		warn_cflags="$warn_cflags -Wredundant-decls"
		warn_cflags="$warn_cflags -Wcast-align"
		warn_cflags="$warn_cflags -Wswitch-enum"
		warn_cflags="$warn_cflags -Wformat -Wformat-security"
		warn_cflags="$warn_cflags -DG_DISABLE_DEPRECATED"
	fi
	AC_SUBST([WARNING_CFLAGS], $warn_cflags)
])

AC_DEFUN([COMPILER_BUILD_CFLAGS], [
	build_cflags=""
	build_ldflags=""
	AC_ARG_ENABLE(optimization, AC_HELP_STRING([--disable-optimization],
			[disable code optimization]), [
		if (test "${enableval}" = "no"); then
			build_cflags="$build_cflags -O0"
		fi
	])
	AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
			[enable debugging information]), [
		if (test "${enableval}" = "yes"); then
			build_cflags="$build_cflags -g"
		fi
	])
	AC_ARG_ENABLE(pie, AC_HELP_STRING([--enable-pie],
			[enable position independent executables flag]), [
		if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_pie}" = "yes"); then
			build_cflags="$build_cflags -fPIC"
			build_ldflags="$build_ldflags -pie"
		fi
	])
	AC_SUBST([BUILD_CFLAGS], $build_cflags)
	AC_SUBST([BUILD_LDFLAGS], $build_ldflags)
])
