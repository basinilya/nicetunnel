AC_PREREQ(2.63)
AC_INIT(nicetunnel, 0.0.1)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS(config.h)

dnl We don't call AC_CANONICAL_TARGET to avoid enabling:
dnl   program_transform_name = s&^&x86_64-w64-mingw32-&
AC_CANONICAL_BUILD
AC_CANONICAL_HOST

dnl -Wno-portability 
AM_INIT_AUTOMAKE([1.11 parallel-tests tar-ustar])

dnl define missing macro as noop for automake 1.11
AC_DEFUN([AM_EXTRA_RECURSIVE_TARGETS], [])

dnl # useful for gdb when libtool creates only wrapper scripts
dnl AM_EXTRA_RECURSIVE_TARGETS([
dnl   all-prelink
dnl   ])

LT_INIT([disable-static])
AC_PREFIX_DEFAULT("/usr")
# missing in automake 1.11
AC_SUBST(AM_DEFAULT_VERBOSITY)
AC_PROG_CC

dnl AX_PTHREAD
dnl LIBS="$PTHREAD_LIBS $LIBS"
dnl CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
dnl CC="$PTHREAD_CC"

dnl # for g_tree_*
PKG_CHECK_MODULES([GLIB], [glib-2.0 gthread-2.0 gio-2.0 nice])
LIBS="$LIBS $GLIB_LIBS"
CPPFLAGS="$CPPFLAGS $GLIB_CFLAGS"

dnl AC_MSG_CHECKING( whether ANSI or K&R style C)
dnl AC_TRY_COMPILE([ ], [void *p; p = "test";], [
dnl AC_MSG_RESULT(ANSI)
dnl AC_DEFINE( __USE_ANSI_C__, 1, [use ANSI or K&R style C?])
dnl ], [
dnl AC_MSG_RESULT(K&R)
dnl ])

dnl AC_C_INLINE
dnl AC_TYPE_SIZE_T
dnl AC_C_CONST

dnl #VPATH build?
dnl AM_CONDITIONAL([VPATHBUILD], [test "x$srcdir" != x.])

case $host_os in
 *mingw32*|*mingw64*|*msys*)
    AC_MSG_NOTICE([Applying feature macros for MinGW/Windows build])
    have_win=yes
    AC_CHECK_TOOL([WINDRES], [windres], [])
    ;;
esac

AM_CONDITIONAL(NICETUNNEL_WIN32,  [ test x"$have_win" = x"yes" ])

AC_CONFIG_FILES(Makefile
  src/Makefile
  test/Makefile
  )
AC_OUTPUT
