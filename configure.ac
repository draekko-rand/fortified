dnl Process this file with autoconf to produce a configure script.

dnl init autoconf
AC_INIT([Fortified], [1.1.0], [draekko.software+fortified@gmail.com])

AC_PREREQ(2.50)
AC_CONFIG_SRCDIR(src/fortified.c)
AC_CONFIG_AUX_DIR(.)
AC_PROG_INTLTOOL([0.49])

dnl init automake
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE

AC_ISC_POSIX
AC_PROG_CC
AM_PROG_CC_STDC
AC_HEADER_STDC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AM_PROG_LIBTOOL

AC_PATH_PROG(GCONFTOOL, gconftool-2, no)

if test x"$GCONFTOOL" = xno; then
  AC_MSG_ERROR([gconftool-2 executable not found in your path - should be installed with GConf2])
fi

LIBGNOME_REQUIRED=2.0.0
LIBGNOMEUI_REQUIRED=2.0.0
GTK_REQUIRED=2.4.0
GNOME_VFS_REQUIRED=2.6.0
LIBGLADE_REQUIRED=2.3.6

PKG_CHECK_MODULES(FORTIFIED,
                  libgnome-2.0 >= $LIBGNOME_REQUIRED
                  libgnomeui-2.0 >= $LIBGNOMEUI_REQUIRED
                  gtk+-2.0 >= $GTK_REQUIRED
                  gnome-vfs-2.0 >= $GNOME_VFS_REQUIRED
                  libglade-2.0 >= $LIBGLADE_REQUIRED)

AC_CHECK_LIB([X11], [XFlush], [],[
         echo "X11 library is required for this program"
         exit -1])

AC_SUBST(FORTIFIED_CFLAGS)
AC_SUBST(FORTIFIED_LIBS)

dnl i18n
ALL_LINGUAS="az ca cs da de el en_CA en_GB es fi fr ga hr hu it ja ko lv ml nb nl no pa pl pt pt_BR ro ru sk sq sr sr@Latn sv tr uk vi zh_CN zh_TW"
GETTEXT_PACKAGE=fortified
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE",[Useful for glib-gettextize])
AM_GLIB_GNU_GETTEXT

dnl Set PACKAGE_LOCALE_DIR in config.h.
if test "x${prefix}" = "xNONE"; then
  AC_DEFINE_UNQUOTED(PACKAGE_LOCALE_DIR, "${ac_default_prefix}/${DATADIRNAME}/locale", [Localization])
else
  AC_DEFINE_UNQUOTED(PACKAGE_LOCALE_DIR, "${prefix}/${DATADIRNAME}/locale", [Localization])
fi

ACLOCAL="$ACLOCAL $ACLOCAL_FLAGS"

AC_OUTPUT([
Makefile
src/Makefile
src/xpm/Makefile
po/Makefile.in
pixmaps/Makefile
scripts/Makefile
])

