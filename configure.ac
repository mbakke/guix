#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.68)
AC_INIT([GNU Guix], [0.12.0], [bug-guix@gnu.org], [guix],
  [http://www.gnu.org/software/guix/])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([1.12 gnu silent-rules subdir-objects \
 color-tests parallel-tests -Woverride -Wno-portability])

# Enable silent rules by default.
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR([guix.scm])
AC_CONFIG_MACRO_DIR([m4])

dnl For the C++ code.  This must be used early.
AC_USE_SYSTEM_EXTENSIONS

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.18.1])

GUIX_SYSTEM_TYPE
GUIX_ASSERT_SUPPORTED_SYSTEM

AC_ARG_WITH(store-dir,
  AC_HELP_STRING([--with-store-dir=PATH],
    [file name of the store (defaults to /gnu/store)]),
  [storedir="$withval"],
  [storedir="/gnu/store"])
AC_SUBST(storedir)

AC_ARG_WITH([bash-completion-dir],
  AC_HELP_STRING([--with-bash-completion-dir=DIR],
    [name of the Bash completion directory]),
  [bashcompletiondir="$withval"],
  [bashcompletiondir='${sysconfdir}/bash_completion.d'])
AC_SUBST([bashcompletiondir])

AC_ARG_WITH([zsh-completion-dir],
  AC_HELP_STRING([--with-zsh-completion-dir=DIR],
    [name of the Zsh completion directory]),
  [zshcompletiondir="$withval"],
  [zshcompletiondir='${datadir}/zsh/site-functions'])
AC_SUBST([zshcompletiondir])

dnl Better be verbose.
AC_MSG_CHECKING([for the store directory])
AC_MSG_RESULT([$storedir])

AC_ARG_ENABLE([daemon],
  [AS_HELP_STRING([--disable-daemon], [build the Nix daemon (C++)])],
  [guix_build_daemon="$enableval"],
  [guix_build_daemon="yes"])

# Prepare a version of $localstatedir & co. that does not contain references
# to shell variables.
guix_prefix="`eval echo $prefix | sed -e"s|NONE|/usr/local|g"`"
guix_localstatedir="`eval echo $localstatedir | sed -e "s|NONE|$guix_prefix|g"`"
guix_sysconfdir="`eval echo $sysconfdir | sed -e "s|NONE|$guix_prefix|g"`"
guix_sbindir="`eval echo $sbindir | sed -e "s|NONE|$guix_prefix|g"`"
AC_SUBST([guix_localstatedir])
AC_SUBST([guix_sysconfdir])
AC_SUBST([guix_sbindir])

GUIX_CHECK_FILE_NAME_LIMITS([can_run_tests])
AM_CONDITIONAL([CAN_RUN_TESTS], [test "x$can_run_tests" = "xyes"])

dnl We require pkg.m4 (from pkg-config) and guile.m4 (from Guile.)
dnl Make sure they are available.
m4_pattern_forbid([PKG_CHECK_MODULES])
m4_pattern_forbid([GUILE_MODULE_AVAILABLE])
m4_pattern_forbid([^GUILE_P$])

dnl Search for 'guile' and 'guild'.  Prefer 2.0 until the 2.2 upgrade is
dnl complete.  This macro defines 'GUILE_EFFECTIVE_VERSION'.
GUILE_PKG([2.0 2.2])
GUILE_PROGS
if test "x$GUILD" = "x"; then
   AC_MSG_ERROR(['guild' binary not found; please check your guile-2.x installation.])
fi

if test "x$GUILE_EFFECTIVE_VERSION" = "x2.0"; then
  PKG_CHECK_MODULES([GUILE], [guile-2.0 >= 2.0.7])
else
  AC_MSG_WARN([Guile $GUILE_EFFECTIVE_VERSION is not fully supported!])
fi

dnl Installation directory for .scm and .go files.
guilemoduledir="${datarootdir}/guile/site/$GUILE_EFFECTIVE_VERSION"
AC_SUBST([guilemoduledir])

dnl guile-json is used for the PyPI package importer
GUILE_MODULE_AVAILABLE([have_guile_json], [(json)])
AM_CONDITIONAL([HAVE_GUILE_JSON], [test "x$have_guile_json" = "xyes"])

dnl Make sure we have a full-fledged Guile.
GUIX_ASSERT_GUILE_FEATURES([regex posix socket net-db threads])

dnl Check whether (srfi srfi-37) works, and provide our own if it doesn't.
GUIX_CHECK_SRFI_37
AM_CONDITIONAL([INSTALL_SRFI_37], [test "x$ac_cv_guix_srfi_37_broken" = xyes])

dnl Decompressors, for use by the substituter and other modules.
AC_PATH_PROG([GZIP], [gzip])
AC_PATH_PROG([BZIP2], [bzip2])
AC_PATH_PROG([XZ], [xz])
AC_SUBST([GZIP])
AC_SUBST([BZIP2])
AC_SUBST([XZ])

AC_ARG_WITH([nix-prefix],
  [AS_HELP_STRING([--with-nix-prefix=DIR],
    [search for Nix in DIR (for testing purposes and '--disable-daemon' builds)])],
  [case "$withval" in
    yes|no) ;;
    *)
      NIX_PREFIX="$withval"
      PATH="$NIX_PREFIX/bin:$PATH"; export PATH
      AC_SUBST([NIX_PREFIX])
      ;;
   esac],
  [])

AC_PATH_PROG([NIX_INSTANTIATE], [nix-instantiate])
AC_PATH_PROG([NIX_HASH], [nix-hash])
if test "x$guix_build_daemon$NIX_INSTANTIATE$NIX_HASH" = "xno"; then
   AC_MSG_ERROR([Nix programs not found; please install Nix or use `--with-nix-prefix'.])
fi

if test "x$NIX_INSTANTIATE" = "x"; then
   # This program is an optional dependency, so we just want it to be
   # taken from $PATH if it's not available right now.
   NIX_INSTANTIATE="nix-instantiate"
fi

AC_ARG_WITH([nixpkgs],
  [AS_HELP_STRING([--with-nixpkgs=DIR],
    [search for Nixpkgs in DIR (for testing purposes only)])],
  [case "$withval" in
    yes|no) AC_MSG_ERROR([Please use `--with-nixpkgs=DIR'.]);;
    *)      NIXPKGS="$withval";;
   esac],
  [])

AC_MSG_CHECKING([for Nixpkgs source tree])
if test -f "$NIXPKGS/default.nix"; then
   AC_MSG_RESULT([$NIXPKGS])
   AC_SUBST([NIXPKGS])
else
   AC_MSG_RESULT([not found])
fi

LIBGCRYPT="libgcrypt"
LIBGCRYPT_LIBDIR="no"
LIBGCRYPT_PREFIX="no"

AC_ARG_WITH([libgcrypt-prefix],
  [AS_HELP_STRING([--with-libgcrypt-prefix=DIR], [search for GNU libgcrypt in DIR])],
  [case "$withval" in
    yes|no)
      ;;
    *)
      LIBGCRYPT="$withval/lib/libgcrypt"
      LIBGCRYPT_PREFIX="$withval"
      LIBGCRYPT_LIBDIR="$withval/lib"
      ;;
   esac])

AC_ARG_WITH([libgcrypt-libdir],
  [AS_HELP_STRING([--with-libgcrypt-libdir=DIR],
     [search for GNU libgcrypt's shared library in DIR])],
  [case "$withval" in
    yes|no)
      LIBGCRYPT="libgcrypt"
      LIBGCRYPT_LIBDIR="no"
      ;;
    *)
      LIBGCRYPT="$withval/libgcrypt"
      LIBGCRYPT_LIBDIR="$withval"
      ;;
   esac])

dnl If none of the --with-libgcrypt-* options was used, try to determine the
dnl absolute file name of libgcrypt.so.
case "x$LIBGCRYPT_PREFIX$LIBGCRYPT_LIBDIR" in
  xnono)
    GUIX_LIBGCRYPT_LIBDIR([LIBGCRYPT_LIBDIR])
    if test "x$LIBGCRYPT_LIBDIR" != x; then
      LIBGCRYPT="$LIBGCRYPT_LIBDIR/libgcrypt"
    else
      dnl 'config-daemon.ac' expects "no" in this case.
      LIBGCRYPT_LIBDIR="no"
    fi
    ;;
esac

dnl Library name suitable for `dynamic-link'.
AC_MSG_CHECKING([for libgcrypt shared library name])
AC_MSG_RESULT([$LIBGCRYPT])
AC_SUBST([LIBGCRYPT])
AC_SUBST([LIBGCRYPT_PREFIX])
AC_SUBST([LIBGCRYPT_LIBDIR])

GUIX_ASSERT_LIBGCRYPT_USABLE

dnl Library name of zlib suitable for 'dynamic-link'.
GUIX_LIBZ_LIBDIR([libz_libdir])
if test "x$libz_libdir" = "x"; then
  LIBZ="libz"
else
  LIBZ="$libz_libdir/libz"
fi
AC_MSG_CHECKING([for zlib's shared library name])
AC_MSG_RESULT([$LIBZ])
AC_SUBST([LIBZ])

AC_CACHE_SAVE

m4_include([config-daemon.ac])

dnl `dot' (from the Graphviz package) is only needed for maintainers.
dnl See `Building from Git' in the manual for more info.
AM_MISSING_PROG([DOT], [dot])

dnl Manual pages.
AM_MISSING_PROG([HELP2MAN], [help2man])

AC_CONFIG_FILES([Makefile
                 po/guix/Makefile.in
                 po/packages/Makefile.in
		 guix/config.scm])

AC_CONFIG_FILES([scripts/guix], [chmod +x scripts/guix])
AC_CONFIG_FILES([test-env:build-aux/test-env.in], [chmod +x test-env])
AC_CONFIG_FILES([pre-inst-env:build-aux/pre-inst-env.in],
  [chmod +x pre-inst-env])

dnl Emacs interface.
AC_PATH_PROG([DOT_USER_PROGRAM], [dot], [dot])
AM_PATH_LISPDIR
AM_CONDITIONAL([HAVE_EMACS], [test "x$EMACS" != "xno"])

emacsuidir="${guilemoduledir}/guix/emacs"
AC_SUBST([emacsuidir])
AC_CONFIG_FILES([emacs/guix-config.el
                 emacs/guix-helper.scm])

AC_OUTPUT
