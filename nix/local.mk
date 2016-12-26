# GNU Guix --- Functional package management for GNU
# Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
# Copyright © 2016 Mathieu Lirzin <mthl@gnu.org>
#
# This file is part of GNU Guix.
#
# GNU Guix is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or (at
# your option) any later version.
#
# GNU Guix is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Guix.  If not, see <http://www.gnu.org/licenses/>.

#
# Integration of the `guix-daemon' code taken from upstream Nix.
#

BUILT_SOURCES += %D%/libstore/schema.sql.hh
CLEANFILES += $(BUILT_SOURCES)

noinst_LIBRARIES = libformat.a libutil.a libstore.a

# Use '-std=c++11' for 'std::shared_ptr', 'auto', lambdas, and more.
AM_CXXFLAGS = -Wall -std=c++11

libformat_a_SOURCES =				\
  %D%/boost/format/free_funcs.cc		\
  %D%/boost/format/parsing.cc			\
  %D%/boost/format/format_implementation.cc

libformat_headers =				\
  %D%/boost/throw_exception.hpp			\
  %D%/boost/format.hpp				\
  %D%/boost/assert.hpp				\
  %D%/boost/format/macros_default.hpp		\
  %D%/boost/format/format_fwd.hpp		\
  %D%/boost/format/format_class.hpp		\
  %D%/boost/format/exceptions.hpp		\
  %D%/boost/format/group.hpp			\
  %D%/boost/format/feed_args.hpp		\
  %D%/boost/format/internals_fwd.hpp		\
  %D%/boost/format/internals.hpp

libformat_a_CPPFLAGS =				\
  -I$(top_srcdir)/nix

libutil_a_SOURCES =				\
  %D%/libutil/archive.cc			\
  %D%/libutil/affinity.cc			\
  %D%/libutil/serialise.cc			\
  %D%/libutil/util.cc				\
  %D%/libutil/hash.cc				\
  %D%/libutil/gcrypt-hash.cc

libutil_headers =				\
  %D%/libutil/affinity.hh			\
  %D%/libutil/hash.hh				\
  %D%/libutil/serialise.hh			\
  %D%/libutil/util.hh				\
  %D%/libutil/archive.hh			\
  %D%/libutil/types.hh				\
  %D%/libutil/gcrypt-hash.hh			\
  %D%/libutil/md5.h				\
  %D%/libutil/sha1.h				\
  %D%/libutil/sha256.h				\
  %D%/libutil/sha512.h

libutil_a_CPPFLAGS =				\
  -I$(top_builddir)/nix				\
  -I$(top_srcdir)/%D%/libutil			\
  $(libformat_a_CPPFLAGS)

libstore_a_SOURCES =				\
  %D%/libstore/gc.cc				\
  %D%/libstore/globals.cc			\
  %D%/libstore/misc.cc				\
  %D%/libstore/references.cc			\
  %D%/libstore/store-api.cc			\
  %D%/libstore/optimise-store.cc		\
  %D%/libstore/local-store.cc			\
  %D%/libstore/build.cc				\
  %D%/libstore/pathlocks.cc			\
  %D%/libstore/derivations.cc			\
  %D%/libstore/builtins.cc			\
  %D%/libstore/sqlite.cc

libstore_headers =				\
  %D%/libstore/references.hh			\
  %D%/libstore/pathlocks.hh			\
  %D%/libstore/globals.hh			\
  %D%/libstore/worker-protocol.hh		\
  %D%/libstore/derivations.hh			\
  %D%/libstore/misc.hh				\
  %D%/libstore/local-store.hh			\
  %D%/libstore/sqlite.hh			\
  %D%/libstore/builtins.hh			\
  %D%/libstore/store-api.hh

libstore_a_CPPFLAGS =				\
  $(libutil_a_CPPFLAGS)				\
  -I$(top_srcdir)/%D%/libstore			\
  -I$(top_builddir)/%D%/libstore		\
  -DNIX_STORE_DIR=\"$(storedir)\"		\
  -DNIX_DATA_DIR=\"$(datadir)\"			\
  -DNIX_STATE_DIR=\"$(localstatedir)/guix\"	\
  -DNIX_LOG_DIR=\"$(localstatedir)/log/guix\"	\
  -DGUIX_CONFIGURATION_DIRECTORY=\"$(sysconfdir)/guix\"		\
  -DNIX_LIBEXEC_DIR=\"$(libexecdir)\"		\
  -DNIX_BIN_DIR=\"$(bindir)\"			\
  -DOPENSSL_PATH="\"guix-authenticate\""	\
  -DDEFAULT_CHROOT_DIRS="\"\""

libstore_a_CXXFLAGS = $(AM_CXXFLAGS)		\
  $(SQLITE3_CFLAGS) $(LIBGCRYPT_CFLAGS)

bin_PROGRAMS = guix-daemon
sbin_PROGRAMS = guix-register

guix_daemon_SOURCES =				\
  %D%/nix-daemon/nix-daemon.cc			\
  %D%/nix-daemon/guix-daemon.cc

guix_daemon_CPPFLAGS =				\
  -DLOCALEDIR=\"$(localedir)\"			\
  $(libutil_a_CPPFLAGS)				\
  -I$(top_srcdir)/%D%/libstore

guix_daemon_LDADD =				\
  libstore.a libutil.a libformat.a -lbz2	\
  $(SQLITE3_LIBS) $(LIBGCRYPT_LIBS)

guix_daemon_headers =				\
  %D%/nix-daemon/shared.hh


guix_register_SOURCES =				\
  %D%/guix-register/guix-register.cc

guix_register_CPPFLAGS =			\
  $(libutil_a_CPPFLAGS)				\
  $(libstore_a_CPPFLAGS)			\
  -I$(top_srcdir)/%D%/libstore

# XXX: Should we start using shared libs?
guix_register_LDADD =				\
  libstore.a libutil.a libformat.a -lbz2	\
  $(SQLITE3_LIBS) $(LIBGCRYPT_LIBS)


noinst_HEADERS =						\
  $(libformat_headers) $(libutil_headers) $(libstore_headers)	\
  $(guix_daemon_headers)

%D%/libstore/schema.sql.hh: %D%/libstore/schema.sql
	$(AM_V_GEN)$(GUILE) --no-auto-compile -c		\
	  "(use-modules (rnrs io ports))			\
	   (call-with-output-file \"$@\"			\
	     (lambda (out)					\
	       (call-with-input-file \"$^\"			\
	         (lambda (in)					\
	           (write (get-string-all in) out)))))"

nodist_pkglibexec_SCRIPTS =			\
  %D%/scripts/list-runtime-roots		\
  %D%/scripts/substitute			\
  %D%/scripts/download

if BUILD_DAEMON_OFFLOAD

nodist_pkglibexec_SCRIPTS +=			\
  %D%/scripts/offload

endif BUILD_DAEMON_OFFLOAD


# XXX: It'd be better to hide it in $(pkglibexecdir).
nodist_libexec_SCRIPTS =			\
  %D%/scripts/guix-authenticate

# The '.service' files for systemd.
systemdservicedir = $(libdir)/systemd/system
nodist_systemdservice_DATA = etc/guix-daemon.service etc/guix-publish.service

etc/guix-%.service: etc/guix-%.service.in	\
			 $(top_builddir)/config.status
	$(AM_V_GEN)$(MKDIR_P) "`dirname $@`";	\
	$(SED) -e 's|@''bindir''@|$(bindir)|' <	\
	       "$<" > "$@.tmp";		\
	mv "$@.tmp" "$@"

# The '.conf' jobs for Upstart.
upstartjobdir = $(libdir)/upstart/system
nodist_upstartjob_DATA = etc/guix-daemon.conf etc/guix-publish.conf

etc/guix-%.conf: etc/guix-%.conf.in	\
			 $(top_builddir)/config.status
	$(AM_V_GEN)$(MKDIR_P) "`dirname $@`";	\
	$(SED) -e 's|@''bindir''@|$(bindir)|' <	\
	       "$<" > "$@.tmp";		\
	mv "$@.tmp" "$@"

CLEANFILES +=					\
  $(nodist_systemdservice_DATA)			\
  $(nodist_upstartjob_DATA)

EXTRA_DIST +=					\
  %D%/libstore/schema.sql			\
  %D%/AUTHORS					\
  %D%/COPYING					\
  etc/guix-daemon.service.in			\
  etc/guix-daemon.conf.in			\
  etc/guix-publish.service.in			\
  etc/guix-publish.conf.in

if CAN_RUN_TESTS

AM_TESTS_ENVIRONMENT +=				\
  top_builddir="$(abs_top_builddir)"

TESTS +=					\
  tests/guix-daemon.sh

endif CAN_RUN_TESTS

clean-local:
	-if test -d "$(GUIX_TEST_ROOT)"; then		\
	  find "$(GUIX_TEST_ROOT)" | xargs chmod +w;	\
	 fi
	-rm -rf "$(GUIX_TEST_ROOT)"
