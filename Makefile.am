# GNU Guix --- Functional package management for GNU
# Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
# Copyright © 2013 Andreas Enge <andreas@enge.fr>
# Copyright © 2015 Alex Kost <alezost@gmail.com>
# Copyright © 2016 Mathieu Lirzin <mthl@gnu.org>
# Copyright © 2016 Mark H Weaver <mhw@netris.org>
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

bin_SCRIPTS =					\
  scripts/guix

nodist_noinst_SCRIPTS =				\
  pre-inst-env					\
  test-env

include gnu/local.mk

MODULES =					\
  guix/base32.scm				\
  guix/base64.scm				\
  guix/cpio.scm					\
  guix/records.scm				\
  guix/gcrypt.scm				\
  guix/hash.scm					\
  guix/pk-crypto.scm				\
  guix/pki.scm					\
  guix/combinators.scm				\
  guix/utils.scm				\
  guix/sets.scm					\
  guix/modules.scm				\
  guix/download.scm				\
  guix/git-download.scm				\
  guix/hg-download.scm				\
  guix/monads.scm				\
  guix/monad-repl.scm				\
  guix/gexp.scm					\
  guix/profiles.scm				\
  guix/serialization.scm			\
  guix/nar.scm					\
  guix/derivations.scm				\
  guix/grafts.scm				\
  guix/gnu-maintenance.scm			\
  guix/upstream.scm				\
  guix/licenses.scm				\
  guix/graph.scm				\
  guix/cve.scm					\
  guix/zlib.scm					\
  guix/build-system.scm				\
  guix/build-system/ant.scm			\
  guix/build-system/cargo.scm			\
  guix/build-system/cmake.scm			\
  guix/build-system/emacs.scm			\
  guix/build-system/asdf.scm			\
  guix/build-system/glib-or-gtk.scm		\
  guix/build-system/gnu.scm			\
  guix/build-system/haskell.scm			\
  guix/build-system/perl.scm			\
  guix/build-system/python.scm			\
  guix/build-system/waf.scm			\
  guix/build-system/r.scm			\
  guix/build-system/ruby.scm			\
  guix/build-system/trivial.scm			\
  guix/ftp-client.scm				\
  guix/http-client.scm				\
  guix/gnupg.scm				\
  guix/elf.scm					\
  guix/store.scm				\
  guix/cvs-download.scm				\
  guix/svn-download.scm				\
  guix/ui.scm					\
  guix/build/ant-build-system.scm		\
  guix/build/download.scm			\
  guix/build/cargo-build-system.scm		\
  guix/build/cmake-build-system.scm		\
  guix/build/emacs-build-system.scm		\
  guix/build/asdf-build-system.scm		\
  guix/build/git.scm				\
  guix/build/hg.scm				\
  guix/build/glib-or-gtk-build-system.scm	\
  guix/build/gnu-build-system.scm		\
  guix/build/gnu-dist.scm			\
  guix/build/perl-build-system.scm		\
  guix/build/python-build-system.scm		\
  guix/build/r-build-system.scm			\
  guix/build/ruby-build-system.scm		\
  guix/build/waf-build-system.scm		\
  guix/build/haskell-build-system.scm		\
  guix/build/store-copy.scm			\
  guix/build/utils.scm				\
  guix/build/union.scm				\
  guix/build/profiles.scm			\
  guix/build/pull.scm				\
  guix/build/rpath.scm				\
  guix/build/cvs.scm				\
  guix/build/svn.scm				\
  guix/build/syscalls.scm                       \
  guix/build/gremlin.scm			\
  guix/build/emacs-utils.scm			\
  guix/build/lisp-utils.scm			\
  guix/build/graft.scm				\
  guix/build/bournish.scm			\
  guix/build/qt-utils.scm			\
  guix/build/make-bootstrap.scm			\
  guix/search-paths.scm				\
  guix/packages.scm				\
  guix/import/utils.scm				\
  guix/import/gnu.scm				\
  guix/import/snix.scm				\
  guix/import/cabal.scm				\
  guix/import/cran.scm				\
  guix/import/crate.scm				\
  guix/import/hackage.scm			\
  guix/import/elpa.scm   			\
  guix/scripts.scm				\
  guix/scripts/download.scm			\
  guix/scripts/perform-download.scm		\
  guix/scripts/build.scm			\
  guix/scripts/archive.scm			\
  guix/scripts/import.scm			\
  guix/scripts/package.scm			\
  guix/scripts/gc.scm				\
  guix/scripts/hash.scm				\
  guix/scripts/pull.scm				\
  guix/scripts/substitute.scm			\
  guix/scripts/authenticate.scm			\
  guix/scripts/refresh.scm			\
  guix/scripts/system.scm			\
  guix/scripts/lint.scm				\
  guix/scripts/challenge.scm			\
  guix/scripts/import/cran.scm			\
  guix/scripts/import/crate.scm			\
  guix/scripts/import/gnu.scm			\
  guix/scripts/import/nix.scm			\
  guix/scripts/import/hackage.scm		\
  guix/scripts/import/elpa.scm  		\
  guix/scripts/environment.scm			\
  guix/scripts/publish.scm			\
  guix/scripts/edit.scm				\
  guix/scripts/size.scm				\
  guix/scripts/graph.scm			\
  guix/scripts/container.scm			\
  guix/scripts/container/exec.scm		\
  guix.scm					\
  $(GNU_SYSTEM_MODULES)

if HAVE_GUILE_JSON

MODULES +=					\
  guix/import/github.scm   			\
  guix/import/json.scm				\
  guix/import/pypi.scm				\
  guix/scripts/import/pypi.scm			\
  guix/import/cpan.scm				\
  guix/scripts/import/gem.scm			\
  guix/import/gem.scm

endif

if BUILD_DAEMON_OFFLOAD

MODULES +=					\
  guix/scripts/offload.scm

endif BUILD_DAEMON_OFFLOAD

# Internal modules with test suite support.
dist_noinst_DATA = guix/tests.scm guix/tests/http.scm

# Linux-Libre configurations.
KCONFIGS =					\
  gnu/packages/linux-libre-4.8-i686.conf	\
  gnu/packages/linux-libre-4.8-x86_64.conf	\
  gnu/packages/linux-libre-4.4-i686.conf	\
  gnu/packages/linux-libre-4.4-x86_64.conf	\
  gnu/packages/linux-libre-4.1-i686.conf	\
  gnu/packages/linux-libre-4.1-x86_64.conf

# Templates, examples.
EXAMPLES =					\
  gnu/system/examples/bare-bones.tmpl		\
  gnu/system/examples/desktop.tmpl		\
  gnu/system/examples/lightweight-desktop.tmpl

GOBJECTS = $(MODULES:%.scm=%.go) guix/config.go $(dist_noinst_DATA:%.scm=%.go)

nobase_dist_guilemodule_DATA =                  \
  $(MODULES) $(KCONFIGS) $(EXAMPLES)            \
  $(MISC_DISTRO_FILES)
nobase_nodist_guilemodule_DATA = $(GOBJECTS) guix/config.scm

# Do we need to provide our own non-broken (srfi srfi-37) module?
if INSTALL_SRFI_37

nobase_nodist_guilemodule_DATA += srfi/srfi-37.scm
GOBJECTS += srfi/srfi-37.go

srfi/srfi-37.scm: srfi/srfi-37.scm.in
	$(MKDIR_P) srfi
	cp "$<" "$@"

endif INSTALL_SRFI_37

# Handy way to remove the .go files without removing all the rest.
clean-go:
	-$(RM) -f $(GOBJECTS)
	@find . -name '*.go' -print | \
	  if test -t 1; then \
	    xargs -r echo -e "\033[31mwarning:\033[0m stray .go files:"; \
	  else \
	    xargs -r echo "warning: stray .go files:"; \
	  fi


# Test extensions; has to be unconditional.
TEST_EXTENSIONS = .scm .sh

if CAN_RUN_TESTS

SCM_TESTS =					\
  tests/base32.scm				\
  tests/base64.scm				\
  tests/cpio.scm				\
  tests/hash.scm				\
  tests/pk-crypto.scm				\
  tests/pki.scm					\
  tests/sets.scm				\
  tests/modules.scm				\
  tests/gnu-maintenance.scm			\
  tests/substitute.scm				\
  tests/builders.scm				\
  tests/derivations.scm				\
  tests/grafts.scm				\
  tests/ui.scm					\
  tests/records.scm				\
  tests/upstream.scm				\
  tests/combinators.scm				\
  tests/utils.scm				\
  tests/build-utils.scm				\
  tests/packages.scm				\
  tests/snix.scm				\
  tests/hackage.scm				\
  tests/cran.scm				\
  tests/elpa.scm				\
  tests/store.scm				\
  tests/monads.scm				\
  tests/gexp.scm				\
  tests/nar.scm					\
  tests/union.scm				\
  tests/profiles.scm				\
  tests/syscalls.scm				\
  tests/gremlin.scm				\
  tests/bournish.scm				\
  tests/lint.scm				\
  tests/publish.scm				\
  tests/scripts.scm				\
  tests/size.scm				\
  tests/graph.scm				\
  tests/challenge.scm				\
  tests/cve.scm					\
  tests/zlib.scm				\
  tests/file-systems.scm			\
  tests/system.scm				\
  tests/services.scm				\
  tests/scripts-build.scm			\
  tests/containers.scm				\
  tests/import-utils.scm

if HAVE_GUILE_JSON

SCM_TESTS += 					\
  tests/pypi.scm				\
  tests/cpan.scm				\
  tests/gem.scm					\
  tests/crate.scm

endif

SH_TESTS =					\
  tests/guix-build.sh				\
  tests/guix-download.sh			\
  tests/guix-gc.sh				\
  tests/guix-hash.sh				\
  tests/guix-package.sh				\
  tests/guix-package-net.sh			\
  tests/guix-system.sh				\
  tests/guix-archive.sh				\
  tests/guix-authenticate.sh			\
  tests/guix-environment.sh			\
  tests/guix-environment-container.sh		\
  tests/guix-graph.sh				\
  tests/guix-lint.sh

if BUILD_DAEMON

SH_TESTS += tests/guix-register.sh

endif BUILD_DAEMON


TESTS = $(SCM_TESTS) $(SH_TESTS)

AM_TESTS_ENVIRONMENT = abs_top_srcdir="$(abs_top_srcdir)" GUILE_AUTO_COMPILE=0

SCM_LOG_DRIVER =				\
  $(top_builddir)/test-env --quiet-stderr	\
  $(GUILE) --no-auto-compile -e main		\
      $(top_srcdir)/build-aux/test-driver.scm

AM_SCM_LOG_DRIVER_FLAGS = --brief=yes

SH_LOG_COMPILER = $(top_builddir)/test-env $(SHELL)
AM_SH_LOG_FLAGS = -x -e

# Make sure `tests/guix-gc.sh' runs last, after all the others.  Otherwise it
# could end up removing files from the store while they are being used by
# other instances of the daemon.
tests/guix-gc.log:							\
  $(patsubst %.sh,%.log,$(filter-out tests/guix-gc.sh,$(SH_TESTS)))	\
  $(SCM_TESTS:%.scm=%.log)

else !CAN_RUN_TESTS

TESTS =
SH_TESTS =
SCM_TESTS =

# Automake always generates a 'check' target, so better not override it.
check-local:
	@echo
	@echo "Cannot run tests because file name limits would be exceeded." >&2
	@echo "Look for 'length' in the 'config.log' file for details." >&2
	@echo
	@exit 1

endif !CAN_RUN_TESTS

check-system: $(GOBJECTS)
	$(AM_V_at)$(top_builddir)/pre-inst-env			\
	   $(GUILE) --no-auto-compile				\
	   -e '(@@ (run-system-tests) run-system-tests)'	\
	   $(top_srcdir)/build-aux/run-system-tests.scm

# Public key used to sign substitutes from hydra.gnu.org.
dist_pkgdata_DATA = hydra.gnu.org.pub

# Bash completion file.
dist_bashcompletion_DATA = etc/completion/bash/guix

# Zsh completion file.
dist_zshcompletion_DATA = etc/completion/zsh/_guix

EXTRA_DIST =						\
  HACKING						\
  ROADMAP						\
  TODO							\
  CODE-OF-CONDUCT					\
  .dir-locals.el					\
  build-aux/build-self.scm				\
  build-aux/compile-all.scm				\
  build-aux/hydra/evaluate.scm				\
  build-aux/hydra/gnu-system.scm			\
  build-aux/hydra/demo-os.scm				\
  build-aux/hydra/guix.scm				\
  build-aux/check-available-binaries.scm		\
  build-aux/check-final-inputs-self-contained.scm	\
  build-aux/download.scm				\
  build-aux/make-binary-tarball.scm			\
  build-aux/generate-authors.scm			\
  build-aux/test-driver.scm				\
  build-aux/run-system-tests.scm			\
  d3.v3.js						\
  graph.js						\
  srfi/srfi-37.scm.in					\
  srfi/srfi-64.scm					\
  srfi/srfi-64.upstream.scm				\
  tests/test.drv					\
  tests/signing-key.pub					\
  tests/signing-key.sec					\
  tests/cve-sample.xml					\
  build-aux/config.rpath				\
  bootstrap						\
  release.nix						\
  $(TESTS)

if !BUILD_DAEMON_OFFLOAD

EXTRA_DIST +=					\
  guix/scripts/offload.scm

endif !BUILD_DAEMON_OFFLOAD


CLEANFILES =					\
  $(GOBJECTS)					\
  $(SCM_TESTS:tests/%.scm=%.log)

# Unset 'GUILE_LOAD_COMPILED_PATH' altogether while compiling.  Otherwise, if
# $GUILE_LOAD_COMPILED_PATH contains $(moduledir), we may find .go files in
# there that are newer than the local .scm files (for instance because the
# user ran 'make install' recently).  When that happens, we end up loading
# those previously-installed .go files, which may be stale, thereby breaking
# the whole thing.  Likewise, set 'XDG_CACHE_HOME' to avoid loading possibly
# stale files from ~/.cache/guile/ccache.
%.go: make-go ; @:
make-go: $(MODULES) guix/config.scm $(dist_noinst_DATA)
	$(AM_V_at)echo "Compiling Scheme modules..." ;			\
	unset GUILE_LOAD_COMPILED_PATH ;				\
	XDG_CACHE_HOME=/nowhere						\
	host=$(host) srcdir="$(top_srcdir)"				\
	$(top_builddir)/pre-inst-env					\
	$(GUILE) -L "$(top_builddir)" -L "$(top_srcdir)"		\
	  --no-auto-compile 						\
	  -s "$(top_srcdir)"/build-aux/compile-all.scm $^

SUFFIXES = .go

# Make sure source files are installed first, so that the mtime of
# installed compiled files is greater than that of installed source
# files.  See
# <http://lists.gnu.org/archive/html/guile-devel/2010-07/msg00125.html>
# for details.
guix_install_go_files = install-nobase_nodist_guilemoduleDATA
$(guix_install_go_files): install-nobase_dist_guilemoduleDATA

# The above trick doesn't work for 'config.go' because both 'config.scm' and
# 'config.go' are listed in $(nobase_nodist_guilemodule_DATA).  Thus, give it
# special treatment.
install-data-hook: set-bootstrap-executable-permissions
	touch "$(DESTDIR)$(guilemoduledir)/guix/config.go"


SUBDIRS = po/guix po/packages
BUILT_SOURCES =

include doc/local.mk

if BUILD_DAEMON

include nix/local.mk

endif BUILD_DAEMON

ACLOCAL_AMFLAGS = -I m4

# Pass an explicit '--localstatedir' so that configure does not error out if
# it finds an existing installation with a different localstatedir.
AM_DISTCHECK_CONFIGURE_FLAGS =			\
  --localstatedir="$$dc_install_base/var"	\
  --with-libgcrypt-prefix="$(LIBGCRYPT_PREFIX)"	\
  --with-libgcrypt-libdir="$(LIBGCRYPT_LIBDIR)"	\
  --with-nix-prefix="$(NIX_PREFIX)"		\
  --enable-daemon

dist_emacsui_DATA = emacs/guix-main.scm
nodist_emacsui_DATA = emacs/guix-helper.scm
include emacs/local.mk

# The self-contained tarball.
guix-binary.%.tar.xz:
	$(AM_V_GEN)GUIX_PACKAGE_PATH= \
	$(top_builddir)/pre-inst-env "$(GUILE)"			\
	  "$(top_srcdir)/build-aux/make-binary-tarball.scm" "$*" "$@"


dist-hook: sync-descriptions gen-ChangeLog gen-AUTHORS
dist-hook: assert-no-store-file-names

distcheck-hook: assert-binaries-available assert-final-inputs-self-contained

sync-descriptions:
	$(AM_V_at)GUIX_PACKAGE_PATH= \
	 $(top_builddir)/pre-inst-env guix lint --checkers=gnu-description

gen-ChangeLog:
	$(AM_V_GEN)if test -d .git; then		\
	  $(top_srcdir)/build-aux/gitlog-to-changelog	\
	    > $(distdir)/cl-t;				\
	  rm -f $(distdir)/ChangeLog;			\
	  mv $(distdir)/cl-t $(distdir)/ChangeLog;	\
	fi

gen-AUTHORS:
	$(AM_V_GEN)if test -d .git; then			\
	  rm -f "$(distdir)/AUTHORS";				\
	  $(top_builddir)/pre-inst-env "$(GUILE)"		\
	    "$(top_srcdir)/build-aux/generate-authors.scm"	\
	    "$(top_srcdir)" "$(distdir)/AUTHORS";		\
	fi

# Make sure we're not shipping a file that embeds a local /gnu/store file name.
assert-no-store-file-names:
	$(AM_V_at)if grep -r --exclude=*.texi --exclude=*.info			\
	     --exclude=*.info-[0-9] --exclude=*.dot				\
	     --exclude=*.eps --exclude-dir=bootstrap				\
	     --exclude=guix-prettify.el						\
	     --exclude=ChangeLog						\
	     -E "$(storedir)/[a-z0-9]{32}-" $(distdir) ;			\
	then									\
	  echo "error: store file names embedded in the distribution" >&2 ;	\
	  exit 1 ;								\
	fi

# Make sure hydra.gnu.org has the important binaries.
assert-binaries-available: $(GOBJECTS)
	$(AM_V_at)$(top_builddir)/pre-inst-env "$(GUILE)"			\
	  "$(top_srcdir)/build-aux/check-available-binaries.scm"

# Make sure the final inputs don't refer to bootstrap tools.
assert-final-inputs-self-contained: $(GOBJECTS)
	$(AM_V_at)$(top_builddir)/pre-inst-env "$(GUILE)"			\
	  "$(top_srcdir)/build-aux/check-final-inputs-self-contained.scm"

# Compute the Hydra jobs and write them in the target file.
hydra-jobs.scm: $(GOBJECTS)
	$(AM_V_at)$(MKDIR_P) "`dirname "$@"`"
	$(AM_V_GEN)$(top_builddir)/pre-inst-env "$(GUILE)"		\
	  "$(top_srcdir)/build-aux/hydra/evaluate.scm"			\
	  "$(top_srcdir)/build-aux/hydra/gnu-system.scm" > "$@.tmp"
	$(AM_V_at)mv "$@.tmp" "$@"

.PHONY: sync-descriptions gen-ChangeLog gen-AUTHORS clean-go make-go
.PHONY: assert-no-store-file-names assert-binaries-available
.PHONY: assert-final-inputs-self-contained

## -------------- ##
## Silent rules.  ##
## -------------- ##

AM_V_DL = $(AM_V_DL_$(V))
AM_V_DL_ = $(AM_V_DL_$(AM_DEFAULT_VERBOSITY))
AM_V_DL_0 = @echo "  DL      " $@;

AM_V_DOT = $(AM_V_DOT_$(V))
AM_V_DOT_ = $(AM_V_DOT_$(AM_DEFAULT_VERBOSITY))
AM_V_DOT_0 = @echo "  DOT     " $@;

AM_V_EMACS = $(AM_V_EMACS_$(V))
AM_V_EMACS_ = $(AM_V_EMACS_$(AM_DEFAULT_VERBOSITY))
AM_V_EMACS_0 = @echo "  EMACS   " $@;

AM_V_HELP2MAN = $(AM_V_HELP2MAN_$(V))
AM_V_HELP2MAN_ = $(AM_V_HELP2MAN_$(AM_DEFAULT_VERBOSITY))
AM_V_HELP2MAN_0 = @echo "  HELP2MAN" $@;
