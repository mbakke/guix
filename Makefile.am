# GNU Guix --- Functional package management for GNU
# Copyright © 2012-2022 Ludovic Courtès <ludo@gnu.org>
# Copyright © 2013 Andreas Enge <andreas@enge.fr>
# Copyright © 2015, 2017 Alex Kost <alezost@gmail.com>
# Copyright © 2016, 2018 Mathieu Lirzin <mthl@gnu.org>
# Copyright © 2016, 2017, 2018, 2019 Mark H Weaver <mhw@netris.org>
# Copyright © 2017 Mathieu Othacehe <m.othacehe@gmail.com>
# Copyright © 2017 Leo Famulari <leo@famulari.name>
# Copyright © 2017 Ricardo Wurmus <rekado@elephly.net>
# Copyright © 2017, 2020 Jan (janneke) Nieuwenhuizen <janneke@gnu.org>
# Copyright © 2017 Arun Isaac <arunisaac@systemreboot.net>
# Copyright © 2018 Nikita <nikita@n0.is>
# Copyright © 2018 Julien Lepiller <julien@lepiller.eu>
# Copyright © 2018 Oleg Pykhalov <go.wigust@gmail.com>
# Copyright © 2018 Alex Vong <alexvong1995@gmail.com>
# Copyright © 2019 Efraim Flashner <efraim@flashner.co.il>
# Copyright © 2021 Chris Marusich <cmmarusich@gmail.com>
# Copyright © 2021 Andrew Tropin <andrew@trop.in>
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

MSGMERGE_UPDATE = @MSGMERGE@ --update

bin_SCRIPTS = scripts/guix

# Handle substitution of fully-expanded Autoconf variables.
do_subst = $(SED)					\
  -e 's,[@]GUILE[@],$(GUILE),g'				\
  -e 's,[@]guilemoduledir[@],$(guilemoduledir),g'	\
  -e 's,[@]guileobjectdir[@],$(guileobjectdir),g'	\
  -e 's,[@]abs_top_builddir[@],$(abs_top_builddir),g'	\
  -e 's,[@]localedir[@],$(localedir),g'

scripts/guix: scripts/guix.in Makefile
	$(AM_V_at)rm -f $@ $@-t
	$(AM_V_at)$(MKDIR_P) "$(@D)"
	$(AM_V_GEN)$(do_subst) < "$(srcdir)/$@.in" > "$@-t"
	$(AM_V_at)chmod a+x,a-w "$@-t" && mv -f "$@-t" "$@"

# This is our variant of the 'guile' executable, one that doesn't complain
# about locales.
pkglibexec_PROGRAMS = guile
guile_SOURCES = gnu/packages/aux-files/guile-launcher.c
guile_LDADD   = $(GUILE_LIBS)
guile_CFLAGS  = $(GUILE_CFLAGS)

# Have the 'guix' command refer to our 'guile'.
install-exec-hook:
	$(SED) -i "$(DESTDIR)$(bindir)/guix"				\
	       -e 's,^#![[:graph:]]\+,#!$(pkglibexecdir)/guile,g'

nodist_noinst_SCRIPTS =				\
  pre-inst-env					\
  test-env

# Modules that are not compiled but are installed nonetheless, such as
# build-side modules with unusual dependencies.
MODULES_NOT_COMPILED =				\
  guix/build/po.scm				\
  guix/man-db.scm

include gnu/local.mk
include po/doc/local.mk

MODULES =					\
  guix/base16.scm				\
  guix/base32.scm				\
  guix/base64.scm				\
  guix/ci.scm					\
  guix/cpio.scm					\
  guix/cpu.scm					\
  guix/deprecation.scm				\
  guix/docker.scm	   			\
  guix/records.scm				\
  guix/openpgp.scm				\
  guix/pki.scm					\
  guix/progress.scm				\
  guix/combinators.scm				\
  guix/memoization.scm				\
  guix/utils.scm				\
  guix/sets.scm					\
  guix/modules.scm				\
  guix/download.scm				\
  guix/discovery.scm				\
  guix/android-repo-download.scm		\
  guix/bzr-download.scm            		\
  guix/git-download.scm				\
  guix/hg-download.scm				\
  guix/hash.scm					\
  guix/swh.scm					\
  guix/monads.scm				\
  guix/monad-repl.scm				\
  guix/gexp.scm					\
  guix/profiles.scm				\
  guix/serialization.scm			\
  guix/nar.scm					\
  guix/narinfo.scm				\
  guix/derivations.scm				\
  guix/grafts.scm				\
  guix/repl.scm					\
  guix/transformations.scm			\
  guix/inferior.scm				\
  guix/describe.scm				\
  guix/quirks.scm				\
  guix/channels.scm				\
  guix/gnu-maintenance.scm			\
  guix/self.scm					\
  guix/substitutes.scm				\
  guix/upstream.scm				\
  guix/licenses.scm				\
  guix/lint.scm				\
  guix/glob.scm					\
  guix/git.scm					\
  guix/git-authenticate.scm			\
  guix/graph.scm				\
  guix/cache.scm				\
  guix/cve.scm					\
  guix/workers.scm				\
  guix/least-authority.scm			\
  guix/read-print.scm				\
  guix/ipfs.scm					\
  guix/platform.scm                             \
  guix/platforms/arm.scm                        \
  guix/platforms/mips.scm                       \
  guix/platforms/powerpc.scm                    \
  guix/platforms/riscv.scm                      \
  guix/platforms/x86.scm                        \
  guix/build-system.scm				\
  guix/build-system/android-ndk.scm		\
  guix/build-system/ant.scm			\
  guix/build-system/cargo.scm			\
  guix/build-system/channel.scm			\
  guix/build-system/chicken.scm			\
  guix/build-system/clojure.scm			\
  guix/build-system/cmake.scm			\
  guix/build-system/dub.scm			\
  guix/build-system/dune.scm			\
  guix/build-system/elm.scm			\
  guix/build-system/emacs.scm			\
  guix/build-system/font.scm			\
  guix/build-system/go.scm			\
  guix/build-system/meson.scm			\
  guix/build-system/minify.scm			\
  guix/build-system/minetest.scm		\
  guix/build-system/asdf.scm			\
  guix/build-system/copy.scm			\
  guix/build-system/glib-or-gtk.scm		\
  guix/build-system/gnu.scm			\
  guix/build-system/guile.scm			\
  guix/build-system/haskell.scm			\
  guix/build-system/julia.scm			\
  guix/build-system/linux-module.scm		\
  guix/build-system/maven.scm			\
  guix/build-system/node.scm			\
  guix/build-system/perl.scm			\
  guix/build-system/pyproject.scm		\
  guix/build-system/python.scm			\
  guix/build-system/renpy.scm			\
  guix/build-system/ocaml.scm			\
  guix/build-system/qt.scm			\
  guix/build-system/waf.scm			\
  guix/build-system/r.scm			\
  guix/build-system/rakudo.scm			\
  guix/build-system/rebar.scm			\
  guix/build-system/ruby.scm			\
  guix/build-system/scons.scm			\
  guix/build-system/texlive.scm			\
  guix/build-system/trivial.scm			\
  guix/ftp-client.scm				\
  guix/http-client.scm				\
  guix/gnupg.scm				\
  guix/elf.scm					\
  guix/profiling.scm				\
  guix/store.scm				\
  guix/cvs-download.scm				\
  guix/svn-download.scm				\
  guix/colors.scm				\
  guix/i18n.scm					\
  guix/diagnostics.scm				\
  guix/ui.scm					\
  guix/status.scm				\
  guix/build/android-ndk-build-system.scm	\
  guix/build/ant-build-system.scm		\
  guix/build/download.scm			\
  guix/build/download-nar.scm			\
  guix/build/cargo-build-system.scm		\
  guix/build/cargo-utils.scm			\
  guix/build/chicken-build-system.scm		\
  guix/build/cmake-build-system.scm		\
  guix/build/dub-build-system.scm		\
  guix/build/dune-build-system.scm		\
  guix/build/elm-build-system.scm		\
  guix/build/emacs-build-system.scm		\
  guix/build/meson-build-system.scm		\
  guix/build/minify-build-system.scm		\
  guix/build/font-build-system.scm		\
  guix/build/go-build-system.scm		\
  guix/build/android-repo.scm			\
  guix/build/asdf-build-system.scm		\
  guix/build/bzr.scm				\
  guix/build/copy-build-system.scm		\
  guix/build/git.scm				\
  guix/build/hg.scm				\
  guix/build/glib-or-gtk-build-system.scm	\
  guix/build/gnu-bootstrap.scm			\
  guix/build/gnu-build-system.scm		\
  guix/build/gnu-dist.scm			\
  guix/build/guile-build-system.scm		\
  guix/build/maven-build-system.scm		\
  guix/build/minetest-build-system.scm		\
  guix/build/node-build-system.scm		\
  guix/build/perl-build-system.scm		\
  guix/build/pyproject-build-system.scm		\
  guix/build/python-build-system.scm		\
  guix/build/ocaml-build-system.scm		\
  guix/build/qt-build-system.scm		\
  guix/build/r-build-system.scm			\
  guix/build/renpy-build-system.scm			\
  guix/build/rakudo-build-system.scm		\
  guix/build/rebar-build-system.scm		\
  guix/build/ruby-build-system.scm		\
  guix/build/scons-build-system.scm		\
  guix/build/texlive-build-system.scm		\
  guix/build/waf-build-system.scm		\
  guix/build/haskell-build-system.scm		\
  guix/build/julia-build-system.scm		\
  guix/build/kconfig.scm			\
  guix/build/linux-module-build-system.scm	\
  guix/build/store-copy.scm			\
  guix/build/json.scm				\
  guix/build/pack.scm				\
  guix/build/utils.scm				\
  guix/build/union.scm				\
  guix/build/profiles.scm			\
  guix/build/compile.scm			\
  guix/build/cvs.scm				\
  guix/build/svn.scm				\
  guix/build/syscalls.scm                       \
  guix/build/gremlin.scm			\
  guix/build/debug-link.scm			\
  guix/build/clojure-build-system.scm		\
  guix/build/clojure-utils.scm			\
  guix/build/emacs-utils.scm			\
  guix/build/java-utils.scm			\
  guix/build/lisp-utils.scm			\
  guix/build/meson-configuration.scm		\
  guix/build/maven/java.scm			\
  guix/build/maven/plugin.scm			\
  guix/build/maven/pom.scm			\
  guix/build/graft.scm				\
  guix/build/bournish.scm			\
  guix/build/qt-utils.scm			\
  guix/build/make-bootstrap.scm			\
  guix/search-paths.scm				\
  guix/packages.scm				\
  guix/import/cabal.scm				\
  guix/import/cpan.scm				\
  guix/import/cran.scm				\
  guix/import/crate.scm				\
  guix/import/egg.scm   			\
  guix/import/elm.scm				\
  guix/import/elpa.scm   			\
  guix/import/gem.scm				\
  guix/import/git.scm                           \
  guix/import/github.scm   			\
  guix/import/gnome.scm				\
  guix/import/gnu.scm				\
  guix/import/go.scm				\
  guix/import/hackage.scm			\
  guix/import/hexpm.scm				\
  guix/import/json.scm				\
  guix/import/kde.scm				\
  guix/import/launchpad.scm   			\
  guix/import/minetest.scm   			\
  guix/import/opam.scm				\
  guix/import/print.scm				\
  guix/import/pypi.scm				\
  guix/import/stackage.scm			\
  guix/import/texlive.scm   			\
  guix/import/utils.scm				\
  guix/scripts.scm				\
  guix/scripts/download.scm			\
  guix/scripts/perform-download.scm		\
  guix/scripts/build.scm			\
  guix/scripts/archive.scm			\
  guix/scripts/import.scm			\
  guix/scripts/package.scm			\
  guix/scripts/install.scm			\
  guix/scripts/remove.scm			\
  guix/scripts/upgrade.scm			\
  guix/scripts/search.scm			\
  guix/scripts/show.scm				\
  guix/scripts/gc.scm				\
  guix/scripts/hash.scm				\
  guix/scripts/pack.scm				\
  guix/scripts/pull.scm				\
  guix/scripts/processes.scm			\
  guix/scripts/substitute.scm			\
  guix/scripts/authenticate.scm			\
  guix/scripts/refresh.scm			\
  guix/scripts/repl.scm				\
  guix/scripts/describe.scm			\
  guix/scripts/style.scm			\
  guix/scripts/system.scm			\
  guix/scripts/system/edit.scm			\
  guix/scripts/system/reconfigure.scm		\
  guix/scripts/system/search.scm		\
  guix/scripts/home.scm			\
  guix/scripts/home/edit.scm			\
  guix/scripts/home/import.scm			\
  guix/scripts/lint.scm				\
  guix/scripts/challenge.scm			\
  guix/scripts/import/crate.scm			\
  guix/scripts/import/cran.scm			\
  guix/scripts/import/egg.scm   		\
  guix/scripts/import/elm.scm			\
  guix/scripts/import/elpa.scm  		\
  guix/scripts/import/gem.scm			\
  guix/scripts/import/gnu.scm			\
  guix/scripts/import/go.scm			\
  guix/scripts/import/hackage.scm		\
  guix/scripts/import/hexpm.scm			\
  guix/scripts/import/json.scm  		\
  guix/scripts/import/minetest.scm  		\
  guix/scripts/import/opam.scm			\
  guix/scripts/import/pypi.scm			\
  guix/scripts/import/stackage.scm		\
  guix/scripts/import/texlive.scm  		\
  guix/scripts/environment.scm			\
  guix/scripts/shell.scm			\
  guix/scripts/publish.scm			\
  guix/scripts/edit.scm				\
  guix/scripts/size.scm				\
  guix/scripts/git.scm				\
  guix/scripts/git/authenticate.scm		\
  guix/scripts/graph.scm			\
  guix/scripts/weather.scm			\
  guix/scripts/container.scm			\
  guix/scripts/container/exec.scm		\
  guix/scripts/deploy.scm			\
  guix/scripts/time-machine.scm			\
  guix.scm					\
  $(GNU_SYSTEM_MODULES)

if HAVE_GUILE_SSH

MODULES +=					\
  guix/ssh.scm					\
  guix/remote.scm				\
  guix/scripts/copy.scm				\
  guix/store/ssh.scm

endif HAVE_GUILE_SSH

if HAVE_GUILE_AVAHI

MODULES += 					\
  guix/avahi.scm				\
  guix/scripts/discover.scm

endif HAVE_GUILE_AVAHI

if BUILD_DAEMON_OFFLOAD

MODULES +=					\
  guix/scripts/offload.scm

endif BUILD_DAEMON_OFFLOAD

# Scheme implementation of the build daemon and related functionality.
STORE_MODULES =					\
  guix/store/database.scm			\
  guix/store/deduplication.scm			\
  guix/store/roots.scm

MODULES += $(STORE_MODULES)

# Internal modules with test suite support.
dist_noinst_DATA =				\
  guix/tests.scm				\
  guix/tests/http.scm				\
  guix/tests/git.scm				\
  guix/tests/gnupg.scm

# Auxiliary files for packages.
AUX_FILES =						\
  gnu/packages/aux-files/chromium/master-preferences.json		\
  gnu/packages/aux-files/emacs/guix-emacs.el		\
  gnu/packages/aux-files/guix.vim			\
  gnu/packages/aux-files/linux-libre/6.0-arm.conf	\
  gnu/packages/aux-files/linux-libre/6.0-arm64.conf	\
  gnu/packages/aux-files/linux-libre/6.0-i686.conf	\
  gnu/packages/aux-files/linux-libre/6.0-x86_64.conf	\
  gnu/packages/aux-files/linux-libre/6.0-x86_64-virtual.conf	\
  gnu/packages/aux-files/linux-libre/5.15-arm.conf	\
  gnu/packages/aux-files/linux-libre/5.15-arm64.conf	\
  gnu/packages/aux-files/linux-libre/5.15-i686.conf	\
  gnu/packages/aux-files/linux-libre/5.15-x86_64.conf	\
  gnu/packages/aux-files/linux-libre/5.10-arm.conf	\
  gnu/packages/aux-files/linux-libre/5.10-arm64.conf	\
  gnu/packages/aux-files/linux-libre/5.10-i686.conf	\
  gnu/packages/aux-files/linux-libre/5.10-x86_64.conf	\
  gnu/packages/aux-files/linux-libre/5.4-arm.conf	\
  gnu/packages/aux-files/linux-libre/5.4-arm64.conf	\
  gnu/packages/aux-files/linux-libre/5.4-i686.conf	\
  gnu/packages/aux-files/linux-libre/5.4-x86_64.conf	\
  gnu/packages/aux-files/linux-libre/4.19-arm.conf	\
  gnu/packages/aux-files/linux-libre/4.19-arm64.conf	\
  gnu/packages/aux-files/linux-libre/4.19-i686.conf	\
  gnu/packages/aux-files/linux-libre/4.19-x86_64.conf	\
  gnu/packages/aux-files/linux-libre/4.14-arm.conf	\
  gnu/packages/aux-files/linux-libre/4.14-i686.conf	\
  gnu/packages/aux-files/linux-libre/4.14-x86_64.conf	\
  gnu/packages/aux-files/linux-libre/4.9-i686.conf	\
  gnu/packages/aux-files/linux-libre/4.9-x86_64.conf	\
  gnu/packages/aux-files/pack-audit.c			\
  gnu/packages/aux-files/python/sanity-check.py		\
  gnu/packages/aux-files/python/sanity-check-next.py	\
  gnu/packages/aux-files/python/sitecustomize.py	\
  gnu/packages/aux-files/renpy/renpy.in	\
  gnu/packages/aux-files/run-in-namespace.c

# Templates, examples.
EXAMPLES =					\
  gnu/system/examples/asus-c201.tmpl		\
  gnu/system/examples/bare-bones.tmpl		\
  gnu/system/examples/bare-hurd.tmpl		\
  gnu/system/examples/beaglebone-black.tmpl	\
  gnu/system/examples/desktop.tmpl		\
  gnu/system/examples/lightweight-desktop.tmpl	\
  gnu/system/examples/docker-image.tmpl		\
  gnu/system/examples/raspberry-pi-64.tmpl	\
  gnu/system/examples/raspberry-pi-64-nfs-root.tmpl	\
  gnu/system/examples/vm-image.tmpl

GOBJECTS = $(MODULES:%.scm=%.go) guix/config.go $(dist_noinst_DATA:%.scm=%.go)

nobase_dist_guilemodule_DATA =					\
  guix/d3.v3.js							\
  guix/graph.js							\
  guix/store/schema.sql						\
  $(MODULES) $(MODULES_NOT_COMPILED) $(AUX_FILES) $(EXAMPLES)	\
  $(MISC_DISTRO_FILES)
nobase_nodist_guilemodule_DATA = guix/config.scm
nobase_nodist_guileobject_DATA = $(GOBJECTS)

# Handy way to remove the .go files without removing all the rest.
clean-go:
	-$(RM) -f $(GOBJECTS)
	@find . -path ./test-tmp -prune -o -name '*.go' -print | \
	  if test -t 1; then \
	    xargs -r echo -e "\033[31mwarning:\033[0m stray .go files:"; \
	  else \
	    xargs -r echo "warning: stray .go files:"; \
	  fi


# Test extensions; has to be unconditional.
TEST_EXTENSIONS = .scm .sh

if CAN_RUN_TESTS

SCM_TESTS =					\
  tests/accounts.scm				\
  tests/base16.scm				\
  tests/base32.scm				\
  tests/base64.scm				\
  tests/boot-parameters.scm			\
  tests/bournish.scm				\
  tests/builders.scm				\
  tests/build-emacs-utils.scm			\
  tests/build-utils.scm			\
  tests/cache.scm				\
  tests/challenge.scm				\
  tests/channels.scm				\
  tests/combinators.scm			\
  tests/containers.scm				\
  tests/cpan.scm				\
  tests/cpio.scm				\
  tests/cran.scm				\
  tests/crate.scm				\
  tests/cve.scm				\
  tests/debug-link.scm				\
  tests/derivations.scm			\
  tests/discovery.scm				\
  tests/egg.scm				\
  tests/elm.scm				\
  tests/elpa.scm				\
  tests/file-systems.scm			\
  tests/gem.scm				\
  tests/gexp.scm				\
  tests/git.scm					\
  tests/git-authenticate.scm			\
  tests/glob.scm				\
  tests/gnu-maintenance.scm			\
  tests/grafts.scm				\
  tests/graph.scm				\
  tests/gremlin.scm				\
  tests/hackage.scm				\
  tests/home-import.scm				\
  tests/home-services.scm			\
  tests/http-client.scm				\
  tests/import-git.scm				\
  tests/import-github.scm			\
  tests/import-utils.scm			\
  tests/inferior.scm				\
  tests/lint.scm				\
  tests/minetest.scm				\
  tests/modules.scm				\
  tests/monads.scm				\
  tests/nar.scm				\
  tests/networking.scm				\
  tests/opam.scm				\
  tests/openpgp.scm				\
  tests/packages.scm				\
  tests/pack.scm				\
  tests/pki.scm				\
  tests/print.scm				\
  tests/processes.scm				\
  tests/profiles.scm				\
  tests/publish.scm				\
  tests/pypi.scm				\
  tests/read-print.scm				\
  tests/records.scm				\
  tests/scripts.scm				\
  tests/search-paths.scm			\
  tests/services.scm				\
  tests/services/file-sharing.scm		\
  tests/services/configuration.scm		\
  tests/services/lightdm.scm			\
  tests/services/linux.scm			\
  tests/services/telephony.scm			\
  tests/sets.scm				\
  tests/size.scm				\
  tests/status.scm				\
  tests/store-database.scm			\
  tests/store-deduplication.scm		\
  tests/store-roots.scm			\
  tests/store.scm				\
  tests/substitute.scm				\
  tests/swh.scm				\
  tests/syscalls.scm				\
  tests/system.scm				\
  tests/style.scm				\
  tests/texlive.scm				\
  tests/transformations.scm			\
  tests/ui.scm					\
  tests/union.scm				\
  tests/upstream.scm				\
  tests/utils.scm				\
  tests/uuid.scm				\
  tests/workers.scm

if HAVE_GUILE_LIB
SCM_TESTS += tests/go.scm
else
EXTRA_DIST += tests/go.scm
endif

if BUILD_DAEMON_OFFLOAD
SCM_TESTS  += tests/offload.scm
else
EXTRA_DIST += tests/offload.scm
endif

SH_TESTS =					\
  tests/guix-build.sh				\
  tests/guix-build-branch.sh			\
  tests/guix-download.sh			\
  tests/guix-gc.sh				\
  tests/guix-git-authenticate.sh		\
  tests/guix-hash.sh				\
  tests/guix-pack.sh				\
  tests/guix-pack-localstatedir.sh		\
  tests/guix-pack-relocatable.sh		\
  tests/guix-package.sh				\
  tests/guix-package-aliases.sh			\
  tests/guix-package-net.sh			\
  tests/guix-style.sh				\
  tests/guix-system.sh				\
  tests/guix-home.sh				\
  tests/guix-archive.sh				\
  tests/guix-authenticate.sh			\
  tests/guix-environment.sh			\
  tests/guix-environment-container.sh		\
  tests/guix-shell.sh				\
  tests/guix-shell-export-manifest.sh		\
  tests/guix-graph.sh				\
  tests/guix-describe.sh			\
  tests/guix-repl.sh     			\
  tests/guix-lint.sh

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
	  guix build -m $(top_srcdir)/etc/system-tests.scm -K

# Public keys used to sign substitutes.
dist_pkgdata_DATA =				\
  etc/substitutes/berlin.guix.gnu.org.pub	\
  etc/substitutes/ci.guix.gnu.org.pub		\
  etc/substitutes/ci.guix.info.pub		\
  etc/substitutes/bordeaux.guix.gnu.org.pub

# Bash completion file.
dist_bashcompletion_DATA = etc/completion/bash/guix	\
  etc/completion/bash/guix-daemon

# Zsh completion file.
dist_zshcompletion_DATA = etc/completion/zsh/_guix

# Fish completion file.
dist_fishcompletion_DATA = etc/completion/fish/guix.fish

# SELinux policy
nodist_selinux_policy_DATA = etc/guix-daemon.cil

EXTRA_DIST +=						\
  .dir-locals.el					\
  .guix-authorizations					\
  .guix-channel						\
  CODE-OF-CONDUCT					\
  HACKING						\
  ROADMAP						\
  TODO							\
  bootstrap						\
  build-aux/build-self.scm				\
  build-aux/check-channel-news.scm			\
  build-aux/check-final-inputs-self-contained.scm	\
  build-aux/compile-all.scm				\
  build-aux/compile-as-derivation.scm			\
  build-aux/config.rpath				\
  build-aux/convert-xref.scm			\
  build-aux/cuirass/hurd-manifest.scm			\
  build-aux/generate-authors.scm			\
  build-aux/test-driver.scm				\
  build-aux/update-NEWS.scm				\
  build-aux/update-guix-package.scm			\
  doc/build.scm						\
  etc/disarchive-manifest.scm				\
  etc/guix-install.sh					\
  etc/historical-authorizations				\
  etc/news.scm						\
  etc/release-manifest.scm				\
  etc/source-manifest.scm				\
  etc/system-tests.scm					\
  etc/time-travel-manifest.scm				\
  scripts/guix.in					\
  tests/cve-sample.json					\
  tests/keys/civodul.pub				\
  tests/keys/dsa.pub					\
  tests/keys/ed25519-2.pub				\
  tests/keys/ed25519-2.sec				\
  tests/keys/ed25519-3.pub				\
  tests/keys/ed25519-3.sec				\
  tests/keys/ed25519.pub				\
  tests/keys/ed25519.sec				\
  tests/keys/rsa.pub					\
  tests/keys/signing-key.pub				\
  tests/keys/signing-key.sec				\
  tests/test.drv					\
  $(TESTS)

if !BUILD_DAEMON_OFFLOAD

EXTRA_DIST +=					\
  guix/scripts/offload.scm

endif !BUILD_DAEMON_OFFLOAD


CLEANFILES =					\
  $(bin_SCRIPTS)				\
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
make-go: make-core-go make-packages-go make-system-go make-cli-go

# Define a rule to build a subset of the .go files.
define guile-compilation-rule

$(1): $(2)
	$(AM_V_at)echo "Compiling Scheme modules..." ;		\
	unset GUILE_LOAD_COMPILED_PATH ;			\
	XDG_CACHE_HOME=/nowhere					\
	host=$(host) srcdir="$(top_srcdir)"			\
	$(top_builddir)/pre-inst-env				\
	$(GUILE) -L "$(top_builddir)" -L "$(top_srcdir)"	\
	  --no-auto-compile					\
	  -s "$(top_srcdir)"/build-aux/compile-all.scm		\
	  --total $(words $(MODULES))				\
	  --completed $(3)					\
	  $$(filter %.scm,$$^)

endef

# Split compilation in several steps, each of which building a subset of
# $(MODULES).  The main goal is to reduce peak memory consumption, as reported
# in <https://issues.guix.gnu.org/48963>.  Each 'eval' call below creates a
# 'make-*-go' phony target that builds the corresponding subset.

first_half :=								\
  gnu/packages/a% gnu/packages/b% gnu/packages/c% gnu/packages/d%	\
  gnu/packages/e% gnu/packages/f% gnu/packages/g% gnu/packages/h%	\
  gnu/packages/i% gnu/packages/j% gnu/packages/k% gnu/packages/l%

MODULES_CORE      := guix.scm $(filter-out guix/scripts/%,$(filter guix/%,$(MODULES)))
MODULES_PACKAGES1 := $(filter $(first_half),$(MODULES))
MODULES_PACKAGES2 := $(filter-out $(first_half),$(filter gnu/packages/%,$(MODULES)))
MODULES_PACKAGES  := $(MODULES_PACKAGES1) $(MODULES_PACKAGES2)
MODULES_SYSTEM    := gnu.scm $(filter-out gnu/packages/%,$(filter gnu/%,$(MODULES)))
MODULES_CLI       := $(filter guix/scripts/%,$(MODULES))
MODULES_PO        := guix/build/po.scm

$(eval $(call guile-compilation-rule,make-core-go,	\
  $(MODULES_CORE) guix/config.scm $(dist_noinst_DATA),	\
  0))
.PHONY: make-core-go

$(eval $(call guile-compilation-rule,make-packages1-go,	\
  $(MODULES_PACKAGES1) make-core-go,			\
  $(words $(MODULES_CORE))))
.PHONY: make-packages1-go

$(eval $(call guile-compilation-rule,make-packages2-go,	\
  $(MODULES_PACKAGES2) make-core-go make-packages1-go,	\
  $(words $(MODULES_CORE) $(MODULES_PACKAGES1))))
.PHONY: make-packages2-go

make-packages-go: make-packages1-go make-packages2-go
.PHONY: make-packages-go

$(eval $(call guile-compilation-rule,make-system-go,	\
  $(MODULES_SYSTEM) make-packages-go make-core-go,	\
  $(words $(MODULES_CORE) $(MODULES_PACKAGES))))
.PHONY: make-system-go

$(eval $(call guile-compilation-rule,make-cli-go,			\
  $(MODULES_CLI) make-system-go make-packages-go make-core-go,		\
  $(words $(MODULES_CORE) $(MODULES_PACKAGES) $(MODULES_SYSTEM))))
.PHONY: make-cli-go

$(eval $(call guile-compilation-rule,guix/build/po.go,			\
  $(MODULES_PO),							\
  0))

SUFFIXES = .go

# Make sure source files are installed first, so that the mtime of
# installed compiled files is greater than that of installed source
# files.  See
# <http://lists.gnu.org/archive/html/guile-devel/2010-07/msg00125.html>
# for details.
guix_install_go_files = install-nobase_nodist_guileobjectDATA
$(guix_install_go_files): install-nobase_dist_guilemoduleDATA

# The above trick doesn't work for 'config.go' because both 'config.scm' and
# 'config.go' are listed in $(nobase_nodist_guileobject_DATA).  Thus, give it
# special treatment.
install-data-hook:
	touch "$(DESTDIR)$(guileobjectdir)/guix/config.go"

# Commit corresponding to the 'v1.0.0' tag.
commit_v1_0_0 = 6298c3ffd9654d3231a6f25390b056483e8f407c

# Introduction of the 'guix' channel.  Keep in sync with (guix channels)!
channel_intro_commit = 9edb3f66fd807b096b48283debdcddccfea34bad
channel_intro_signer = BBB0 2DDF 2CEA F6A8 0D1D  E643 A2A0 6DF2 A33A 54FA

# Authenticate the current Git checkout by checking signatures on every commit.
GUIX_GIT_KEYRING = origin/keyring
authenticate:
	$(AM_V_at)echo "Authenticating Git checkout..." ;	\
	guix git authenticate					\
	    --keyring=$(GUIX_GIT_KEYRING)			\
	    --cache-key=channels/guix --stats			\
	    "$(channel_intro_commit)" "$(channel_intro_signer)"

# Assuming Guix is already installed and the daemon is up and running, this
# rule builds from $(srcdir), creating and building derivations.
as-derivation:
	$(AM_V_at)echo "Building Guix in Guix..." ;		\
	$(GUILE) --no-auto-compile				\
	  "$(top_srcdir)/build-aux/compile-as-derivation.scm"	\
	  "$(abs_top_srcdir)"

SUBDIRS = po/guix po/packages
BUILT_SOURCES =

include doc/local.mk

if BUILD_DAEMON

include nix/local.mk

endif BUILD_DAEMON

ACLOCAL_AMFLAGS = -I m4

# Pass an explicit '--localstatedir' so that configure does not error out if
# it finds an existing installation with a different localstatedir.  Inherit
# 'ac_cv_guix_test_root' so that "make check" in $(distdir) does not have to
# repopulate the whole store, and to make sure $(GUIX_TEST_ROOT) is short
# enough for shebangs.
AM_DISTCHECK_CONFIGURE_FLAGS =			\
  --localstatedir="$$dc_install_base/var"	\
  --with-libgcrypt-prefix="$(LIBGCRYPT_PREFIX)"	\
  --with-libgcrypt-libdir="$(LIBGCRYPT_LIBDIR)"	\
  --enable-daemon				\
  ac_cv_guix_test_root="$(GUIX_TEST_ROOT)"

# The self-contained tarball.
guix-binary.%.tar.xz:
	$(AM_V_GEN)GUIX_PACKAGE_PATH=					\
	tarball=`$(top_builddir)/pre-inst-env guix pack -C xz		\
	  --fallback							\
	  -s "$*" --localstatedir --profile-name=current-guix		\
	  guix` ;					\
	cp "$$tarball" "$@.tmp" ; mv "$@.tmp" "$@"


# The dependency on doc-pot-update is to generate the .pot files, which are
# not checked in.
dist: doc-pot-update

dist-hook: gen-ChangeLog gen-AUTHORS gen-tarball-version
dist-hook: assert-no-store-file-names

distcheck-hook: assert-binaries-available assert-final-inputs-self-contained

EXTRA_DIST += $(top_srcdir)/.version
BUILT_SOURCES += $(top_srcdir)/.version
$(top_srcdir)/.version: config.status
	$(AM_V_GEN)echo $(VERSION) > "$@-t" && mv "$@-t" "$@"

gen-tarball-version:
	echo $(VERSION) > "$(distdir)/.tarball-version"

gen-ChangeLog:
	$(AM_V_GEN)if test -d .git; then		\
	  $(top_srcdir)/build-aux/gitlog-to-changelog	\
	    > $(distdir)/ChangeLog.tmp;			\
	  rm -f $(distdir)/ChangeLog;			\
	  mv $(distdir)/ChangeLog.tmp $(distdir)/ChangeLog;	\
	fi

gen-AUTHORS:
	$(AM_V_GEN)if test -d .git; then			\
	  rm -f "$(distdir)/AUTHORS";				\
	  $(top_builddir)/pre-inst-env "$(GUILE)"		\
	    "$(top_srcdir)/build-aux/generate-authors.scm"	\
	    "$(top_srcdir)" "$(distdir)/AUTHORS";		\
	fi

# Like 'dist', but regenerate 'configure' so we get an up-to-date
# 'PACKAGE_VERSION' string.  (In Gnulib, 'GNUmakefile' has a special trick to
# do that whenever a 'dist' target is used.)
dist-with-updated-version:
	@echo "Running './bootstrap' for new version string..."
	$(top_srcdir)/bootstrap
	$(MAKE) $(AM_MAKEFLAGS) $(top_srcdir)/.version dist

.PHONY: dist-with-updated-version


#
# Release management.
#

releasedir = release-$(PACKAGE_VERSION)

PACKAGE_FULL_TARNAME = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)

# List of source tarballs produced.  This must be kept in sync with the
# 'dist-' options of 'AM_INIT_AUTOMAKE' in 'configure.ac'.
SOURCE_TARBALLS =					\
  $(foreach ext,tar.gz,$(PACKAGE_FULL_TARNAME).$(ext))

# Systems supported by Guix.
SUPPORTED_SYSTEMS ?= x86_64-linux i686-linux armhf-linux aarch64-linux \
  powerpc64le-linux

# Guix binary tarballs.
BINARY_TARBALLS =							\
  $(foreach system,$(SUPPORTED_SYSTEMS),guix-binary.$(system).tar.xz)

# Systems supported by Guix System.
GUIX_SYSTEM_SUPPORTED_SYSTEMS ?= x86_64-linux i686-linux

# Systems for which we build Guix VMs.
GUIX_SYSTEM_VM_SYSTEMS ?= x86_64-linux

# Prefix of the Guix installation image file name.
GUIX_SYSTEM_IMAGE_BASE = guix-system-install-$(PACKAGE_VERSION)

# Prefix of the Guix VM image file name.
GUIX_SYSTEM_VM_IMAGE_BASE = guix-system-vm-image-$(PACKAGE_VERSION)

# Flags for 'guix system vm-image'.  By default create a VM image that appears
# to have a 20G hard disk.
GUIX_SYSTEM_VM_IMAGE_FLAGS ?= --image-size=30G

# Return the sequence of '-s' flags for the given systems.
system_flags = $(foreach system,$(1),-s $(system))

# The release process works in several phases:
#
#   0. We assume the developer created a 'vX.Y.Z' tag.
#   1. Build the source tarball.
#   2. Update the 'guix' package so that it corresponds to the 'vX.Y.Z' tag.
#   3. Build the binary tarballs for that 'guix' package.
#   4. Update the 'guix' package again.
#   5. Build the installation and VM images.  The images will run 'guix'
#      corresponding to 'vX.Y.Z' + 1 commit, and they will install 'vX.Y.Z'.
#
# This 'release' target takes care of everything and copies the resulting
# files to $(releasedir).
#
# XXX: Depend on 'dist' rather than 'distcheck' to work around the Gettext
# issue described at <https://savannah.gnu.org/bugs/index.php?51027>.
release: dist-with-updated-version all
	@if ! git diff-index --quiet HEAD; then			\
	  echo "There are uncommitted changes; stopping." >&2 ;	\
	  exit 1 ;						\
	fi
	$(MKDIR_P) "$(releasedir)"
	rm -f "$(releasedir)"/*
	mv $(SOURCE_TARBALLS) "$(releasedir)"
# Bump the Guix package version and build it.
	GUIX_ALLOW_ME_TO_USE_PRIVATE_COMMIT=yes \
	$(top_builddir)/pre-inst-env "$(GUILE)"	\
		$(top_srcdir)/build-aux/update-guix-package.scm	\
	   	"`git rev-parse HEAD`" "$(PACKAGE_VERSION)"
	git add $(top_srcdir)/gnu/packages/package-management.scm
	git commit -m "gnu: guix: Update to $(PACKAGE_VERSION)."
	$(top_builddir)/pre-inst-env guix build guix	\
	      $(call system_flags,$(SUPPORTED_SYSTEMS))	\
	      -v1 --no-grafts --fallback
# Generate the binary release tarballs.
	rm -f $(BINARY_TARBALLS)
	$(MAKE) $(BINARY_TARBALLS)
	for system in $(SUPPORTED_SYSTEMS) ; do					\
	  mv "guix-binary.$$system.tar.xz"					\
	      "$(releasedir)/guix-binary-$(PACKAGE_VERSION).$$system.tar.xz" ;	\
	done
# Build 'current-guix' to speed things up for the next step.
	$(top_builddir)/pre-inst-env guix build				\
	      -e '((@ (gnu packages package-management) current-guix))'	\
	      $(call system_flags,$(GUIX_SYSTEM_SUPPORTED_SYSTEMS))	\
	      -v1 --no-grafts --fallback
# Generate the ISO installation images.
	for system in $(GUIX_SYSTEM_SUPPORTED_SYSTEMS) ; do				\
	  GUIX_DISPLAYED_VERSION="`git describe --match=v* | sed -'es/^v//'`" ;		\
	  image=`$(top_builddir)/pre-inst-env						\
	    guix system image -t iso9660						\
	    --label="GUIX_$${system}_$(VERSION)"					\
            --system=$$system --fallback						\
	    gnu/system/install.scm` ;							\
	  if [ ! -f "$$image" ] ; then							\
	    echo "failed to produce Guix installation image for $$system" >&2 ;		\
	    exit 1 ;									\
	  fi ;										\
	  cp "$$image" "$(releasedir)/$(GUIX_SYSTEM_IMAGE_BASE).$$system.iso.tmp" ;	\
	  mv "$(releasedir)/$(GUIX_SYSTEM_IMAGE_BASE).$$system.iso.tmp"			\
	     "$(releasedir)/$(GUIX_SYSTEM_IMAGE_BASE).$$system.iso" ;			\
	done
# Generate the VM images.
	for system in $(GUIX_SYSTEM_VM_SYSTEMS) ; do					\
	  GUIX_DISPLAYED_VERSION="`git describe --match=v* | sed -'es/^v//'`" ;		\
	  image=`$(top_builddir)/pre-inst-env						\
	    guix system image -t qcow2 $(GUIX_SYSTEM_VM_IMAGE_FLAGS)			\
	    --save-provenance								\
	    --system=$$system --fallback						\
	    gnu/system/examples/vm-image.tmpl` ;					\
	  if [ ! -f "$$image" ] ; then							\
	    echo "failed to produce Guix VM image for $$system" >&2 ;			\
	    exit 1 ;									\
	  fi ;										\
	  cp "$$image" "$(releasedir)/$(GUIX_SYSTEM_VM_IMAGE_BASE).$$system.qcow2";	\
	done
	@echo
	@echo "Congratulations!  All the release files are now in $(releasedir)."
	@echo

update-guix-package:
	git rev-parse HEAD
	$(top_builddir)/pre-inst-env "$(GUILE)"			\
	   $(top_srcdir)/build-aux/update-guix-package.scm	\
	   "`git rev-parse HEAD`"

# Location of a checkout of <git://git.savannah.gnu.org/guix/maintenance.git>.
# Package data from this checkout is used by 'update-NEWS.scm'.
GUIX_MAINTENANCE_DIRECTORY ?= $(top_srcdir)/../guix-maintenance

update-NEWS: $(GOBJECTS)
	$(top_builddir)/pre-inst-env "$(GUILE)"				\
	  $(top_srcdir)/build-aux/update-NEWS.scm			\
	  $(top_srcdir)/NEWS "$(GUIX_MAINTENANCE_DIRECTORY)/data"

# Make sure we're not shipping a file that embeds a local /gnu/store file name.
assert-no-store-file-names:
	$(AM_V_at)if grep -r --exclude=*.texi --exclude=*.info			\
	     --exclude=*.info-[0-9] --exclude=*.dot				\
	     --exclude=*.eps --exclude-dir=bootstrap				\
	     --exclude=guix-manual.pot --exclude=guix-manual.*.po		\
	     --exclude=guix-cookbook.pot --exclude=guix-cookbook.*.po		\
	     --exclude=guix-prettify.el						\
	     --exclude=ChangeLog*						\
	     --exclude=binutils-boot-2.20*.patch				\
	     -E "$(storedir)/[a-z0-9]{32}-" $(distdir) ;			\
	then									\
	  echo "error: store file names embedded in the distribution" >&2 ;	\
	  exit 1 ;								\
	fi

# Make sure important substitutes are available.  Check only the primary
# server so that '--display-missing' doesn't print two lists.
assert-binaries-available: $(GOBJECTS)
	$(AM_V_at)$(top_builddir)/pre-inst-env				\
	  guix weather -m "$(top_srcdir)/etc/release-manifest.scm"	\
	                --substitute-urls="https://ci.guix.gnu.org"	\
	                --display-missing

# Make sure the final inputs don't refer to bootstrap tools.
assert-final-inputs-self-contained: $(GOBJECTS)
	$(AM_V_at)$(top_builddir)/pre-inst-env "$(GUILE)"			\
	  "$(top_srcdir)/build-aux/check-final-inputs-self-contained.scm"

# Validate channel news.
check-channel-news: $(GOBJECTS)
	$(AM_V_at)$(top_builddir)/pre-inst-env "$(GUILE)"	\
	  "$(top_srcdir)/build-aux/check-channel-news.scm"

# Compute the Cuirass jobs.
cuirass-jobs: $(GOBJECTS)
	rm -rf "$@"
	$(AM_V_at)$(MKDIR_P) "$@"
	$(AM_V_GEN)$(top_builddir)/pre-inst-env "$(GUILE)"		\
	  "$(top_srcdir)/build-aux/cuirass/evaluate.scm" "$@"

.PHONY: gen-ChangeLog gen-AUTHORS gen-tarball-version
.PHONY: assert-no-store-file-names assert-binaries-available
.PHONY: assert-final-inputs-self-contained check-channel-news
.PHONY: clean-go make-go as-derivation authenticate
.PHONY: update-guix-package update-NEWS cuirass-jobs release

# Downloading up-to-date PO files.

WEBLATE_REPO = https://framagit.org/tyreunom/guix-translations

# Shallow clone the Git repository behind Weblate and copy files from it if
# they contain at least one translation, and they are well-formed (Scheme
# format only), warn otherwise.  Copied files are converted to a canonical
# form.
download-po:
	dir=$$(mktemp -d); \
	git clone --depth 1 "$(WEBLATE_REPO)" "$$dir/translations" && \
	for domain in po/doc po/guix po/packages; do \
	    for po in "$$dir/translations/$$domain"/*.po; do \
	        translated=$$(LANG=en_US.UTF-8 msgfmt --statistics "$$po" 2>&1 | cut -f1 -d' '); \
	        untranslated=$$(LANG=en_US.UTF-8 msgfmt --statistics "$$po" 2>&1 | rev | cut -f3 -d' ' | rev); \
	        untranslated=$${untranslated:-0}; \
	        total=$$(($$translated+$$untranslated)); \
	        target=$$(basename "$$po"); \
	        target="$$domain/$$target"; \
	        msgfmt -c "$$po"; \
	        if msgfmt -c "$$po" && [ "$$translated" != "0" ] && ([ "$$domain" != "po/doc" ] || [ "$$translated" -gt $$(($$total/10)) ] || [ -f $$target ]); then \
	            msgfilter --no-wrap -i "$$po" cat > "$$po".tmp; \
	            mv "$$po".tmp "$$target"; \
	            echo "copied $$target."; \
	        else \
	            echo "WARN: $$target ($$translated translated messages ($$((translated/total*100))%)) was not added/updated."; \
	        fi; \
	    done; \
	done; \
	for po in po/doc/*.po; do \
	    translated=$$(LANG=en_US.UTF-8 msgfmt --statistics "$$po" 2>&1 | cut -f1 -d' '); \
	    untranslated=$$(LANG=en_US.UTF-8 msgfmt --statistics "$$po" 2>&1 | rev | cut -f3 -d' ' | rev); \
	    untranslated=$${untranslated:-0}; \
	    total=$$(($$translated + $$untranslated)); \
	    if [ "$$translated" -lt "$$(($$total/20))" ]; then \
	        echo "WARN: $$po was removed because it is below the 5% threshold: $$((translated/total*100))%"; \
	        rm $$po; \
	    fi; \
	done; \
	rm -rf "$$dir"
.PHONY: download-po

## -------------- ##
## Silent rules.  ##
## -------------- ##

AM_V_DL = $(AM_V_DL_$(V))
AM_V_DL_ = $(AM_V_DL_$(AM_DEFAULT_VERBOSITY))
AM_V_DL_0 = @echo "  DL      " $@;

AM_V_DOT = $(AM_V_DOT_$(V))
AM_V_DOT_ = $(AM_V_DOT_$(AM_DEFAULT_VERBOSITY))
AM_V_DOT_0 = @echo "  DOT     " $@;

AM_V_HELP2MAN = $(AM_V_HELP2MAN_$(V))
AM_V_HELP2MAN_ = $(AM_V_HELP2MAN_$(AM_DEFAULT_VERBOSITY))
AM_V_HELP2MAN_0 = @echo "  HELP2MAN" $@;

AM_V_PO4A = $(AM_V_PO4A_$(V))
AM_V_PO4A_ = $(AM_V_PO4A_$(AM_DEFAULT_VERBOSITY))
AM_V_PO4A_0 = @echo "  PO4A" $@;

AM_V_POXREF = $(AM_V_POXREF_$(V))
AM_V_POXREF_ = $(AM_V_POXREF_$(AM_DEFAULT_VERBOSITY))
AM_V_POXREF_0 = @echo "  POXREF" $@;
