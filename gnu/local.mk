# GNU Guix --- Functional package management for GNU
# Copyright © 2012, 2013, 2014, 2015, 2016, 2017 Ludovic Courtès <ludo@gnu.org>
# Copyright © 2013, 2014, 2015, 2016, 2017 Andreas Enge <andreas@enge.fr>
# Copyright © 2016 Mathieu Lirzin <mthl@gnu.org>
# Copyright © 2013, 2014, 2015, 2016, 2017 Mark H Weaver <mhw@netris.org>
# Copyright © 2016 Chris Marusich <cmmarusich@gmail.com>
# Copyright © 2016, 2017 Kei Kebreau <kei@openmailbox.org>
# Copyright © 2016, 2017 Rene Saavedra <rennes@openmailbox.org>
# Copyright © 2016 Adonay "adfeno" Felipe Nogueira <https://libreplanet.org/wiki/User:Adfeno> <adfeno@openmailbox.org>
# Copyright © 2016, 2017 Ricardo Wurmus <rekado@elephly.net>
# Copyright © 2016 Ben Woodcroft <donttrustben@gmail.com>
# Copyright © 2016, 2017 Alex Vong <alexvong1995@gmail.com>
# Copyright © 2016, 2017 Efraim Flashner <efraim@flashner.co.il>
# Copyright © 2017 Tobias Geerinckx-Rice <me@tobias.gr>
# Copyright © 2017 Clément Lassieur <clement@lassieur.org>
# Copyright © 2017 Mathieu Othacehe <m.othacehe@gmail.com>
# Copyright © 2017 Gábor Boskovits <boskovits@gmail.com>
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

# Definitions for the GNU System: package modules, patches, bootstrap
# binaries.

GNU_SYSTEM_MODULES =				\
  gnu.scm					\
  %D%/artwork.scm				\
  %D%/bootloader.scm				\
  %D%/bootloader/grub.scm                       \
  %D%/bootloader/extlinux.scm                   \
  %D%/bootloader/u-boot.scm                     \
  %D%/packages.scm				\
  %D%/packages/abduco.scm			\
  %D%/packages/abiword.scm			\
  %D%/packages/accessibility.scm		\
  %D%/packages/acct.scm				\
  %D%/packages/acl.scm				\
  %D%/packages/admin.scm			\
  %D%/packages/adns.scm				\
  %D%/packages/algebra.scm			\
  %D%/packages/aidc.scm				\
  %D%/packages/android.scm			\
  %D%/packages/animation.scm			\
  %D%/packages/anthy.scm			\
  %D%/packages/apl.scm				\
  %D%/packages/apr.scm				\
  %D%/packages/aspell.scm			\
  %D%/packages/assembly.scm			\
  %D%/packages/astronomy.scm			\
  %D%/packages/attr.scm				\
  %D%/packages/audio.scm			\
  %D%/packages/augeas.scm			\
  %D%/packages/autogen.scm			\
  %D%/packages/autotools.scm			\
  %D%/packages/avahi.scm			\
  %D%/packages/avr.scm				\
  %D%/packages/backup.scm			\
  %D%/packages/base.scm				\
  %D%/packages/bash.scm				\
  %D%/packages/bdw-gc.scm			\
  %D%/packages/benchmark.scm			\
  %D%/packages/bioinformatics.scm		\
  %D%/packages/bittorrent.scm			\
  %D%/packages/bison.scm			\
  %D%/packages/boost.scm			\
  %D%/packages/bootloaders.scm			\
  %D%/packages/bootstrap.scm			\
  %D%/packages/build-tools.scm			\
  %D%/packages/busybox.scm			\
  %D%/packages/c.scm				\
  %D%/packages/calcurse.scm			\
  %D%/packages/ccache.scm			\
  %D%/packages/cdrom.scm			\
  %D%/packages/certs.scm			\
  %D%/packages/check.scm			\
  %D%/packages/chez.scm				\
  %D%/packages/chromium.scm			\
  %D%/packages/ci.scm				\
  %D%/packages/cmake.scm			\
  %D%/packages/code.scm				\
  %D%/packages/commencement.scm			\
  %D%/packages/compression.scm			\
  %D%/packages/compton.scm 			\
  %D%/packages/conkeror.scm			\
  %D%/packages/conky.scm			\
  %D%/packages/connman.scm			\
  %D%/packages/cook.scm				\
  %D%/packages/cpio.scm				\
  %D%/packages/cpp.scm 				\
  %D%/packages/cppi.scm				\
  %D%/packages/cran.scm				\
  %D%/packages/cross-base.scm			\
  %D%/packages/crypto.scm			\
  %D%/packages/cryptsetup.scm			\
  %D%/packages/cups.scm				\
  %D%/packages/curl.scm				\
  %D%/packages/cyrus-sasl.scm			\
  %D%/packages/databases.scm			\
  %D%/packages/datamash.scm			\
  %D%/packages/datastructures.scm		\
  %D%/packages/dav.scm				\
  %D%/packages/dc.scm				\
  %D%/packages/debug.scm			\
  %D%/packages/dejagnu.scm			\
  %D%/packages/dico.scm				\
  %D%/packages/dictionaries.scm			\
  %D%/packages/direct-connect.scm		\
  %D%/packages/disk.scm				\
  %D%/packages/display-managers.scm		\
  %D%/packages/django.scm			\
  %D%/packages/djvu.scm				\
  %D%/packages/dns.scm				\
  %D%/packages/docbook.scm			\
  %D%/packages/docker.scm			\
  %D%/packages/documentation.scm		\
  %D%/packages/dunst.scm			\
  %D%/packages/dvtm.scm				\
  %D%/packages/ebook.scm			\
  %D%/packages/ed.scm				\
  %D%/packages/education.scm			\
  %D%/packages/electronics.scm			\
  %D%/packages/elf.scm				\
  %D%/packages/elixir.scm			\
  %D%/packages/embedded.scm			\
  %D%/packages/emacs.scm			\
  %D%/packages/enchant.scm			\
  %D%/packages/engineering.scm			\
  %D%/packages/enlightenment.scm		\
  %D%/packages/entr.scm				\
  %D%/packages/erlang.scm			\
  %D%/packages/fcitx.scm			\
  %D%/packages/figlet.scm			\
  %D%/packages/file.scm				\
  %D%/packages/file-systems.scm			\
  %D%/packages/finance.scm			\
  %D%/packages/firmware.scm			\
  %D%/packages/flashing-tools.scm		\
  %D%/packages/flex.scm				\
  %D%/packages/fltk.scm				\
  %D%/packages/fonts.scm			\
  %D%/packages/fontutils.scm			\
  %D%/packages/fpga.scm				\
  %D%/packages/forth.scm			\
  %D%/packages/freedesktop.scm			\
  %D%/packages/freeipmi.scm			\
  %D%/packages/ftp.scm				\
  %D%/packages/fribidi.scm			\
  %D%/packages/fvwm.scm				\
  %D%/packages/game-development.scm		\
  %D%/packages/games.scm			\
  %D%/packages/gawk.scm				\
  %D%/packages/gcal.scm				\
  %D%/packages/gcc.scm				\
  %D%/packages/gd.scm				\
  %D%/packages/gdb.scm				\
  %D%/packages/geo.scm				\
  %D%/packages/gettext.scm			\
  %D%/packages/ghostscript.scm			\
  %D%/packages/gimp.scm				\
  %D%/packages/gkrellm.scm			\
  %D%/packages/gl.scm				\
  %D%/packages/glib.scm				\
  %D%/packages/gnome.scm			\
  %D%/packages/gnu-doc.scm			\
  %D%/packages/gnucash.scm			\
  %D%/packages/gnunet.scm			\
  %D%/packages/gnupg.scm			\
  %D%/packages/gnustep.scm			\
  %D%/packages/gnuzilla.scm			\
  %D%/packages/gnu-pw-mgr.scm			\
  %D%/packages/gobby.scm			\
  %D%/packages/golang.scm			\
  %D%/packages/gperf.scm			\
  %D%/packages/gprolog.scm			\
  %D%/packages/gps.scm				\
  %D%/packages/graphics.scm			\
  %D%/packages/graphviz.scm			\
  %D%/packages/groff.scm			\
  %D%/packages/gsasl.scm			\
  %D%/packages/gstreamer.scm			\
  %D%/packages/gtk.scm				\
  %D%/packages/guile.scm			\
  %D%/packages/guile-wm.scm			\
  %D%/packages/gv.scm				\
  %D%/packages/gxmessage.scm			\
  %D%/packages/haskell.scm			\
  %D%/packages/hexedit.scm			\
  %D%/packages/hugs.scm				\
  %D%/packages/hurd.scm				\
  %D%/packages/ibus.scm				\
  %D%/packages/icu4c.scm			\
  %D%/packages/idris.scm			\
  %D%/packages/idutils.scm			\
  %D%/packages/image.scm			\
  %D%/packages/image-processing.scm	\
  %D%/packages/image-viewers.scm	\
  %D%/packages/imagemagick.scm			\
  %D%/packages/indent.scm			\
  %D%/packages/inklingreader.scm		\
  %D%/packages/inkscape.scm			\
  %D%/packages/irc.scm  			\
  %D%/packages/iso-codes.scm			\
  %D%/packages/java.scm				\
  %D%/packages/javascript.scm			\
  %D%/packages/jemalloc.scm			\
  %D%/packages/jrnl.scm				\
  %D%/packages/julia.scm			\
  %D%/packages/kde.scm              \
  %D%/packages/kde-frameworks.scm		\
  %D%/packages/kerberos.scm			\
  %D%/packages/key-mon.scm			\
  %D%/packages/kodi.scm				\
  %D%/packages/language.scm			\
  %D%/packages/ldc.scm				\
  %D%/packages/lego.scm				\
  %D%/packages/less.scm				\
  %D%/packages/lesstif.scm			\
  %D%/packages/libbsd.scm			\
  %D%/packages/libcanberra.scm			\
  %D%/packages/libdaemon.scm			\
  %D%/packages/libedit.scm			\
  %D%/packages/libevent.scm			\
  %D%/packages/libffcall.scm			\
  %D%/packages/libffi.scm			\
  %D%/packages/libftdi.scm			\
  %D%/packages/calendar.scm			\
  %D%/packages/libidn.scm			\
  %D%/packages/libphidget.scm			\
  %D%/packages/libreoffice.scm			\
  %D%/packages/libsigsegv.scm			\
  %D%/packages/libunistring.scm			\
  %D%/packages/libusb.scm			\
  %D%/packages/libunwind.scm			\
  %D%/packages/libupnp.scm			\
  %D%/packages/lighting.scm                     \
  %D%/packages/linux.scm			\
  %D%/packages/lirc.scm				\
  %D%/packages/lisp.scm				\
  %D%/packages/llvm.scm				\
  %D%/packages/lout.scm				\
  %D%/packages/logging.scm			\
  %D%/packages/lolcode.scm                      \
  %D%/packages/lsof.scm				\
  %D%/packages/lua.scm				\
  %D%/packages/lxde.scm				\
  %D%/packages/lxqt.scm				\
  %D%/packages/m4.scm				\
  %D%/packages/machine-learning.scm		\
  %D%/packages/man.scm				\
  %D%/packages/mail.scm				\
  %D%/packages/make-bootstrap.scm		\
  %D%/packages/markup.scm			\
  %D%/packages/marst.scm			\
  %D%/packages/mate.scm             \
  %D%/packages/maths.scm			\
  %D%/packages/mc.scm				\
  %D%/packages/mcrypt.scm			\
  %D%/packages/medical.scm			\
  %D%/packages/mes.scm				\
  %D%/packages/messaging.scm			\
  %D%/packages/mingw.scm			\
  %D%/packages/microcom.scm			\
  %D%/packages/moe.scm				\
  %D%/packages/monitoring.scm			\
  %D%/packages/mono.scm				\
  %D%/packages/moreutils.scm			\
  %D%/packages/mpd.scm				\
  %D%/packages/mp3.scm				\
  %D%/packages/mpi.scm				\
  %D%/packages/multiprecision.scm		\
  %D%/packages/music.scm			\
  %D%/packages/musl.scm				\
  %D%/packages/mtools.scm			\
  %D%/packages/nano.scm				\
  %D%/packages/ncdu.scm				\
  %D%/packages/ncurses.scm			\
  %D%/packages/netpbm.scm			\
  %D%/packages/nettle.scm			\
  %D%/packages/networking.scm			\
  %D%/packages/nfs.scm                          \
  %D%/packages/nickle.scm                       \
  %D%/packages/nim.scm  			\
  %D%/packages/ninja.scm			\
  %D%/packages/node.scm				\
  %D%/packages/noweb.scm			\
  %D%/packages/ntp.scm				\
  %D%/packages/nutrition.scm			\
  %D%/packages/nvi.scm				\
  %D%/packages/ocaml.scm			\
  %D%/packages/ocr.scm				\
  %D%/packages/onc-rpc.scm			\
  %D%/packages/openbox.scm			\
  %D%/packages/openldap.scm			\
  %D%/packages/openstack.scm			\
  %D%/packages/orpheus.scm			\
  %D%/packages/ots.scm				\
  %D%/packages/package-management.scm		\
  %D%/packages/parallel.scm			\
  %D%/packages/password-utils.scm		\
  %D%/packages/patchutils.scm			\
  %D%/packages/pciutils.scm			\
  %D%/packages/pcre.scm				\
  %D%/packages/pdf.scm				\
  %D%/packages/pem.scm				\
  %D%/packages/perl.scm				\
  %D%/packages/perl-web.scm			\
  %D%/packages/photo.scm			\
  %D%/packages/php.scm				\
  %D%/packages/pkg-config.scm			\
  %D%/packages/plotutils.scm			\
  %D%/packages/polkit.scm			\
  %D%/packages/popt.scm				\
  %D%/packages/pth.scm				\
  %D%/packages/pulseaudio.scm			\
  %D%/packages/pumpio.scm			\
  %D%/packages/pretty-print.scm			\
  %D%/packages/protobuf.scm			\
  %D%/packages/pv.scm				\
  %D%/packages/python.scm			\
  %D%/packages/tryton.scm			\
  %D%/packages/qt.scm				\
  %D%/packages/ragel.scm			\
  %D%/packages/rails.scm			\
  %D%/packages/ratpoison.scm			\
  %D%/packages/rdesktop.scm			\
  %D%/packages/rdf.scm				\
  %D%/packages/re2c.scm				\
  %D%/packages/readline.scm			\
  %D%/packages/regex.scm				\
  %D%/packages/rrdtool.scm			\
  %D%/packages/rsync.scm			\
  %D%/packages/ruby.scm				\
  %D%/packages/rush.scm				\
  %D%/packages/rust.scm				\
  %D%/packages/samba.scm			\
  %D%/packages/sawfish.scm			\
  %D%/packages/scanner.scm			\
  %D%/packages/scheme.scm			\
  %D%/packages/screen.scm			\
  %D%/packages/scribus.scm			\
  %D%/packages/scsi.scm				\
  %D%/packages/sdcc.scm				\
  %D%/packages/sdl.scm				\
  %D%/packages/search.scm			\
  %D%/packages/security-token.scm		\
  %D%/packages/selinux.scm			\
  %D%/packages/serialization.scm		\
  %D%/packages/serveez.scm			\
  %D%/packages/shells.scm			\
  %D%/packages/shellutils.scm			\
  %D%/packages/simh.scm				\
  %D%/packages/skarnet.scm			\
  %D%/packages/skribilo.scm			\
  %D%/packages/slang.scm			\
  %D%/packages/smalltalk.scm			\
  %D%/packages/sml.scm				\
  %D%/packages/speech.scm			\
  %D%/packages/spice.scm			\
  %D%/packages/ssh.scm				\
  %D%/packages/sssd.scm				\
  %D%/packages/stalonetray.scm			\
  %D%/packages/statistics.scm			\
  %D%/packages/storage.scm			\
  %D%/packages/suckless.scm			\
  %D%/packages/swig.scm				\
  %D%/packages/sync.scm			\
  %D%/packages/synergy.scm			\
  %D%/packages/syndication.scm			\
  %D%/packages/task-management.scm		\
  %D%/packages/tbb.scm				\
  %D%/packages/tcl.scm				\
  %D%/packages/telephony.scm			\
  %D%/packages/terminals.scm			\
  %D%/packages/texinfo.scm			\
  %D%/packages/tex.scm				\
  %D%/packages/textutils.scm			\
  %D%/packages/text-editors.scm			\
  %D%/packages/time.scm				\
  %D%/packages/tls.scm				\
  %D%/packages/tmux.scm				\
  %D%/packages/tor.scm				\
  %D%/packages/tv.scm				\
  %D%/packages/uml.scm				\
  %D%/packages/unrtf.scm			\
  %D%/packages/upnp.scm				\
  %D%/packages/uucp.scm				\
  %D%/packages/valgrind.scm			\
  %D%/packages/version-control.scm		\
  %D%/packages/video.scm			\
  %D%/packages/vim.scm				\
  %D%/packages/virtualization.scm		\
  %D%/packages/vpn.scm				\
  %D%/packages/w3m.scm				\
  %D%/packages/wdiff.scm			\
  %D%/packages/web.scm				\
  %D%/packages/web-browsers.scm			\
  %D%/packages/webkit.scm			\
  %D%/packages/wget.scm				\
  %D%/packages/wicd.scm				\
  %D%/packages/wine.scm				\
  %D%/packages/wm.scm				\
  %D%/packages/wordnet.scm			\
  %D%/packages/wv.scm				\
  %D%/packages/wxwidgets.scm			\
  %D%/packages/xfig.scm				\
  %D%/packages/xiph.scm				\
  %D%/packages/xml.scm				\
  %D%/packages/xnee.scm				\
  %D%/packages/xdisorg.scm			\
  %D%/packages/xorg.scm				\
  %D%/packages/xfce.scm				\
  %D%/packages/zile.scm				\
						\
  %D%/services.scm				\
  %D%/services/admin.scm			\
  %D%/services/avahi.scm			\
  %D%/services/base.scm				\
  %D%/services/configuration.scm		\
  %D%/services/cuirass.scm			\
  %D%/services/cups.scm				\
  %D%/services/databases.scm			\
  %D%/services/dbus.scm				\
  %D%/services/desktop.scm			\
  %D%/services/dict.scm				\
  %D%/services/dns.scm				\
  %D%/services/kerberos.scm			\
  %D%/services/lirc.scm				\
  %D%/services/mail.scm				\
  %D%/services/mcron.scm			\
  %D%/services/messaging.scm			\
  %D%/services/networking.scm			\
  %D%/services/nfs.scm			\
  %D%/services/shepherd.scm			\
  %D%/services/herd.scm				\
  %D%/services/pm.scm				\
  %D%/services/sddm.scm				\
  %D%/services/spice.scm				\
  %D%/services/ssh.scm				\
  %D%/services/sysctl.scm			\
  %D%/services/version-control.scm              \
  %D%/services/vpn.scm				\
  %D%/services/web.scm				\
  %D%/services/xorg.scm				\
						\
  %D%/system.scm				\
  %D%/system/file-systems.scm			\
  %D%/system/install.scm			\
  %D%/system/linux-container.scm		\
  %D%/system/linux-initrd.scm			\
  %D%/system/locale.scm				\
  %D%/system/mapped-devices.scm			\
  %D%/system/nss.scm				\
  %D%/system/pam.scm				\
  %D%/system/shadow.scm				\
  %D%/system/vm.scm				\
						\
  %D%/build/activation.scm			\
  %D%/build/cross-toolchain.scm			\
  %D%/build/file-systems.scm			\
  %D%/build/install.scm				\
  %D%/build/linux-boot.scm			\
  %D%/build/linux-container.scm			\
  %D%/build/linux-initrd.scm			\
  %D%/build/linux-modules.scm			\
  %D%/build/marionette.scm			\
  %D%/build/shepherd.scm			\
  %D%/build/vm.scm				\
						\
  %D%/tests.scm					\
  %D%/tests/admin.scm				\
  %D%/tests/base.scm				\
  %D%/tests/databases.scm			\
  %D%/tests/dict.scm				\
  %D%/tests/nfs.scm				\
  %D%/tests/install.scm				\
  %D%/tests/mail.scm				\
  %D%/tests/messaging.scm			\
  %D%/tests/networking.scm			\
  %D%/tests/ssh.scm				\
  %D%/tests/web.scm

# Modules that do not need to be compiled.
MODULES_NOT_COMPILED +=				\
  %D%/build/svg.scm

patchdir = $(guilemoduledir)/%D%/packages/patches
dist_patch_DATA =						\
  %D%/packages/patches/4store-fix-buildsystem.patch		\
  %D%/packages/patches/a2ps-CVE-2001-1593.patch	\
  %D%/packages/patches/a2ps-CVE-2014-0466.patch	\
  %D%/packages/patches/abiword-explictly-cast-bools.patch	\
  %D%/packages/patches/abiword-black-drawing-with-gtk322.patch	\
  %D%/packages/patches/acl-hurd-path-max.patch			\
  %D%/packages/patches/aegis-constness-error.patch         	\
  %D%/packages/patches/aegis-perl-tempdir1.patch           	\
  %D%/packages/patches/aegis-perl-tempdir2.patch           	\
  %D%/packages/patches/aegis-test-fixup-1.patch            	\
  %D%/packages/patches/aegis-test-fixup-2.patch            	\
  %D%/packages/patches/agg-am_c_prototype.patch			\
  %D%/packages/patches/ansible-wrap-program-hack.patch		\
  %D%/packages/patches/antiword-CVE-2014-8123.patch			\
  %D%/packages/patches/apr-skip-getservbyname-test.patch	\
  %D%/packages/patches/aspell-default-dict-dir.patch		\
  %D%/packages/patches/ath9k-htc-firmware-binutils.patch	\
  %D%/packages/patches/ath9k-htc-firmware-gcc.patch		\
  %D%/packages/patches/ath9k-htc-firmware-objcopy.patch		\
  %D%/packages/patches/automake-skip-amhello-tests.patch	\
  %D%/packages/patches/automake-regexp-syntax.patch		\
  %D%/packages/patches/automake-test-gzip-warning.patch		\
  %D%/packages/patches/avahi-localstatedir.patch		\
  %D%/packages/patches/avidemux-install-to-lib.patch		\
  %D%/packages/patches/awesome-reproducible-png.patch		\
  %D%/packages/patches/azr3.patch				\
  %D%/packages/patches/bash-completion-directories.patch	\
  %D%/packages/patches/binutils-ld-new-dtags.patch		\
  %D%/packages/patches/binutils-loongson-workaround.patch	\
  %D%/packages/patches/blast+-fix-makefile.patch		\
  %D%/packages/patches/byobu-writable-status.patch		\
  %D%/packages/patches/cairo-CVE-2016-9082.patch			\
  %D%/packages/patches/calibre-drop-unrar.patch			\
  %D%/packages/patches/calibre-no-updates-dialog.patch		\
  %D%/packages/patches/calibre-use-packaged-feedparser.patch	\
  %D%/packages/patches/cdparanoia-fpic.patch			\
  %D%/packages/patches/cdrtools-3.01-mkisofs-isoinfo.patch 	\
  %D%/packages/patches/ceph-disable-cpu-optimizations.patch	\
  %D%/packages/patches/ceph-disable-unittest-throttle.patch	\
  %D%/packages/patches/ceph-skip-collect-sys-info-test.patch	\
  %D%/packages/patches/ceph-skip-unittest_blockdev.patch	\
  %D%/packages/patches/chicken-CVE-2017-6949.patch		\
  %D%/packages/patches/chicken-CVE-2017-11343.patch		\
  %D%/packages/patches/chmlib-inttypes.patch			\
  %D%/packages/patches/chromium-disable-api-keys-warning.patch	\
  %D%/packages/patches/chromium-disable-third-party-cookies.patch	\
  %D%/packages/patches/chromium-gn-bootstrap.patch		\
  %D%/packages/patches/chromium-system-libevent.patch		\
  %D%/packages/patches/chromium-system-libxml.patch		\
  %D%/packages/patches/chromium-system-icu.patch		\
  %D%/packages/patches/chromium-system-nspr.patch		\
  %D%/packages/patches/clang-libc-search-path.patch		\
  %D%/packages/patches/clang-3.8-libc-search-path.patch		\
  %D%/packages/patches/clucene-pkgconfig.patch			\
  %D%/packages/patches/clx-remove-demo.patch			\
  %D%/packages/patches/cmake-fix-tests.patch			\
  %D%/packages/patches/coda-use-system-libs.patch		\
  %D%/packages/patches/cool-retro-term-dont-check-uninit-member.patch	\
  %D%/packages/patches/cool-retro-term-fix-array-size.patch	\
  %D%/packages/patches/cool-retro-term-memory-leak-1.patch	\
  %D%/packages/patches/cool-retro-term-remove-non-free-fonts.patch	\
  %D%/packages/patches/coreutils-cut-huge-range-test.patch	\
  %D%/packages/patches/cpio-CVE-2016-2037.patch			\
  %D%/packages/patches/cpufrequtils-fix-aclocal.patch		\
  %D%/packages/patches/cracklib-CVE-2016-6318.patch		\
  %D%/packages/patches/cracklib-fix-buffer-overflow.patch	\
  %D%/packages/patches/crawl-upgrade-saves.patch		\
  %D%/packages/patches/crda-optional-gcrypt.patch		\
  %D%/packages/patches/crossmap-allow-system-pysam.patch	\
  %D%/packages/patches/csound-header-ordering.patch		\
  %D%/packages/patches/clucene-contribs-lib.patch               \
  %D%/packages/patches/cursynth-wave-rand.patch			\
  %D%/packages/patches/cyrus-sasl-CVE-2013-4122.patch		\
  %D%/packages/patches/dblatex-remove-multirow.patch		\
  %D%/packages/patches/dbus-helper-search-path.patch		\
  %D%/packages/patches/deja-dup-use-ref-keyword-for-iter.patch	\
  %D%/packages/patches/dfu-programmer-fix-libusb.patch		\
  %D%/packages/patches/diffutils-gets-undeclared.patch		\
  %D%/packages/patches/doc++-include-directives.patch		\
  %D%/packages/patches/doc++-segfault-fix.patch			\
  %D%/packages/patches/doxygen-test.patch			\
  %D%/packages/patches/dvd+rw-tools-add-include.patch 		\
  %D%/packages/patches/elfutils-tests-ptrace.patch		\
  %D%/packages/patches/elixir-disable-failing-tests.patch	\
  %D%/packages/patches/einstein-build.patch			\
  %D%/packages/patches/emacs-exec-path.patch			\
  %D%/packages/patches/emacs-fix-scheme-indent-function.patch	\
  %D%/packages/patches/emacs-scheme-complete-scheme-r5rs-info.patch	\
  %D%/packages/patches/emacs-source-date-epoch.patch		\
  %D%/packages/patches/erlang-man-path.patch			\
  %D%/packages/patches/eudev-rules-directory.patch		\
  %D%/packages/patches/evilwm-lost-focus-bug.patch		\
  %D%/packages/patches/exim-CVE-2017-1000369.patch		\
  %D%/packages/patches/fastcap-mulGlobal.patch			\
  %D%/packages/patches/fastcap-mulSetup.patch			\
  %D%/packages/patches/fasthenry-spAllocate.patch		\
  %D%/packages/patches/fasthenry-spBuild.patch			\
  %D%/packages/patches/fasthenry-spUtils.patch			\
  %D%/packages/patches/fasthenry-spSolve.patch			\
  %D%/packages/patches/fasthenry-spFactor.patch			\
  %D%/packages/patches/fcgi-2.4.0-gcc44-fixes.patch		\
  %D%/packages/patches/fcgi-2.4.0-poll.patch			\
  %D%/packages/patches/findutils-localstatedir.patch		\
  %D%/packages/patches/findutils-gnulib-multi-core.patch	\
  %D%/packages/patches/findutils-test-xargs.patch		\
  %D%/packages/patches/flint-ldconfig.patch			\
  %D%/packages/patches/fltk-shared-lib-defines.patch		\
  %D%/packages/patches/fltk-xfont-on-demand.patch		\
  %D%/packages/patches/fontforge-svg-modtime.patch		\
  %D%/packages/patches/freeimage-CVE-2015-0852.patch		\
  %D%/packages/patches/freeimage-CVE-2016-5684.patch		\
  %D%/packages/patches/freeimage-fix-build-with-gcc-5.patch	\
  %D%/packages/patches/fuse-overlapping-headers.patch				\
  %D%/packages/patches/gawk-shell.patch				\
  %D%/packages/patches/gcc-arm-bug-71399.patch			\
  %D%/packages/patches/gcc-arm-link-spec-fix.patch		\
  %D%/packages/patches/gcc-asan-powerpc-missing-include.patch	\
  %D%/packages/patches/gcc-cross-environment-variables.patch	\
  %D%/packages/patches/gcc-libvtv-runpath.patch			\
  %D%/packages/patches/gcc-strmov-store-file-names.patch	\
  %D%/packages/patches/gcc-4.6-gnu-inline.patch			\
  %D%/packages/patches/gcc-4.9.3-mingw-gthr-default.patch	\
  %D%/packages/patches/gcc-5.0-libvtv-runpath.patch		\
  %D%/packages/patches/gcc-5-source-date-epoch-1.patch		\
  %D%/packages/patches/gcc-5-source-date-epoch-2.patch		\
  %D%/packages/patches/gcc-6-arm-none-eabi-multilib.patch	\
  %D%/packages/patches/gcc-6-cross-environment-variables.patch	\
  %D%/packages/patches/gcr-disable-failing-tests.patch		\
  %D%/packages/patches/gcr-fix-collection-tests-to-work-with-gpg-21.patch	\
  %D%/packages/patches/gdk-pixbuf-list-dir.patch		\
  %D%/packages/patches/gd-CVE-2017-7890.patch		\
  %D%/packages/patches/gd-fix-gd2-read-test.patch		\
  %D%/packages/patches/gd-fix-tests-on-i686.patch		\
  %D%/packages/patches/gd-freetype-test-failure.patch		\
  %D%/packages/patches/gd-php-73968-Fix-109-XBM-reading.patch		\
  %D%/packages/patches/gegl-CVE-2012-4433.patch			\
  %D%/packages/patches/gemma-intel-compat.patch			\
  %D%/packages/patches/geoclue-config.patch			\
  %D%/packages/patches/gettext-multi-core.patch          	\
  %D%/packages/patches/gettext-gnulib-multi-core.patch          \
  %D%/packages/patches/ghc-dont-pass-linker-flags-via-response-files.patch	\
  %D%/packages/patches/ghostscript-CVE-2017-8291.patch		\
  %D%/packages/patches/ghostscript-no-header-id.patch		\
  %D%/packages/patches/ghostscript-no-header-uuid.patch		\
  %D%/packages/patches/ghostscript-no-header-creationdate.patch \
  %D%/packages/patches/ghostscript-runpath.patch		\
  %D%/packages/patches/glib-networking-ssl-cert-file.patch	\
  %D%/packages/patches/glib-tests-timer.patch			\
  %D%/packages/patches/glibc-CVE-2015-5180.patch		\
  %D%/packages/patches/glibc-CVE-2015-7547.patch		\
  %D%/packages/patches/glibc-CVE-2016-3075.patch		\
  %D%/packages/patches/glibc-CVE-2016-3706.patch		\
  %D%/packages/patches/glibc-CVE-2016-4429.patch		\
  %D%/packages/patches/glibc-CVE-2017-1000366-pt1.patch		\
  %D%/packages/patches/glibc-CVE-2017-1000366-pt2.patch		\
  %D%/packages/patches/glibc-CVE-2017-1000366-pt3.patch		\
  %D%/packages/patches/glibc-bootstrap-system.patch		\
  %D%/packages/patches/glibc-ldd-x86_64.patch			\
  %D%/packages/patches/glibc-locales.patch			\
  %D%/packages/patches/glibc-memchr-overflow-i686.patch		\
  %D%/packages/patches/glibc-o-largefile.patch			\
  %D%/packages/patches/glibc-vectorized-strcspn-guards.patch	\
  %D%/packages/patches/glibc-versioned-locpath.patch		\
  %D%/packages/patches/glog-gcc-5-demangling.patch		\
  %D%/packages/patches/gmp-arm-asm-nothumb.patch		\
  %D%/packages/patches/gmp-faulty-test.patch			\
  %D%/packages/patches/gnome-tweak-tool-search-paths.patch	\
  %D%/packages/patches/gnucash-price-quotes-perl.patch		\
  %D%/packages/patches/gnutls-skip-trust-store-test.patch	\
  %D%/packages/patches/gnutls-skip-pkgconfig-test.patch		\
  %D%/packages/patches/gobject-introspection-absolute-shlib-path.patch \
  %D%/packages/patches/gobject-introspection-cc.patch		\
  %D%/packages/patches/gobject-introspection-girepository.patch	\
  %D%/packages/patches/graphite2-ffloat-store.patch		\
  %D%/packages/patches/grep-gnulib-lock.patch                   \
  %D%/packages/patches/grep-timing-sensitive-test.patch		\
  %D%/packages/patches/groff-source-date-epoch.patch		\
  %D%/packages/patches/gsl-test-i686.patch			\
  %D%/packages/patches/gspell-dash-test.patch			\
  %D%/packages/patches/guile-1.8-cpp-4.5.patch			\
  %D%/packages/patches/guile-2.2-default-utf8.patch		\
  %D%/packages/patches/guile-bytestructures-name-clash.patch	\
  %D%/packages/patches/guile-default-utf8.patch			\
  %D%/packages/patches/guile-linux-syscalls.patch		\
  %D%/packages/patches/guile-present-coding.patch		\
  %D%/packages/patches/guile-relocatable.patch			\
  %D%/packages/patches/guile-rsvg-pkgconfig.patch		\
  %D%/packages/patches/gtk2-respect-GUIX_GTK2_PATH.patch	\
  %D%/packages/patches/gtk2-respect-GUIX_GTK2_IM_MODULE_FILE.patch \
  %D%/packages/patches/gtk2-theme-paths.patch			\
  %D%/packages/patches/gtk3-respect-GUIX_GTK3_PATH.patch	\
  %D%/packages/patches/gtk3-respect-GUIX_GTK3_IM_MODULE_FILE.patch \
  %D%/packages/patches/gtkglext-disable-disable-deprecated.patch \
  %D%/packages/patches/handbrake-pkg-config-path.patch		\
  %D%/packages/patches/hdf4-architectures.patch 		\
  %D%/packages/patches/hdf4-reproducibility.patch 		\
  %D%/packages/patches/hdf4-shared-fortran.patch 		\
  %D%/packages/patches/hdf5-config-date.patch			\
  %D%/packages/patches/hdf-eos2-build-shared.patch 		\
  %D%/packages/patches/hdf-eos2-remove-gctp.patch		\
  %D%/packages/patches/hdf-eos2-fortrantests.patch		\
  %D%/packages/patches/hdf-eos5-build-shared.patch 		\
  %D%/packages/patches/hdf-eos5-remove-gctp.patch		\
  %D%/packages/patches/hdf-eos5-fix-szip.patch			\
  %D%/packages/patches/hdf-eos5-fortrantests.patch		\
  %D%/packages/patches/heimdal-CVE-2017-6594.patch		\
  %D%/packages/patches/heimdal-CVE-2017-11103.patch		\
  %D%/packages/patches/hmmer-remove-cpu-specificity.patch	\
  %D%/packages/patches/higan-remove-march-native-flag.patch	\
  %D%/packages/patches/hubbub-sort-entities.patch		\
  %D%/packages/patches/hurd-fix-eth-multiplexer-dependency.patch        \
  %D%/packages/patches/hydra-disable-darcs-test.patch		\
  %D%/packages/patches/icecat-avoid-bundled-libraries.patch	\
  %D%/packages/patches/icu4c-CVE-2017-7867-CVE-2017-7868.patch	\
  %D%/packages/patches/icu4c-reset-keyword-list-iterator.patch	\
  %D%/packages/patches/id3lib-CVE-2007-4460.patch			\
  %D%/packages/patches/ilmbase-fix-tests.patch			\
  %D%/packages/patches/intltool-perl-compatibility.patch	\
  %D%/packages/patches/isl-0.11.1-aarch64-support.patch	\
  %D%/packages/patches/jacal-fix-texinfo.patch			\
  %D%/packages/patches/jbig2dec-ignore-testtest.patch		\
  %D%/packages/patches/jbig2dec-CVE-2016-9601.patch		\
  %D%/packages/patches/jbig2dec-CVE-2017-7885.patch		\
  %D%/packages/patches/jbig2dec-CVE-2017-7975.patch		\
  %D%/packages/patches/jbig2dec-CVE-2017-7976.patch		\
  %D%/packages/patches/jq-CVE-2015-8863.patch			\
  %D%/packages/patches/kdbusaddons-kinit-file-name.patch	\
  %D%/packages/patches/khmer-use-libraries.patch                \
  %D%/packages/patches/kiki-level-selection-crash.patch		\
  %D%/packages/patches/kiki-makefile.patch			\
  %D%/packages/patches/kiki-missing-includes.patch		\
  %D%/packages/patches/kiki-portability-64bit.patch		\
  %D%/packages/patches/kmod-module-directory.patch		\
  %D%/packages/patches/kobodeluxe-paths.patch			\
  %D%/packages/patches/kobodeluxe-enemies-pipe-decl.patch	\
  %D%/packages/patches/kobodeluxe-const-charp-conversion.patch	\
  %D%/packages/patches/kobodeluxe-manpage-minus-not-hyphen.patch	\
  %D%/packages/patches/kobodeluxe-midicon-segmentation-fault.patch	\
  %D%/packages/patches/kobodeluxe-graphics-window-signed-char.patch	\
  %D%/packages/patches/laby-make-install.patch			\
  %D%/packages/patches/lcms-CVE-2016-10165.patch		\
  %D%/packages/patches/ldc-disable-tests.patch			\
  %D%/packages/patches/ldc-1.1.0-disable-dmd-tests.patch	\
  %D%/packages/patches/ldc-1.1.0-disable-phobos-tests.patch	\
  %D%/packages/patches/liba52-enable-pic.patch			\
  %D%/packages/patches/liba52-link-with-libm.patch		\
  %D%/packages/patches/liba52-set-soname.patch			\
  %D%/packages/patches/liba52-use-mtune-not-mcpu.patch		\
  %D%/packages/patches/libbase-fix-includes.patch		\
  %D%/packages/patches/libbase-use-own-logging.patch		\
  %D%/packages/patches/libbonobo-activation-test-race.patch	\
  %D%/packages/patches/libcanberra-sound-theme-freedesktop.patch \
  %D%/packages/patches/libcroco-CVE-2017-7960.patch		\
  %D%/packages/patches/libcroco-CVE-2017-7961.patch		\
  %D%/packages/patches/libdrm-symbol-check.patch		\
  %D%/packages/patches/libetonyek-build-with-mdds-1.2.patch     \
  %D%/packages/patches/libevent-dns-tests.patch			\
  %D%/packages/patches/libevent-2.0-CVE-2016-10195.patch	\
  %D%/packages/patches/libevent-2.0-CVE-2016-10196.patch	\
  %D%/packages/patches/libevent-2.0-CVE-2016-10197.patch	\
  %D%/packages/patches/libevent-2.0-evbuffer-add-use-last-with-datap.patch	\
  %D%/packages/patches/libevent-2.1-dns-tests.patch		\
  %D%/packages/patches/libevent-2.1-skip-failing-test.patch	\
  %D%/packages/patches/libgit2-0.25.1-mtime-0.patch		\
  %D%/packages/patches/libgdata-fix-tests.patch			\
  %D%/packages/patches/libgdata-glib-duplicate-tests.patch	\
  %D%/packages/patches/libffi-3.2.1-complex-alpha.patch		\
  %D%/packages/patches/libjxr-fix-function-signature.patch	\
  %D%/packages/patches/libjxr-fix-typos.patch			\
  %D%/packages/patches/liboop-mips64-deplibs-fix.patch		\
  %D%/packages/patches/libotr-test-auth-fix.patch		\
  %D%/packages/patches/liblxqt-include.patch			\
  %D%/packages/patches/libmad-armv7-thumb-pt1.patch		\
  %D%/packages/patches/libmad-armv7-thumb-pt2.patch		\
  %D%/packages/patches/libmad-frame-length.patch		\
  %D%/packages/patches/libmad-mips-newgcc.patch			\
  %D%/packages/patches/libmwaw-CVE-2017-9433.patch		\
  %D%/packages/patches/libsndfile-armhf-type-checks.patch	\
  %D%/packages/patches/libsndfile-CVE-2017-8361-8363-8365.patch	\
  %D%/packages/patches/libsndfile-CVE-2017-8362.patch		\
  %D%/packages/patches/libssh-hostname-parser-bug.patch		\
  %D%/packages/patches/libssh2-fix-build-failure-with-gcrypt.patch	\
  %D%/packages/patches/libtar-CVE-2013-4420.patch 		\
  %D%/packages/patches/libtasn1-CVE-2017-10790.patch		\
  %D%/packages/patches/libtheora-config-guess.patch		\
  %D%/packages/patches/libtiff-CVE-2016-10688.patch		\
  %D%/packages/patches/libtiff-CVE-2017-9936.patch		\
  %D%/packages/patches/libtiff-tiffgetfield-bugs.patch		\
  %D%/packages/patches/libtiff-tiffycbcrtorgb-integer-overflow.patch	\
  %D%/packages/patches/libtiff-tiffycbcrtorgbinit-integer-overflow.patch	\
  %D%/packages/patches/libtirpc-CVE-2017-8779.patch		\
  %D%/packages/patches/libtorrent-rasterbar-boost-compat.patch	\
  %D%/packages/patches/libtool-skip-tests2.patch		\
  %D%/packages/patches/libunwind-CVE-2015-3239.patch		\
  %D%/packages/patches/libunistring-gnulib-multi-core.patch	\
  %D%/packages/patches/libusb-0.1-disable-tests.patch		\
  %D%/packages/patches/libvpx-CVE-2016-2818.patch		\
  %D%/packages/patches/libxcb-python-3.5-compat.patch		\
  %D%/packages/patches/libxml2-CVE-2016-4658.patch		\
  %D%/packages/patches/libxml2-CVE-2016-5131.patch		\
  %D%/packages/patches/libxslt-generated-ids.patch		\
  %D%/packages/patches/libxslt-CVE-2016-4738.patch		\
  %D%/packages/patches/libxt-guix-search-paths.patch		\
  %D%/packages/patches/lierolibre-check-unaligned-access.patch	\
  %D%/packages/patches/lierolibre-is-free-software.patch	\
  %D%/packages/patches/lierolibre-newer-libconfig.patch		\
  %D%/packages/patches/lierolibre-remove-arch-warning.patch	\
  %D%/packages/patches/lierolibre-try-building-other-arch.patch	\
  %D%/packages/patches/linux-pam-no-setfsuid.patch		\
  %D%/packages/patches/lirc-localstatedir.patch			\
  %D%/packages/patches/llvm-3.5-fix-clang-build-with-gcc5.patch	\
  %D%/packages/patches/llvm-for-extempore.patch			\
  %D%/packages/patches/lm-sensors-hwmon-attrs.patch		\
  %D%/packages/patches/lua-CVE-2014-5461.patch                      \
  %D%/packages/patches/lua-pkgconfig.patch                      \
  %D%/packages/patches/lua51-liblua-so.patch                    \
  %D%/packages/patches/lua51-pkgconfig.patch                    \
  %D%/packages/patches/lua-liblua-so.patch                      \
  %D%/packages/patches/luajit-no_ldconfig.patch			\
  %D%/packages/patches/luajit-symlinks.patch			\
  %D%/packages/patches/luit-posix.patch				\
  %D%/packages/patches/luminance-hdr-qt-printer.patch		\
  %D%/packages/patches/lvm2-static-link.patch			\
  %D%/packages/patches/lxsession-use-gapplication.patch         \
  %D%/packages/patches/lxterminal-CVE-2016-10369.patch		\
  %D%/packages/patches/lz4-fix-test-failures.patch		\
  %D%/packages/patches/make-impure-dirs.patch			\
  %D%/packages/patches/mars-install.patch			\
  %D%/packages/patches/mars-sfml-2.3.patch			\
  %D%/packages/patches/maxima-defsystem-mkdir.patch		\
  %D%/packages/patches/mcron-install.patch			\
  %D%/packages/patches/mcrypt-CVE-2012-4409.patch			\
  %D%/packages/patches/mcrypt-CVE-2012-4426.patch			\
  %D%/packages/patches/mcrypt-CVE-2012-4527.patch			\
  %D%/packages/patches/mesa-skip-disk-cache-test.patch		\
  %D%/packages/patches/mesa-wayland-egl-symbols-check-mips.patch	\
  %D%/packages/patches/metabat-remove-compilation-date.patch	\
  %D%/packages/patches/metabat-fix-compilation.patch		\
  %D%/packages/patches/metabat-fix-boost-issue.patch		\
  %D%/packages/patches/mhash-keygen-test-segfault.patch		\
  %D%/packages/patches/mingw-w64-5.0rc2-gcc-4.9.3.patch		\
  %D%/packages/patches/mpc123-initialize-ao.patch		\
  %D%/packages/patches/module-init-tools-moduledir.patch	\
  %D%/packages/patches/mozjs17-aarch64-support.patch		\
  %D%/packages/patches/mozjs24-aarch64-support.patch		\
  %D%/packages/patches/mozjs38-pkg-config-version.patch		\
  %D%/packages/patches/mozjs38-shell-version.patch		\
  %D%/packages/patches/mozjs38-tracelogger.patch		\
  %D%/packages/patches/mozjs38-version-detection.patch		\
  %D%/packages/patches/multiqc-fix-git-subprocess-error.patch	\
  %D%/packages/patches/mumps-build-parallelism.patch		\
  %D%/packages/patches/mupdf-build-with-openjpeg-2.1.patch	\
  %D%/packages/patches/mupen64plus-ui-console-notice.patch	\
  %D%/packages/patches/musl-CVE-2016-8859.patch			\
  %D%/packages/patches/mutt-store-references.patch		\
  %D%/packages/patches/ncurses-CVE-2017-10684-10685.patch	\
  %D%/packages/patches/net-tools-bitrot.patch			\
  %D%/packages/patches/netcdf-date-time.patch			\
  %D%/packages/patches/netcdf-tst_h_par.patch			\
  %D%/packages/patches/netsurf-system-utf8proc.patch		\
  %D%/packages/patches/netsurf-y2038-tests.patch		\
  %D%/packages/patches/netsurf-longer-test-timeout.patch	\
  %D%/packages/patches/ngircd-handle-zombies.patch		\
  %D%/packages/patches/ninja-zero-mtime.patch			\
  %D%/packages/patches/node-9077.patch				\
  %D%/packages/patches/nss-increase-test-timeout.patch		\
  %D%/packages/patches/nss-pkgconfig.patch			\
  %D%/packages/patches/ntfs-3g-CVE-2017-0358.patch		\
  %D%/packages/patches/nvi-assume-preserve-path.patch		\
  %D%/packages/patches/nvi-dbpagesize-binpower.patch		\
  %D%/packages/patches/nvi-db4.patch				\
  %D%/packages/patches/ocaml-bisect-fix-camlp4-in-another-directory.patch	\
  %D%/packages/patches/ocaml-bitstring-fix-configure.patch \
  %D%/packages/patches/ocaml-CVE-2015-8869.patch		\
  %D%/packages/patches/ocaml-Add-a-.file-directive.patch	\
  %D%/packages/patches/ocaml-findlib-make-install.patch	\
  %D%/packages/patches/omake-fix-non-determinism.patch	\
  %D%/packages/patches/ola-readdir-r.patch			\
  %D%/packages/patches/openscenegraph-ffmpeg3.patch             \
  %D%/packages/patches/openexr-missing-samples.patch		\
  %D%/packages/patches/openjpeg-CVE-2016-9850-CVE-2016-9851.patch		\
  %D%/packages/patches/openjpeg-CVE-2016-9572-CVE-2016-9573.patch		\
  %D%/packages/patches/openldap-CVE-2017-9287.patch		\
  %D%/packages/patches/openocd-nrf52.patch			\
  %D%/packages/patches/openssl-runpath.patch			\
  %D%/packages/patches/openssl-1.1.0-c-rehash-in.patch		\
  %D%/packages/patches/openssl-c-rehash-in.patch		\
  %D%/packages/patches/orpheus-cast-errors-and-includes.patch	\
  %D%/packages/patches/osip-CVE-2017-7853.patch			\
  %D%/packages/patches/ots-no-include-missing-file.patch	\
  %D%/packages/patches/p7zip-CVE-2016-9296.patch			\
  %D%/packages/patches/p7zip-remove-unused-code.patch		\
  %D%/packages/patches/patchelf-page-size.patch			\
  %D%/packages/patches/patchelf-rework-for-arm.patch		\
  %D%/packages/patches/patchutils-xfail-gendiff-tests.patch	\
  %D%/packages/patches/patch-hurd-path-max.patch		\
  %D%/packages/patches/pcre-CVE-2017-7186.patch			\
  %D%/packages/patches/pcre2-CVE-2017-7186.patch		\
  %D%/packages/patches/pcre2-CVE-2017-8786.patch		\
  %D%/packages/patches/perl-file-path-CVE-2017-6512.patch	\
  %D%/packages/patches/perl-autosplit-default-time.patch	\
  %D%/packages/patches/perl-dbd-mysql-CVE-2017-10788.patch	\
  %D%/packages/patches/perl-deterministic-ordering.patch	\
  %D%/packages/patches/perl-finance-quote-unuse-mozilla-ca.patch \
  %D%/packages/patches/perl-gd-options-passthrough-and-fontconfig.patch \
  %D%/packages/patches/perl-io-socket-ssl-openssl-1.0.2f-fix.patch \
  %D%/packages/patches/perl-net-amazon-s3-moose-warning.patch	\
  %D%/packages/patches/perl-net-dns-resolver-programmable-fix.patch	\
  %D%/packages/patches/perl-no-sys-dirs.patch			\
  %D%/packages/patches/perl-module-pluggable-search.patch	\
  %D%/packages/patches/perl-reproducible-build-date.patch	\
  %D%/packages/patches/perl-www-curl-remove-symbol.patch	\
  %D%/packages/patches/pidgin-add-search-path.patch		\
  %D%/packages/patches/pinball-const-fix.patch			\
  %D%/packages/patches/pinball-cstddef.patch			\
  %D%/packages/patches/pinball-missing-separators.patch		\
  %D%/packages/patches/pinball-src-deps.patch			\
  %D%/packages/patches/pinball-system-ltdl.patch		\
  %D%/packages/patches/pingus-sdl-libs-config.patch		\
  %D%/packages/patches/pixman-CVE-2016-5296.patch		\
  %D%/packages/patches/plink-1.07-unclobber-i.patch		\
  %D%/packages/patches/plink-endian-detection.patch		\
  %D%/packages/patches/plotutils-libpng-jmpbuf.patch		\
  %D%/packages/patches/polkit-drop-test.patch			\
  %D%/packages/patches/policycoreutils-make-sepolicy-use-python3.patch	\
  %D%/packages/patches/portaudio-audacity-compat.patch		\
  %D%/packages/patches/portmidi-modular-build.patch		\
  %D%/packages/patches/procmail-ambiguous-getline-debian.patch  \
  %D%/packages/patches/procmail-CVE-2014-3618.patch		\
  %D%/packages/patches/proot-test-fhs.patch			\
  %D%/packages/patches/pt-scotch-build-parallelism.patch	\
  %D%/packages/patches/pulseaudio-fix-mult-test.patch		\
  %D%/packages/patches/pulseaudio-longer-test-timeout.patch	\
  %D%/packages/patches/pycairo-wscript.patch			\
  %D%/packages/patches/pybugz-encode-error.patch		\
  %D%/packages/patches/pybugz-stty.patch			\
  %D%/packages/patches/pygpgme-disable-problematic-tests.patch  \
  %D%/packages/patches/pyqt-configure.patch			\
  %D%/packages/patches/python-2-deterministic-build-info.patch	\
  %D%/packages/patches/python-2.7-getentropy-on-old-kernels.patch	\
  %D%/packages/patches/python-2.7-search-paths.patch		\
  %D%/packages/patches/python-2.7-site-prefixes.patch		\
  %D%/packages/patches/python-2.7-source-date-epoch.patch	\
  %D%/packages/patches/python-3-deterministic-build-info.patch	\
  %D%/packages/patches/python-3-search-paths.patch		\
  %D%/packages/patches/python-3.5-fix-tests.patch		\
  %D%/packages/patches/python-3.5-getentropy-on-old-kernels.patch	\
  %D%/packages/patches/python-dendropy-fix-tests.patch		\
  %D%/packages/patches/python-fix-tests.patch			\
  %D%/packages/patches/python-genshi-add-support-for-python-3.4-AST.patch	\
  %D%/packages/patches/python-genshi-buildable-on-python-2.7.patch	\
  %D%/packages/patches/python-genshi-disable-speedups-on-python-3.3.patch	\
  %D%/packages/patches/python-genshi-fix-tests-on-python-3.5.patch	\
  %D%/packages/patches/python-genshi-isstring-helper.patch	\
  %D%/packages/patches/python-genshi-stripping-of-unsafe-script-tags.patch	\
  %D%/packages/patches/python-parse-too-many-fields.patch	\
  %D%/packages/patches/python2-rdflib-drop-sparqlwrapper.patch	\
  %D%/packages/patches/python-statsmodels-fix-tests.patch	\
  %D%/packages/patches/python-configobj-setuptools.patch	\
  %D%/packages/patches/python-cython-fix-tests-32bit.patch	\
  %D%/packages/patches/python-faker-fix-build-32bit.patch	\
  %D%/packages/patches/python-pandas-skip-failing-tests.patch	\
  %D%/packages/patches/python-paste-remove-website-test.patch	\
  %D%/packages/patches/python-paste-remove-timing-test.patch	\
  %D%/packages/patches/python-pillow-freetype-2.7-test-failure.patch	\
  %D%/packages/patches/python-pygit2-disable-network-tests.patch	\
  %D%/packages/patches/python-pycrypto-CVE-2013-7459.patch	\
  %D%/packages/patches/python2-pygobject-2-gi-info-type-error-domain.patch \
  %D%/packages/patches/python-pygpgme-fix-pinentry-tests.patch	\
  %D%/packages/patches/python2-subprocess32-disable-input-test.patch	\
  %D%/packages/patches/qemu-CVE-2017-7493.patch			\
  %D%/packages/patches/qemu-CVE-2017-8112.patch			\
  %D%/packages/patches/qemu-CVE-2017-8309.patch			\
  %D%/packages/patches/qemu-CVE-2017-8379.patch			\
  %D%/packages/patches/qemu-CVE-2017-8380.patch			\
  %D%/packages/patches/qemu-CVE-2017-9524.patch			\
  %D%/packages/patches/qemu-CVE-2017-11334.patch		\
  %D%/packages/patches/qt4-ldflags.patch			\
  %D%/packages/patches/qtscript-disable-tests.patch		\
  %D%/packages/patches/quagga-reproducible-build.patch          \
  %D%/packages/patches/quassel-fix-tls-check.patch              \
  %D%/packages/patches/quickswitch-fix-dmenu-check.patch	\
  %D%/packages/patches/rapicorn-isnan.patch			\
  %D%/packages/patches/raptor2-heap-overflow.patch		\
  %D%/packages/patches/ratpoison-shell.patch			\
  %D%/packages/patches/rcs-5.9.4-noreturn.patch			\
  %D%/packages/patches/readline-link-ncurses.patch		\
  %D%/packages/patches/readline-6.2-CVE-2014-2524.patch		\
  %D%/packages/patches/readline-7.0-mingw.patch			\
  %D%/packages/patches/reptyr-fix-gcc-7.patch			\
  %D%/packages/patches/ripperx-missing-file.patch		\
  %D%/packages/patches/rpcbind-CVE-2017-8779.patch		\
  %D%/packages/patches/rpm-CVE-2014-8118.patch			\
  %D%/packages/patches/rsem-makefile.patch			\
  %D%/packages/patches/ruby-concurrent-ignore-broken-test.patch	\
  %D%/packages/patches/ruby-concurrent-test-arm.patch		\
  %D%/packages/patches/ruby-puma-ignore-broken-test.patch       \
  %D%/packages/patches/ruby-rack-ignore-failing-test.patch      \
  %D%/packages/patches/ruby-tzinfo-data-ignore-broken-test.patch\
  %D%/packages/patches/rxvt-unicode-escape-sequences.patch	\
  %D%/packages/patches/scheme48-tests.patch			\
  %D%/packages/patches/scotch-test-threading.patch		\
  %D%/packages/patches/sdl-libx11-1.6.patch			\
  %D%/packages/patches/seq24-rename-mutex.patch			\
  %D%/packages/patches/shishi-fix-libgcrypt-detection.patch	\
  %D%/packages/patches/slim-session.patch			\
  %D%/packages/patches/slim-config.patch			\
  %D%/packages/patches/slim-sigusr1.patch			\
  %D%/packages/patches/slim-reset.patch				\
  %D%/packages/patches/slim-login.patch				\
  %D%/packages/patches/slurm-configure-remove-nonfree-contribs.patch \
  %D%/packages/patches/sooperlooper-build-with-wx-30.patch 	\
  %D%/packages/patches/spice-CVE-2016-9577.patch		\
  %D%/packages/patches/spice-CVE-2016-9578-1.patch		\
  %D%/packages/patches/spice-CVE-2016-9578-2.patch		\
  %D%/packages/patches/spice-CVE-2017-7506.patch		\
  %D%/packages/patches/steghide-fixes.patch			\
  %D%/packages/patches/superlu-dist-scotchmetis.patch		\
  %D%/packages/patches/supertuxkart-angelscript-ftbfs.patch		\
  %D%/packages/patches/swish-e-search.patch			\
  %D%/packages/patches/swish-e-format-security.patch		\
  %D%/packages/patches/synfigstudio-fix-ui-with-gtk3.patch 	\
  %D%/packages/patches/t1lib-CVE-2010-2642.patch		\
  %D%/packages/patches/t1lib-CVE-2011-0764.patch		\
  %D%/packages/patches/t1lib-CVE-2011-1552+CVE-2011-1553+CVE-2011-1554.patch		\
  %D%/packages/patches/tar-CVE-2016-6321.patch			\
  %D%/packages/patches/tar-skip-unreliable-tests.patch		\
  %D%/packages/patches/tcl-mkindex-deterministic.patch		\
  %D%/packages/patches/tclxml-3.2-install.patch			\
  %D%/packages/patches/tcsh-fix-autotest.patch			\
  %D%/packages/patches/tcsh-fix-out-of-bounds-read.patch	\
  %D%/packages/patches/teensy-loader-cli-help.patch		\
  %D%/packages/patches/teeworlds-use-latest-wavpack.patch	\
  %D%/packages/patches/texlive-texmf-CVE-2016-10243.patch	\
  %D%/packages/patches/texi2html-document-encoding.patch	\
  %D%/packages/patches/texi2html-i18n.patch			\
  %D%/packages/patches/thefuck-test-environ.patch		\
  %D%/packages/patches/tidy-CVE-2015-5522+5523.patch		\
  %D%/packages/patches/tinyxml-use-stl.patch			\
  %D%/packages/patches/tipp10-fix-compiling.patch		\
  %D%/packages/patches/tipp10-remove-license-code.patch		\
  %D%/packages/patches/tk-find-library.patch			\
  %D%/packages/patches/ttf2eot-cstddef.patch			\
  %D%/packages/patches/ttfautohint-source-date-epoch.patch	\
  %D%/packages/patches/tophat-build-with-later-seqan.patch	\
  %D%/packages/patches/tuxpaint-stamps-path.patch		\
  %D%/packages/patches/unrtf-CVE-2016-10091.patch		\
  %D%/packages/patches/unzip-CVE-2014-8139.patch		\
  %D%/packages/patches/unzip-CVE-2014-8140.patch		\
  %D%/packages/patches/unzip-CVE-2014-8141.patch		\
  %D%/packages/patches/unzip-CVE-2014-9636.patch		\
  %D%/packages/patches/unzip-CVE-2015-7696.patch		\
  %D%/packages/patches/unzip-CVE-2015-7697.patch		\
  %D%/packages/patches/unzip-allow-greater-hostver-values.patch	\
  %D%/packages/patches/unzip-attribs-overflow.patch		\
  %D%/packages/patches/unzip-overflow-on-invalid-input.patch	\
  %D%/packages/patches/unzip-format-secure.patch		\
  %D%/packages/patches/unzip-initialize-symlink-flag.patch	\
  %D%/packages/patches/unzip-overflow-long-fsize.patch		\
  %D%/packages/patches/unzip-remove-build-date.patch		\
  %D%/packages/patches/ustr-fix-build-with-gcc-5.patch		\
  %D%/packages/patches/util-linux-tests.patch			\
  %D%/packages/patches/upower-builddir.patch			\
  %D%/packages/patches/valgrind-enable-arm.patch		\
  %D%/packages/patches/virglrenderer-CVE-2017-6386.patch 	\
  %D%/packages/patches/vorbis-tools-CVE-2014-9638+CVE-2014-9639.patch		\
  %D%/packages/patches/vorbis-tools-CVE-2014-9640.patch		\
  %D%/packages/patches/vorbis-tools-CVE-2015-6749.patch		\
  %D%/packages/patches/vpnc-script.patch			\
  %D%/packages/patches/vsearch-unbundle-cityhash.patch		\
  %D%/packages/patches/vte-CVE-2012-2738-pt1.patch			\
  %D%/packages/patches/vte-CVE-2012-2738-pt2.patch			\
  %D%/packages/patches/weechat-python.patch			\
  %D%/packages/patches/wget-CVE-2017-6508.patch			\
  %D%/packages/patches/wget-fix-504-test-timeout.patch			\
  %D%/packages/patches/wget-perl-5.26.patch			\
  %D%/packages/patches/wicd-bitrate-none-fix.patch		\
  %D%/packages/patches/wicd-get-selected-profile-fix.patch	\
  %D%/packages/patches/wicd-urwid-1.3.patch			\
  %D%/packages/patches/wicd-wpa2-ttls.patch			\
  %D%/packages/patches/wmctrl-64-fix.patch			\
  %D%/packages/patches/wmfire-update-for-new-gdk-versions.patch	\
  %D%/packages/patches/woff2-libbrotli.patch			\
  %D%/packages/patches/wordnet-CVE-2008-2149.patch			\
  %D%/packages/patches/wordnet-CVE-2008-3908-pt1.patch			\
  %D%/packages/patches/wordnet-CVE-2008-3908-pt2.patch			\
  %D%/packages/patches/xcb-proto-python3-print.patch		\
  %D%/packages/patches/xcb-proto-python3-whitespace.patch	\
  %D%/packages/patches/wxwidgets-fix-windowGTK.patch		\
  %D%/packages/patches/xdotool-fix-makefile.patch               \
  %D%/packages/patches/xf86-video-ark-remove-mibstore.patch	\
  %D%/packages/patches/xf86-video-ast-remove-mibstore.patch	\
  %D%/packages/patches/xf86-video-geode-glibc-2.20.patch	\
  %D%/packages/patches/xf86-video-i128-remove-mibstore.patch	\
  %D%/packages/patches/xf86-video-mach64-glibc-2.20.patch	\
  %D%/packages/patches/xf86-video-tga-remove-mibstore.patch	\
  %D%/packages/patches/xfce4-panel-plugins.patch		\
  %D%/packages/patches/xfce4-session-fix-xflock4.patch		\
  %D%/packages/patches/xfce4-settings-defaults.patch		\
  %D%/packages/patches/xinetd-fix-fd-leak.patch			\
  %D%/packages/patches/xinetd-CVE-2013-4342.patch		\
  %D%/packages/patches/xmodmap-asprintf.patch 			\
  %D%/packages/patches/xorg-server-CVE-2017-10971.patch		\
  %D%/packages/patches/xorg-server-CVE-2017-10972.patch 	\
  %D%/packages/patches/libyaml-CVE-2014-9130.patch 		\
  %D%/packages/patches/zathura-plugindir-environment-variable.patch	\
  %D%/packages/patches/zziplib-CVE-2017-5974.patch		\
  %D%/packages/patches/zziplib-CVE-2017-5975.patch		\
  %D%/packages/patches/zziplib-CVE-2017-5976.patch		\
  %D%/packages/patches/zziplib-CVE-2017-5978.patch		\
  %D%/packages/patches/zziplib-CVE-2017-5979.patch		\
  %D%/packages/patches/zziplib-CVE-2017-5981.patch

MISC_DISTRO_FILES =				\
  %D%/packages/ld-wrapper.in

bootstrapdir = $(guilemoduledir)/%D%/packages/bootstrap
bootstrap_x86_64_linuxdir = $(bootstrapdir)/x86_64-linux
bootstrap_i686_linuxdir = $(bootstrapdir)/i686-linux
bootstrap_armhf_linuxdir = $(bootstrapdir)/armhf-linux
bootstrap_aarch64_linuxdir = $(bootstrapdir)/aarch64-linux
bootstrap_mips64el_linuxdir = $(bootstrapdir)/mips64el-linux

dist_bootstrap_x86_64_linux_DATA =		\
  %D%/packages/bootstrap/x86_64-linux/bash	\
  %D%/packages/bootstrap/x86_64-linux/mkdir	\
  %D%/packages/bootstrap/x86_64-linux/tar	\
  %D%/packages/bootstrap/x86_64-linux/xz

dist_bootstrap_i686_linux_DATA =		\
  %D%/packages/bootstrap/i686-linux/bash	\
  %D%/packages/bootstrap/i686-linux/mkdir	\
  %D%/packages/bootstrap/i686-linux/tar		\
  %D%/packages/bootstrap/i686-linux/xz

dist_bootstrap_armhf_linux_DATA =		\
  %D%/packages/bootstrap/armhf-linux/bash	\
  %D%/packages/bootstrap/armhf-linux/mkdir	\
  %D%/packages/bootstrap/armhf-linux/tar	\
  %D%/packages/bootstrap/armhf-linux/xz

dist_bootstrap_aarch64_linux_DATA =		\
  %D%/packages/bootstrap/aarch64-linux/bash	\
  %D%/packages/bootstrap/aarch64-linux/mkdir	\
  %D%/packages/bootstrap/aarch64-linux/tar	\
  %D%/packages/bootstrap/aarch64-linux/xz

dist_bootstrap_mips64el_linux_DATA =		\
  %D%/packages/bootstrap/mips64el-linux/bash	\
  %D%/packages/bootstrap/mips64el-linux/mkdir	\
  %D%/packages/bootstrap/mips64el-linux/tar	\
  %D%/packages/bootstrap/mips64el-linux/xz

# Big bootstrap binaries are not included in the tarball.  Instead, they
# are downloaded.
nodist_bootstrap_x86_64_linux_DATA =					\
  %D%/packages/bootstrap/x86_64-linux/guile-2.0.9.tar.xz
nodist_bootstrap_i686_linux_DATA =					\
  %D%/packages/bootstrap/i686-linux/guile-2.0.9.tar.xz
nodist_bootstrap_armhf_linux_DATA =					\
  %D%/packages/bootstrap/armhf-linux/guile-2.0.11.tar.xz
nodist_bootstrap_aarch64_linux_DATA =					\
  %D%/packages/bootstrap/aarch64-linux/guile-2.0.14.tar.xz
nodist_bootstrap_mips64el_linux_DATA =					\
  %D%/packages/bootstrap/mips64el-linux/guile-2.0.9.tar.xz

# Those files must remain executable, so they remain executable once
# imported into the store.
set-bootstrap-executable-permissions:
	chmod +x $(DESTDIR)$(bootstrapdir)/*/{bash,mkdir,tar,xz}

BOOTSTRAP_GUILE_TARBALLS =			\
  $(nodist_bootstrap_x86_64_linux_DATA)		\
  $(nodist_bootstrap_i686_linux_DATA)		\
  $(nodist_bootstrap_armhf_linux_DATA)		\
  $(nodist_bootstrap_aarch64_linux_DATA)	\
  $(nodist_bootstrap_mips64el_linux_DATA)

DISTCLEANFILES = $(BOOTSTRAP_GUILE_TARBALLS)

# Method to download a file from an external source.
DOWNLOAD_FILE =								\
  GUILE_LOAD_COMPILED_PATH="$(top_builddir):$$GUILE_LOAD_COMPILED_PATH"	\
  $(GUILE) --no-auto-compile -L "$(top_builddir)" -L "$(top_srcdir)"	\
           "$(top_srcdir)/build-aux/download.scm"

%D%/packages/bootstrap/x86_64-linux/guile-2.0.9.tar.xz:
	$(AM_V_DL)$(MKDIR_P) `dirname "$@"`;	\
	$(DOWNLOAD_FILE) "$@"			\
	  "037b103522a2d0d7d69c7ffd8de683dfe5bb4b59c1fafd70b4ffd397fd2f57f0"
%D%/packages/bootstrap/i686-linux/guile-2.0.9.tar.xz:
	$(AM_V_DL)$(MKDIR_P) `dirname "$@"`;	\
	$(DOWNLOAD_FILE) "$@"			\
	  "b757cd46bf13ecac83fb8e955fb50096ac2d17bb610ca8eb816f29302a00a846"
%D%/packages/bootstrap/armhf-linux/guile-2.0.11.tar.xz:
	$(AM_V_DL)$(MKDIR_P) `dirname "$@"`;	\
	$(DOWNLOAD_FILE) "$@"			\
	  "e551d05d4d385d6706ab8d574856a087758294dc90ab4c06e70a157a685e23d6"
%D%/packages/bootstrap/aarch64-linux/guile-2.0.14.tar.xz:
	$(AM_V_DL)$(MKDIR_P) `dirname "$@"`;	\
	$(DOWNLOAD_FILE) "$@"			\
	  "3939909f24dcb955621aa7f81ecde6844bea8a083969c2d275c55699af123ebe"
%D%/packages/bootstrap/mips64el-linux/guile-2.0.9.tar.xz:
	$(AM_V_DL)$(MKDIR_P) `dirname "$@"`;	\
	$(DOWNLOAD_FILE) "$@" 			\
	  "994680f0001346864aa2c2cc5110f380ee7518dcd701c614291682b8e948f73b"
