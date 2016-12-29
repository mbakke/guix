;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2014, 2015, 2016 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Sou Bunnbu <iyzsong@gmail.com>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Alex Griffin <a@ajgrf.com>
;;;
;;; This file is part of GNU Guix.
;;;
;;; GNU Guix is free software; you can redistribute it and/or modify it
;;; under the terms of the GNU General Public License as published by
;;; the Free Software Foundation; either version 3 of the License, or (at
;;; your option) any later version.
;;;
;;; GNU Guix is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with GNU Guix.  If not, see <http://www.gnu.org/licenses/>.

(define-module (gnu packages gnuzilla)
  #:use-module ((srfi srfi-1) #:hide (zip))
  #:use-module (gnu packages)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages base)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gstreamer)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages libcanberra)
  #:use-module (gnu packages cups)
  #:use-module (gnu packages mit-krb5)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages libevent)
  #:use-module (gnu packages libreoffice)  ;for hunspell
  #:use-module (gnu packages image)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages python)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages assembly)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages video)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages zip))

(define-public mozjs
  (package
    (name "mozjs")
    (version "17.0.0")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "https://ftp.mozilla.org/pub/mozilla.org/js/"
                   name version ".tar.gz"))
             (sha256
              (base32
               "1fig2wf4f10v43mqx67y68z6h77sy900d1w0pz9qarrqx57rc7ij"))
             (modules '((guix build utils)))
             (snippet
              ;; Fix incompatibility with Perl 5.22+.
              '(substitute* '("js/src/config/milestone.pl")
                 (("defined\\(@TEMPLATE_FILE)") "@TEMPLATE_FILE")))))
    (build-system gnu-build-system)
    (native-inputs
      `(("perl" ,perl)
        ("python" ,python-2)))
    (arguments
      `(;; XXX: parallel build fails, lacking:
        ;;   mkdir -p "system_wrapper_js/"
        #:parallel-build? #f
        #:phases
          (alist-cons-before
           'configure 'chdir
           (lambda _
             (chdir "js/src"))
           (alist-replace
            'configure
            ;; configure fails if it is followed by SHELL and CONFIG_SHELL
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (setenv "SHELL" (which "sh"))
                (setenv "CONFIG_SHELL" (which "sh"))
                (zero? (system*
                        "./configure" (string-append "--prefix=" out)))))
            %standard-phases))))
    (home-page
     "https://developer.mozilla.org/en-US/docs/Mozilla/Projects/SpiderMonkey")
    (synopsis "Mozilla javascript engine")
    (description "SpiderMonkey is Mozilla's JavaScript engine written
in C/C++.")
    (license license:mpl2.0))) ; and others for some files

(define-public mozjs-24
  (package (inherit mozjs)
    (name "mozjs")
    (version "24.2.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://ftp.mozilla.org/pub/mozilla.org/js/"
                    name "-" version ".tar.bz2"))
              (sha256
               (base32
                "1n1phk8r3l8icqrrap4czplnylawa0ddc2cc4cgdz46x3lrkybz6"))
              (modules '((guix build utils)))
              (snippet
               ;; Fix incompatibility with Perl 5.22+.
               '(substitute* '("js/src/config/milestone.pl")
                  (("defined\\(@TEMPLATE_FILE)") "@TEMPLATE_FILE")))))
    (arguments
     '(;; XXX: parallel build fails, lacking:
       ;;   mkdir -p "system_wrapper_js/"
       #:parallel-build? #f
       #:phases
       (modify-phases %standard-phases
         (replace
          'configure
          (lambda* (#:key outputs #:allow-other-keys)
            (let ((out (assoc-ref outputs "out")))
              (chdir "js/src")
              ;; configure fails if it is follwed by SHELL and CONFIG_SHELL
              (setenv "SHELL" (which "sh"))
              (setenv "CONFIG_SHELL" (which "sh"))
              (zero? (system* "./configure"
                              (string-append "--prefix=" out)
                              "--with-system-nspr"
                              "--enable-system-ffi"
                              "--enable-threadsafe"))))))))
    (native-inputs
     `(("perl" ,perl)
       ("pkg-config" ,pkg-config)
       ("python" ,python-2)))
    (propagated-inputs
     `(("nspr" ,nspr))) ; in the Requires.private field of mozjs-24.pc
    (inputs
     `(("libffi" ,libffi)
       ("zlib" ,zlib)))))

(define-public nspr
  (package
    (name "nspr")
    (version "4.12")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "https://ftp.mozilla.org/pub/mozilla.org/nspr/releases/v"
                   version "/src/nspr-" version ".tar.gz"))
             (sha256
              (base32
               "1pk98bmc5xzbl62q5wf2d6mryf0v95z6rsmxz27nclwiaqg0mcg0"))))
    (build-system gnu-build-system)
    (native-inputs
      `(("perl" ,perl)))
    (arguments
     `(#:tests? #f ; no check target
       #:configure-flags (list "--enable-64bit"
                               (string-append "LDFLAGS=-Wl,-rpath="
                                              (assoc-ref %outputs "out")
                                              "/lib"))
       #:phases (alist-cons-before
                 'configure 'chdir
                 (lambda _
                   (chdir "nspr"))
                 %standard-phases)))
    (home-page
     "https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSPR")
    (synopsis "Netscape API for system level and libc-like functions")
    (description "Netscape Portable Runtime (NSPR) provides a
platform-neutral API for system level and libc-like functions.  It is used
in the Mozilla clients.")
    (license license:mpl2.0)))

(define-public nss
  (package
    (name "nss")
    (version "3.27.2")
    (source (origin
              (method url-fetch)
              (uri (let ((version-with-underscores
                          (string-join (string-split version #\.) "_")))
                     (string-append
                      "https://ftp.mozilla.org/pub/mozilla.org/security/nss/"
                      "releases/NSS_" version-with-underscores "_RTM/src/"
                      "nss-" version ".tar.gz")))
              (sha256
               (base32
                "0945q9yyhax9lkhxs1bjlr5gwknpvhzsa4zxfh127l398i9ci2nw"))
              ;; Create nss.pc and nss-config.
              (patches (search-patches "nss-pkgconfig.patch"))))
    (build-system gnu-build-system)
    (outputs '("out" "bin"))
    (arguments
     '(#:parallel-build? #f ; failed
       #:make-flags
       (let* ((out (assoc-ref %outputs "out"))
              (nspr (string-append (assoc-ref %build-inputs "nspr")))
              (rpath (string-append "-Wl,-rpath=" out "/lib/nss")))
         (list "-C" "nss" (string-append "PREFIX=" out)
               "NSDISTMODE=copy"
               "NSS_USE_SYSTEM_SQLITE=1"
               (string-append "NSPR_INCLUDE_DIR=" nspr "/include/nspr")
               ;; Add $out/lib/nss to RPATH.
               (string-append "RPATH=" rpath)
               (string-append "LDFLAGS=" rpath)))
       #:modules ((guix build gnu-build-system)
                  (guix build utils)
                  (ice-9 ftw)
                  (ice-9 match)
                  (srfi srfi-26))
       #:phases
       (alist-replace
        'configure
        (lambda* (#:key system inputs #:allow-other-keys)
          (setenv "CC" "gcc")
          ;; Tells NSS to build for the 64-bit ABI if we are 64-bit system.
          (when (string-prefix? "x86_64" system)
            (setenv "USE_64" "1"))
          #t)
        (alist-replace
         'check
         (lambda _
           ;; Use 127.0.0.1 instead of $HOST.$DOMSUF as HOSTADDR for testing.
           ;; The later requires a working DNS or /etc/hosts.
           (setenv "DOMSUF" "(none)")
           (setenv "USE_IP" "TRUE")
           (setenv "IP_ADDRESS" "127.0.0.1")
           (zero? (system* "./nss/tests/all.sh")))
         (alist-replace
          'install
          (lambda* (#:key outputs #:allow-other-keys)
            (let* ((out (assoc-ref outputs "out"))
                   (bin (string-append (assoc-ref outputs "bin") "/bin"))
                   (inc (string-append out "/include/nss"))
                   (lib (string-append out "/lib/nss"))
                   (obj (match (scandir "dist" (cut string-suffix? "OBJ" <>))
                          ((obj) (string-append "dist/" obj)))))
              ;; Install nss-config to $out/bin.
              (install-file (string-append obj "/bin/nss-config")
                            (string-append out "/bin"))
              (delete-file (string-append obj "/bin/nss-config"))
              ;; Install nss.pc to $out/lib/pkgconfig.
              (install-file (string-append obj "/lib/pkgconfig/nss.pc")
                            (string-append out "/lib/pkgconfig"))
              (delete-file (string-append obj "/lib/pkgconfig/nss.pc"))
              (rmdir (string-append obj "/lib/pkgconfig"))
              ;; Install other files.
              (copy-recursively "dist/public/nss" inc)
              (copy-recursively (string-append obj "/bin") bin)
              (copy-recursively (string-append obj "/lib") lib)

              ;; FIXME: libgtest1.so is installed in the above step, and it's
              ;; (unnecessarily) linked with several NSS libraries, but
              ;; without the needed rpaths, causing the 'validate-runpath'
              ;; phase to fail.  Here we simply delete libgtest1.so, since it
              ;; seems to be used only during the tests.
              (delete-file (string-append lib "/libgtest1.so"))

              #t))
          %standard-phases)))))
    (inputs
     `(("sqlite" ,sqlite)
       ("zlib" ,zlib)))
    (propagated-inputs `(("nspr" ,nspr))) ; required by nss.pc.
    (native-inputs `(("perl" ,perl)))

    ;; The NSS test suite takes around 48 hours on Loongson 3A (MIPS) when
    ;; another build is happening concurrently on the same machine.
    (properties '((timeout . 216000)))  ; 60 hours

    (home-page
     "https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS")
    (synopsis "Network Security Services")
    (description
     "Network Security Services (NSS) is a set of libraries designed to support
cross-platform development of security-enabled client and server applications.
Applications built with NSS can support SSL v2 and v3, TLS, PKCS #5, PKCS #7,
PKCS #11, PKCS #12, S/MIME, X.509 v3 certificates, and other security
standards.")
    (license license:mpl2.0)))

(define (mozilla-patch file-name changeset hash)
  "Return an origin for CHANGESET from the mozilla-esr45 repository."
  (origin
    (method url-fetch)
    (uri (string-append "https://hg.mozilla.org/releases/mozilla-esr45/raw-rev/"
                        changeset))
    (sha256 (base32 hash))
    (file-name file-name)))

(define-public icecat
  (package
    (name "icecat")
    (version "45.5.1-gnu1")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://gnu/gnuzilla/"
                          (first (string-split version #\-))
                          "/" name "-" version ".tar.bz2"))
      (sha256
       (base32
        "1sbfgsibmb8wfmb2g40gmqwq3nikmrgzksf51ydrz7gnafyfaqw1"))
      (patches
       (list
        (search-patch "icecat-avoid-bundled-libraries.patch")
        (search-patch "icecat-binutils.patch")
        (mozilla-patch "icecat-bug-1301381.patch"       "2e5438a92617" "0pyjbzyy04759ldpcar8q8cccv67j1jkxsg46rkq7a3rbhmwmw4p") ;CVE-2016-9897
        (mozilla-patch "icecat-bug-1317409.patch"       "7391f60fb790" "1hydggpmmm2cs9lb15micnkxn4wl4cda9g74hkn3zmks805vjz3h") ;CVE-2016-9899
        (mozilla-patch "icecat-bug-1309834.patch"       "744e01001e6e" "0z2fq765kap3ll9as5rvjpnbj3pw26074alw7df0zi215qz47nxr") ;CVE-2016-9893-pt1
        (mozilla-patch "icecat-bug-1317936-pt1.patch"   "8ae673f34a5b" "1rlbihckl9afa0y91lqs7gpnv6a7zxzrmxjv95y3yrl03kibqp76") ;CVE-2016-9904-pt1
        (mozilla-patch "icecat-bug-1317936-pt2.patch"   "409c23c144fe" "05kgs16y8s5pxmg2dxp93247zagnj6zgj3209qpm5hz3an7gr13h") ;CVE-2016-9904-pt2
        (mozilla-patch "icecat-bug-1319122.patch"       "994d9bd0e28d" "007wifyx3b2ln4fwv1i8n24yz5ngjf4mkzd7sqr5bpd3q88ff293") ;CVE-2016-9900
        (mozilla-patch "icecat-bug-1312609.patch"       "0fc43af8982e" "0pc8q9knzq2knj723mwkay1lnzbzysb07ygxnc16mcb6f7vl2mw8") ;CVE-2016-9893-pt2
        (mozilla-patch "icecat-bug-1319524.patch"       "19f9a4643d77" "0w5yxj1l0hvs66q9agjp4m5sfby7fj05lx33gaqf899bw4hn4vcf") ;CVE-2016-9893-pt3
        (mozilla-patch "icecat-bug-1312548.patch"       "c58442c414f5" "1z1w1v8xagkhrwgp51ij1k2gx0ripslia09vm78812n7gcwddaas") ;CVE-2016-9893-pt4
        (mozilla-patch "icecat-bug-1314442.patch"       "5054047b7328" "0xlw8irymfp3bcaa5jpf7clf7bq6qxp3i8zapp8jya8lzr1nf868") ;CVE-2016-9898
        (mozilla-patch "icecat-bug-881832-pt1.patch"    "1123263318a3" "1qkxwva3zrcs1zhga8ncmndq03988dx75i896g53gbvpskj06915")
        (mozilla-patch "icecat-bug-881832-pt2.patch"    "dc87c0a39adf" "01rapf14f3r2wk0cjd16dn1rll4ipgs33cnjmjck48nvk67ikz6h")
        (mozilla-patch "icecat-bug-881832-pt3.patch"    "f20e5f488368" "15ql9ywifb3gm2g1057k63f821dbs3wqsh3zhndprzf3dn6aha4i")
        (mozilla-patch "icecat-bug-881832-pt4.patch"    "7950c4d5bd7c" "0jhkg5hq5yfy7rh21k1mpbsbr81ql85aazym30zy3n2cf28xxhd7")
        (mozilla-patch "icecat-bug-881832-pt5.patch"    "972734ec21b6" "073i4v1f1ydy49i57pvzscz95sjr5bbk9s5sajxvmmcsmwhpjdfy")
        (mozilla-patch "icecat-bug-1293985-pt1.patch"   "aebd3687e05e" "1qz6hdgflcrqyg7fv66cbg23v4b7q5bc2yxzrgjxs4j1d7jy1s0s") ;CVE-2016-9905-pt1
        (mozilla-patch "icecat-bug-1293985-pt2.patch"   "63d8e5cd27cb" "11fsgyngy7v59ma30xdbmycwf4izwikzvaljngm3ks4534inpl4a") ;CVE-2016-9905-pt2
        (mozilla-patch "icecat-bug-1279202.patch"       "e560997291af" "1hn35slasfcj3ryka4fsarx4l9r99z0iwj67fmbv6zxz4z133kks")
        (mozilla-patch "icecat-bug-1320039.patch"       "21c615b65048" "0ibgsxa36x9ajn2jqbhxxvrfvj6x6iyspsmzzn4brdz11n93skhr") ;CVE-2016-9902
        (mozilla-patch "icecat-bug-1320057.patch"       "c15e5afc0430" "17gj32agqs94548z8lvz0l6zz3kbwajn8as0y4iw5nb6jsll4c66") ;CVE-2016-9901
        (mozilla-patch "icecat-bug-1163212.patch"       "46163fb1cb34" "1yikayczfgfla3aka0159apq3149d52sgvlca0sivx4myd0lvjm7") ;CVE-2016-9893-pt5
        (mozilla-patch "icecat-bug-1317805.patch"       "cde2a37100f5" "100abggnhwyw84almxrkxqfpyfkd4pqkcrh5y9g4d3jd2h16asvl") ;CVE-2016-9893-pt6
        (mozilla-patch "icecat-bug-1298773-pt1.patch"   "9b78ab1e6d07" "19ib6bp96xk000ll40b8qxvizkncyzclz2rsb9w5fa42qs9978ff") ;CVE-2016-9893-pt7
        (mozilla-patch "icecat-bug-1298773-pt2.patch"   "78ebf9c9dfb0" "1shgr4rk6r2zxr1qqk1j3qnnqzqxnbi093qhlrfh8q5q1ivqf6k1") ;CVE-2016-9893-pt8
        (mozilla-patch "icecat-bug-1299098.patch"       "a46a9f16823c" "0dwkyz3kcqnfcbhbfh2lss7s0yh87rgzb871qxx3x4ynyqph9mnz") ;CVE-2016-9893-pt9
        (mozilla-patch "icecat-bug-1311687.patch"       "6bc7cc7a33a6" "1wggcqv84n8mp7xps7hy4rwy61fkh45imfqzc0b46s3w5hyhypn2")
        (mozilla-patch "icecat-bug-1287912.patch"       "778f65148b40" "0j2a153sk0654vv2lnxjib4lwml3mlqn6vs46c2pp82iba8nyfrm") ;CVE-2016-9893-pt10
        (mozilla-patch "icecat-bug-1312272.patch"       "94bd2b43c766" "10h0qpr6m9cqyqxxnkbb6mzb3cagavzlynkxgd7a4izyq1bv28rk") ;CVE-2016-9895
        (mozilla-patch "icecat-bug-1315631.patch"       "893de7431d51" "11gyik8mwipl6ipypkvdq519pw7ccbg0g0bnvxb7271n44cqqcq5"))) ;CVE-2016-9893-pt11
      (modules '((guix build utils)))
      (snippet
       '(begin
          (use-modules (ice-9 ftw))
          ;; Remove bundled libraries that we don't use, since they may
          ;; contain unpatched security flaws, they waste disk space and
          ;; network bandwidth, and may cause confusion.
          (for-each delete-file-recursively
                    '(;; FIXME: Removing the bundled icu breaks configure.
                      ;;   * The bundled icu headers are used in some places.
                      ;;   * The version number is taken from the bundled copy.
                      ;;"intl/icu"
                      ;;
                      ;; FIXME: A script from the bundled nspr is used.
                      ;;"nsprpub"
                      ;;
                      ;; TODO: Use system media libraries.  Waiting for:
                      ;; <https://bugzilla.mozilla.org/show_bug.cgi?id=517422>
                      ;;   * libogg
                      ;;   * libtheora
                      ;;   * libvorbis
                      ;;   * libtremor (not yet in guix)
                      ;;   * libopus
                      ;;   * speex
                      ;;   * soundtouch (not yet in guix)
                      ;;
                      ;; TODO: Use system harfbuzz.  Waiting for:
                      ;; <https://bugzilla.mozilla.org/show_bug.cgi?id=847568>
                      ;;
                      ;; TODO: Use system graphite2.
                      ;;
                      "modules/freetype2"
                      "modules/zlib"
                      "modules/libbz2"
                      "ipc/chromium/src/third_party/libevent"
                      "media/libjpeg"
                      "media/libvpx"
                      "security/nss"
                      "gfx/cairo"
                      "js/src/ctypes/libffi"
                      "db/sqlite3"))
          ;; Delete .pyc files, typically present in icecat source tarballs
          (for-each delete-file (find-files "." "\\.pyc$"))
          ;; Delete obj-* directories, sometimes present in icecat tarballs
          (for-each delete-file-recursively
                    (scandir "." (lambda (name)
                                   (string-prefix? "obj-" name))))
          #t))))
    (build-system gnu-build-system)
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("bzip2" ,bzip2)
       ("cairo" ,cairo)
       ("cups" ,cups)
       ("dbus-glib" ,dbus-glib)
       ("gdk-pixbuf" ,gdk-pixbuf)
       ("glib" ,glib)
       ("gstreamer" ,gstreamer)
       ("gst-plugins-base" ,gst-plugins-base)
       ("gtk+" ,gtk+-2)
       ("pango" ,pango)
       ("freetype" ,freetype)
       ("hunspell" ,hunspell)
       ("libcanberra" ,libcanberra)
       ("libgnome" ,libgnome)
       ("libjpeg-turbo" ,libjpeg-turbo)
       ("libxft" ,libxft)
       ("libevent" ,libevent)
       ("libxinerama" ,libxinerama)
       ("libxscrnsaver" ,libxscrnsaver)
       ("libxcomposite" ,libxcomposite)
       ("libxt" ,libxt)
       ("libffi" ,libffi)
       ("libvpx" ,libvpx)
       ("icu4c" ,icu4c)
       ("pixman" ,pixman)
       ("pulseaudio" ,pulseaudio)
       ("mesa" ,mesa)
       ("mit-krb5" ,mit-krb5)
       ("nspr" ,nspr)
       ("nss" ,nss)
       ("sqlite" ,sqlite)
       ("startup-notification" ,startup-notification)
       ("unzip" ,unzip)
       ("yasm" ,yasm)
       ("zip" ,zip)
       ("zlib" ,zlib)))
    (native-inputs
     `(("perl" ,perl)
       ("python" ,python-2) ; Python 3 not supported
       ("python2-pysqlite" ,python2-pysqlite)
       ("pkg-config" ,pkg-config)
       ("which" ,which)))
    (arguments
     `(#:tests? #f          ; no check target
       #:out-of-source? #t  ; must be built outside of the source directory
       #:parallel-build? #f

       ;; XXX: There are RUNPATH issues such as
       ;; $prefix/lib/icecat-31.6.0/plugin-container NEEDing libmozalloc.so,
       ;; which is not in its RUNPATH, but they appear to be harmless in
       ;; practice somehow.  See <http://hydra.gnu.org/build/378133>.
       #:validate-runpath? #f

       #:configure-flags '("--enable-default-toolkit=cairo-gtk2"
                           "--enable-pango"
                           "--enable-gio"
                           "--enable-svg"
                           "--enable-canvas"
                           "--enable-mathml"
                           "--enable-startup-notification"
                           "--enable-pulseaudio"
                           "--enable-gstreamer=1.0"

                           "--disable-gnomevfs"
                           "--disable-gconf"
                           "--disable-gnomeui"

                           ;; Building with debugging symbols takes ~5GiB, so
                           ;; disable it.
                           "--disable-debug"
                           "--disable-debug-symbols"

                           ;; Hack to work around missing
                           ;; "unofficial" branding in icecat.
                           "--enable-official-branding"

                           ;; Avoid bundled libraries.
                           "--with-system-zlib"
                           "--with-system-bz2"
                           "--with-system-jpeg"        ; must be libjpeg-turbo
                           "--with-system-libevent"
                           "--with-system-libvpx"
                           "--with-system-icu"
                           "--with-system-nspr"
                           "--with-system-nss"
                           "--enable-system-pixman"
                           "--enable-system-cairo"
                           "--enable-system-ffi"
                           "--enable-system-hunspell"
                           "--enable-system-sqlite"

                           ;; Fails with "--with-system-png won't work because
                           ;; the system's libpng doesn't have APNG support".
                           ;; According to
                           ;; http://sourceforge.net/projects/libpng-apng/ ,
                           ;; "the Animated Portable Network Graphics (APNG)
                           ;; is an unofficial extension of the Portable
                           ;; Network Graphics (PNG) format";
                           ;; we probably do not wish to support it.
                           ;; "--with-system-png"
                           )

       #:modules ((ice-9 ftw)
                  (ice-9 rdelim)
                  (ice-9 match)
                  ,@%gnu-build-system-modules)
       #:phases
       (modify-phases %standard-phases
         (add-after
          'unpack 'ensure-no-mtimes-pre-1980
          (lambda _
            ;; Without this, the 'source/test/addons/packed.xpi' and
            ;; 'source/test/addons/simple-prefs.xpi' targets fail while trying
            ;; to create zip archives.
            (let ((early-1980 315619200)) ; 1980-01-02 UTC
              (ftw "." (lambda (file stat flag)
                         (unless (<= early-1980 (stat:mtime stat))
                           (utime file early-1980 early-1980))
                         #t))
              #t)))
         (add-after
          'unpack 'remove-h264parse-from-blacklist
          (lambda _
            ;; Remove h264parse from gstreamer format helper blacklist.  It
            ;; was put there to work around a bug in a pre-1.0 version of
            ;; gstreamer.  See:
            ;; https://www.mozilla.org/en-US/security/advisories/mfsa2015-47/
            (substitute* "dom/media/gstreamer/GStreamerFormatHelper.cpp"
              (("^  \"h264parse\",\n") ""))
            #t))
         (add-after
          'unpack 'arrange-to-link-libxul-with-libraries-it-might-dlopen
          (lambda _
            ;; libxul.so dynamically opens libraries, so here we explicitly
            ;; link them into libxul.so instead.
            ;;
            ;; TODO: It might be preferable to patch in absolute file names in
            ;; calls to dlopen or PR_LoadLibrary, but that didn't seem to
            ;; work.  More investigation is needed.
            (substitute* "toolkit/library/moz.build"
              (("^# This needs to be last")
               "OS_LIBS += [
    'GL', 'gnome-2', 'canberra', 'Xss', 'cups', 'gssapi_krb5',
    'gstreamer-1.0', 'gstapp-1.0', 'gstvideo-1.0' ]\n\n"))
            #t))
         (replace
          'configure
          ;; configure does not work followed by both "SHELL=..." and
          ;; "CONFIG_SHELL=..."; set environment variables instead
          (lambda* (#:key outputs configure-flags #:allow-other-keys)
            (let* ((out (assoc-ref outputs "out"))
                   (bash (which "bash"))
                   (abs-srcdir (getcwd))
                   (srcdir (string-append "../" (basename abs-srcdir)))
                   (flags `(,(string-append "--prefix=" out)
                            ,(string-append "--with-l10n-base="
                                            abs-srcdir "/l10n")
                            ,@configure-flags)))
              (setenv "SHELL" bash)
              (setenv "CONFIG_SHELL" bash)
              (mkdir "../build")
              (chdir "../build")
              (format #t "build directory: ~s~%" (getcwd))
              (format #t "configure flags: ~s~%" flags)
              (zero? (apply system* bash
                            (string-append srcdir "/configure")
                            flags)))))
         (add-before 'configure 'install-desktop-entry
           (lambda* (#:key outputs #:allow-other-keys)
             ;; Install the '.desktop' file.
             (define (swallow-%%-directives input output)
               ;; Interpret '%%ifdef' directives found in the '.desktop' file.
               (let loop ((state 'top))
                 (match (read-line input 'concat)
                   ((? eof-object?)
                    #t)
                   ((? string? line)
                    (cond ((string-prefix? "%%ifdef" line)
                           (loop 'ifdef))
                          ((string-prefix? "%%else" line)
                           (loop 'else))
                          ((string-prefix? "%%endif" line)
                           (loop 'top))
                          (else
                           (case state
                             ((top else)
                              (display line output)
                              (loop state))
                             (else
                              (loop state)))))))))

             (let* ((out (assoc-ref outputs "out"))
                    (applications (string-append out "/share/applications")))
               (call-with-input-file "debian/icecat.desktop.in"
                 (lambda (input)
                   (call-with-output-file "debian/icecat.desktop"
                     (lambda (output)
                       (swallow-%%-directives input output)))))

               (substitute* "debian/icecat.desktop"
                 (("@MOZ_DISPLAY_NAME@")
                  "GNU IceCat")
                 (("^Exec=@MOZ_APP_NAME@")
                  (string-append "Exec=" out "/bin/icecat"))
                 (("@MOZ_APP_NAME@")
                  "icecat"))
               (install-file "debian/icecat.desktop" applications)
               #t)))
         (add-after 'install-desktop-entry 'install-icons
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (with-directory-excursion "browser/branding/official"
                 (for-each
                  (lambda (file)
                    (let* ((size (string-filter char-numeric? file))
                           (icons (string-append out "/share/icons/hicolor/"
                                                 size "x" size "/apps")))
                      (mkdir-p icons)
                      (copy-file file (string-append icons "/icecat.png"))))
                  '("default16.png" "default22.png" "default24.png"
                    "default32.png" "default48.png" "content/icon64.png"
                    "mozicon128.png" "default256.png")))))))))
    (home-page "http://www.gnu.org/software/gnuzilla/")
    (synopsis "Entirely free browser derived from Mozilla Firefox")
    (description
     "IceCat is the GNU version of the Firefox browser.  It is entirely free
software, which does not recommend non-free plugins and addons.  It also
features built-in privacy-protecting features.")
    (license license:mpl2.0)     ;and others, see toolkit/content/license.html
    (properties
     `((ftp-directory . "/gnu/gnuzilla")
       (cpe-name . "firefox_esr")
       (cpe-version . ,(first (string-split version #\-)))))))
