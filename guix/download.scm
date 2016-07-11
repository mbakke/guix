;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2012, 2013, 2014, 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013, 2014, 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2015 Federico Beffa <beffa@fbengineering.ch>
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

(define-module (guix download)
  #:use-module (ice-9 match)
  #:use-module (guix derivations)
  #:use-module (guix packages)
  #:use-module (guix store)
  #:use-module ((guix build download) #:prefix build:)
  #:use-module (guix monads)
  #:use-module (guix gexp)
  #:use-module (guix utils)
  #:use-module (web uri)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:export (%mirrors
            url-fetch
            url-fetch/tarbomb
            download-to-store))

;;; Commentary:
;;;
;;; Produce fixed-output derivations with data fetched over HTTP or FTP.
;;;
;;; Code:

(define %mirrors
  ;; Mirror lists used when `mirror://' URLs are passed.
  (let* ((gnu-mirrors
          '(;; This one redirects to a (supposedly) nearby and (supposedly)
            ;; up-to-date mirror.
            "http://ftpmirror.gnu.org/"

            "ftp://ftp.cs.tu-berlin.de/pub/gnu/"
            "ftp://ftp.funet.fi/pub/mirrors/ftp.gnu.org/gnu/"

            ;; This one is the master repository, and thus it's always
            ;; up-to-date.
            "http://ftp.gnu.org/pub/gnu/")))
    `((gnu ,@gnu-mirrors)
      (gcc
       "ftp://ftp.nluug.nl/mirror/languages/gcc/"
       "ftp://ftp.fu-berlin.de/unix/languages/gcc/"
       "ftp://ftp.irisa.fr/pub/mirrors/gcc.gnu.org/gcc/"
       "ftp://gcc.gnu.org/pub/gcc/"
       ,@(map (cut string-append <> "/gcc") gnu-mirrors))
      (gnupg
       "ftp://gd.tuwien.ac.at/privacy/gnupg/"
       "ftp://mirrors.dotsrc.org/gcrypt/"
       "ftp://mirror.cict.fr/gnupg/"
       "http://artfiles.org/gnupg.org"
       "ftp://ftp.franken.de/pub/crypt/mirror/ftp.gnupg.org/gcrypt/"
       "ftp://ftp.freenet.de/pub/ftp.gnupg.org/gcrypt/"
       "http://www.crysys.hu/"
       "ftp://ftp.hi.is/pub/mirrors/gnupg/"
       "ftp://ftp.heanet.ie/mirrors/ftp.gnupg.org/gcrypt/"
       "ftp://ftp.bit.nl/mirror/gnupg/"
       "ftp://ftp.surfnet.nl/pub/security/gnupg/"
       "ftp://ftp.iasi.roedu.net/pub/mirrors/ftp.gnupg.org/"
       "ftp://ftp.sunet.se/pub/security/gnupg/"
       "ftp://mirror.switch.ch/mirror/gnupg/"
       "ftp://mirror.tje.me.uk/pub/mirrors/ftp.gnupg.org/"
       "ftp://ftp.mirrorservice.org/sites/ftp.gnupg.org/gcrypt/"
       "ftp://ftp.ring.gr.jp/pub/net/gnupg/"
       "ftp://ftp.gnupg.org/gcrypt/")
      (gnome
       "http://ftp.belnet.be/ftp.gnome.org/"
       "http://ftp.linux.org.uk/mirrors/ftp.gnome.org/"
       "http://ftp.gnome.org/pub/GNOME/"
       "http://mirror.yandex.ru/mirrors/ftp.gnome.org/")
      (savannah
       "http://download.savannah.gnu.org/releases/"
       "ftp://ftp.twaren.net/Unix/NonGNU/"
       "ftp://mirror.csclub.uwaterloo.ca/nongnu/"
       "ftp://mirror.publicns.net/pub/nongnu/"
       "ftp://savannah.c3sl.ufpr.br/"
       "http://ftp.cc.uoc.gr/mirrors/nongnu.org/"
       "http://ftp.twaren.net/Unix/NonGNU/"
       "http://mirror.csclub.uwaterloo.ca/nongnu/"
       "http://nongnu.askapache.com/"
       "http://savannah.c3sl.ufpr.br/"
       "http://www.centervenus.com/mirrors/nongnu/"
       "http://download.savannah.gnu.org/releases-noredirect/")
      (sourceforge ; https://sourceforge.net/p/forge/documentation/Mirrors/
       "http://prdownloads.sourceforge.net/"
       "http://heanet.dl.sourceforge.net/sourceforge/"
       "http://dfn.dl.sourceforge.net/sourceforge/"
       "http://freefr.dl.sourceforge.net/sourceforge/"
       "http://internode.dl.sourceforge.net/sourceforge/"
       "http://iweb.dl.sourceforge.net/sourceforge/"
       "http://jaist.dl.sourceforge.net/sourceforge/"
       "http://kaz.dl.sourceforge.net/sourceforge/"
       "http://kent.dl.sourceforge.net/sourceforge/"
       "http://liquidtelecom.dl.sourceforge.net/sourceforge/"
       "http://nbtelecom.dl.sourceforge.net/sourceforge/"
       "http://nchc.dl.sourceforge.net/sourceforge/"
       "http://ncu.dl.sourceforge.net/sourceforge/"
       "http://netcologne.dl.sourceforge.net/sourceforge/"
       "http://netix.dl.sourceforge.net/sourceforge/"
       "http://pilotfiber.dl.sourceforge.net/sourceforge/"
       "http://superb-sea2.dl.sourceforge.net/sourceforge/"
       "http://tenet.dl.sourceforge.net/sourceforge/"
       "http://ufpr.dl.sourceforge.net/sourceforge/"
       "http://vorboss.dl.sourceforge.net/sourceforge/"
       "http://netassist.dl.sourceforge.net/sourceforge/")
      (kernel.org
       "http://www.all.kernel.org/pub/"
       "http://ramses.wh2.tu-dresden.de/pub/mirrors/kernel.org/"
       "http://linux-kernel.uio.no/pub/"
       "http://kernel.osuosl.org/pub/"
       "ftp://ftp.funet.fi/pub/mirrors/ftp.kernel.org/pub/"
       "http://ftp.be.debian.org/pub/"
       "http://mirror.linux.org.au/")
      (apache             ; from http://www.apache.org/mirrors/dist.html
       "http://www.eu.apache.org/dist/"
       "http://www.us.apache.org/dist/"
       "ftp://gd.tuwien.ac.at/pub/infosys/servers/http/apache/dist/"
       "http://apache.belnet.be/"
       "http://mirrors.ircam.fr/pub/apache/"
       "http://apache-mirror.rbc.ru/pub/apache/"

       ;; As a last resort, try the archive.
       "http://archive.apache.org/dist/")
      (xorg               ; from http://www.x.org/wiki/Releases/Download
       "http://www.x.org/releases/" ; main mirrors
       "ftp://mirror.csclub.uwaterloo.ca/x.org/" ; North America
       "ftp://xorg.mirrors.pair.com/"
       "http://mirror.csclub.uwaterloo.ca/x.org/"
       "http://xorg.mirrors.pair.com/"
       "http://mirror.us.leaseweb.net/xorg/"
       "ftp://artfiles.org/x.org/" ; Europe
       "ftp://ftp.chg.ru/pub/X11/x.org/"
       "ftp://ftp.fu-berlin.de/unix/X11/FTP.X.ORG/"
       "ftp://ftp.gwdg.de/pub/x11/x.org/"
       "ftp://ftp.mirrorservice.org/sites/ftp.x.org/"
       "ftp://ftp.ntua.gr/pub/X11/"
       "ftp://ftp.piotrkosoft.net/pub/mirrors/ftp.x.org/"
       "ftp://ftp.portal-to-web.de/pub/mirrors/x.org/"
       "ftp://ftp.solnet.ch/mirror/x.org/"
       "ftp://gd.tuwien.ac.at/X11/"
       "ftp://mi.mirror.garr.it/mirrors/x.org/"
       "ftp://mirror.cict.fr/x.org/"
       "ftp://mirror.switch.ch/mirror/X11/"
       "ftp://mirrors.ircam.fr/pub/x.org/"
       "ftp://x.mirrors.skynet.be/pub/ftp.x.org/"
       "ftp://ftp.cs.cuhk.edu.hk/pub/X11" ; East Asia
       "ftp://ftp.u-aizu.ac.jp/pub/x11/x.org/"
       "ftp://ftp.yz.yamagata-u.ac.jp/pub/X11/x.org/"
       "ftp://ftp.kaist.ac.kr/x.org/"
       "ftp://mirrors.go-part.com/xorg/"
       "http://x.cs.pu.edu.tw/"
       "ftp://ftp.is.co.za/pub/x.org")            ; South Africa
      (cpan                              ; from http://www.cpan.org/SITES.html
       "http://mirror.ibcp.fr/pub/CPAN/"
       "ftp://ftp.ciril.fr/pub/cpan/"
       "ftp://artfiles.org/cpan.org/"
       "http://www.cpan.org/"
       "ftp://cpan.rinet.ru/pub/mirror/CPAN/"
       "ftp://cpan.inode.at/"
       "ftp://cpan.iht.co.il/"
       "ftp://ftp.osuosl.org/pub/CPAN/"
       "ftp://ftp.nara.wide.ad.jp/pub/CPAN/"
       "http://mirrors.163.com/cpan/"
       "ftp://cpan.mirror.ac.za/"
       "http://cpan.mirrors.ionfish.org/"
       "http://cpan.mirror.dkm.cz/pub/CPAN/"
       "http://cpan.mirror.iphh.net/"
       "http://mirrors.teentelecom.net/CPAN/"
       "http://mirror.teklinks.com/CPAN/"
       "http://cpan.weepeetelecom.be/"
       "http://mirrors.xservers.ro/CPAN/"
       "http://cpan.yimg.com/"
       "http://mirror.yazd.ac.ir/cpan/"
       "http://ftp.belnet.be/ftp.cpan.org/")
      (cran
       ;; Arbitrary mirrors from http://cran.r-project.org/mirrors.html
       ;; This one automatically redirects to servers worldwide
       "http://cran.r-project.org/"
       "http://cran.rstudio.com/"
       "http://cran.univ-lyon1.fr/"
       "http://cran.ism.ac.jp/"
       "http://cran.stat.auckland.ac.nz/"
       "http://cran.mirror.ac.za/"
       "http://cran.csie.ntu.edu.tw/")
      (imagemagick
       ;; from http://www.imagemagick.org/script/download.php
       ;; (without mirrors that are unavailable or not up to date)
       ;; mirrors keeping old versions at the top level
       "ftp://sunsite.icm.edu.pl/packages/ImageMagick/"
       ;; mirrors moving old versions to "legacy"
       "http://mirrors-au.go-parts.com/mirrors/ImageMagick/"
       "ftp://mirror.aarnet.edu.au/pub/imagemagick/"
       "http://mirror.checkdomain.de/imagemagick/"
       "ftp://ftp.kddlabs.co.jp/graphics/ImageMagick/"
       "ftp://ftp.u-aizu.ac.jp/pub/graphics/image/ImageMagick/imagemagick.org/"
       "ftp://ftp.nluug.nl/pub/ImageMagick/"
       "http://ftp.surfnet.nl/pub/ImageMagick/"
       "http://mirror.searchdaimon.com/ImageMagick"
       "ftp://ftp.tpnet.pl/pub/graphics/ImageMagick/"
       "http://mirrors-ru.go-parts.com/mirrors/ImageMagick/"
       "http://mirror.is.co.za/pub/imagemagick/"
       "http://mirrors-uk.go-parts.com/mirrors/ImageMagick/"
       "http://mirrors-usa.go-parts.com/mirrors/ImageMagick/"
       "ftp://ftp.fifi.org/pub/ImageMagick/"
       "http://www.imagemagick.org/download/"
       ;; one legacy location as a last resort
       "http://www.imagemagick.org/download/legacy/")
      (debian
       "http://ftp.de.debian.org/debian/"
       "http://ftp.fr.debian.org/debian/"
       "http://ftp.debian.org/debian/"
       "http://archive.debian.org/debian/"))))

(define %mirror-file
  ;; Copy of the list of mirrors to a file.  This allows us to keep a single
  ;; copy in the store, and computing it here avoids repeated calls to
  ;; 'object->string'.
  (plain-file "mirrors" (object->string %mirrors)))

(define %content-addressed-mirrors
  ;; List of content-addressed mirrors.  Each mirror is represented as a
  ;; procedure that takes an algorithm (symbol) and a hash (bytevector), and
  ;; returns a URL or #f.
  ;; TODO: Add more.
  '(list (lambda (algo hash)
           ;; 'tarballs.nixos.org' supports several algorithms.
           (string-append "http://tarballs.nixos.org/"
                          (symbol->string algo) "/"
                          (bytevector->nix-base32-string hash)))))

(define %content-addressed-mirror-file
  ;; Content-addressed mirrors stored in a file.
  (plain-file "content-addressed-mirrors"
              (object->string %content-addressed-mirrors)))

(define (gnutls-package)
  "Return the default GnuTLS package."
  (let ((module (resolve-interface '(gnu packages tls))))
    (module-ref module 'gnutls)))

(define* (url-fetch url hash-algo hash
                    #:optional name
                    #:key (system (%current-system))
                    (guile (default-guile)))
  "Return a fixed-output derivation that fetches URL (a string, or a list of
strings denoting alternate URLs), which is expected to have hash HASH of type
HASH-ALGO (a symbol).  By default, the file name is the base name of URL;
optionally, NAME can specify a different file name.

When one of the URL starts with mirror://, then its host part is
interpreted as the name of a mirror scheme, taken from %MIRROR-FILE.

Alternately, when URL starts with file://, return the corresponding file name
in the store."
  (define file-name
    (match url
      ((head _ ...)
       (basename head))
      (_
       (basename url))))

  (define need-gnutls?
    ;; True if any of the URLs need TLS support.
    (let ((https? (cut string-prefix? "https://" <>)))
      (match url
        ((? string?)
         (https? url))
        ((url ...)
         (any https? url)))))

  (define builder
    (with-imported-modules '((guix build download)
                             (guix build utils)
                             (guix ftp-client)
                             (guix base32)
                             (guix base64))
      #~(begin
          #+(if need-gnutls?

                ;; Add GnuTLS to the inputs and to the load path.
                #~(eval-when (load expand eval)
                    (set! %load-path
                      (cons (string-append #+(gnutls-package)
                                           "/share/guile/site/"
                                           (effective-version))
                            %load-path)))
                #~#t)

          (use-modules (guix build download)
                       (guix base32))

          (let ((value-from-environment (lambda (variable)
                                          (call-with-input-string
                                              (getenv variable)
                                            read))))
            (url-fetch (value-from-environment "guix download url")
                       #$output
                       #:mirrors (call-with-input-file #$%mirror-file read)

                       ;; Content-addressed mirrors.
                       #:hashes
                       (value-from-environment "guix download hashes")
                       #:content-addressed-mirrors
                       (primitive-load #$%content-addressed-mirror-file))))))

  (let ((uri (and (string? url) (string->uri url))))
    (if (or (and (string? url) (not uri))
            (and uri (memq (uri-scheme uri) '(#f file))))
        (interned-file (if uri (uri-path uri) url)
                       (or name file-name))
        (mlet %store-monad ((guile (package->derivation guile system)))
          (gexp->derivation (or name file-name) builder
                            #:guile-for-build guile
                            #:system system
                            #:hash-algo hash-algo
                            #:hash hash

                            ;; Use environment variables and a fixed script
                            ;; name so there's only one script in store for
                            ;; all the downloads.
                            #:script-name "download"
                            #:env-vars
                            `(("guix download url" . ,(object->string url))
                              ("guix download hashes"
                               . ,(object->string `((,hash-algo . ,hash)))))

                            ;; Honor the user's proxy settings.
                            #:leaked-env-vars '("http_proxy" "https_proxy")

                            ;; In general, offloading downloads is not a good
                            ;; idea.  Daemons before 0.8.3 would also
                            ;; interpret this as "do not substitute" (see
                            ;; <https://bugs.gnu.org/18747>.)
                            #:local-build? #t)))))

(define* (url-fetch/tarbomb url hash-algo hash
                            #:optional name
                            #:key (system (%current-system))
                            (guile (default-guile)))
  "Similar to 'url-fetch' but unpack the file from URL in a directory of its
own.  This helper makes it easier to deal with \"tar bombs\"."
  (define gzip
    (module-ref (resolve-interface '(gnu packages compression)) 'gzip))
  (define tar
    (module-ref (resolve-interface '(gnu packages base)) 'tar))

  (mlet %store-monad ((drv (url-fetch url hash-algo hash
                                      (string-append "tarbomb-" name)
                                      #:system system
                                      #:guile guile)))
    ;; Take the tar bomb, and simply unpack it as a directory.
    (gexp->derivation name
                      #~(begin
                          (mkdir #$output)
                          (setenv "PATH" (string-append #$gzip "/bin"))
                          (chdir #$output)
                          (zero? (system* (string-append #$tar "/bin/tar")
                                          "xf" #$drv)))
                      #:local-build? #t)))

(define* (download-to-store store url #:optional (name (basename url))
                            #:key (log (current-error-port)) recursive?)
  "Download from URL to STORE, either under NAME or URL's basename if
omitted.  Write progress reports to LOG.  RECURSIVE? has the same effect as
the same-named parameter of 'add-to-store'."
  (define uri
    (string->uri url))

  (if (or (not uri) (memq (uri-scheme uri) '(file #f)))
      (add-to-store store name recursive? "sha256"
                    (if uri (uri-path uri) url))
      (call-with-temporary-output-file
       (lambda (temp port)
         (let ((result
                (parameterize ((current-output-port log))
                  (build:url-fetch url temp #:mirrors %mirrors))))
           (close port)
           (and result
                (add-to-store store name recursive? "sha256" temp)))))))

;;; download.scm ends here
