;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2016 Jan Nieuwenhuizen <janneke@gnu.org>
;;; Copyright © 2016 Mathieu Lirzin <mthl@gnu.org>
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

(define-module (gnu packages ci)
  #:use-module ((guix licenses) #:prefix l:)
  #:use-module (gnu packages)
  #:use-module (guix packages)
  #:use-module (guix git-download)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages base)
  #:use-module (gnu packages docbook)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages mail)
  #:use-module (gnu packages package-management)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages version-control)
  #:use-module (gnu packages web)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages zip)
  #:use-module (guix build-system gnu))

(define-public hydra
  (let ((commit "1ff48da3d3d4a425063f5b7dd0b89d35270f8932"))
    (package
      (name "hydra")
      (version (string-append "20151030." (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/NixOS/hydra")
                      (commit commit)))
                (file-name (string-append name "-" version))
                (patches (search-patches
                          ;; TODO: Remove once we have a darcs input
                          "hydra-disable-darcs-test.patch"))
                (sha256
                 (base32
                  "0ni8i8v1nxxfr51rz8m6znwpbm77vr7i05k506hmgmg32r938lap"))))
      (build-system gnu-build-system)
      (native-inputs
       `(("unzip" ,unzip)
         ("pkg-config" ,pkg-config)
         ;; For documentation
         ("dblatex" ,dblatex)
         ("xsltproc" ,libxslt)
         ("docbook-xsl" ,docbook-xsl)
         ;; For bootstrap
         ("autoconf" ,autoconf)
         ("automake" ,automake)
         ("libtool" ,libtool)
         ;; For tests
         ("git" ,git)
         ("subversion" ,subversion)
         ("mercurial" ,mercurial)
         ("bazaar" ,bazaar)))
      (inputs
       `(("libpqxx" ,libpqxx)
         ("perl" ,perl)
         ("guile" ,guile-2.0)
         ("openssl" ,openssl)
         ("bzip2" ,bzip2)
         ("gzip" ,gzip)
         ("sed" ,sed)
         ("starman" ,starman)
         ("git" ,git)
         ("subversion" ,subversion)
         ("mercurial" ,mercurial)
         ("bazaar" ,bazaar)
         ("nix" ,nix)
         ;; Lots o' perl modules...
         ("perl-catalyst-action-rest" ,perl-catalyst-action-rest)
         ("perl-catalyst-authentication-store-dbix-class"
          ,perl-catalyst-authentication-store-dbix-class)
         ("perl-catalyst-devel" ,perl-catalyst-devel)
         ("perl-catalyst-dispatchtype-regex" ,perl-catalyst-dispatchtype-regex)
         ("perl-catalyst-plugin-accesslog" ,perl-catalyst-plugin-accesslog)
         ("perl-catalyst-plugin-authorization-roles"
          ,perl-catalyst-plugin-authorization-roles)
         ("perl-catalyst-plugin-captcha" ,perl-catalyst-plugin-captcha)
         ("perl-catalyst-plugin-session-state-cookie"
          ,perl-catalyst-plugin-session-state-cookie)
         ("perl-catalyst-plugin-session-store-fastmmap"
          ,perl-catalyst-plugin-session-store-fastmmap)
         ("perl-catalyst-plugin-stacktrace" ,perl-catalyst-plugin-stacktrace)
         ("perl-catalyst-traitfor-request-proxybase"
          ,perl-catalyst-traitfor-request-proxybase)
         ("perl-catalyst-view-download" ,perl-catalyst-view-download)
         ("perl-catalyst-view-json" ,perl-catalyst-view-json)
         ("perl-catalyst-view-tt" ,perl-catalyst-view-tt)
         ("perl-catalystx-roleapplicator" ,perl-catalystx-roleapplicator)
         ("perl-catalystx-script-server-starman"
          ,perl-catalystx-script-server-starman)
         ("perl-crypt-randpasswd" ,perl-crypt-randpasswd)
         ("perl-data-dump" ,perl-data-dump)
         ("perl-datetime" ,perl-datetime)
         ("perl-dbd-pg" ,perl-dbd-pg)
         ("perl-dbd-sqlite" ,perl-dbd-sqlite)
         ("perl-digest-sha1" ,perl-digest-sha1)
         ("perl-email-mime" ,perl-email-mime)
         ("perl-email-sender" ,perl-email-sender)
         ("perl-file-slurp" ,perl-file-slurp)
         ("perl-io-compress" ,perl-io-compress)
         ("perl-ipc-run" ,perl-ipc-run)
         ("perl-json-any" ,perl-json-any)
         ("perl-json-xs" ,perl-json-xs)
         ("perl-libwww" ,perl-libwww)
         ("perl-lwp-protocol-https" ,perl-lwp-protocol-https)
         ("perl-net-amazon-s3" ,perl-net-amazon-s3)
         ("perl-net-statsd" ,perl-net-statsd)
         ("perl-padwalker" ,perl-padwalker)
         ("perl-readonly" ,perl-readonly)
         ("perl-set-scalar" ,perl-set-scalar)
         ("perl-sql-splitstatement" ,perl-sql-splitstatement)
         ("perl-sys-hostname-long" ,perl-sys-hostname-long)
         ("perl-text-diff" ,perl-text-diff)
         ("perl-text-table" ,perl-text-table)
         ("perl-xml-simple" ,perl-xml-simple)))
      (arguments
       `(#:configure-flags
         (let ((docbook (assoc-ref %build-inputs "docbook-xsl")))
           (list (string-append "--with-docbook-xsl="
                                docbook "/xml/xsl/docbook-xsl-"
                                ,(package-version docbook-xsl))
                 (string-append "--docdir=" %output
                                "/doc/hydra-" ,version)))
         #:phases (modify-phases %standard-phases
                    (add-after
                     'unpack 'bootstrap
                     (lambda _ (zero? (system* "autoreconf" "-vfi"))))
                    (add-before
                     'check 'check-setup
                     (lambda _ (setenv "LOGNAME" "test.log")))
                    (add-after
                     'install 'wrap-program
                     (lambda* (#:key inputs outputs #:allow-other-keys)
                       (let ((out (assoc-ref outputs "out")))
                         (for-each
                          (lambda (file)
                            (wrap-program file
                              `("PATH" ":" prefix
                                (,(string-append out "/bin")
                                 ,@(map (lambda (i)
                                          (string-append (assoc-ref inputs i)
                                                         "/bin"))
                                        '("subversion" "git" "bazaar"
                                          "mercurial" "coreutils" "gzip"
                                          "sed" "unzip" "nix"))))
                              `("PERL5LIB" ":" prefix
                                (,(string-append out "/libexec/hydra/lib")
                                 ,@(search-path-as-string->list
                                    (getenv "PERL5LIB"))))
                              `("HYDRA_RELEASE" = (,,version))
                              `("HYDRA_HOME" =
                                (,(string-append out "/libexec/hydra")))
                              `("NIX_RELEASE" = (,,(package-version nix)))))
                          (find-files (string-append out "/bin")
                                      ".*"))))))))
      (home-page "https://nixos.org/hydra")
      (synopsis "Continuous build system")
      (description
       "Hydra is a tool for continuous integration testing and software
release that uses a purely functional language to describe build jobs and
their dependencies.")
      (license l:gpl3+))))

(define-public cuirass
  (let ((commit "cbdb59af8e7a1b40d687f80e62c5892686d384d2")
        (revision "2"))
    (package
      (name "cuirass")
      (version (string-append "0.0.1-" revision "." (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://notabug.org/mthl/cuirass")
                      (commit commit)))
                (file-name (string-append name "-" version))
                (sha256
                 (base32
                  "0qmhchazg8wyrfn6d2im4jg7d52gb0xp8afjan5szl3bpphi4s28"))))
      (build-system gnu-build-system)
      (arguments
       '(#:phases
         (modify-phases %standard-phases
           (add-after 'unpack 'bootstrap
             (lambda _ (zero? (system* "sh" "bootstrap"))))
           (add-after 'install 'wrap-program
             (lambda* (#:key inputs outputs #:allow-other-keys)
               ;; Wrap the 'cuirass' command to refer to the right modules.
               (let* ((out    (assoc-ref outputs "out"))
                      (json   (assoc-ref inputs "guile-json"))
                      (sqlite (assoc-ref inputs "guile-sqlite3"))
                      (git    (assoc-ref inputs "git"))
                      (guix   (assoc-ref inputs "guix"))
                      (mods   (string-append json "/share/guile/site/2.0:"
                                             sqlite "/share/guile/site/2.0:"
                                             guix "/share/guile/site/2.0")))
                 ;; Make sure 'cuirass' can find the 'git' and 'evaluate'
                 ;; commands, as well as the relevant Guile modules.
                 (wrap-program (string-append out "/bin/cuirass")
                   `("PATH" ":" prefix (,(string-append out "/bin")
                                        ,(string-append git "/bin")))
                   `("GUILE_LOAD_PATH" ":" prefix (,mods))
                   `("GUILE_LOAD_COMPILED_PATH" ":" prefix (,mods)))
                 #t))))))
      (inputs
       `(("guile" ,guile-2.0)
         ("guile-json" ,guile-json)
         ("guile-sqlite3" ,guile-sqlite3)
         ("guix" ,guix)
         ("git" ,git)))
      (native-inputs
       `(("autoconf" ,autoconf)
         ("automake" ,automake)
         ("pkg-config" ,pkg-config)
         ("texinfo" ,texinfo)))
      (synopsis "Continuous integration system")
      (description
       "Cuirass is a continuous integration tool using GNU Guix.  It is
intended as a replacement for Hydra.")
      (home-page "https://notabug.org/mthl/cuirass")
      (license l:gpl3+))))
