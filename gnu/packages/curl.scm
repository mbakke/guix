;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2015 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2015 Tomáš Čech <sleep_walker@suse.cz>
;;; Copyright © 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 Leo Famulari <leo@famulari.name>
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

(define-module (gnu packages curl)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages groff)
  #:use-module (gnu packages gsasl)
  #:use-module (gnu packages libidn)
  #:use-module (gnu packages openldap)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages ssh)
  #:use-module (gnu packages tls))

(define-public curl
  (package
   (name "curl")
   (replacement curl-7.52.1)
   (version "7.50.3")
   (source (origin
            (method url-fetch)
            (uri (string-append "https://curl.haxx.se/download/curl-"
                                version ".tar.lzma"))
            (sha256
             (base32
              "1spmk0345hq0sgpwxs8d410268lmg3wf1x9v23hxff7wxki5fm4c"))))
   (build-system gnu-build-system)
   (outputs '("out"
              "doc"))                             ;1.2 MiB of man3 pages
   (inputs `(("gnutls" ,gnutls)
             ("gss" ,gss)
             ("libidn" ,libidn)
             ("libssh2" ,libssh2)
             ("openldap" ,openldap)
             ("zlib" ,zlib)))
   (native-inputs
     `(("perl" ,perl)
       ;; to enable the --manual option and make test 1026 pass
       ("groff" ,groff)
       ("pkg-config" ,pkg-config)
       ("python" ,python-2)))
   (arguments
    `(#:configure-flags '("--with-gnutls" "--with-gssapi")
      ;; Add a phase to patch '/bin/sh' occurances in tests/runtests.pl
      #:phases
      (modify-phases %standard-phases
        (add-after
         'install 'move-man3-pages
         (lambda* (#:key outputs #:allow-other-keys)
           ;; Move section 3 man pages to "doc".
           (let ((out (assoc-ref outputs "out"))
                 (doc (assoc-ref outputs "doc")))
             (mkdir-p (string-append doc "/share/man"))
             (rename-file (string-append out "/share/man/man3")
                          (string-append doc "/share/man/man3"))
             #t)))
        (replace
         'check
         (lambda _
           (substitute* "tests/runtests.pl"
             (("/bin/sh") (which "sh")))

           ;; XXX FIXME: Test #1510 seems to work on some machines and not
           ;; others, possibly based on the kernel version.  It works on GuixSD
           ;; on x86_64 with linux-libre-4.1, but fails on Hydra for both i686
           ;; and x86_64 with the following error:
           ;;
           ;; test 1510...[HTTP GET connection cache limit (CURLOPT_MAXCONNECTS)]
           ;;
           ;;  1510: output (log/stderr1510) FAILED:
           ;; --- log/check-expected    2015-06-27 07:45:53.166720834 +0000
           ;; +++ log/check-generated   2015-06-27 07:45:53.166720834 +0000
           ;; @@ -1,5 +1,5 @@
           ;;  * Connection #0 to host server1.example.com left intact[LF]
           ;;  * Connection #1 to host server2.example.com left intact[LF]
           ;;  * Connection #2 to host server3.example.com left intact[LF]
           ;; -* Closing connection 0[LF]
           ;; +* Closing connection 1[LF]
           ;;  * Connection #3 to host server4.example.com left intact[LF]
           (delete-file "tests/data/test1510")

           ;; The top-level "make check" does "make -C tests quiet-test", which
           ;; is too quiet.  Use the "test" target instead, which is more
           ;; verbose.
           (zero? (system* "make" "-C" "tests" "test")))))))
   (synopsis "Command line tool for transferring data with URL syntax")
   (description
    "curl is a command line tool for transferring data with URL syntax,
supporting DICT, FILE, FTP, FTPS, Gopher, HTTP, HTTPS, IMAP, IMAPS, LDAP,
LDAPS, POP3, POP3S, RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, Telnet and TFTP.
curl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP
form based upload, proxies, cookies, file transfer resume, user+password
authentication (Basic, Digest, NTLM, Negotiate, kerberos...), proxy
tunneling, and so on.")
   (license (license:non-copyleft "file://COPYING"
                                  "See COPYING in the distribution."))
   (home-page "https://curl.haxx.se/")))

(define curl-7.52.1
  (package
    (inherit curl)
    (source
      (let ((version "7.52.1"))
        (origin
          (method url-fetch)
          (uri (string-append "https://curl.haxx.se/download/curl-"
                              version ".tar.lzma"))
          (sha256
           (base32
            "0r937wplchjxifxqqcjxd9rzp6l9rqqdfjn41x1y4djrh95nsa24")))))))
