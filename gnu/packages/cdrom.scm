;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013, 2014, 2015 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2013, 2014 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2015 Taylan Ulrich Bayırlı/Kammer <taylanbayirli@gmail.com>
;;; Copyright © 2015 Paul van der Walt <paul@denknerd.org>
;;; Copyright © 2015, 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Alex Kost <alezost@gmail.com>
;;; Copyright © 2016 Marius Bakke <mbakke@fastmail.com>
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

(define-module (gnu packages cdrom)
  #:use-module (guix download)
  #:use-module (guix packages)
  #:use-module ((guix licenses) #:select (lgpl2.1+ gpl2 gpl2+ gpl3+))
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system glib-or-gtk)
  #:use-module (guix gexp)
  #:use-module (gnu packages)
  #:use-module (gnu packages acl)
  #:use-module (gnu packages audio)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages flex)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages man)
  #:use-module (gnu packages mp3)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages elf)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages base)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages python)
  #:use-module (gnu packages wget)
  #:use-module (gnu packages xiph))

(define-public libcddb
  (package
    (name "libcddb")
    (version "1.3.2")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://sourceforge/libcddb/libcddb/" version
                                 "/libcddb-" version ".tar.bz2"))
             (sha256
              (base32
               "0fr21a7vprdyy1bq6s99m0x420c9jm5fipsd63pqv8qyfkhhxkim"))))
    (build-system gnu-build-system)
    (arguments '(#:tests? #f))      ; tests rely on access to external servers
    (home-page "http://libcddb.sourceforge.net/")
    (synopsis "C library to access data on a CDDB server")
    (description
     "Libcddb is a C library to access data on a CDDB server (freedb.org).  It
allows you to:

 1. search the database for possible CD matches;

 2. retrieve detailed information about a specific CD;

 3. submit new CD entries to the database.

Libcddb supports both the custom CDDB protocol and tunnelling the query and
read operations over plain HTTP.  It is also possible to use an HTTP proxy
server.  If you want to speed things up, you can make use of the built-in
caching facility provided by the library.")
    (license lgpl2.1+)))

(define-public libcdio
  (package
    (name "libcdio")
    (version "0.94")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnu/libcdio/libcdio-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "0nh222bnj0hgdic5nvr8l9j194mh5niqy15rypwrdbk6z01wkqln"))))
    (build-system gnu-build-system)
    (inputs
     `(("ncurses" ,ncurses)
       ("libcddb" ,libcddb)))
    (native-inputs
     `(("help2man" ,help2man)
       ("pkg-config" ,pkg-config)))
    (home-page "https://www.gnu.org/software/libcdio/")
    (synopsis "CD Input and Control library")
    (description
     "The GNU Compact Disc Input and Control Library (libcdio) is a library
for CD-ROM and CD image file access.  It allows the developer to add CD
access to an application without having to worry about the OS- and
device-dependent properties of CD-ROM or the specific details of CD image
formats.  It includes pycdio, a Python interface to libcdio, and
libcdio-paranoia, a library providing jitter-free and error-free audio
extraction from CDs.")
    (license gpl3+)))

(define-public libcdio-paranoia
  (package
    (name "libcdio-paranoia")
    (version "10.2+0.93+1")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnu/libcdio/libcdio-paranoia-"
                                 version ".tar.bz2"))
             (sha256
              (base32
               "14x4b4jk5b0zvcalrg02y4jmbkmmlb07qfmk5hph9k18b8frn7gc"))))
    (build-system gnu-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)))
    (propagated-inputs `(("libcdio" ,libcdio)))
    (home-page "http://www.gnu.org/software/libcdio/")
    (synopsis "Jitter- and error-tolerant CD audio extraction")
    (description
     "libcdio-paranoia is an implementation of CD paranoia libraries based on
libcdio.")
    (license gpl3+)))

(define-public xorriso
  (package
    (name "xorriso")
    (version "1.4.6")
    (source (origin
             (method url-fetch)
             (uri (string-append "mirror://gnu/xorriso/xorriso-"
                                 version ".tar.gz"))
             (sha256
              (base32
               "112p0ghwzxrcjbsir1n2jxhq103ckrw93wzvd55qqvzfgs674vsj"))))
    (build-system gnu-build-system)
    (inputs
     `(("acl" ,acl)
       ("readline" ,readline)
       ("bzip2" ,bzip2)
       ("zlib" ,zlib)
       ("libcdio" ,libcdio)))
    (home-page "https://www.gnu.org/software/xorriso/")
    (synopsis "Create, manipulate, burn ISO-9660 file systems")
    (description
     "GNU Xorriso is a tool for copying files to and from ISO 9660 Rock
Ridge, a.k.a. Compact Disc File System, file systems and it allows
session-wise manipulation of them.  It features a formatter and burner for
CD, DVD and BD.  It can operate on existing ISO images or it can create new
ones.  xorriso can then be used to copy files directly into or out of ISO
files.")
    (license gpl3+)))

(define-public cdparanoia
  (package
    (name "cdparanoia")
    (version "10.2")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://downloads.xiph.org/releases/"
                                 "cdparanoia/cdparanoia-III-"
                                 version ".src.tgz"))
             (sha256
              (base32
               "1pv4zrajm46za0f6lv162iqffih57a8ly4pc69f7y0gfyigb8p80"))
             (patches (search-patches "cdparanoia-fpic.patch"))
             (modules '((guix build utils)))
             (snippet
              ;; Make libraries respect LDFLAGS.
              '(substitute* '("paranoia/Makefile.in" "interface/Makefile.in")
                 (("-Wl,-soname") "$(LDFLAGS) -Wl,-soname")))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; there is no check target
       #:configure-flags ; Add $libdir to the RUNPATH of all the executables.
       (list (string-append "LDFLAGS=-Wl,-rpath=" %output "/lib"))))
    (home-page "http://www.xiph.org/paranoia/")
    (synopsis "Audio CD reading utility")
    (description "Cdparanoia retrieves audio tracks from CDDA capable CDROM
drives.  The data can be saved to a file or directed to standard output
in WAV, AIFF, AIFF-C or raw format.  Most ATAPI, SCSI and several
proprietary CDROM drive makes are supported; cdparanoia can determine if the
target drive is CDDA capable.  In addition to simple reading, cdparanoia adds
extra-robust data verification, synchronization, error handling and scratch
reconstruction capability.")
    (license gpl2))) ; libraries under lgpl2.1

(define-public dvdisaster
  (package
    (name "dvdisaster")
    (version "0.79.5")
    (source (origin
             (method url-fetch)
             (uri (string-append "http://dvdisaster.net/downloads/dvdisaster-"
                                 version ".tar.bz2"))
             (sha256
              (base32
               "0f8gjnia2fxcbmhl8b3qkr5b7idl8m855dw7xw2fnmbqwvcm6k4w"))))
    (build-system gnu-build-system)
    (inputs
     `(("gtk+" ,gtk+-2)))
    (native-inputs
     `(("gettext" ,gettext-minimal)
       ("pkg-config" ,pkg-config)
       ("which" ,which)))
    (arguments
     `(;; Parallel builds appear to be unsafe, see
       ;; <http://hydra.gnu.org/build/49331/nixlog/1/raw>.
       #:parallel-build? #f
       #:tests? #f)) ; no check target
    (home-page "http://dvdisaster.net/en/index.html")
    (synopsis "Error correcting codes for optical media images")
    (description "Optical media (CD,DVD,BD) keep their data only for a
finite time (typically for many years).  After that time, data loss develops
slowly with read errors growing from the outer media region towards the
inside.

Dvdisaster stores data on CD/DVD/BD (supported media) in a way that it is
fully recoverable even after some read errors have developed.  This enables
you to rescue the complete data to a new medium.

Data loss is prevented by using error correcting codes.  Error correction
data is either added to the medium or kept in separate error correction
files.  Dvdisaster works at the image level so that the recovery does not
depend on the file system of the medium.  The maximum error correction
capacity is user-selectable.")
    (license gpl2+)))

(define-public libcue
  (package
    (name "libcue")
    (version "2.1.0")
    (source (origin
             (method url-fetch)
             (uri (string-append
                   "https://github.com/lipnitsk/libcue/archive/v"
                   version ".tar.gz"))
             (file-name (string-append name "-" version ".tar.gz"))
             (sha256
              (base32
               "1fradl3dx0pyy9rn1a0gak9gzgg40wax61f2s00zks7rwl0xv398"))))
    (build-system cmake-build-system)
    (native-inputs
     `(("bison" ,bison)
       ("flex" ,flex)))
    (home-page "https://github.com/lipnitsk/libcue")
    (synopsis "C library to parse cue sheets")
    (description "Libcue is a C library to parse so-called @dfn{cue sheets}
which contain meta-data for CD/DVD tracks.  It provides an API to manipulate
the data.")
    (license gpl2+)))

(define-public cd-discid
  (package
    (name "cd-discid")
    (version "1.4")
    (home-page "http://linukz.org/cd-discid.shtml")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://linukz.org/download/cd-discid-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0qrcvn7227qaayjcd5rm7z0k5q89qfy5qkdgwr5pd7ih0va8rmpz"))
              (modules '((guix build utils)))
              (snippet
               '(substitute* "Makefile"
                  (("/usr/bin/install")
                   "install")))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f
       #:phases (alist-delete 'configure %standard-phases)
       #:make-flags (list "CC=gcc"
                          (string-append "PREFIX="
                                         (assoc-ref %outputs "out")))))
    (synopsis "Get CDDB discid information from an audio CD")
    (description
     "cd-discid is a command-line tool to retrieve CDDB discid information
from an audio CD.")
    (license gpl2+)))

(define-public abcde
  (package
    (name "abcde")
    (version "2.7.2")
    (home-page "https://abcde.einval.com/")
    (source (origin
              (method url-fetch)
              (uri (string-append home-page "/download/abcde-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1pakpi41k8yd780mfp0snhia6mmwjwxk9lcrq6gynimch8b8hfda"))
              (modules '((guix build utils)))
              (snippet
               '(substitute* "Makefile"
                  (("/usr/bin/install")
                   "install")
                  (("^etcdir = .*$")
                   (string-append "etcdir = $(prefix)/etc\n"))))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key outputs inputs #:allow-other-keys)
             (substitute* "Makefile"
               (("^prefix = .*$")
                (string-append "prefix = "
                               (assoc-ref outputs "out")
                               "\n"))
               (("^sysconfdir = .*$")
                (string-append "sysconfdir = "
                               (assoc-ref outputs "out")
                               "/etc/\n")))
             #t))
         (add-after 'install 'wrap
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let ((wget   (assoc-ref inputs "wget"))
                   (vorbis (assoc-ref inputs "vorbis-tools"))
                   (parano (assoc-ref inputs "cdparanoia"))
                   (which  (assoc-ref inputs "which"))
                   (discid (assoc-ref inputs "cd-discid"))
                   (flac   (assoc-ref inputs "flac"))
                   (out    (assoc-ref outputs "out")))
               (define (wrap file)
                 (wrap-program file
                               `("PATH" ":" prefix
                                 (,(string-append out "/bin:"
                                                  wget "/bin:"
                                                  flac "/bin:"
                                                  which "/bin:"
                                                  vorbis "/bin:"
                                                  discid "/bin:"
                                                  parano "/bin")))))

               (for-each wrap
                         (find-files (string-append out "/bin")
                                     ".*"))))))
       #:tests? #f)) ; no test target

    (inputs `(("wget" ,wget)
              ("which" ,which)
              ("cdparanoia" ,cdparanoia)
              ("cd-discid" ,cd-discid)
              ("vorbis-tools" ,vorbis-tools)
              ("flac" ,flac)

              ;; A couple of Python and Perl scripts are included.
              ("python" ,python)
              ("perl" ,perl)))

    (synopsis "Command-line audio CD ripper")
    (description
     "abcde is a front-end command-line utility (actually, a shell script)
that grabs tracks off a CD, encodes them to Ogg/Vorbis, MP3, FLAC, Ogg/Speex
and/or MPP/MP+ (Musepack) format, and tags them, all in one go.")
    (license gpl2+)))

(define-public geteltorito
  (package
    (name "geteltorito")
    (version "0.6")
    (home-page
     "https://userpages.uni-koblenz.de/~krienke/ftp/noarch/geteltorito/")
    (source (origin
              (method url-fetch)
              (uri (string-append home-page name "-" version ".tar.gz"))
              (sha256
               (base32
                "1gkbm9ahj2mgqrkrfpibzclsriqgsbsvjh19fr815vpd9f6snkxv"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; No tests.
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (delete 'build)
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (install-file "geteltorito"
                             (string-append out "/bin"))))))))
    (inputs `(("perl" ,perl)))
    (synopsis "Extract the boot image from a CD-ROM")
    (description
     "@command{geteltorito} can extract the initial/default boot
image from CDs (and ISOs) that follow the El Torito specification
for bootable CD-ROMs.

Image data is written to standard output by default and all other
information is written to standard error.")
    (license gpl2+)))

(define-public asunder
  (package
    (name "asunder")
    (version "2.8")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "http://www.littlesvr.ca/asunder/releases/asunder-"
                              version
                              ".tar.bz2"))
              (sha256
               (base32
                "1nq9kd4rd4k2kibf57gdbm0zw2gxa234vvvdhxkm8g5bhx5h3iyq"))))
    (build-system glib-or-gtk-build-system)
    (arguments
     '(#:out-of-source? #f
       #:phases (modify-phases %standard-phases
                  (add-after 'install 'wrap
                    (lambda* (#:key inputs outputs #:allow-other-keys)
                      (let ((program (string-append (assoc-ref outputs "out")
                                                    "/bin/asunder")))
                        (define (bin-directory input-name)
                          (string-append (assoc-ref inputs input-name) "/bin"))
                        (wrap-program program
                          `("PATH" ":" prefix
                            ,(map bin-directory (list "cdparanoia"
                                                      "lame"
                                                      "vorbis-tools"
                                                      "flac"
                                                      "opus-tools"
                                                      "wavpack"))))))))))
    (native-inputs `(("intltool" ,intltool)
                     ("pkg-config" ,pkg-config)))
    ;; TODO: Add the necessary packages for Musepack encoding.
    (inputs `(("gtk+-2" ,gtk+-2)
              ("glib" ,glib)
              ("libcddb" ,libcddb)
              ("cdparanoia" ,cdparanoia)
              ("lame" ,lame)
              ("vorbis-tools" ,vorbis-tools)
              ("flac" ,flac)
              ("opus-tools" ,opus-tools)
              ("wavpack" ,wavpack)))
    (home-page "http://www.littlesvr.ca/asunder/")
    (synopsis "Graphical audio CD ripper and encoder")
    (description
     "Asunder is a graphical audio CD ripper and encoder.  It can save audio
tracks as WAV, MP3, Ogg Vorbis, FLAC, Opus, Wavpack, and Musepack.  It can use
CDDB to name and tag each track automatically, and it allows for each track to
be by a different artist.  Asunder can encode to multiple formats in one
session, and it can create M3U playlists.")
    (license gpl2)))
