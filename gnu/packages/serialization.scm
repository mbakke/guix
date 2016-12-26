;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Lukas Gradl <lgradl@openmailbox.org>
;;; Copyright © 2016 David Craven <david@craven.ch>
;;; Copyright © 2016 Marius Bakke <mbakke@fastmail.com>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
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

(define-module (gnu packages serialization)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages boost)
  #:use-module (gnu packages check)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages documentation)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python))

(define-public cereal
  (package
    (name "cereal")
    (version "1.2.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/USCiLab/cereal/archive/v"
                                  version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0kj32h3j2128anig0g9gzw82kfyd5xqfkwq6vdyv900jx8i1qckx"))))
    (build-system cmake-build-system)
    (arguments
     `(;; The only included tests are portability tests requiring
       ;; cross-compilation and boost.  Since we are building cereal on more
       ;; platforms anyway, there is no compelling reason to build the tests.
       #:tests? #f
       #:out-of-source? #f
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'build
          (lambda _
            (substitute* "doc/doxygen.in"
              (("@CMAKE_CURRENT_SOURCE_DIR@") "."))
            (zero? (system* "doxygen" "doc/doxygen.in"))))
         ;; There is no "install" target, so we have to provide our own
         ;; "install" phase.
         (replace 'install
          (lambda* (#:key outputs #:allow-other-keys)
            (let* ((out     (assoc-ref outputs "out"))
                   (doc     (string-append out "/share/cereal/docs"))
                   (include (string-append out "/include/cereal")))
              (mkdir-p doc)
              (mkdir-p include)
              (copy-recursively "include/cereal" include)
              (copy-recursively "doc/html" doc))
            #t)))))
    (native-inputs
     `(("doxygen" ,doxygen)))
    (home-page "http://uscilab.github.io/cereal/")
    (synopsis "C++11 library for serialization")
    (description
     "Cereal is a header-only C++11 serialization library.  Cereal takes
arbitrary data types and reversibly turns them into different representations,
such as compact binary encodings, XML, or JSON.")
    (license license:bsd-3)))


(define-public msgpack
  (package
    (name "msgpack")
    (version "1.4.1")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append
         "https://github.com/msgpack/msgpack-c/releases/download/"
         "cpp-" version "/msgpack-" version ".tar.gz"))
       (snippet
        '(let ((p (open-file "msgpack.pc.in" "a")))
           (begin
             (display
              (string-append "Requires: " "zlib" "\n") p)
             (close-output-port p))))
       (sha256
        (base32
         "0bpjfh9vz0n2k93mph3x15clmigkgs223xfn8h12ymrh5gsi5ica"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("googletest" ,googletest)
       ("autoconf" ,autoconf)
       ("automake" ,automake)
       ("libtool" ,libtool)
       ("pkg-config" ,pkg-config)))
    (propagated-inputs
     `(("zlib" ,zlib))) ;; Msgpack installs two headers (zbuffer.h,
    ;; zbuffer.hpp) which #include <zlib.h>.  However, 'guix gc --references'
    ;; does not detect a store reference to zlib since these headers are not
    ;; compiled.
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'configure 'autoconf
           (lambda _
             (system* "autoreconf" "-vfi"))))))
    (home-page "http://www.msgpack.org")
    (synopsis "Binary serialization library")
    (description "Msgpack is a library for C/C++ that implements binary
serialization.")
    (license license:boost1.0)))

(define-public yaml-cpp
  (package
    (name "yaml-cpp")
    (version "0.5.3")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/jbeder/yaml-cpp/archive/"
                    "yaml-cpp-" version ".tar.gz"))
              (sha256
               (base32
                "1vk6pjh0f5k6jwk2sszb9z5169whmiha9ainbdpa1arxlkq7v3b6"))))
    (build-system cmake-build-system)
    (inputs
     `(("boost" ,boost)))
    (native-inputs
     `(("python" ,python)))
    (home-page "https://github.com/jbeder/yaml-cpp")
    (synopsis "YAML parser and emitter in C++")
    (description "YAML parser and emitter in C++ matching the YAML 1.2 spec.")
    (license license:bsd-3)))

(define-public jsoncpp
  (package
    (name "jsoncpp")
    (version "1.8.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/open-source-parsers/jsoncpp/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1g35ci93s03wph4kabi46iz42wgyfbn2763cklf15h7hrdi29ssx"))))
    (build-system cmake-build-system)
    (home-page "https://github.com/open-source-parsers/jsoncpp")
    (arguments
     `(#:configure-flags '("-DBUILD_SHARED_LIBS:BOOL=YES")))
    (synopsis "C++ library for interacting with JSON")
    (description "JsonCpp is a C++ library that allows manipulating JSON values,
including serialization and deserialization to and from strings.  It can also
preserve existing comment in unserialization/serialization steps, making
it a convenient format to store user input files.")
    (license license:expat)))

(define-public capnproto
  (package
    (name "capnproto")
    (version "0.5.3")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://capnproto.org/capnproto-c++-"
                    version ".tar.gz"))
              (sha256
               (base32
                "1yvaadhgakskqq5wpv53hd6fc3pp17mrdldw4i5cvgck4iwprcfd"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'do-not-require-/etc/services
           (lambda _
             ;; Workaround for test that tries to resolve port name from
             ;; /etc/services, which is not present in build environment.
             (substitute* "src/kj/async-io-test.c++" ((":http") ":80"))
             #t)))))
    (home-page "https://capnproto.org")
    (synopsis "Capability-based RPC and serialization system")
    (description
     "Cap'n Proto is a very fast data interchange format and capability-based
RPC system.  Think JSON, except binary.  Or think Protocol Buffers, except faster.")
    (license license:expat)))
