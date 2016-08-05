;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2013 Cyril Roelandt <tipecaml@gmail.com>
;;; Copyright © 2014 Mark H Weaver <mhw@netris.org>
;;; Copyright © 2014 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2014 Ian Denhardt <ian@zenhack.net>
;;; Copyright © 2015 Sou Bunnbu <iyzsong@gmail.com>
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

(define-module (gnu packages cmake)
  #:use-module ((guix licenses) #:select (bsd-3))
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages backup)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages file)
  #:use-module (gnu packages xml))

(define-public cmake
  (package
    (name "cmake")
    (version "3.5.2")
    (source (origin
             (method url-fetch)
             (uri (string-append "https://www.cmake.org/files/v"
                                 (version-major+minor version)
                                 "/cmake-" version ".tar.gz"))
             (sha256
              (base32
               "0ap6nlmv6nda942db43k9k9mhnm5dm3fsapzvy0vh6wq7l6l3n4j"))
             (patches (search-patches "cmake-fix-tests.patch"))))
    (build-system gnu-build-system)
    (arguments
     `(#:test-target "test"
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'patch-bin-sh
           (lambda _
           ;; Replace "/bin/sh" by the right path in... a lot of
           ;; files.
           (substitute*
               '("Modules/CompilerId/Xcode-3.pbxproj.in"
                 "Modules/CompilerId/Xcode-1.pbxproj.in"
                 "Modules/CompilerId/Xcode-2.pbxproj.in"
                 "Modules/CPack.RuntimeScript.in"
                 "Source/cmakexbuild.cxx"
                 "Source/cmGlobalXCodeGenerator.cxx"
                 "Source/CTest/cmCTestBatchTestHandler.cxx"
                 "Source/cmLocalUnixMakefileGenerator3.cxx"
                 "Source/cmExecProgramCommand.cxx"
                 "Utilities/cmbzip2/Makefile-libbz2_so"
                 "Utilities/Release/release_cmake.cmake"
                 "Utilities/cmlibarchive/libarchive/archive_write_set_format_shar.c"
                 "Tests/CMakeLists.txt"
                 "Tests/RunCMake/File_Generate/RunCMakeTest.cmake")
               (("/bin/sh") (which "sh")))))
         (add-before 'configure 'set-paths
           (lambda _
             ;; Help cmake's bootstrap process to find system libraries
             (begin
               (setenv "CMAKE_LIBRARY_PATH" (getenv "LIBRARY_PATH"))
               (setenv "CMAKE_INCLUDE_PATH" (getenv "C_INCLUDE_PATH"))
               ;; Get verbose output from failed tests
               (setenv "CTEST_OUTPUT_ON_FAILURE" "TRUE"))))
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (zero? (system*
                       "./configure"
                       (string-append "--prefix=" out)
                       "--system-libs"
                       "--no-system-jsoncpp" ; not packaged yet
                       ;; By default, the man pages and other docs land
                       ;; in PREFIX/man and PREFIX/doc, but we want them
                       ;; in share/{man,doc}.  Note that unlike
                       ;; autoconf-generated configure scripts, cmake's
                       ;; configure prepends "PREFIX/" to what we pass
                       ;; to --mandir and --docdir.
                       "--mandir=share/man"
                       ,(string-append
                         "--docdir=share/doc/cmake-"
                         (version-major+minor version)))))))
         (add-after 'unpack 'remove-libarchive-version-test
           ; This test check has been failing consistantly over libarchive 3.2.x
           ; and cmake 3.4.x and 3.5.x so we disable it for now
           (lambda _
               (substitute*
               "Tests/CMakeOnly/AllFindModules/CMakeLists.txt"
               (("LibArchive") ""))
               #t)))))
    (inputs
     `(("file"       ,file)
       ("curl"       ,curl)
       ("zlib"       ,zlib)
       ("expat"      ,expat)
       ("bzip2"      ,bzip2)
       ("libarchive" ,libarchive)))
    (native-search-paths
     (list (search-path-specification
             (variable "CMAKE_PREFIX_PATH")
             (files '("")))))
    (home-page "http://www.cmake.org/")
    (synopsis "Cross-platform build system")
    (description
     "CMake is a family of tools designed to build, test and package software.
CMake is used to control the software compilation process using simple platform
and compiler independent configuration files.  CMake generates native makefiles
and workspaces that can be used in the compiler environment of your choice.")
    (license bsd-3)))
