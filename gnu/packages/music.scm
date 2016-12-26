;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014 Eric Bavier <bavier@member.fsf.org>
;;; Copyright © 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015 Paul van der Walt <paul@denknerd.org>
;;; Copyright © 2016 Al McElrath <hello@yrns.org>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Leo Famulari <leo@famulari.name>
;;; Copyright © 2016 Kei Kebreau <kei@openmailbox.org>
;;; Copyright © 2016 John J. Foerch <jjfoerch@earthlink.net>
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

(define-module (gnu packages music)
  #:use-module (guix utils)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system ant)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system python)
  #:use-module (guix build-system waf)
  #:use-module (gnu packages)
  #:use-module (gnu packages algebra)
  #:use-module (gnu packages apr)
  #:use-module (gnu packages audio)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages backup)
  #:use-module (gnu packages base) ;libbdf
  #:use-module (gnu packages bison)
  #:use-module (gnu packages boost)
  #:use-module (gnu packages cdrom)
  #:use-module (gnu packages code)
  #:use-module (gnu packages check)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages cyrus-sasl)
  #:use-module (gnu packages docbook)
  #:use-module (gnu packages documentation)
  #:use-module (gnu packages emacs)
  #:use-module (gnu packages file)
  #:use-module (gnu packages flex)
  #:use-module (gnu packages fltk)
  #:use-module (gnu packages fonts)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages freedesktop)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages gnupg)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages graphics)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages image)
  #:use-module (gnu packages imagemagick)
  #:use-module (gnu packages java)
  #:use-module (gnu packages linux) ; for alsa-utils
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages llvm)
  #:use-module (gnu packages man)
  #:use-module (gnu packages mp3)
  #:use-module (gnu packages mpd)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages netpbm)
  #:use-module (gnu packages pcre)
  #:use-module (gnu packages pdf)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages pulseaudio) ;libsndfile
  #:use-module (gnu packages python)
  #:use-module (gnu packages qt)
  #:use-module (gnu packages rdf)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages rsync)
  #:use-module (gnu packages sdl)
  #:use-module (gnu packages tcl)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages tex)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages video)
  #:use-module (gnu packages web)
  #:use-module (gnu packages wxwidgets)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages xiph)
  #:use-module (gnu packages zip)
  #:use-module ((srfi srfi-1) #:select (last)))

(define-public aria-maestosa
  (package
    (name "aria-maestosa")
    (version "1.4.11")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/ariamaestosa/ariamaestosa/"
                                  version "/AriaSrc-" version ".tar.bz2"))
              (sha256
               (base32
                "0gf9z96z83jiabxhpl856j15vl9flfgs6x1r0r6hc7g2xvwag0vy"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f  ;no tests
       #:phases
       ;; TODO: Add scons-build-system and use it here.
       (modify-phases %standard-phases
         (delete 'configure)
         (add-after 'unpack 'scons-propagate-environment
           (lambda _
             ;; By design, SCons does not, by default, propagate
             ;; environment variables to subprocesses.  See:
             ;; <http://comments.gmane.org/gmane.linux.distributions.nixos/4969>
             ;; Here, we modify the SConstruct file to arrange for
             ;; environment variables to be propagated.
             (substitute* "SConstruct"
               (("env = Environment\\(\\)")
                "env = Environment(ENV=os.environ)")
               ;; Scons errors out when copying subdirectories from Resources,
               ;; so we move them instead.
               (("Copy") "Move")
               ;; We move the "score" and "Documentation" directories at once,
               ;; so we have to ignore files contained therein.
               (("if \".svn\" in file" line)
                (string-append line
                               " or \"score/\" in file"
                               " or \"Documentation/\" in file")))
             #t))
         (replace 'build (lambda _ (zero? (system* "scons"))))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (and
                (zero? (system* "scons"
                                (string-append "prefix=" out)
                                "install"))
                ;; Fix directory permissions
                (begin
                  (chmod (string-append out "/share/Aria/Documentation") #o555)
                  (chmod (string-append out "/share/Aria/score") #o555)
                  #t))))))))
    (inputs
     `(("wxwidgets" ,wxwidgets)
       ("glib" ,glib)
       ("alsa-lib" ,alsa-lib)))
    (native-inputs
     `(("scons" ,scons)
       ("pkg-config" ,pkg-config)))
    (home-page "http://ariamaestosa.sourceforge.net/")
    (synopsis "MIDI sequencer and editor")
    (description
     "Aria Maestosa is a MIDI sequencer and editor.  It lets you compose, edit
and play MIDI files with a few clicks in a user-friendly interface offering
score, keyboard, guitar, drum and controller views.")
    (license license:gpl3+)))

(define-public cmus
  (package
    (name "cmus")
    (version "2.7.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/" name "/" name "/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0raixgjavkm7hxppzsc5zqbfbh2bhjcmbiplhnsxsmyj8flafyc1"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; cmus does not include tests
       #:phases
       (modify-phases %standard-phases
         (replace
          'configure
          (lambda* (#:key outputs #:allow-other-keys)
            (let ((out (assoc-ref outputs "out")))

              ;; It's an idiosyncratic configure script that doesn't
              ;; understand --prefix=..; it wants prefix=.. instead.
              (zero?
               (system* "./configure"
                        (string-append "prefix=" out)))))))))
    ;; TODO: cmus optionally supports the following formats, which haven't yet
    ;; been added to Guix:
    ;;
    ;; - Roar, libroar
    ;;
    ;; - DISCID_LIBS, apparently different from cd-discid which is included in
    ;;   Guix.  See <http://sourceforge.net/projects/discid/>
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("ao" ,ao)
       ("ffmpeg" ,ffmpeg)
       ("flac" ,flac)
       ("jack" ,jack-1)
       ("libcddb" ,libcddb)
       ("libcdio-paranoia" ,libcdio-paranoia)
       ("libcue" ,libcue)
       ("libmad" ,libmad)
       ("libmodplug" ,libmodplug)
       ("libmpcdec" ,libmpcdec)
       ("libsamplerate" ,libsamplerate)
       ("libvorbis" ,libvorbis)
       ("ncurses" ,ncurses)
       ("opusfile" ,opusfile)
       ("pulseaudio" ,pulseaudio)
       ("wavpack" ,wavpack)))
     (home-page "https://cmus.github.io/")
     (synopsis "Small console music player")
     (description "Cmus is a small and fast console music player.  It supports
many input formats and provides a customisable Vi-style user interface.")
     (license license:gpl2+)))

(define-public denemo
  (package
    (name "denemo")
    (version "2.0.14")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/denemo/denemo-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1a7g38695g7jjypx25qp0dx0asrh72xwdj0mdhmb9pfyzlppq0wh"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           ;; Denemo's documentation says to use this command to run its
           ;; testsuite.
           (lambda _
             (zero? (system* "make" "-C" "tests" "check"))))
         (add-before 'build 'set-lilypond
           ;; This phase sets the default path for lilypond to its current
           ;; location in the store.
           (lambda* (#:key inputs #:allow-other-keys)
             (let* ((lilypond (string-append (assoc-ref inputs "lilypond")
                                             "/bin/lilypond")))
               (substitute* "src/core/prefops.c"
                 (("g_string_new \\(\"lilypond\"\\);")
                  (string-append "g_string_new (\""
                                 lilypond
                                 "\");"))))
             #t))
         (add-after 'install 'correct-filename
           ;; "graft-derivation/shallow" from the (guix grafts) module runs in
           ;; the C locale, expecting file names to be ASCII encoded. This
           ;; phase renames a filename with a Unicode character in it to meet
           ;; the aforementioned condition.
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out")))
               (chdir (string-append
                       out
                       "/share/denemo/templates/instruments/woodwind"))
               (rename-file "Clarinet in B♭.denemo"
                            "Clarinet in Bb.denemo"))
             #t)))))
    (native-inputs
     `(("glib:bin", glib "bin")   ; for gtester
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("aubio" ,aubio)
       ("evince" ,evince)
       ("fftw" ,fftw)
       ("fluidsynth" ,fluidsynth)
       ("glib" ,glib)
       ("gtk+" ,gtk+)
       ("gtk-doc" ,gtk-doc)
       ("gtksourceview" ,gtksourceview)
       ("guile" ,guile-2.0)
       ("intltool" ,intltool)
       ("librsvg" ,librsvg)
       ("libsndfile" ,libsndfile)
       ("libtool" ,libtool)
       ("libxml2" ,libxml2)
       ("lilypond", lilypond)
       ("portaudio" ,portaudio)
       ("portmidi" ,portmidi)
       ("rubberband" ,rubberband)))
    (synopsis "Graphical music notation, front-end to GNU Lilypond")
    (description
     "GNU Denemo is a music notation editor that provides a convenient
interface to the powerful music engraving program Lilypond.  Music can be
typed in using the computer keyboard, played in using a MIDI keyboard, or
even input via a microphone connected to the sound card.  The final product
is publication-quality music notation that is continuously generated in the
background while you work.")
    (home-page "http://www.denemo.org")
    (license license:gpl3+)))

(define-public hydrogen
  (package
    (name "hydrogen")
    (version "0.9.7")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/hydrogen-music/hydrogen/archive/"
                    version ".tar.gz"))
              (sha256
               (base32
                "1dy2jfkdw0nchars4xi4isrz66fqn53a9qk13bqza7lhmsg3s3qy"))))
    (build-system cmake-build-system)
    (arguments
    `(#:test-target "tests"))
    (native-inputs
     `(("cppunit" ,cppunit)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("jack" ,jack-1)
       ;; ("ladspa" ,ladspa) ; cannot find during configure
       ("lash" ,lash)
       ("libarchive" ,libarchive)
       ("libsndfile" ,libsndfile)
       ("libtar" ,libtar)
       ("lrdf" ,lrdf)
       ("qt" ,qt-4)
       ("zlib" ,zlib)))
    (home-page "http://www.hydrogen-music.org")
    (synopsis "Drum machine")
    (description
     "Hydrogen is an advanced drum machine for GNU/Linux.  Its main goal is to
enable professional yet simple and intuitive pattern-based drum programming.")
    (license license:gpl2+)))

(define-public extempore
  (package
    (name "extempore")
    (version "0.7.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/digego/extempore/archive/"
                    version ".tar.gz"))
              (sha256
               (base32
                "1wap1mvsicrhlazikf7l8zxg37fir8bmnh9rin28m1rix730vcch"))
              (file-name (string-append name "-" version ".tar.gz"))))
    (build-system cmake-build-system)
    (arguments
     `(;; The default target also includes ahead-of-time compilation of the
       ;; standard libraries.  However, during the "install" phase this would
       ;; happen *again* for unknown reasons.  Hence we only build the
       ;; extempore executable during the build phase.
       #:make-flags '("extempore")
       #:configure-flags '("-DJACK=ON"
                           ;; We want to distribute.
                           "-DIN_TREE=OFF"
                           ;; Don't download any dependencies.
                           "-DBUILD_DEPS=OFF")
       #:modules ((ice-9 match)
                  (guix build cmake-build-system)
                  (guix build utils))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-directories
           (lambda* (#:key outputs #:allow-other-keys)
             ;; Rewrite default path to runtime directory
             (substitute* "src/Extempore.cpp"
               (("runtimedir \\+= \"runtime\"")
                (string-append "runtimedir = \""
                               (assoc-ref outputs "out")
                               "/lib/extempore/runtime\"")))
             (substitute* "extras/extempore.el"
               (("\\(runtime-directory \\(concat default-directory \"runtime\"\\)\\)")
                (string-append "(runtime-directory \""
                               (assoc-ref outputs "out")
                               "/lib/extempore/runtime"
                               "\")")))
             #t))
         (add-after 'unpack 'link-with-additional-libs
           (lambda _
             ;; The executable must be linked with libffi and zlib.
             (substitute* "CMakeLists.txt"
               (("add_dependencies\\(aot_extended extended_deps\\)") "")
               (("target_link_libraries\\(extempore PRIVATE dl" line)
                (string-append line " ffi z")))
             #t))
         ;; FIXME: AOT compilation of the nanovg bindings fail with the error:
         ;; "Compiler Error  could not bind _nvgLinearGradient"
         (add-after 'unpack 'disable-nanovg
           (lambda _
             (substitute* "CMakeLists.txt"
               (("aotcompile_lib\\(libs/external/nanovg.xtm.*") ""))
             #t))
         ;; FIXME: All examples that are used as tests segfault for some
         ;; unknown reason.
         (add-after 'unpack 'disable-broken-tests
           (lambda _
             (substitute* "CMakeLists.txt"
               (("extempore_add_example_as_test\\(.*") ""))
             #t))
         (add-after 'unpack 'hardcode-external-lib-paths
           (lambda* (#:key inputs #:allow-other-keys)
             (use-modules (ice-9 match))
             (for-each
              (match-lambda
                ((file-name lib pkg-name)
                 (substitute* (string-append "libs/external/" file-name ".xtm")
                   ((lib) (string-append (assoc-ref inputs pkg-name)
                                         "/lib/" lib)))))
              '(("assimp"    "libassimp.so"    "assimp")
                ("portmidi"  "libportmidi.so"  "portmidi")
                ("sndfile"   "libsndfile.so"   "libsndfile")
                ("fft"       "libkiss_fft.so"  "kiss-fft")
                ("stb_image" "libstb_image.so" "stb-image")
                ("nanovg"    "libnanovg.so"    "nanovg")
                ("glext"     "libGL.so"        "mesa")
                ("glfw3"     "libglfw.so"      "glfw")
                ("gl/glcore-directbind"   "libGL.so" "mesa")
                ("gl/glcompat-directbind" "libGL.so" "mesa")))
             #t))
         (add-after 'unpack 'use-own-llvm
          (lambda* (#:key inputs #:allow-other-keys)
            (setenv "EXT_LLVM_DIR" (assoc-ref inputs "llvm"))
            ;; Our LLVM builds shared libraries, so Extempore should use
            ;; those.
            (substitute* "CMakeLists.txt"
              (("CMAKE_STATIC_LIBRARY") "CMAKE_SHARED_LIBRARY"))
            #t))
         (add-after 'unpack 'fix-aot-compilation
           (lambda* (#:key outputs #:allow-other-keys)
             (substitute* "CMakeLists.txt"
               ;; EXT_SHARE_DIR does not exist before installation, so the
               ;; working directory should be the source directory instead.
               (("WORKING_DIRECTORY \\$\\{EXT_SHARE_DIR\\}")
                "WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}")
               ;; Extempore needs to be told where the runtime is to be found.
               ;; While we're at it we disable automatic tuning for a specific
               ;; CPU to make binary substitution possible.
               (("COMMAND extempore" prefix)
                (string-append prefix " --sharedir " (getcwd)
                               " --mcpu=generic --attr=none")))
             #t)))))
    (inputs
     `(("llvm" ,llvm-for-extempore)
       ("libffi" ,libffi)
       ("jack" ,jack-1)
       ("libsndfile" ,libsndfile)
       ("glfw" ,glfw)
       ("apr" ,apr)
       ("stb-image" ,stb-image-for-extempore)
       ("kiss-fft" ,kiss-fft-for-extempore)
       ("nanovg" ,nanovg-for-extempore)
       ("portmidi" ,portmidi-for-extempore)
       ("assimp" ,assimp)
       ("alsa-lib" ,alsa-lib)
       ("portaudio" ,portaudio)
       ("mesa" ,mesa)
       ("pcre" ,pcre)
       ("zlib" ,zlib)))
    (native-inputs
     `(("perl" ,perl)
       ("emacs" ,emacs-no-x)))
    ;; Extempore refuses to build on architectures other than x86_64
    (supported-systems '("x86_64-linux"))
    (home-page "http://benswift.me/extempore-docs/index.html")
    (synopsis "Programming environment for live coding of multimedia")
    (description
     "Extempore is a programming language and runtime environment designed
with live programming in mind.  It supports interactive programming in a REPL
style, compiling and binding code just-in-time.  Although Extempore has its
roots in 'live coding' of audiovisual media art, it is suitable for any task
domain where dynamic run-time modifiability and good numerical performance are
required.  Extempore also has strong timing and concurrency semantics, which
are helpful when working in problem spaces where timing is important (such as
audio and video).")
    (license license:bsd-2)))

(define-public klick
  (package
    (name "klick")
    (version "0.12.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://das.nasophon.de/download/klick-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0hmcaywnwzjci3pp4xpvbijnnwvibz7gf9xzcdjbdca910y5728j"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ;no "check" target
       #:phases
       ;; TODO: Add scons-build-system and use it here.
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'build
                  (lambda* (#:key inputs outputs #:allow-other-keys)
                    (let ((out (assoc-ref outputs "out")))
                      (mkdir-p out)
                      (zero? (system* "scons" (string-append "PREFIX=" out))))))
         (replace 'install (lambda _ (zero? (system* "scons" "install")))))))
    (inputs
     `(("boost" ,boost)
       ("jack" ,jack-1)
       ("libsndfile" ,libsndfile)
       ("libsamplerate" ,libsamplerate)
       ("liblo" ,liblo)
       ("rubberband" ,rubberband)))
    (native-inputs
     `(("scons" ,scons)
       ("python" ,python-2)
       ("pkg-config" ,pkg-config)))
    (home-page "http://das.nasophon.de/klick/")
    (synopsis "Metronome for JACK")
    (description
     "klick is an advanced command-line based metronome for JACK.  It allows
you to define complex tempo maps for entire songs or performances.")
    (license license:gpl2+)))

(define-public gtklick
  (package
    (name "gtklick")
    (version "0.6.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://das.nasophon.de/download/gtklick-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0dq1km6njnzsqdqyf6wzir9g733z0mc9vmxfg2383k3c2a2di6bp"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f ; no tests
       #:python ,python-2
       #:phases
       (modify-phases %standard-phases
         (add-before 'build 'add-sitedirs
           ;; .pth files are not automatically interpreted unless the
           ;; directories containing them are added as "sites".  The directories
           ;; are then added to those in the PYTHONPATH.  This is required for
           ;; the operation of pygtk.
           (lambda _
             (substitute* "gtklick/gtklick.py"
               (("import pygtk")
                "import pygtk, site, sys
for path in [path for path in sys.path if 'site-packages' in path]: site.addsitedir(path)"))))
         (add-after 'unpack 'inject-store-path-to-klick
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "gtklick/klick_backend.py"
               (("KLICK_PATH = 'klick'")
                (string-append "KLICK_PATH = '"
                               (assoc-ref inputs "klick")
                               "/bin/klick'")))
             #t)))))
    (inputs
     `(("klick" ,klick)
       ("python2-pyliblo" ,python2-pyliblo)
       ("python2-pygtk" ,python2-pygtk)))
    (native-inputs
     `(("gettext" ,gettext-minimal)))
    (home-page "http://das.nasophon.de/gtklick/")
    (synopsis "Simple metronome with an easy-to-use graphical interface")
    (description
     "Gtklick is a simple metronome with an easy-to-use graphical user
interface.  It is implemented as a frontend to @code{klick}.")
    (license license:gpl2+)))

(define-public lilypond
  (package
    (name "lilypond")
    (version "2.19.51")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://download.linuxaudio.org/lilypond/sources/v"
                    (version-major+minor version) "/"
                    name "-" version ".tar.gz"))
              (sha256
               (base32
                "1b4jvc0fixbnp8x457fzk5wgb4zd03npwwivp60kc27fmv63w5l1"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; out-test/collated-files.html fails
       #:out-of-source? #t
       #:make-flags '("conf=www") ;to generate images for info manuals
       #:configure-flags
       (list "CONFIGURATION=www"
             (string-append "--with-texgyre-dir="
                            (assoc-ref %build-inputs "font-tex-gyre")
                            "/share/fonts/opentype/"))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-path-references
          (lambda _
            (substitute* "scm/backend-library.scm"
              (("\\(search-executable '\\(\"gs\"\\)\\)")
               (string-append "\"" (which "gs") "\""))
              (("\"/bin/sh\"")
               (string-append "\"" (which "sh") "\"")))
            #t))
         (add-before 'configure 'prepare-configuration
          (lambda _
            (substitute* "configure"
              (("SHELL=/bin/sh") "SHELL=sh")
              ;; When checking the fontforge version do not consider the
              ;; version string that's part of the directory.
              (("head -n") "tail -n"))
            (setenv "out" "www")
            (setenv "conf" "www")
            #t))
         (add-after 'install 'install-info
           (lambda _
             (zero? (system* "make"
                             "-j" (number->string (parallel-job-count))
                             "conf=www" "install-info")))))))
    (inputs
     `(("guile" ,guile-1.8)
       ("font-dejavu" ,font-dejavu)
       ("font-tex-gyre" ,font-tex-gyre)
       ("fontconfig" ,fontconfig)
       ("freetype" ,freetype)
       ("ghostscript" ,ghostscript)
       ("pango" ,pango)
       ("python" ,python-2)))
    (native-inputs
     `(("bison" ,bison)
       ("perl" ,perl)
       ("flex" ,flex)
       ("fontforge" ,fontforge)
       ("dblatex" ,dblatex)
       ("gettext" ,gettext-minimal)
       ("imagemagick" ,imagemagick)
       ("netpbm" ,netpbm) ;for pngtopnm
       ("texlive" ,texlive) ;metafont and metapost
       ("texinfo" ,texinfo)
       ("texi2html" ,texi2html)
       ("rsync" ,rsync)
       ("pkg-config" ,pkg-config)
       ("zip" ,zip)))
    (home-page "http://www.lilypond.org/")
    (synopsis "Music typesetting")
    (description
     "GNU LilyPond is a music typesetter, which produces high-quality sheet
music.  Music is input in a text file containing control sequences which are
interpreted by LilyPond to produce the final document.  It is extendable with
Guile.")
    (license license:gpl3+)

    ;; On armhf and mips64el, building the documentation sometimes leads to
    ;; more than an hour of silence, so double the max silent time.
    (properties `((max-silent-time . 7200)))))

(define-public non-sequencer
  ;; The latest tagged release is three years old and uses a custom build
  ;; system, so we take the last commit.
  (let ((commit "a22f33f486a5c6f75b60e36f66504c036c0f6f8c")
        (revision "2"))
    (package
      (name "non-sequencer")
      (version (string-append "1.9.5-" revision "." (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "git://git.tuxfamily.org/gitroot/non/non.git")
                      (commit commit)))
                (sha256
                 (base32
                  "09q5x8i4f8mqnl8w6xnsq5zriy4bzdl4x2vq9n34a433rfrk84bg"))
                (file-name (string-append name "-" version "-checkout"))))
      (build-system waf-build-system)
      (arguments
       `(#:tests? #f ;no "check" target
         #:configure-flags
         (list "--project=sequencer"
               ;; Disable the use of SSE unless on x86_64.
               ,@(if (not (string-prefix? "x86_64" (or (%current-target-system)
                                                       (%current-system))))
                     '("--disable-sse")
                     '()))
         #:phases
         (modify-phases %standard-phases
           (add-before
            'configure 'set-flags
            (lambda _
              ;; Compile with C++11, required by libsigc++.
              (setenv "CXXFLAGS" "-std=c++11")
              #t)))
         #:python ,python-2))
      (inputs
       `(("jack" ,jack-1)
         ("libsigc++" ,libsigc++)
         ("liblo" ,liblo)
         ("ntk" ,ntk)))
      (native-inputs
       `(("pkg-config" ,pkg-config)))
      (home-page "http://non.tuxfamily.org/wiki/Non%20Sequencer")
      (synopsis "Pattern-based MIDI sequencer")
      (description
       "The Non Sequencer is a powerful, lightweight, real-time,
pattern-based MIDI sequencer.  It utilizes the JACK Audio Connection Kit for
MIDI I/O and the NTK GUI toolkit for its user interface.  Everything in Non
Sequencer happens on-line, in real-time.  Music can be composed live, while the
transport is rolling.")
      (license license:gpl2+))))

(define-public non-session-manager
  (package (inherit non-sequencer)
    (name "non-session-manager")
    (arguments
     (substitute-keyword-arguments (package-arguments non-sequencer)
       ((#:configure-flags flags)
        `(cons "--project=session-manager"
               (delete "--project=sequencer" ,flags)))))
    (inputs
     `(("jack" ,jack-1)
       ("liblo" ,liblo)
       ("ntk" ,ntk)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://non.tuxfamily.org/nsm/")
    (synopsis "Audio session management")
    (description
     "The Non Session Manager is an API and an implementation for audio
session management.  NSM clients use a well-specified OSC protocol to
communicate with the session management daemon.")
    (license license:gpl2+)))

(define-public solfege
  (package
    (name "solfege")
    (version "3.22.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://gnu/solfege/solfege-"
                    version ".tar.xz"))
              (sha256
               (base32
                "1w25rxdbj907nsx285k9nm480pvy12w3yknfh4n1dfv17cwy072i"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; xmllint attempts to download DTD
       #:test-target "test"
       #:phases
       (alist-cons-after
        'unpack 'fix-configuration
        (lambda* (#:key inputs #:allow-other-keys)
          (substitute* "default.config"
            (("csound=csound")
             (string-append "csound="
                            (assoc-ref inputs "csound")
                            "/bin/csound"))
            (("/usr/bin/aplay")
             (string-append (assoc-ref inputs "aplay")
                            "/bin/aplay"))
            (("/usr/bin/timidity")
             (string-append (assoc-ref inputs "timidity")
                            "/bin/timidity"))
            (("/usr/bin/mpg123")
             (string-append (assoc-ref inputs "mpg123")
                            "/bin/mpg123"))
            (("/usr/bin/ogg123")
             (string-append (assoc-ref inputs "ogg123")
                            "/bin/ogg123"))))
        (alist-cons-before
         'build 'patch-python-shebangs
         (lambda _
           ;; Two python scripts begin with a Unicode BOM, so patch-shebang
           ;; has no effect.
           (substitute* '("solfege/parsetree.py"
                          "solfege/presetup.py")
             (("#!/usr/bin/python") (string-append "#!" (which "python")))))
         (alist-cons-before
          'build 'add-sitedirs
          ;; .pth files are not automatically interpreted unless the
          ;; directories containing them are added as "sites".  The directories
          ;; are then added to those in the PYTHONPATH.  This is required for
          ;; the operation of pygtk and pygobject.
          (lambda _
            (substitute* "run-solfege.py"
              (("import os")
               "import os, site
for path in [path for path in sys.path if 'site-packages' in path]: site.addsitedir(path)")))
          (alist-cons-before
           'build 'adjust-config-file-prefix
           (lambda* (#:key outputs #:allow-other-keys)
             (substitute* "run-solfege.py"
               (("prefix = os.path.*$")
                (string-append "prefix = " (assoc-ref outputs "out")))))
           (alist-cons-after
            'install 'wrap-program
            (lambda* (#:key inputs outputs #:allow-other-keys)
              ;; Make sure 'solfege' runs with the correct PYTHONPATH.
              (let* ((out (assoc-ref outputs "out"))
                     (path (getenv "PYTHONPATH")))
                (wrap-program (string-append out "/bin/solfege")
                  `("PYTHONPATH" ":" prefix (,path)))))
            %standard-phases)))))))
    (inputs
     `(("python" ,python-2)
       ("pygtk" ,python2-pygtk)
       ("gettext" ,gettext-minimal)
       ("gtk" ,gtk+)
       ("lilypond" ,lilypond)
       ;; players needed at runtime
       ("aplay" ,alsa-utils)
       ("csound" ,csound) ; optional, needed for some exercises
       ("mpg123" ,mpg123)
       ("ogg123" ,vorbis-tools)
       ("timidity" ,timidity++)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("txt2man" ,txt2man)
       ("libxml2" ,libxml2) ; for tests
       ("ghostscript" ,ghostscript)
       ("texinfo" ,texinfo)))
    (home-page "https://www.gnu.org/software/solfege/")
    (synopsis "Ear training")
    (description
     "GNU Solfege is a program for practicing musical ear-training.  With it,
you can practice your recognition of various musical intervals and chords.  It
features a statistics overview so you can monitor your progress across several
sessions.  Solfege is also designed to be extensible so you can easily write
your own lessons.")
    (license license:gpl3+)))

(define-public powertabeditor
  (package
    (name "powertabeditor")
    (version "2.0.0-alpha8")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/powertab/powertabeditor/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0gaa2x209v3azql8ak3r1n9a9qbxjx2ssirvwdxwklv2lmfqkm82"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  ;; Remove bundled sources for external libraries
                  (delete-file-recursively "external")
                  (substitute* "CMakeLists.txt"
                    (("include_directories\\(\\$\\{PROJECT_SOURCE_DIR\\}/external/.*") "")
                    (("add_subdirectory\\(external\\)") ""))
                  (substitute* "test/CMakeLists.txt"
                    (("include_directories\\(\\$\\{PROJECT_SOURCE_DIR\\}/external/.*") ""))

                  ;; Add install target
                  (substitute* "source/CMakeLists.txt"
                    (("qt5_use_modules")
                     (string-append
                      "install(TARGETS powertabeditor "
                      "RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)\n"
                      "install(FILES data/tunings.json DESTINATION "
                      "${CMAKE_INSTALL_PREFIX}/share/powertabeditor/)\n"
                      "qt5_use_modules")))
                  #t))))
    (build-system cmake-build-system)
    (arguments
     `(#:modules ((guix build cmake-build-system)
                  (guix build utils)
                  (ice-9 match))
       #:configure-flags
       ;; CMake appears to lose the RUNPATH for some reason, so it has to be
       ;; explicitly set with CMAKE_INSTALL_RPATH.
       (list "-DCMAKE_BUILD_WITH_INSTALL_RPATH=TRUE"
             "-DCMAKE_ENABLE_PRECOMPILED_HEADERS=OFF" ; if ON pte_tests cannot be built
             (string-append "-DCMAKE_INSTALL_RPATH="
                            (string-join (map (match-lambda
                                                ((name . directory)
                                                 (string-append directory "/lib")))
                                              %build-inputs) ";")))
       #:phases
       (modify-phases %standard-phases
         (replace
          'check
          (lambda _
            (zero? (system* "bin/pte_tests"
                            ;; Exclude this failing test
                            "~Formats/PowerTabOldImport/Directions"))))
         (add-before
          'configure 'fix-tests
          (lambda _
            ;; Tests cannot be built with precompiled headers
            (substitute* "test/CMakeLists.txt"
              (("cotire\\(pte_tests\\)") ""))
            #t))
         (add-before
          'configure 'remove-third-party-libs
          (lambda* (#:key inputs #:allow-other-keys)
            ;; Link with required static libraries, because we're not
            ;; using the bundled version of withershins.
            (substitute* '("source/CMakeLists.txt"
                           "test/CMakeLists.txt")
              (("target_link_libraries\\((powertabeditor|pte_tests)" _ target)
               (string-append "target_link_libraries(" target " "
                              (assoc-ref inputs "binutils")
                              "/lib/libbfd.a "
                              (assoc-ref inputs "libiberty")
                              "/lib/libiberty.a "
                              "dl")))
            #t)))))
    (inputs
     `(("boost" ,boost)
       ("alsa-lib" ,alsa-lib)
       ("qtbase" ,qtbase)
       ("withershins" ,withershins)
       ("libiberty" ,libiberty) ;for withershins
       ("binutils" ,binutils) ;for -lbfd and -liberty (for withershins)
       ("timidity" ,timidity++)
       ("pugixml" ,pugixml)
       ("rtmidi" ,rtmidi)
       ("rapidjson" ,rapidjson)
       ("zlib" ,zlib)))
    (native-inputs
     `(("catch" ,catch-framework)
       ("pkg-config" ,pkg-config)))
    (home-page "http://powertabs.net")
    (synopsis "Guitar tablature editor")
    (description
     "Power Tab Editor 2.0 is the successor to the famous original Power Tab
Editor.  It is compatible with Power Tab Editor 1.7 and Guitar Pro.")
    (license license:gpl3+)))

(define-public jalv-select
  (package
    (name "jalv-select")
    (version "0.7")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/brummer10/jalv_select/"
                                  "archive/V" version ".tar.gz"))
              (sha256
               (base32
                "01y93l5c1f8za04a0y4b3v0nhsm1lhj6rny9xpdgd7jz6sl6w581"))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags
       (list (string-append "PREFIX=" (assoc-ref %outputs "out")))
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (add-after 'unpack 'ignore-PATH
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "jalv.select.cpp"
               (("echo \\$PATH | tr ':' '\\\n' | xargs ls")
                (string-append "ls -1 " (assoc-ref inputs "jalv") "/bin")))
             (substitute* "jalv.select.h"
               (("gtkmm.h") "gtkmm-2.4/gtkmm.h"))
             #t)))))
    (inputs
     `(("lilv" ,lilv)
       ("lv2" ,lv2)
       ("jalv" ,jalv)
       ("gtkmm" ,gtkmm-2)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "https://github.com/brummer10/jalv_select")
    (synopsis "GUI to select LV2 plugins and run them with jalv")
    (description
     "The jalv.select package provides a graphical user interface allowing
users to select LV2 plugins and run them with jalv.")
    (license license:public-domain)))

(define-public synthv1
  (package
    (name "synthv1")
    (version "0.8.0")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "mirror://sourceforge/synthv1/synthv1/" version
                              "/synthv1-" version ".tar.gz"))
              (sha256
               (base32
                "155pfyhr6d35ciw95pbxlqy7751cmij8j5d849rvblqbjzyzb5qx"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; There are no tests.
       #:configure-flags
       '("CXXFLAGS=-std=gnu++11")))
    (inputs
     `(("jack" ,jack-1)
       ("lv2" ,lv2)
       ("alsa-lib" ,alsa-lib)
       ("liblo" ,liblo)
       ("qtbase" ,qtbase)
       ("qttools" ,qttools)))
    (home-page "http://synthv1.sourceforge.net")
    (synopsis "Polyphonic subtractive synthesizer")
    (description
     "Synthv1 is an old-school subtractive polyphonic synthesizer with four
oscillators and stereo effects.")
    (license license:gpl2+)))

(define-public drumkv1
  (package
    (name "drumkv1")
    (version "0.8.0")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "mirror://sourceforge/drumkv1/drumkv1/" version
                              "/drumkv1-" version ".tar.gz"))
              (sha256
               (base32
                "1n2kd468kn71yp2asmamprvblmdlvh0zd8lsh3598dwi4b7aa3ga"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; There are no tests.
       #:configure-flags
       '("CXXFLAGS=-std=gnu++11")))
    (inputs
     `(("jack" ,jack-1)
       ("lv2" ,lv2)
       ("libsndfile" ,libsndfile)
       ("alsa-lib" ,alsa-lib)
       ("liblo" ,liblo)
       ("qtbase" ,qtbase)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("qttools" ,qttools)))
    (home-page "http://drumkv1.sourceforge.net")
    (synopsis "Drum-kit sampler synthesizer with stereo effects")
    (description
     "Drumkv1 is an old-school drum-kit sampler synthesizer with stereo
effects.")
    (license license:gpl2+)))

(define-public samplv1
  (package
    (name "samplv1")
    (version "0.8.0")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "mirror://sourceforge/samplv1/samplv1/" version
                              "/samplv1-" version ".tar.gz"))
              (sha256
               (base32
                "0j3hkmd9q0bw9b7nk9cssqywlrishkd1n790a9vq6gh3pdc5sf3r"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; There are no tests.
       #:configure-flags
       '("CXXFLAGS=-std=gnu++11")))
    (inputs
     `(("jack" ,jack-1)
       ("lv2" ,lv2)
       ("libsndfile" ,libsndfile)
       ("alsa-lib" ,alsa-lib)
       ("liblo" ,liblo)
       ("qtbase" ,qtbase)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("qttools" ,qttools)))
    (home-page "http://samplv1.sourceforge.net")
    (synopsis "Polyphonic sampler synthesizer with stereo effects")
    (description
     "Samplv1 is an old-school polyphonic sampler synthesizer with stereo
effects.")
    (license license:gpl2+)))

(define-public amsynth
  (package
    (name "amsynth")
    (version "1.6.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/amsynth/amsynth/releases/"
                           "download/release-" version
                           "/amsynth-" version ".tar.bz2"))
       (sha256
        (base32
         "07dp9dl38g9krjqxxh89l2z42z08yzrl57cx95b1l67xnxwjp5k3"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'configure 'set-flags
           (lambda _
             ;; Compile with C++11, required by gtkmm.
             (setenv "CXXFLAGS" "-std=c++11")
             #t)))))
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("jack" ,jack-1)
       ("lv2" ,lv2)
       ("libsndfile" ,libsndfile)
       ("gtk+" ,gtk+-2)
       ("gtkmm" ,gtkmm-2)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://amsynth.github.io")
    (synopsis "Analog modeling synthesizer")
    (description
     "amsynth is an easy-to-use software synthesizer with a classic
subtractive synthesizer topology.  Its features include: dual
oscillators (sine, saw, square, noise) with hard sync; 12 and 24 dB/oct
resonant filters (low-pass, high-pass, band-pass, notch); mono, poly, legato
keyboard modes; dual ADSR envelope generators for filter and amplitude; LFO
which can modulate the oscillators, filter, and amplitude; distortion and
reverb effects.")
    (license license:gpl2+)))

(define-public setbfree
  (package
    (name "setbfree")
    (version "0.8.1")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "https://github.com/pantherb/setBfree/archive/v"
                              version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0hj0rqk5yd4fzs7bwy6a6nhqgrmcggkjcr4il76rxy92r7nwabf3"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; no "check" target
       #:make-flags
       (list (string-append "PREFIX=" (assoc-ref %outputs "out"))
             (string-append "FONTFILE="
                            (assoc-ref %build-inputs "font-bitstream-vera")
                            "/share/fonts/truetype/VeraBd.ttf")
             ;; Disable unsupported optimization flags on non-x86
             ,@(let ((system (or (%current-target-system)
                                 (%current-system))))
                 (if (or (string-prefix? "x86_64" system)
                         (string-prefix? "i686" system))
                     '()
                     '("OPTIMIZATIONS=-ffast-math -fomit-frame-pointer -O3"))))
       #:phases
       (modify-phases %standard-phases
         (add-before 'build 'set-CC-variable
                     (lambda _ (setenv "CC" "gcc") #t))
         (delete 'configure))))
    (inputs
     `(("jack" ,jack-1)
       ("lv2" ,lv2)
       ("zita-convolver" ,zita-convolver)
       ("glu" ,glu)
       ("ftgl" ,ftgl)
       ("font-bitstream-vera" ,font-bitstream-vera)))
    (native-inputs
     `(("help2man" ,help2man)
       ("pkg-config" ,pkg-config)))
    (home-page "http://setbfree.org")
    (synopsis "Tonewheel organ")
    (description
     "setBfree is a MIDI-controlled, software synthesizer designed to imitate
the sound and properties of the electromechanical organs and sound
modification devices that brought world-wide fame to the names and products of
Laurens Hammond and Don Leslie.")
    (license license:gpl2+)))

(define-public beast
  (package
    (name "beast")
    (version "0.10.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://testbit.eu/pub/dists/beast/beast-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "1jzzmfwssklzw8fvvil04n8csc0zm99fnd9p2xa7c0xchg37lvhn"))))
    (build-system gnu-build-system)
    (arguments
     '(#:parallel-build? #f)) ; Race conditions cause build failures
    (inputs
     `(("rapicorn" ,rapicorn)
       ("guile" ,guile-1.8)
       ("python" ,python-2)
       ("libgnomecanvas" ,libgnomecanvas)
       ("libogg" ,libogg)
       ("libmad" ,libmad)
       ("flac" ,flac)
       ("alsa-lib" ,alsa-lib)
       ("libvorbis" ,libvorbis)
       ("gettext" ,gettext-minimal)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("glib:bin" ,glib "bin")
       ("cython" ,python2-cython)
       ("perl" ,perl)
       ("perl-xml-parser" ,perl-xml-parser)))
    (home-page "https://testbit.eu/wiki/Beast_Home")
    (synopsis "Music composition and modular synthesis environment")
    (description
     "Beast is a music composition and modular synthesis application.  It
supports a wide range of standards in the field, such as MIDI, various audio
file formats and LADSPA modules.  It allows for multitrack editing, real-time
synthesis, 32bit audio rendering, precise timing down to sample granularity,
on-demand and partial loading of wave files, on the fly decoding, stereo
mixing, FFT scopes, MIDI automation and full scriptability in Scheme.")
    (license license:gpl3+)))

(define-public bristol
  (package
    (name "bristol")
    (version "0.60.11")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/bristol/bristol/"
                                  (version-major+minor version)
                                  "/bristol-" version ".tar.gz"))
              (sha256
               (base32
                "1fi2m4gmvxdi260821y09lxsimq82yv4k5bbgk3kyc3x1nyhn7vx"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'remove-sse-flags
           (lambda* (#:key system #:allow-other-keys)
             (when (not (or (string-prefix? "x86_64" system)
                            (string-prefix? "i686" system)))
               (substitute* "bristol/Makefile.in"
                 (("-msse -mfpmath=sse") "")))
             #t))
         ;; We know that Bristol has been linked with JACK and we don't have
         ;; ldd, so we can just skip this check.
         (add-after 'unpack 'do-not-grep-for-jack
           (lambda _
             (substitute* "bin/startBristol.in"
               (("ldd `which bristol` | grep jack") "echo guix"))
             #t)))))
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("jack" ,jack-1)
       ("liblo" ,liblo)
       ("libx11" ,libx11)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://bristol.sourceforge.net/")
    (synopsis "Synthesizer emulator")
    (description
     "Bristol is an emulation package for a number of different 'classic'
synthesizers including additive and subtractive and a few organs.  The
application consists of the engine, which is called bristol, and its own GUI
library called brighton that represents all the emulations.  There are
currently more than twenty different emulations; each does sound different
although the author maintains that the quality and accuracy of each emulation
is subjective.")
    (license license:gpl3+)))

(define-public tuxguitar
  (package
    (name "tuxguitar")
    (version "1.3.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://sourceforge/tuxguitar/TuxGuitar/TuxGuitar-"
                    version "/tuxguitar-" version "-src.tar.gz"))
              (sha256
               (base32
                "0ldml31zvywid1w28mfd65ramyiics55fdl0ch846vm7j7nwv58j"))
              (modules '((guix build utils)))
              (snippet
               ;; Delete pre-built classes
               '(delete-file-recursively "TuxGuitar-android/bin"))))
    (build-system ant-build-system)
    (arguments
     `(#:build-target "build"
       #:tests? #f ; no tests
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'enter-dir
           (lambda _ (chdir "TuxGuitar-lib") #t))
         (add-after 'build 'build-editor-utils
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (chdir "..")
             (let ((cwd (getcwd)))
               (setenv "CLASSPATH"
                       (string-append
                        cwd "/TuxGuitar-lib/tuxguitar-lib.jar" ":"
                        cwd "/TuxGuitar-editor-utils/build/jar/tuxguitar-editor-utils.jar" ":"
                        (getenv "CLASSPATH"))))
             (chdir "TuxGuitar-editor-utils")
             ;; Generate default build.xml
             ((@@ (guix build ant-build-system) default-build.xml)
              "tuxguitar-editor-utils.jar"
              (string-append (assoc-ref outputs "out")
                             "/share/java"))
             ((assoc-ref %standard-phases 'build))))
         (add-after 'build-editor-utils 'build-application
           (lambda _
             (chdir "../TuxGuitar")
             ((assoc-ref %standard-phases 'build)
              #:build-target "build")))
         (replace 'install
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out   (assoc-ref outputs "out"))
                    (bin   (string-append out "/bin"))
                    (share (string-append out "/share"))
                    (lib   (string-append share "/java"))
                    (swt   (assoc-ref inputs "java-swt")))
               (mkdir-p bin)
               ;; install all jars
               (for-each (lambda (file)
                           (install-file file lib))
                         (find-files ".." "\\.jar$"))
               ;; install all resources
               (for-each (lambda (file)
                           (install-file file share))
                         (find-files "share" ".*"))
               ;; create wrapper
               (call-with-output-file (string-append bin "/tuxguitar")
                 (lambda (port)
                   (let ((classpath (string-join (append (find-files lib "\\.jar$")
                                                         (find-files swt "\\.jar$"))
                                                 ":")))
                     (format
                      port
                      (string-append "#!/bin/sh\n"
                                     (which "java")
                                     " -cp " classpath
                                     " -Dtuxguitar.home.path=" out
                                     " -Dtuxguitar.share.path=" out "/share"
                                     " -Dswt.library.path=" swt "/lib"
                                     " org.herac.tuxguitar.app.TGMainSingleton"
                                     " \"$1\" \"$2\"")))))
               (chmod (string-append bin "/tuxguitar") #o555)
               #t))))))
    (inputs
     `(("java-swt" ,java-swt)))
    (home-page "http://tuxguitar.com.ar")
    (synopsis "Multitrack tablature editor and player")
    (description
     "TuxGuitar is a guitar tablature editor with player support through midi.
It can display scores and multitrack tabs.  TuxGuitar provides various
additional features, including autoscrolling while playing, note duration
management, bend/slide/vibrato/hammer-on/pull-off effects, support for
tuplets, time signature management, tempo management, gp3/gp4/gp5 import and
export.")
    (license license:lgpl2.1+)))

(define-public pd
  (package
    (name "pd")
    (version "0.45.4")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "mirror://sourceforge/pure-data/pure-data/"
                              version "/pd-" (version-major+minor version)
                              "-" (last (string-split version #\.))
                              ".src.tar.gz"))
              (sha256
               (base32
                "1ls2ap5yi2zxvmr247621g4jx0hhfds4j5704a050bn2n3l0va2p"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; no "check" target
       #:phases
       (modify-phases %standard-phases
         (add-before
          'configure 'fix-wish-path
          (lambda _
            (substitute* "src/s_inter.c"
              (("  wish ") (string-append "  " (which "wish8.6") " ")))
            (substitute* "tcl/pd-gui.tcl"
              (("exec wish ") (string-append "exec " (which "wish8.6") " ")))
            #t))
         (add-after
          'unpack 'autoconf
          (lambda _ (zero? (system* "autoreconf" "-vfi")))))))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("libtool" ,libtool)
       ("gettext" ,gettext-minimal)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("tk" ,tk)
       ("alsa-lib" ,alsa-lib)
       ("jack" ,jack-1)))
    (home-page "http://puredata.info")
    (synopsis "Visual programming language for artistic performances")
    (description
     "Pure Data (aka Pd) is a visual programming language.  Pd enables
musicians, visual artists, performers, researchers, and developers to create
software graphically, without writing lines of code.  Pd is used to process
and generate sound, video, 2D/3D graphics, and interface sensors, input
devices, and MIDI.  Pd can easily work over local and remote networks to
integrate wearable technology, motor systems, lighting rigs, and other
equipment.  Pd is suitable for learning basic multimedia processing and visual
programming methods as well as for realizing complex systems for large-scale
projects.")
    (license license:bsd-3)))

(define-public portmidi
  (package
    (name "portmidi")
    (version "217")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/portmedia/portmidi/"
                                  version "/portmidi-src-" version ".zip"))
              (sha256
               (base32
                "03rfsk7z6rdahq2ihy5k13qjzgx757f75yqka88v3gc0pn9ais88"))
              (patches (list (search-patch "portmidi-modular-build.patch")))))
    (build-system cmake-build-system)
    (arguments
     `(#:tests? #f ; tests cannot be linked
       #:configure-flags
       (list "-DPORTMIDI_ENABLE_JAVA=Off"
             "-DCMAKE_BUILD_TYPE=Release"    ; needed to have PMALSA set
             "-DPORTMIDI_ENABLE_TEST=Off"))) ; tests fail linking
    (inputs
     `(("alsa-lib" ,alsa-lib)))
    (native-inputs
     `(("unzip" ,unzip)))
    (home-page "http://portmedia.sourceforge.net/portmidi/")
    (synopsis "Library for MIDI I/O")
    (description
     "PortMidi is a library supporting real-time input and output of MIDI data
using a system-independent interface.")
    (license license:expat)))

(define-public portmidi-for-extempore
  (package (inherit portmidi)
    (name "portmidi-for-extempore")
    (version "217")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/extemporelang/portmidi/"
                                  "archive/" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0gjikwciyr8kk4y3qiv1pcq58xpgw38ql1m2gs6g0qc1s8sx4235"))))
    (build-system cmake-build-system)
    (arguments `(#:tests? #f)) ; no tests
    (native-inputs '())
    ;; Extempore refuses to build on architectures other than x86_64
    (supported-systems '("x86_64-linux"))
    (home-page "https://github.com/extemporelang/portmidi/")))

(define-public python-pyportmidi
  (package
    (name "python-pyportmidi")
    (version (package-version portmidi))
    (source (package-source portmidi))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f ; no tests included
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'enter-dir
           (lambda _ (chdir "pm_python") #t))
         (add-after 'enter-dir 'fix-setup.py
           (lambda _
             (substitute* "setup.py"
               ;; Use Python 3 syntax
               (("print (\".*\")" _ text)
                (string-append "print(" text ")\n"))
               ;; TODO.txt and CHANGES.txt don't exist
               (("CHANGES =.*") "CHANGES = \"\"\n")
               (("TODO =.*") "TODO = \"\"\n"))
             #t)))))
    (inputs
     `(("portmidi" ,portmidi)
       ("alsa-lib" ,alsa-lib)))
    (native-inputs
     `(("python-cython" ,python-cython)
       ("unzip" ,unzip)))
    (home-page "http://portmedia.sourceforge.net/portmidi/")
    (synopsis "Python bindings to PortMidi")
    (description
     "This package provides Python bindings to the PortMidi library.")
    (license license:expat)))

(define-public frescobaldi
  (package
    (name "frescobaldi")
    (version "2.19.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/wbsoft/frescobaldi/releases/download/v"
                    version "/frescobaldi-" version ".tar.gz"))
              (sha256
               (base32
                "1rnk8i8dlshzx16n2qxcsqcs7kywgyazzyzw2vy4vp2gsm9vs9ml"))))
    (build-system python-build-system)
    (arguments `(#:tests? #f)) ; no tests included
    (inputs
     `(("lilypond" ,lilypond)
       ("portmidi" ,portmidi)
       ("python-pyqt-4" ,python-pyqt-4)
       ("python-ly" ,python-ly)
       ("python-pyportmidi" ,python-pyportmidi)
       ("poppler" ,poppler)
       ("python-poppler-qt4" ,python-poppler-qt4)
       ("python-sip" ,python-sip)))
    (home-page "http://www.frescobaldi.org/")
    (synopsis "LilyPond sheet music text editor")
    (description
     "Frescobaldi is a LilyPond sheet music text editor with syntax
highlighting and automatic completion.  Among other things, it can render
scores next to the source, can capture input from MIDI or read MusicXML and
ABC files, has a MIDI player for proof-listening, and includes a documentation
browser.")
    (license license:gpl2+)))

(define-public drumstick
  (package
    (name "drumstick")
    (version "1.1.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/drumstick/"
                                  version "/drumstick-" version ".tar.bz2"))
              (sha256
               (base32
                "13pkfqrav30bbcddgf1imd7jk6lpqbxkz1qv31718pdl446jq7df"))))
    (build-system cmake-build-system)
    (arguments
     `(#:tests? #f  ; no test target
       #:configure-flags '("-DLIB_SUFFIX=")
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'fix-docbook
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "cmake_admin/CreateManpages.cmake"
               (("http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl")
                (string-append (assoc-ref inputs "docbook-xsl")
                               "/xml/xsl/docbook-xsl-"
                               ,(package-version docbook-xsl)
                               "/manpages/docbook.xsl")))
             #t)))))
    (inputs
     `(("qtbase" ,qtbase)
       ("qtsvg" ,qtsvg)
       ("alsa-lib" ,alsa-lib)
       ("fluidsynth" ,fluidsynth)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("libxslt" ,libxslt) ;for xsltproc
       ("docbook-xsl" ,docbook-xsl)
       ("doxygen" ,doxygen)))
    (home-page "http://drumstick.sourceforge.net/")
    (synopsis "C++ MIDI library")
    (description
     "Drumstick is a set of MIDI libraries using C++/Qt5 idioms and style.  It
includes a C++ wrapper around the ALSA library sequencer interface.  A
complementary library provides classes for processing SMF (Standard MIDI
files: .MID/.KAR), Cakewalk (.WRK), and Overture (.OVE) file formats.  A
multiplatform realtime MIDI I/O library is also provided with various output
backends, including ALSA, OSS, Network and FluidSynth.")
    (license license:gpl2+)))

(define-public zynaddsubfx
  (package
    (name "zynaddsubfx")
    (version "3.0.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://sourceforge/zynaddsubfx/zynaddsubfx/"
                    version "/zynaddsubfx-" version ".tar.bz2"))
              (sha256
               (base32
                "1qijvlbv41lnqaqbp6gh1i42xzf1syviyxz8wr39xbz55cw7y0d8"))))
    (build-system cmake-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; Move SSE compiler optimization flags from generic target to
         ;; athlon64 and core2 targets, because otherwise the build would fail
         ;; on non-Intel machines.
         (add-after 'unpack 'remove-sse-flags-from-generic-target
          (lambda _
            (substitute* "src/CMakeLists.txt"
              (("-msse -msse2 -mfpmath=sse") "")
              (("-march=(athlon64|core2)" flag)
               (string-append flag " -msse -msse2 -mfpmath=sse")))
            #t)))))
    (inputs
     `(("liblo" ,liblo)
       ("ntk" ,ntk)
       ("mesa" ,mesa)
       ("alsa-lib" ,alsa-lib)
       ("jack" ,jack-1)
       ("fftw" ,fftw)
       ("minixml" ,minixml)
       ("libxpm" ,libxpm)
       ("zlib" ,zlib)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://zynaddsubfx.sf.net/")
    (synopsis "Software synthesizer")
    (description
     "ZynAddSubFX is a feature heavy realtime software synthesizer.  It offers
three synthesizer engines, multitimbral and polyphonic synths, microtonal
capabilities, custom envelopes, effects, etc.")
    (license license:gpl2)))

(define-public yoshimi
  (package
    (name "yoshimi")
    (version "1.5.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/yoshimi/"
                                  (version-major+minor version)
                                  "/yoshimi-" version ".tar.bz2"))
              (sha256
               (base32
                "10s1i18xlmvqfrnr0zn2mj2b28i7p62dlqzzzkmpaapqj1gsgpz5"))))
    (build-system cmake-build-system)
    (arguments
     `(#:tests? #f ; there are no tests
       #:configure-flags
       (list (string-append "-DCMAKE_INSTALL_DATAROOTDIR="
                            (assoc-ref %outputs "out") "/share"))
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'enter-dir
           (lambda _ (chdir "src") #t))
         ;; Move SSE compiler optimization flags from generic target to
         ;; athlon64 and core2 targets, because otherwise the build would fail
         ;; on non-Intel machines.
         (add-after 'unpack 'remove-sse-flags-from-generic-target
          (lambda _
            (substitute* "src/CMakeLists.txt"
              (("-msse -msse2 -mfpmath=sse") "")
              (("-march=(athlon64|core2)" flag)
               (string-append flag " -msse -msse2 -mfpmath=sse")))
            #t))
         ;; Yoshimi tries to find ncurses with pkg-config, but our ncurses
         ;; package does not install .pc files.
         (add-after 'unpack 'find-ncurses
           (lambda _
             (substitute* "src/CMakeLists.txt"
               (("LIBNCURSES REQUIRED") "LIBNCURSES")
               (("NCURSES REQUIRED") "NCURSES")
               (("FATAL_ERROR \"libncurses") "STATUS \"libncurses")
               (("\\$\\{NCURSES_LIBRARIES\\}") "ncurses"))
             #t)))))
    (inputs
     `(("boost" ,boost)
       ("fftwf" ,fftwf)
       ("alsa-lib" ,alsa-lib)
       ("jack" ,jack-1)
       ("fontconfig" ,fontconfig)
       ("minixml" ,minixml)
       ("mesa" ,mesa)
       ("fltk" ,fltk)
       ("lv2" ,lv2)
       ("readline" ,readline)
       ("ncurses" ,ncurses)
       ("cairo" ,cairo)
       ("zlib" ,zlib)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://yoshimi.sourceforge.net/")
    (synopsis "Multi-paradigm software synthesizer")
    (description
     "Yoshimi is a fork of ZynAddSubFX, a feature heavy realtime software
synthesizer.  It offers three synthesizer engines, multitimbral and polyphonic
synths, microtonal capabilities, custom envelopes, effects, etc.  Yoshimi
improves on support for JACK features, such as JACK MIDI.")
    (license license:gpl2)))

(define-public jack-keyboard
  (package
    (name "jack-keyboard")
    (version "2.5")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/jack-keyboard/jack-keyboard/"
                           version "/jack-keyboard-" version ".tar.gz"))
       (sha256
        (base32
         "0mzmg8aavybcfdlq2yd9d0vscqd6is5p6jzrgfpfm5j3xdcvh2s3"))))
    (build-system gnu-build-system)
    (inputs
     `(("jack" ,jack-1)
       ("lash" ,lash)
       ("gtk+" ,gtk+-2)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://jack-keyboard.sourceforge.net/")
    (synopsis "Virtual MIDI keyboard")
    (description "Jack-keyboard is a virtual MIDI keyboard, a program that
allows you to send JACK MIDI events (i.e. play) using your PC keyboard.")
    (license license:bsd-2)))

(define-public cursynth
  (package
    (name "cursynth")
    (version "1.5")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://gnu/cursynth/cursynth-"
                          version ".tar.gz"))
      (sha256
       (base32 "1dhphsya41rv8z6yqcv9l6fwbslsds4zh1y56zizi39nd996d40v"))
      (patches (search-patches "cursynth-wave-rand.patch"))))
    (build-system gnu-build-system)
    (native-inputs `(("pkg-config" ,pkg-config)))
    ;; TODO: See https://github.com/iyoko/cursynth/issues/4 which currently
    ;; prevents us from using pulseaudio
    (inputs `(("ncurses" ,ncurses)
              ("alsa" ,alsa-lib)))
    (home-page "http://www.gnu.org/software/cursynth")
    (synopsis "Polyphonic and MIDI subtractive music synthesizer using curses")
    (description "GNU cursynth is a polyphonic synthesizer that runs
graphically in the terminal.  It is built on a full-featured subtractive
synthesis engine.  Notes and parameter changes may be entered via MIDI or the
computer's keyboard.")
    (license license:gpl3+)))

(define-public qtractor
  (package
    (name "qtractor")
    (version "0.8.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://downloads.sourceforge.net/qtractor/"
                                  "qtractor-" version ".tar.gz"))
              (sha256
               (base32
                "17v563liyqcvil204ry1qfp09d91944nqz2ig33f5c3pyg4z2427"))))
    (build-system gnu-build-system)
    (arguments `(#:tests? #f)) ; no "check" target
    (inputs
     `(("qt" ,qt)
       ("alsa-lib" ,alsa-lib)
       ("jack" ,jack-1)
       ("libsndfile" ,libsndfile)
       ("ladspa" ,ladspa)
       ("lv2" ,lv2)
       ("lilv" ,lilv)
       ("suil" ,suil)
       ("libsamplerate" ,libsamplerate)
       ("libvorbis" ,libvorbis)
       ("libmad" ,libmad)
       ("rubberband" ,rubberband)
       ("liblo" ,liblo)
       ("zlib" ,zlib)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://qtractor.sourceforge.net/")
    (synopsis "Audio/MIDI multi-track sequencer")
    (description
     "Qtractor is an Audio/MIDI multi-track sequencer application.  It uses
JACK for audio and ALSA sequencer for MIDI as multimedia infrastructures and
follows a traditional multi-track tape recorder control paradigm.")
    (license license:gpl2+)))

(define-public ams-lv2
  (package
    (name "ams-lv2")
    (version "1.2.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/blablack/ams-lv2/"
                           "archive/" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1392spswkhfd38fggf584wb3m8aqpg7csfrs9zxnzyvhgmp0fgqk"))))
    (build-system waf-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'remove-sse-flags
           (lambda* (#:key system #:allow-other-keys)
             (when (not (or (string-prefix? "x86_64" system)
                            (string-prefix? "i686" system)))
               (substitute* "wscript"
                 (("'-msse', '-mfpmath=sse', ") ""))
             #t))))
       #:tests? #f)) ; no tests
    (inputs
     `(("lv2" ,lv2)
       ("lvtk" ,lvtk)
       ("gtkmm" ,gtkmm-2)
       ("gtk" ,gtk+-2)
       ("cairo" ,cairo)
       ("fftw" ,fftw)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "https://objectivewave.wordpress.com/ams-lv2/")
    (synopsis "Port of Alsa Modular Synth internal modules into LV2")
    (description "This set of LV2 plugins is a port of the internal modules
found in Alsa Modular Synth.  These plugins are used to create modular
synthesizers and contain: VCO, VCF, VCA, LFO, slew limiter, envelopes, sample
and hold, etc.")
    (license license:gpl2)))

(define-public gxtuner
  (package
    (name "gxtuner")
    (version "2.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/brummer10/gxtuner/"
                                  "archive/v" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1abpxiydn4c9wssz6895hnad9ipkcy3rkgzbnanvwb46nm44x6if"))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags
       (list (string-append "PREFIX=" (assoc-ref %outputs "out"))
             (string-append "INCLUDE_L_DIR="
                            (assoc-ref %build-inputs "zita-resampler")
                            "/include/"))
       #:phases
       (modify-phases %standard-phases
         (delete 'configure))))
    (inputs
     `(("gtk+" ,gtk+-2)
       ("jack" ,jack-1)
       ("fftwf" ,fftwf)
       ("cairo" ,cairo)
       ("zita-resampler" ,zita-resampler)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "https://github.com/brummer10/gxtuner")
    (synopsis "Guitar tuner")
    (description "GXtuner is a simple guitar tuner for JACK with an
analogue-like user interface.")
    (license license:gpl2+)))

(define-public mod-host
  ;; The last release was in 2014 but since then more than 140 commits have
  ;; been made.
  (let ((commit "72aca771e3a4e3889641b9bab84985586c9bb926")
        (revision "1"))
    (package
      (name "mod-host")
      (version (string-append "0.10.6-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/moddevices/mod-host")
                      (commit commit)))
                (sha256
                 (base32
                  "19szi8cy65jlchbrmbjbma03g6gxj9zyyp4dgw1k06r0cxbx82gq"))
                (file-name (string-append name "-" version "-checkout"))))
      (build-system gnu-build-system)
      (arguments
       `(#:tests? #f ; no tests included
         #:make-flags
         (list (string-append "PREFIX=" (assoc-ref %outputs "out"))
               "CC=gcc")
         #:phases
         (modify-phases %standard-phases
           (delete 'configure)
           (add-after 'unpack 'fix-jack-installation-directory
             (lambda _
               ;; Do not attempt to install files to output of "jack" package.
               (substitute* "Makefile"
                 (("\\$\\(shell pkg-config --variable=libdir jack\\)")
                  "lib"))
               #t)))))
      (inputs
       `(("lilv" ,lilv)
         ("fftw" ,fftw-with-threads)
         ("fftwf" ,fftwf-with-threads)
         ("lv2" ,lv2)
         ("jack" ,jack-1)
         ("readline" ,readline)))
      (native-inputs
       `(("pkg-config" ,pkg-config)
         ("python" ,python-2)))
      (home-page "https://github.com/moddevices/mod-host")
      (synopsis "LV2 host for Jack controllable via socket or command line")
      (description "mod-host is an LV2 plugin host for JACK, controllable via
socket or command line.")
      (license license:gpl3+))))

(define-public pianobar
  (package
    (name "pianobar")
    (version "2015.11.22")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/PromyLOPh/"
                                  name "/archive/" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "022df19bhxqvkhy0qy21xahba5s1fm17b13y0p9p9dnf2yl44wfv"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; no tests
       #:make-flags (list "CC=gcc" "CFLAGS=-std=c99"
                          (string-append "PREFIX=" %output))
       #:phases (modify-phases %standard-phases
                  (delete 'configure))))
    (inputs
     `(("ao" ,ao)
       ("curl" ,curl)
       ("libgcrypt" ,libgcrypt)
       ("json-c" ,json-c)
       ("ffmpeg" ,ffmpeg)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://6xq.net/projects/pianobar/")
    (synopsis "Console-based pandora.com player")
    (description "pianobar is a console-based music player for the
personalized online radio pandora.com.  It has configurable keys for playing
and managing stations, can be controlled remotely via fifo, and can run
event-based scripts for scrobbling, notifications, etc.")
    (license license:expat)))

(define-public python-mutagen
  (package
    (name "python-mutagen")
    (version "1.35.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "mutagen" version))
              (sha256
               (base32
                "0klk68c1n3285vvm2xzk8ii7mlqp1dxii04askan0gi1wlpagka9"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-pytest" ,python-pytest)))
    (home-page "https://bitbucket.org/lazka/mutagen")
    (synopsis "Read and write audio tags")
    (description "Mutagen is a Python module to handle audio metadata.  It
supports ASF, FLAC, M4A, Monkey’s Audio, MP3, Musepack, Ogg FLAC, Ogg Speex, Ogg
Theora, Ogg Vorbis, True Audio, WavPack and OptimFROG audio files.  All versions
of ID3v2 are supported, and all standard ID3v2.4 frames are parsed.  It can read
Xing headers to accurately calculate the bitrate and length of MP3s.  ID3 and
APEv2 tags can be edited regardless of audio format.  It can also manipulate Ogg
streams on an individual packet/page level.")
    (license license:gpl2))) ; "later version" never mentioned

(define-public python2-mutagen
  (package-with-python2 python-mutagen))

(define-public python-musicbrainzngs
  (package
    (name "python-musicbrainzngs")
    (version "0.6")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "musicbrainzngs" version))
              (sha256
               (base32
                "1dddarpjawryll2wss65xq3v9q8ln8dan7984l5dxzqx88d2dvr8"))))
    (build-system python-build-system)
    (arguments
     '(;; The tests fail suffer from race conditions:
       ;; https://github.com/alastair/python-musicbrainzngs/issues/211
       #:tests? #f))
    (home-page "https://python-musicbrainzngs.readthedocs.org/")
    (synopsis "Python bindings for MusicBrainz NGS webservice")
    (description "Musicbrainzngs implements Python bindings of the MusicBrainz
web service.  This library can be used to retrieve music metadata from the
MusicBrainz database.")
    ;; 'musicbrainzngs/compat.py' is ISC licensed.
    (license (list license:bsd-2 license:isc))))

(define-public python2-musicbrainzngs
  (package-with-python2 python-musicbrainzngs))

(define-public python2-pyechonest
  (package
    (name "python2-pyechonest")
    (version "9.0.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pyechonest" version))
              (sha256
               (base32
                "1584nira3rkiman9dm81kdshihmkj21s8navndz2l8spnjwb790x"))))
    (build-system python-build-system)
    (arguments
     `(;; Python 3 is not supported:
       ;; https://github.com/echonest/pyechonest/issues/42
       #:python ,python-2))
    (home-page "https://github.com/echonest/pyechonest")
    (synopsis "Python interface to The Echo Nest APIs")
    (description "Pyechonest is a Python library for the Echo Nest API.  With
Pyechonest you have Python access to the entire set of API methods including:

@enumerate
@item artist - search for artists by name, description, or attribute, and get
back detailed information about any artist including audio, similar artists,
blogs, familiarity, hotttnesss, news, reviews, urls and video.
@item song - search songs by artist, title, description, or attribute (tempo,
duration, etc) and get detailed information back about each song, such as
hotttnesss, audio_summary, or tracks.
@item track - upload a track to the Echo Nest and receive summary information
about the track including key, duration, mode, tempo, time signature along with
detailed track info including timbre, pitch, rhythm and loudness information.
@end enumerate\n")
    (license license:bsd-3)))

(define-public python-pylast
  (package
    (name "python-pylast")
    (version "1.6.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pylast" version))
              (sha256
               (base32
                "0bml11gfkxqd3i2jxkn5k2xllc4rvxjcyhs8an05gcyy1zp2bwvb"))))
    (build-system python-build-system)
    (native-inputs
     `(("python-coverage" ,python-coverage)
       ("python-mock" ,python-mock)
       ("python-pep8" ,python-pep8)
       ("python-pytest" ,python-pytest)
       ("python-pyflakes" ,python-pyflakes)
       ("python-pyyaml" ,python-pyyaml)))
    (propagated-inputs
     `(("python-six" ,python-six)))
    (home-page "https://github.com/pylast/pylast")
    (synopsis "Python interface to Last.fm and Libre.fm")
    (description "A Python interface to Last.fm and other API-compatible
websites such as Libre.fm.")
    (license license:asl2.0)))

(define-public python2-pylast
  (package-with-python2 python-pylast))

(define-public beets
  (package
    (name "beets")
    (version "1.4.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "beets" version))
              (sha256
               (base32
                "14yn88xrcinpdg3ic285ar0wmwldzyjfd3ll6clmp3z3r4iqffip"))))
    (build-system python-build-system)
    (arguments
     `(;; Python 3 support is still "alpha", and the upstream maintainers ask
       ;; packagers not to use it yet:
       ;; https://github.com/beetbox/beets/releases/tag/v1.4.1
       ;; TODO Check this again for the next release.
       #:python ,python-2
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'set-HOME
           (lambda _ (setenv "HOME" (string-append (getcwd) "/tmp"))))
         (replace 'check
           (lambda _ (zero? (system* "nosetests" "-v")))))))
    (native-inputs
     `(("python2-beautifulsoup4" ,python2-beautifulsoup4)
       ("python2-flask" ,python2-flask)
       ("python2-mock" ,python2-mock)
       ("python2-mpd2" ,python2-mpd2)
       ("python2-nose" ,python2-nose)
       ("python2-pathlib" ,python2-pathlib)
       ("python2-pyxdg" ,python2-pyxdg)
       ("python2-pyechonest" ,python2-pyechonest)
       ("python2-pylast" ,python2-pylast)
       ("python2-rarfile" ,python2-rarfile)
       ("python2-responses" ,python2-responses)))
    ;; TODO: Install optional plugins and dependencies.
    (inputs
     `(("python2-discogs-client" ,python2-discogs-client)
       ("python2-enum34" ,python2-enum34)
       ("python2-jellyfish" ,python2-jellyfish)
       ("python2-munkres" ,python2-munkres)
       ("python2-musicbrainzngs" ,python2-musicbrainzngs)
       ("python2-mutagen" ,python2-mutagen)
       ("python2-pyyaml" ,python2-pyyaml)
       ("python2-unidecode" ,python2-unidecode)))
    (home-page "http://beets.io")
    (synopsis "Music organizer")
    (description "The purpose of beets is to get your music collection right
once and for all.  It catalogs your collection, automatically improving its
metadata as it goes using the MusicBrainz database.  Then it provides a variety
of tools for manipulating and accessing your music.")
    (license license:expat)))

(define-public milkytracker
  (package
    (name "milkytracker")
    (version "0.90.86")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://milkytracker.titandemo.org/files/"
                                  name "-" version ".tar.bz2"))
              (sha256
               (base32
                "1v9vp8vi24lkagfpr92c128whvakwgrm9pq2zf6ijpl5sh7014zb"))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags '("CXXFLAGS=-lasound")))
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("jack" ,jack-1)
       ("sdl" ,sdl)
       ("zlib" ,zlib)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (synopsis "Music tracker for working with .MOD/.XM module files")
    (description "MilkyTracker is a music application for creating .MOD and .XM
module files.  It attempts to recreate the module replay and user experience of
the popular DOS program Fasttracker II, with special playback modes available
for improved Amiga ProTracker 2/3 compatibility.")
    (home-page "http://milkytracker.titandemo.org/")
    ;; 'src/milkyplay' is under Modified BSD, the rest is under GPL3 or later.
    (license (list license:bsd-3 license:gpl3+))))

(define-public schismtracker
  (package
    (name "schismtracker")
    (version "20160521")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/" name "/" name "/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0c6r24wm3rldm4j8cskl9xnixj3rwi3lnrhckw5gv43wpy6h4jcz"))
              (modules '((guix build utils)))
              (snippet
               ;; Remove use of __DATE__ and __TIME__ for reproducibility.
               `(substitute* "schism/version.c"
                  (("Schism Tracker build %s %s.*$")
                   (string-append "Schism Tracker version " ,version "\");"))))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'autoconf
           (lambda _ (zero? (system* "autoreconf" "-vfi"))))
         (add-before 'configure 'link-libm
           (lambda _ (setenv "LIBS" "-lm") #t)))))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("python" ,python)))
    (inputs
     `(("alsa-lib" ,alsa-lib) ; for asound dependency
       ("libx11" ,libx11)
       ("libxext" ,libxext)
       ("sdl" ,sdl)))
    (home-page "http://schismtracker.org")
    (synopsis "Oldschool sample-based music composition tool")
    (description
     "Schism Tracker is a reimplementation of Impulse Tracker, a program used to
create high quality music without the requirements of specialized, expensive
equipment, and with a unique \"finger feel\" that is difficult to replicate in
part.  The player is based on a highly modified version of the ModPlug engine,
with a number of bugfixes and changes to improve IT playback.")
    (license license:gpl2+)))

(define-public moc
  (package
    (name "moc")
    (version "2.5.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://ftp.daper.net/pub/soft/"
                                  name "/stable/"
                                  name "-" version ".tar.bz2"))
              (sha256
               (base32
                "1wn4za08z64bhsgfhr9c0crfyvy8c3b6a337wx7gz19am5srqh8v"))))
    (build-system gnu-build-system)
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("curl" ,curl)
       ("faad2" ,faad2)
       ("ffmpeg" ,ffmpeg)
       ("file" ,file)
       ("jack" ,jack-1)
       ("libid3tag" ,libid3tag)
       ("libltdl" ,libltdl)
       ("libmodplug" ,libmodplug)
       ("libmpcdec" ,libmpcdec)
       ("libmad" ,libmad)
       ("ncurses" ,ncurses)
       ("openssl" ,openssl)
       ("sasl" ,cyrus-sasl)
       ("speex" ,speex)
       ("taglib" ,taglib)
       ("wavpack" ,wavpack)
       ("zlib" ,zlib)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (synopsis "Console audio player designed to be powerful and easy to use")
    (description
     "Music on Console is a console audio player that supports many file
formats, including most audio formats recognized by FFMpeg.")
    (home-page "http://moc.daper.net")
    (license license:gpl2+)))

(define-public midicsv
  (package
    (name "midicsv")
    (version "1.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://www.fourmilab.ch/webtools/midicsv/"
                                  name "-" version ".tar.gz"))
              (sha256
               (base32
                "1vvhk2nf9ilfw0wchmxy8l13hbw9cnpz079nsx5srsy4nnd78nkw"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases (delete 'configure))
       #:make-flags (list "CC=gcc" (string-append "INSTALL_DEST=" %output))))
    (synopsis "Convert MIDI files to and from CSV")
    (description
     "Midicsv reads a standard MIDI file and decodes it into a comma-separated
value file (CSV), which preserves all the information in the MIDI file.  The
ASCII CSV file may be loaded into a spreadsheet or database application, or
processed by a program to transform the MIDI data (for example, to key
transpose a composition or extract a track from a multi-track sequence).  A
CSV file in the format created by midicsv may be converted back into a
standard MIDI file with the csvmidi program.")
    (home-page "http://www.fourmilab.ch/webtools/midicsv/")
    (license license:public-domain)))

(define-public gx-guvnor-lv2
  (let ((commit "9f528a7623a201383e119bb6a2df32b18396a9d5")
        (revision "1"))
    (package
      (name "gx-guvnor-lv2")
      (version (string-append "0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/brummer10/GxGuvnor.lv2")
                      (commit commit)))
                (sha256
                 (base32
                  "10zx84p2vd7i1yqc5ma9p17927265j4g0zfwv9rxladw0nm8y45k"))
                (file-name (string-append name "-" version "-checkout"))))
      (build-system gnu-build-system)
      (arguments
       `(;; The check target is used only to output a warning.
         #:tests? #f
         #:make-flags
         (list (string-append "DESTDIR=" (assoc-ref %outputs "out")))
         #:phases
         (modify-phases %standard-phases
           (replace 'configure
             (lambda _
               (substitute* "Makefile"
                 (("INSTALL_DIR = .*") "INSTALL_DIR=/lib/lv2\n")
                 ;; Avoid rebuilding everything
                 (("install : all") "install:"))
               #t)))))
      (inputs
       `(("lv2" ,lv2)))
      (home-page "https://github.com/brummer10/GxGuvnor.lv2")
      (synopsis "Overdrive/distortion pedal simulation")
      (description "This package provides the LV2 plugin \"GxGuvnor\", a
simulation of an overdrive or distortion pedal for guitars.")
      ;; The LICENSE file says GPLv3 but the license headers in the files say
      ;; GPLv2 or later.
      (license license:gpl2+))))

(define-public gx-vbass-preamp-lv2
  (let ((commit "0e599abab10c7669dd444e5d06f671c2fc1b9c6c")
        (revision "1"))
    (package (inherit gx-guvnor-lv2)
      (name "gx-vbass-preamp-lv2")
      (version (string-append "0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/brummer10/GxVBassPreAmp.lv2")
                      (commit commit)))
                (sha256
                 (base32
                  "1dzksdfrva666gpi62fd2ni9rhf18sl917f1894qr0b17pbdh9k1"))
                (file-name (string-append name "-" version "-checkout"))))
      (home-page "https://github.com/brummer10/GxVBassPreAmp.lv2")
      (synopsis "Simulation of the Vox Venue Bass 100 Pre Amp Section")
      (description "This package provides the LV2 plugin \"GxVBassPreAmp\", a
pre-amplifier simulation modelled after the 1984 Vox Venue Bass 100 Pre Amp
Section."))))

(define-public gx-overdriver-lv2
  (let ((commit "ed71801987449414bf3adaa0dbfac68e8775f1ce")
        (revision "1"))
    (package (inherit gx-guvnor-lv2)
      (name "gx-overdriver-lv2")
      (version (string-append "0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/brummer10/GxOverDriver.lv2")
                      (commit commit)))
                (sha256
                 (base32
                  "13j614jh525fbkby79nnzwj0z1ac0c9wclyn5pfqvkmx6a7j24r8"))
                (file-name (string-append name "-" version "-checkout"))))
      (home-page "https://github.com/brummer10/GxOverDriver.lv2")
      (synopsis "Overdrive effect with level and tone control")
      (description "This package provides the LV2 plugin \"GxOverDriver\", an
overdrive effect."))))

(define-public gx-tone-mender-lv2
  (let ((commit "b6780b4a3e4782b3ed0e5882d6788f178aed138f")
        (revision "1"))
    (package (inherit gx-guvnor-lv2)
      (name "gx-tone-mender-lv2")
      (version (string-append "0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/brummer10/GxToneMender.lv2")
                      (commit commit)))
                (sha256
                 (base32
                  "07qdcfsvv2vdnfnjh91pfgvjdcs5y91nvwfm8c0z8fp6b4bk7a9q"))
                (file-name (string-append name "-" version "-checkout"))))
      (home-page "https://github.com/brummer10/GxToneMender.lv2")
      (synopsis "Clean boost with a 3-knob tonestack")
      (description "This package provides the LV2 plugin \"GxToneMender\", a
clean boost effect with a 3-knob tonestack."))))

(define-public gx-push-pull-lv2
  (let ((commit "7f76ae2068498643ac8671ee0930b13ee3fd8eb5")
        (revision "1"))
    (package (inherit gx-guvnor-lv2)
      (name "gx-push-pull-lv2")
      (version (string-append "0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/brummer10/GxPushPull.lv2")
                      (commit commit)))
                (sha256
                 (base32
                  "12f5hwck2irph0gjbj8xy8jqcqdwb8l1hlwf29k0clz52h1jhb5q"))
                (file-name (string-append name "-" version "-checkout"))))
      (home-page "https://github.com/brummer10/GxPushPull.lv2")
      (synopsis "Octave up push pull transistor fuzz simulation")
      (description "This package provides the LV2 plugin \"GxPushPull\", a
simulation of a push pull transistor fuzz effect with added high octave."))))

(define-public gx-suppa-tone-bender-lv2
  (let ((commit "4e6dc713ec24e7fcf5ea23b7e685af627c01b9c9")
        (revision "1"))
    (package (inherit gx-guvnor-lv2)
      (name "gx-suppa-tone-bender-lv2")
      (version (string-append "0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/brummer10/GxSuppaToneBender.lv2")
                      (commit commit)))
                (sha256
                 (base32
                  "1i22xr252nkbazkwidll2zb3i96610gx65qn5djdkijlz7j77138"))
                (file-name (string-append name "-" version "-checkout"))))
      (home-page "https://github.com/brummer10/GxSuppaToneBender.lv2")
      (synopsis "Simulation of the Vox Suppa Tone Bender pedal")
      (description "This package provides the LV2 plugin
\"GxSuppaToneBender\", a simulation modelled after the Vox Suppa Tone Bender
pedal."))))

(define-public gx-saturator-lv2
  (let ((commit "0b581ac85c515325b9f16e51937cae6e1bf81a0a")
        (revision "2"))
    (package (inherit gx-guvnor-lv2)
      (name "gx-saturator-lv2")
      (version (string-append "0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/brummer10/GxSaturator.lv2")
                      (commit commit)))
                (sha256
                 (base32
                  "1cl785pzq8zk55m1rnhfd6qsabci6kpf4pf002gwr91vagyq246z"))
                (file-name (string-append name "-" version "-checkout"))))
      (home-page "https://github.com/brummer10/GxSaturator.lv2")
      (synopsis "Saturation effect")
      (description "This package provides the LV2 plugin \"GxSaturator\", a
saturation effect."))))

(define-public gx-hyperion-lv2
  (let ((commit "6a096a664e553e551e179e85cf390bd1683410fb")
        (revision "2"))
    (package (inherit gx-guvnor-lv2)
      (name "gx-hyperion-lv2")
      (version (string-append "0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/brummer10/GxHyperion.lv2")
                      (commit commit)))
                (sha256
                 (base32
                  "1ksv3wmylhwbf6kjl2lnhr14h9rfl291cfm21471gnb1r68yqfxh"))
                (file-name (string-append name "-" version "-checkout"))))
      (home-page "https://github.com/brummer10/GxHyperion.lv2")
      (synopsis "Simulation of the Hyperion Fuzz pedal")
      (description "This package provides the LV2 plugin \"GxHyperion\", a
simulation of the Hyperion Fuzz pedal."))))

(define-public gx-voodoo-fuzz-lv2
  (let ((commit "aec7889b489385e8add06126e7a36ae2e26254b1")
        (revision "2"))
    (package (inherit gx-guvnor-lv2)
      (name "gx-voodoo-fuzz-lv2")
      (version (string-append "0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/brummer10/GxVoodoFuzz.lv2")
                      (commit commit)))
                (sha256
                 (base32
                  "0mc41ldlv89069iaysnfiqxy5h5sr8mdi5cxm3ij5q5v4jv3viwx"))
                (file-name (string-append name "-" version "-checkout"))))
      (home-page "https://github.com/brummer10/GxVoodoFuzz.lv2")
      (synopsis "Fuzz effect modelled after the Voodoo Lab SuperFuzz")
      (description "This package provides the LV2 plugin \"GxVoodooFuzz\", a
simulation modelled after the Voodoo Lab SuperFuzz pedal.  It's basically a
Bosstone circuit, followed by the tone control of the FoxToneMachine in
parallel with a DarkBooster, followed by a volume control."))))

(define-public gx-super-fuzz-lv2
  (let ((commit "f40389575812c909007d140d327ce579930b71f7")
        (revision "2"))
    (package (inherit gx-guvnor-lv2)
      (name "gx-super-fuzz-lv2")
      (version (string-append "0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/brummer10/GxSuperFuzz.lv2")
                      (commit commit)))
                (sha256
                 (base32
                  "174bibj8qzm8zr6f5h8bcj94iry17zravk8flpdy84n6yg7cixji"))
                (file-name (string-append name "-" version "-checkout"))))
      (home-page "https://github.com/brummer10/GxSuperFuzz.lv2")
      (synopsis "Fuzz effect modelled after the UniVox SuperFuzz")
      (description "This package provides the LV2 plugin \"GxVoodooFuzz\", an
analog simulation of the UniVox SuperFuzz pedal.  In this simulation the trim
pot, which is usualy in the housing, is exposed as a control parameter.  It
adjusts the amount of harmonics."))))

(define-public gx-vintage-fuzz-master-lv2
  (let ((commit "0fec0bc1e8a8ba909a68e916e036138a3425d7db")
        (revision "2"))
    (package (inherit gx-guvnor-lv2)
      (name "gx-vintage-fuzz-master-lv2")
      (version (string-append "0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/brummer10/GxVintageFuzzMaster.lv2")
                      (commit commit)))
                (sha256
                 (base32
                  "06szi6d2iwkygbw5azhwzhcl2as4lmk2gs9hanngsf46a1zbdcp7"))
                (file-name (string-append name "-" version "-checkout"))))
      (home-page "https://github.com/brummer10/GxVintageFuzzMaster.lv2")
      (synopsis "Fuzz effect simulation of the vintage Fuzz Master")
      (description "This package provides the LV2 plugin
\"GxVintageFuzzMaster\", a simulation of the vintage Fuzz Master pedal."))))

(define-public gx-slow-gear-lv2
  (let ((commit "cb852e0426f4e6fe077e7f1ede73a4da335cfc5e")
        (revision "2"))
    (package (inherit gx-guvnor-lv2)
      (name "gx-slow-gear-lv2")
      (version (string-append "0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/brummer10/GxSlowGear.lv2")
                      (commit commit)))
                (sha256
                 (base32
                  "0dp7afi1r3kzciiyn1hrkz6arsq47ys9sx5g4b7xa9k1dv92ishp"))
                (file-name (string-append name "-" version "-checkout"))))
      (home-page "https://github.com/brummer10/GxSlowGear.lv2")
      (synopsis "Slow gear audio effect")
      (description "This package provides the LV2 plugin \"GxSlowGear\", a
slow gear audio effect to produce volume swells."))))

(define-public gx-switchless-wah-lv2
  (let ((commit "7b08691203314612999f0ce2328cdc1161cd6665")
        (revision "2"))
    (package (inherit gx-guvnor-lv2)
      (name "gx-switchless-wah-lv2")
      (version (string-append "0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/brummer10/GxSwitchlessWah.lv2")
                      (commit commit)))
                (sha256
                 (base32
                  "04jqfpncmrrqn34p21w4v9m2x5a5wsqwbm4f3byxvq4vcibwxzk2"))
                (file-name (string-append name "-" version "-checkout"))))
      (home-page "https://github.com/brummer10/GxSwitchlessWah.lv2")
      (synopsis "Wah emulation with switchless activation")
      (description "This package provides the LV2 plugin \"GxSwitchlessWah\",
a simulation of an analog Wah pedal with switchless activation."))))

(define-public mod-utilities
  (let ((commit "7cdeeac26ae682730740105ece121d4dddb8ba3f")
        (revision "1"))
    (package
      (name "mod-utilities")
      (version (string-append "0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/moddevices/mod-utilities.git")
                      (commit commit)))
                (sha256
                 (base32
                  "1ilnkbrmwrszxvc21qlb86h29yz7cnc6rcp0jmna1y693ny2qhf4"))
                (file-name (string-append name "-" version "-checkout"))))
      (build-system gnu-build-system)
      (arguments
       `(#:tests? #f ; there are no tests
         #:make-flags
         (list (string-append "INSTALL_PATH="
                              (assoc-ref %outputs "out")
                              "/lib/lv2"))
         #:phases
         (modify-phases %standard-phases
           (delete 'configure))))
      (inputs
       `(("lv2" ,lv2)))
      (home-page "https://github.com/moddevices/mod-utilities")
      (synopsis "LV2 utility plugins")
      (description "This package provides LV2 audio utility plugins, such as
filters, crossovers, simple gain plugins without zipper noise, switch box
plugins, a switch trigger, a toggle switch, and a peakmeter.")
      (license license:gpl2+))))

(define-public ingen
  (let ((commit "fd147d0b888090bfb897505852c1f25dbdf77e18")
        (revision "1"))
    (package
      (name "ingen")
      (version (string-append "0.0.0-" revision "."
                              (string-take commit 9)))
      (source
       (origin
         (method git-fetch)
         (uri (git-reference
               (url "http://git.drobilla.net/ingen.git")
               (commit commit)))
         (file-name (string-append name "-" version "-checkout"))
         (sha256
          (base32
           "1qmg79962my82c43vyrv5sxbqci9c7gc2s9bwaaqd0fcf08xcz1z"))))
      (build-system waf-build-system)
      (arguments
       `(#:tests? #f ; no "check" target
         #:configure-flags (list "--no-webkit")
         #:phases
         (modify-phases %standard-phases
           (add-after 'unpack 'patch-wscript
             (lambda* (#:key outputs #:allow-other-keys)
               (let ((out (assoc-ref outputs "out")))
                 (substitute* "wscript"
                   ;; FIXME: Our version of lv2specgen.py does not behave as
                   ;; expected.  Maybe this requires a development version of
                   ;; LV2.
                   (("lv2specgen.py") "touch ingen.lv2/ingen.html; echo")
                   ;; Add libraries to RUNPATH.
                   (("^(.+)target.*= 'src/ingen/ingen'," line prefix)
                    (string-append prefix
                                   "linkflags=[\"-Wl,-rpath="
                                   out "/lib" "\"]," line)))
                 (substitute* '("src/wscript"
                                "src/server/wscript")
                   ;; Add libraries to RUNPATH.
                   (("bld.env.PTHREAD_LINKFLAGS" line)
                    (string-append line
                                   " + [\"-Wl,-rpath=" out "/lib" "\"]")))
                 (substitute* "src/client/wscript"
                   ;; Add libraries to RUNPATH.
                   (("^(.+)target.*= 'ingen_client'," line prefix)
                    (string-append prefix
                                   "linkflags=[\"-Wl,-rpath="
                                   out "/lib" "\"]," line)))
                 (substitute* "src/gui/wscript"
                   ;; Add libraries to RUNPATH.
                   (("^(.+)target.* = 'ingen_gui.*" line prefix)
                    (string-append prefix
                                   "linkflags=[\"-Wl,-rpath="
                                   out "/lib" "\"]," line))))
               #t)))))
      (inputs
       `(("boost" ,boost)
         ("python-rdflib" ,python-rdflib)
         ("python" ,python)
         ("jack" ,jack-1)
         ("lv2" ,lv2)
         ("lilv" ,lilv)
         ("raul" ,raul-devel)
         ("ganv" ,ganv-devel)
         ("suil" ,suil)
         ("serd" ,serd)
         ("sord" ,sord)
         ("sratom" ,sratom)
         ("gtkmm" ,gtkmm-2)))
      (native-inputs
       `(("pkg-config" ,pkg-config)
         ("python-pygments" ,python-pygments)))
      (home-page "http://drobilla.net/software/ingen")
      (synopsis "Modular audio processing system")
      (description "Ingen is a modular audio processing system for JACK and
LV2 based systems.  Ingen is built around LV2 technology and a strict
separation of engine from user interface.  The engine is controlled
exclusively through a protocol, and can execute as a headless process, with an
in-process GUI, or as an LV2 plugin.  The GUI can run as a program which
communicates over a Unix or TCP/IP socket, or as an embeddable LV2 GUI which
communicates via LV2 ports.  Any saved Ingen graph can be loaded as an LV2
plugin on any system where Ingen is installed.  This allows users to visually
develop custom plugins for use in other applications without programming.")
      (license license:agpl3+))))

(define-public qmidiarp
  (package
    (name "qmidiarp")
    (version "0.6.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/qmidiarp/qmidiarp/"
                                  version "/qmidiarp-" version ".tar.bz2"))
              (sha256
               (base32
                "1gkfv8ajgf86kbn6j5ilfc1zlz17gdi9yxzywqd6jwff4xlm75hx"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags
       (list "--enable-qt5"
             "CXXFLAGS=-std=gnu++11")))
    (inputs
     `(("qtbase" ,qtbase)
       ("alsa-lib" ,alsa-lib)
       ("jack" ,jack-1)
       ("liblo" ,liblo)
       ("lv2" ,lv2)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("qttools" ,qttools)))
    (home-page "http://qmidiarp.sourceforge.net/")
    (synopsis "MIDI arpeggiator")
    (description "QMidiArp is an advanced MIDI arpeggiator, programmable step
sequencer and LFO.  It can hold any number of arpeggiator, sequencer, or LFO
modules running in parallel.")
    (license license:gpl2+)))

(define-public seq24
  (package
    (name "seq24")
    (version "0.9.3")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://launchpad.net/seq24/trunk/"
                                  version "/+download/seq24-"
                                  version ".tar.bz2"))
              (sha256
               (base32
                "12dphdhnvfk1k0vmagi1v2lhyxjyj1j3cz6ksjw0ydcvid1x8ap2"))
              (patches (search-patches "seq24-rename-mutex.patch"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags
       (list "CXXFLAGS=-std=gnu++11")))
    (inputs
     `(("gtkmm" ,gtkmm-2)
       ("alsa-lib" ,alsa-lib)
       ("jack" ,jack-1)
       ("lash" ,lash)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "https://edge.launchpad.net/seq24/")
    (synopsis "Real-time MIDI sequencer")
    (description "Seq24 is a real-time MIDI sequencer.  It was created to
provide a very simple interface for editing and playing MIDI loops.")
    (license license:gpl2+)))

(define-public python-discogs-client
  (package
    (name "python-discogs-client")
    (version "2.2.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "discogs-client" version))
              (sha256
               (base32
                "053ld2psh0yj3z0kg6z5bn4y3cr562m727494n0ayhgzbkjbacly"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-oauthlib" ,python-oauthlib)
       ("python-requests" ,python-requests)))
    (native-inputs
     `(("python-six" ,python-six)))
    (home-page "https://github.com/discogs/discogs_client")
    (synopsis "Official Python client for the Discogs API")
    (description "This is the official Discogs API client for Python. It enables
you to query the Discogs database for information on artists, releases, labels,
users, Marketplace listings, and more.  It also supports OAuth 1.0a
authorization, which allows you to change user data such as profile information,
collections and wantlists, inventory, and orders.")
    (license license:bsd-2)))

(define-public python2-discogs-client
  (package-with-python2 python-discogs-client))
