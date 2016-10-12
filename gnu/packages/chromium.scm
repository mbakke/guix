;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2016, 2017 Marius Bakke <mbakke@fastmail.com>
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

(define-module (gnu packages chromium)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (gnu packages)
  #:use-module (gnu packages assembly)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages cups)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gnuzilla)
  #:use-module (gnu packages gperf)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages image)
  #:use-module (gnu packages libevent)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages libusb)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages kerberos)
  #:use-module (gnu packages ninja)
  #:use-module (gnu packages node)
  #:use-module (gnu packages pciutils)
  #:use-module (gnu packages photo)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages protobuf)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages python)
  #:use-module (gnu packages regex)
  #:use-module (gnu packages serialization)
  #:use-module (gnu packages speech)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages valgrind)
  #:use-module (gnu packages version-control)
  #:use-module (gnu packages video)
  #:use-module (gnu packages xiph)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xorg))

(define opus+custom
  (package (inherit opus)
           (arguments
            `(;; Opus Custom is an optional extension of the Opus
              ;; specification that allows for unsupported frame
              ;; sizes. Chromium requires that this is enabled.
              #:configure-flags '("--enable-custom-modes")
              ,@(package-arguments opus)))))

;; Chromium since 58 depends on an unreleased libvpx. So, we
;; package the latest master branch as of 2017-08-05.
(define libvpx+experimental
  (package
    (inherit libvpx)
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "https://chromium.googlesource.com/webm/libvpx")
                    (commit "cbb83ba4aa99b40b0b4a2a407bfd6d0d8be87d1f")))
              (file-name "libvpx-for-chromium-checkout")
              (sha256
               (base32
                "1rj4ag0zg8c7cn4a9q75vslk5wc7vqy119k669286lxy8dvarh86"))))
    ;; TODO: Make libvpx configure flags overrideable.
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda* (#:key outputs #:allow-other-keys)
             (setenv "CONFIG_SHELL" (which "bash"))
             (let ((out (assoc-ref outputs "out")))
               (setenv "LDFLAGS"
                       (string-append "-Wl,-rpath=" out "/lib"))
               (zero? (system* "./configure"
                               "--enable-shared"
                               "--as=yasm"
                               ;; Limit size to avoid CVE-2015-1258
                               "--size-limit=16384x16384"
                               ;; Spatial SVC is an experimental VP9 encoder
                               ;; used by some packages (i.e. Chromium).
                               "--enable-experimental"
                               "--enable-spatial-svc"
                               (string-append "--prefix=" out)))))))
       #:tests? #f)))) ; No tests.

(define-public chromium
  (package
    (name "chromium")
    (version "60.0.3112.90")
    (synopsis "Graphical web browser")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://commondatastorage.googleapis.com/"
                                  "chromium-browser-official/chromium-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "1rirhwvccidza4q4z1gqdwcd9v1bymh1m9r2cq8jhiabfrjpjbxl"))
       (patches (search-patches
                 "chromium-gn-bootstrap.patch"
                 "chromium-system-nspr.patch"
                 "chromium-system-icu.patch"
                 "chromium-system-libevent.patch"
                 "chromium-system-libxml.patch"
                 "chromium-disable-api-keys-warning.patch"
                 "chromium-disable-third-party-cookies.patch"))
       (modules '((srfi srfi-1)
                  (guix build utils)))
       (snippet
        '(begin
            ;; Replace GN files from third_party with shims for building
            ;; against system libraries.  Keep this list in sync with
            ;; "build/linux/unbundle/replace_gn_files.py".
            (for-each (lambda (pair)
                        (let ((source (string-append
                                       "build/linux/unbundle/" (car pair)))
                              (dest (cdr pair)))
                          (copy-file source dest)))
                      (list
                       '("ffmpeg.gn" . "third_party/ffmpeg/BUILD.gn")
                       '("flac.gn" . "third_party/flac/BUILD.gn")
                       '("freetype.gn" . "third_party/freetype/BUILD.gn")
                       '("harfbuzz-ng.gn" . "third_party/harfbuzz-ng/BUILD.gn")
                       '("icu.gn" . "third_party/icu/BUILD.gn")
                       '("libdrm.gn" . "third_party/libdrm/BUILD.gn")
                       '("libevent.gn" . "base/third_party/libevent/BUILD.gn")
                       '("libjpeg.gn" .
                         "build/secondary/third_party/libjpeg_turbo/BUILD.gn")
                       '("libpng.gn" . "third_party/libpng/BUILD.gn")
                       '("libvpx.gn" . "third_party/libvpx/BUILD.gn")
                       '("libwebp.gn" . "third_party/libwebp/BUILD.gn")
                       '("libxml.gn" . "third_party/libxml/BUILD.gn")
                       '("libxslt.gn" . "third_party/libxslt/BUILD.gn")
                       '("openh264.gn" . "third_party/openh264/BUILD.gn")
                       '("opus.gn" . "third_party/opus/BUILD.gn")
                       '("re2.gn" . "third_party/re2/BUILD.gn")
                       '("snappy.gn" . "third_party/snappy/BUILD.gn")
                       '("yasm.gn" . "third_party/yasm/yasm_assemble.gni")
                       '("zlib.gn" . "third_party/zlib/BUILD.gn")))
            #t))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; How?
       ;; FIXME: There is a "gn" option specifically for setting -rpath, but
       ;; it's not recognized when passed.
       #:validate-runpath? #f
       #:modules ((srfi srfi-26)
                  (ice-9 ftw)
                  (ice-9 regex)
                  (guix build gnu-build-system)
                  (guix build utils))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'remove-bundled-software
           (lambda _
             (let ((keep-libs
                    (list
                     ;; Third party folders that cannot be deleted yet.
                     "base/third_party/dmg_fp"
                     "base/third_party/dynamic_annotations"
                     "base/third_party/icu"
                     "base/third_party/superfasthash"
                     "base/third_party/symbolize" ; glog
                     "base/third_party/xdg_mime"
                     "base/third_party/xdg_user_dirs"
                     "chrome/third_party/mozilla_security_manager"
                     "courgette/third_party"
                     "net/third_party/mozilla_security_manager"
                     "net/third_party/nss"
                     "third_party/adobe/flash/flapper_version.h"
                     ;; FIXME: This is used in:
                     ;; * ui/webui/resources/js/analytics.js
                     ;; * ui/file_manager/
                     "third_party/analytics"
                     "third_party/angle"
                     "third_party/angle/src/common/third_party/numerics"
                     "third_party/angle/src/third_party/compiler"
                     "third_party/angle/src/third_party/libXNVCtrl"
                     "third_party/angle/src/third_party/murmurhash"
                     "third_party/angle/src/third_party/trace_event"
                     "third_party/boringssl"
                     "third_party/brotli"
                     "third_party/cacheinvalidation"
                     "third_party/catapult"
                     "third_party/catapult/third_party/polymer"
                     "third_party/catapult/third_party/py_vulcanize"
                     "third_party/catapult/third_party/py_vulcanize/third_party/rcssmin"
                     "third_party/catapult/third_party/py_vulcanize/third_party/rjsmin"
                     "third_party/catapult/tracing/third_party/d3"
                     "third_party/catapult/tracing/third_party/gl-matrix"
                     "third_party/catapult/tracing/third_party/jszip"
                     "third_party/catapult/tracing/third_party/mannwhitneyu"
                     "third_party/catapult/tracing/third_party/oboe"
                     "third_party/ced"
                     "third_party/cld_3"
                     "third_party/cros_system_api"
                     "third_party/dom_distiller_js"
                     "third_party/fips181"
                     "third_party/flatbuffers"
                     ;; XXX Needed by pdfium since 59.
                     "third_party/freetype"
                     "third_party/glslang-angle"
                     "third_party/google_input_tools"
                     "third_party/google_input_tools/third_party/closure_library"
                     (string-append "third_party/google_input_tools/third_party"
                                    "/closure_library/third_party/closure")
                     "third_party/googletest"
                     "third_party/hunspell"
                     "third_party/iccjpeg"
                     "third_party/inspector_protocol"
                     "third_party/jinja2"
                     "third_party/jstemplate"
                     "third_party/khronos"
                     "third_party/leveldatabase"
                     "third_party/libXNVCtrl"
                     "third_party/libaddressinput"
                     "third_party/libjingle_xmpp"
                     "third_party/libphonenumber"
                     "third_party/libsecret"       ;FIXME: needs pkg-config support.
                     "third_party/libsrtp"         ;TODO: Requires libsrtp@2.
                     "third_party/libudev"
                     "third_party/libwebm"
                     "third_party/libxml/chromium"
                     "third_party/libyuv"
                     "third_party/lss"
                     "third_party/lzma_sdk"
                     "third_party/markupsafe"
                     "third_party/mesa"
                     "third_party/modp_b64"
                     "third_party/mt19937ar"
                     "third_party/node"
                     "third_party/node/node_modules/vulcanize/third_party/UglifyJS2"
                     "third_party/openmax_dl"
                     "third_party/ots"
                     "third_party/pdfium"         ;TODO: can be built standalone.
                     "third_party/pdfium/third_party"
                     "third_party/ply"
                     "third_party/polymer"
                     "third_party/protobuf"
                     "third_party/protobuf/third_party/six"
                     "third_party/qcms"
                     "third_party/sfntly"
                     "third_party/skia"
                     "third_party/skia/third_party/vulkan"
                     "third_party/smhasher"
                     ;; XXX the sources that include this are generated.
                     "third_party/speech-dispatcher"
                     "third_party/spirv-headers"
                     "third_party/spirv-tools-angle"
                     "third_party/sqlite"
                     "third_party/swiftshader"
                     "third_party/swiftshader/third_party"
                     "third_party/usb_ids"
                     "third_party/usrsctp"
                     "third_party/vulkan"
                     "third_party/vulkan-validation-layers"
                     "third_party/WebKit"
                     "third_party/web-animations-js"
                     "third_party/webrtc"
                     "third_party/widevine/cdm/widevine_cdm_version.h"
                     "third_party/widevine/cdm/widevine_cdm_common.h"
                     "third_party/woff2"
                     "third_party/xdg-utils"
                     "third_party/yasm/run_yasm.py"
                     "third_party/zlib/google"
                     "url/third_party/mozilla"
                     "v8/src/third_party/valgrind"
                     "v8/third_party/inspector_protocol")))
               ;; FIXME: implement as source snippet. This traverses
               ;; any "third_party" directory and deletes files that are:
               ;; * not ending with ".gn" or ".gni"; or
               ;; * not explicitly named as argument (folder or file).
               (zero? (apply system* "python"
                             "build/linux/unbundle/remove_bundled_libraries.py"
                             "--do-remove" keep-libs)))))
         (add-after 'remove-bundled-software 'patch-stuff
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "printing/cups_config_helper.py"
               (("cups_config =.*")
                (string-append "cups_config = '" (assoc-ref inputs "cups")
                               "/bin/cups-config'\n")))

             (substitute*
                 '("base/process/launch_posix.cc"
                   "base/tracked_objects.cc"
                   "base/third_party/dynamic_annotations/dynamic_annotations.c"
                   "sandbox/linux/seccomp-bpf/sandbox_bpf.cc"
                   "sandbox/linux/services/credentials.cc"
                   "sandbox/linux/services/namespace_utils.cc"
                   "sandbox/linux/services/syscall_wrappers.cc"
                   "sandbox/linux/syscall_broker/broker_host.cc")
               (("include \"base/third_party/valgrind/") "include \"valgrind/"))

             (for-each (lambda (file)
                         (substitute* file
                           ;; Fix opus include path.
                           ;; Do not substitute opus_private.h.
                           (("#include \"opus\\.h\"")
                            "#include \"opus/opus.h\"")
                           (("#include \"opus_custom\\.h\"")
                            "#include \"opus/opus_custom.h\"")
                           (("#include \"opus_defines\\.h\"")
                            "#include \"opus/opus_defines.h\"")
                           (("#include \"opus_multistream\\.h\"")
                            "#include \"opus/opus_multistream.h\"")
                           (("#include \"opus_types\\.h\"")
                            "#include \"opus/opus_types.h\"")))
                       (append (find-files "third_party/opus/src/celt")
                               (find-files "third_party/opus/src/src")
                               (find-files (string-append "third_party/webrtc/modules"
                                                          "/audio_coding/codecs/opus"))))

             (substitute* "chrome/common/chrome_paths.cc"
               (("/usr/share/chromium/extensions")
                ;; TODO: Add ~/.guix-profile.
                "/run/current-system/profile/share/chromium/extensions"))

             (substitute* "breakpad/src/common/linux/libcurl_wrapper.h"
               (("include \"third_party/curl") "include \"curl"))
             (substitute* "media/base/decode_capabilities.cc"
               (("third_party/libvpx/source/libvpx/") ""))
             #t))
         (replace 'configure
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let ((gn-flags
                    (list
                     ;; See tools/gn/docs/cookbook.md and
                     ;; https://www.chromium.org/developers/gn-build-configuration
                     ;; for usage. Run "./gn args . --list" in the Release
                     ;; directory for an exhaustive list of supported flags.
                     "is_debug=false"
                     "is_official_build=false"
                     "is_clang=false"
                     "use_gold=false"
                     "linux_use_bundled_binutils=false"
                     "use_sysroot=false"
                     "remove_webcore_debug_symbols=true"
                     "enable_iterator_debugging=false"
                     "override_build_date=\"01 01 2000 05:00:00\""
                     ;; Don't fail when using deprecated ffmpeg features.
                     "treat_warnings_as_errors=false"
                     "enable_nacl=false"
                     "enable_nacl_nonsfi=false"
                     "use_allocator=\"none\"" ; Don't use tcmalloc.
                     ;; Don't add any API keys. End users can set them in the
                     ;; environment if necessary.
                     ;; https://www.chromium.org/developers/how-tos/api-keys
                     "use_official_google_api_keys=false"
                     ;; Disable "field trials".
                     "fieldtrial_testing_like_official_build=true"

                     "use_system_libjpeg=true"
                     ;; This is currently not supported on Linux:
                     ;; https://bugs.chromium.org/p/chromium/issues/detail?id=22208
                     ;; "use_system_sqlite=true"
                     "use_gtk3=true"
                     "use_gconf=false"         ; deprecated by gsettings
                     "use_gnome_keyring=false" ; deprecated by libsecret
                     "use_xkbcommon=true"
                     "link_pulseaudio=true"
                     "use_openh264=true"

                     ;; Don't arbitrarily restrict formats supported by our ffmpeg.
                     "proprietary_codecs=true"
                     "ffmpeg_branding=\"Chrome\""

                     ;; WebRTC stuff.
                     "rtc_use_h264=true"
                     ;; Don't use bundled sources.
                     "rtc_build_json=false"
                     "rtc_build_libevent=false"
                     "rtc_build_libjpeg=false"
                     "rtc_build_libvpx=false"
                     "rtc_build_opus=false"
                     "rtc_build_ssl=false"
                     ;; TODO: Package these.
                     "rtc_build_libsrtp=true" ; 2.0
                     "rtc_build_libyuv=true"
                     "rtc_build_openmax_dl=true"
                     "rtc_build_usrsctp=true"
                     (string-append "rtc_jsoncpp_root=\""
                                    (assoc-ref inputs "jsoncpp")
                                    "/include/jsoncpp/json\"")
                     (string-append "rtc_ssl_root=\""
                                    (assoc-ref inputs "openssl")
                                    "/include/openssl\""))))

               ;; XXX: How portable is this.
               (mkdir-p "third_party/node/linux/node-linux-x64")
               (symlink (string-append (assoc-ref inputs "node") "/bin")
                        "third_party/node/linux/node-linux-x64/bin")

               (setenv "CC" "gcc")
               (setenv "CXX" "g++")
               ;; TODO: pre-compile instead. Avoids a race condition.
               (setenv "PYTHONDONTWRITEBYTECODE" "1")
               (and
                ;; Build the "gn" tool.
                (zero? (system* "python"
                                "tools/gn/bootstrap/bootstrap.py" "-s" "-v"))
                ;; Generate ninja build files.
                (zero? (system* "./out/Release/gn" "gen" "out/Release"
                                (string-append "--args="
                                               (string-join gn-flags " "))))))))
         (replace 'build
           (lambda* (#:key outputs #:allow-other-keys)
             (zero? (system* "ninja" "-C" "out/Release"
                             "-j" (number->string (parallel-job-count))
                             "chrome"))))
         (replace 'install
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out            (assoc-ref outputs "out"))
                    (bin            (string-append out "/bin"))
                    (exe            (string-append bin "/chromium"))
                    (lib            (string-append out "/lib"))
                    (man            (string-append out "/share/man/man1"))
                    (applications   (string-append out "/share/applications"))
                    (install-regexp (make-regexp "\\.(so|bin|pak)$"))
                    (locales        (string-append lib "/locales"))
                    (resources      (string-append lib "/resources"))
                    (gtk+           (assoc-ref inputs "gtk+"))
                    (mesa           (assoc-ref inputs "mesa"))
                    (nss            (assoc-ref inputs "nss"))
                    (udev           (assoc-ref inputs "udev"))
                    (sh             (which "sh")))

               (mkdir-p applications)
               (call-with-output-file (string-append applications
                                                     "/chromium.desktop")
                 (lambda (port)
                   (format port
                           "[Desktop Entry]~@
                           Name=Chromium~@
                           Comment=~a~@
                           Exec=~a~@
                           Icon=chromium.png~@
                           Type=Application~%" ,synopsis exe)))

               (with-directory-excursion "out/Release"
                 (for-each (lambda (file)
                             (install-file file lib))
                           (scandir "." (cut regexp-exec install-regexp <>)))
                 (copy-file "chrome" (string-append lib "/chromium"))

                 ;; TODO: Install icons from "../../chrome/app/themes" into
                 ;; "out/share/icons/hicolor/$size".
                 (install-file
                  "product_logo_48.png"
                  (string-append out "/share/icons/48x48/chromium.png"))

                 (copy-recursively "locales" locales)
                 (copy-recursively "resources" resources)

                 (mkdir-p man)
                 (copy-file "chrome.1" (string-append man "/chromium.1"))

                 (mkdir-p bin)
                 ;; Add a thin wrapper to prevent the user from inadvertently
                 ;; installing non-free software through the Web Store.
                 ;; TODO: Discover extensions from the profile and pass
                 ;; something like "--disable-extensions-except=...".
                 (call-with-output-file exe
                   (lambda (port)
                     (format port
                             "#!~a~@
                             CHROMIUM_FLAGS=\"--disable-background-networking\"~@
                             if [ -z \"$CHROMIUM_ENABLE_WEB_STORE\" ]~@
                             then~@
                                 CHROMIUM_FLAGS=\"$CHROMIUM_FLAGS --disable-extensions\"~@
                             fi~@
                             exec ~a $CHROMIUM_FLAGS \"$@\"~%"
                             sh (string-append lib "/chromium"))))
                 (chmod exe #o755)

                 (wrap-program exe
                   ;; TODO: Get these in RUNPATH.
                   `("LD_LIBRARY_PATH" ":" prefix
                     (,(string-append lib ":" nss "/lib/nss:" gtk+ "/lib:"
                                      mesa "/lib:" udev "/lib")))
                   ;; Avoid file manager crash. See <https://bugs.gnu.org/26593>.
                   `("XDG_DATA_DIRS" ":" prefix (,(string-append gtk+ "/share"))))
                #t)))))))
    (native-inputs
     `(("bison" ,bison)
       ("git" ,git) ; last_commit_position.py
       ("gperf" ,gperf)
       ("ninja" ,ninja)
       ("node" ,node)
       ("pkg-config" ,pkg-config)
       ("which" ,which)
       ("yasm" ,yasm)

       ;; Headers.
       ("curl" ,curl)
       ("valgrind" ,valgrind)

       ("python-beautifulsoup4" ,python2-beautifulsoup4)
       ("python-html5lib" ,python2-html5lib)
       ("python" ,python-2)))
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("atk" ,atk)
       ("cups" ,cups)
       ("dbus" ,dbus)
       ("dbus-glib" ,dbus-glib)
       ("udev" ,eudev)
       ("expat" ,expat)
       ("flac" ,flac)
       ("ffmpeg" ,ffmpeg)
       ("fontconfig" ,fontconfig)
       ("freetype" ,freetype)
       ("gdk-pixbuf" ,gdk-pixbuf)
       ("glib" ,glib)
       ("gtk+-2" ,gtk+-2)
       ("gtk+" ,gtk+)
       ("harfbuzz" ,harfbuzz)
       ("icu4c" ,icu4c)
       ("jsoncpp" ,jsoncpp)
       ("libevent" ,libevent)
       ("libffi" ,libffi)
       ("libjpeg-turbo" ,libjpeg-turbo)
       ("libpng" ,libpng)
       ("libusb" ,libusb)
       ("libvpx" ,libvpx+experimental)
       ("libwebp" ,libwebp)
       ("libx11" ,libx11)
       ("libxcb" ,libxcb)
       ("libxcomposite" ,libxcomposite)
       ("libxcursor" ,libxcursor)
       ("libxdamage" ,libxdamage)
       ("libxext" ,libxext)
       ("libxfixes" ,libxfixes)
       ("libxi" ,libxi)
       ("libxkbcommon" ,libxkbcommon)
       ("libxml2" ,libxml2)
       ("libxrandr" ,libxrandr)
       ("libxrender" ,libxrender)
       ("libxscrnsaver" ,libxscrnsaver)
       ("libxslt" ,libxslt)
       ("libxtst" ,libxtst)
       ("mesa" ,mesa)
       ("minizip" ,minizip)
       ("mit-krb5" ,mit-krb5)
       ("nss" ,nss)
       ("openh264" ,openh264)
       ("openssl" ,openssl)
       ("opus" ,opus+custom)
       ("pango" ,pango)
       ("pciutils" ,pciutils)
       ("protobuf" ,protobuf)
       ("pulseaudio" ,pulseaudio)
       ("re2" ,re2)
       ("snappy" ,snappy)
       ("speech-dispatcher" ,speech-dispatcher)
       ("sqlite" ,sqlite)))
    (home-page "https://www.chromium.org/")
    (description
     "Chromium is a web browser using the @code{Blink} rendering engine.")
    (license (list license:bsd-3
                   license:bsd-2
                   license:expat
                   license:lgpl2.0+))))
