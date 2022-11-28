;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2019, 2020, 2021, 2022 Marius Bakke <marius@gnu.org>
;;; Copyright © 2019 Alex Griffin <a@ajgrf.com>
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
  #:use-module (guix gexp)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (gnu packages)
  #:use-module (gnu packages assembly)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages build-tools)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages cups)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages fontutils)
  #:use-module (gnu packages freedesktop)
  #:use-module (gnu packages ghostscript)
  #:use-module (gnu packages gl)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages gnome)
  #:use-module (gnu packages gperf)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages image)
  #:use-module (gnu packages libevent)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages llvm)
  #:use-module (gnu packages kerberos)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages ninja)
  #:use-module (gnu packages node)
  #:use-module (gnu packages nss)
  #:use-module (gnu packages pciutils)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages protobuf)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages python)
  #:use-module (gnu packages python-web)
  #:use-module (gnu packages python-xyz)
  #:use-module (gnu packages qt)
  #:use-module (gnu packages regex)
  #:use-module (gnu packages serialization)
  #:use-module (gnu packages speech)
  #:use-module (gnu packages valgrind)
  #:use-module (gnu packages vulkan)
  #:use-module (gnu packages video)
  #:use-module (gnu packages xiph)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xorg)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-1))

(define %preserved-third-party-files
  '("base/third_party/cityhash" ;Expat
    "base/third_party/double_conversion" ;BSD-3
    "base/third_party/dynamic_annotations" ;BSD-2
    "base/third_party/icu" ;Unicode, X11-style
    "base/third_party/superfasthash" ;BSD-3
    "base/third_party/symbolize" ;BSD-3
    "base/third_party/xdg_mime" ;LGPL2.0+ or Academic 2.0
    "base/third_party/xdg_user_dirs" ;Expat
    "chrome/third_party/mozilla_security_manager" ;MPL-1.1/GPL2+/LGPL2.1+
    "courgette/third_party/bsdiff" ;BSD-2, BSD protection license
    "courgette/third_party/divsufsort" ;Expat
    "net/third_party/mozilla_security_manager" ;MPL-1.1/GPL2+/LGPL2.1+
    "net/third_party/nss" ;MPL-2.0
    "net/third_party/quiche" ;BSD-3
    "net/third_party/uri_template" ;ASL2.0
    "third_party/abseil-cpp" ;ASL2.0
    "third_party/angle" ;BSD-3
    "third_party/angle/src/common/third_party/base" ;BSD-3
    "third_party/angle/src/common/third_party/smhasher" ;Public domain
    "third_party/angle/src/common/third_party/xxhash" ;BSD-2
    "third_party/angle/src/third_party/libXNVCtrl" ;Expat
    "third_party/angle/src/third_party/trace_event" ;BSD-3
    "third_party/angle/src/third_party/volk" ;Expat
    "third_party/apple_apsl" ;APSL2.0
    "third_party/axe-core" ;MPL2.0
    "third_party/bidimapper" ;ASL2.0
    "third_party/blink" ;BSD-3, LGPL2+
    "third_party/boringssl" ;OpenSSL/ISC (Google additions are ISC)
    "third_party/boringssl/src/third_party/fiat" ;Expat
    "third_party/breakpad" ;BSD-3
    "third_party/brotli" ;Expat
    "third_party/catapult" ;BSD-3
    "third_party/catapult/common/py_vulcanize/third_party/rcssmin" ;ASL2.0
    "third_party/catapult/common/py_vulcanize/third_party/rjsmin" ;ASL2.0
    "third_party/catapult/third_party/polymer" ;BSD-3
    "third_party/catapult/third_party/six" ;Expat
    ;; XXX: This is a minified version of <https://d3js.org/>.
    "third_party/catapult/tracing/third_party/d3" ;BSD-3
    "third_party/catapult/tracing/third_party/gl-matrix" ;Expat
    "third_party/catapult/tracing/third_party/jpeg-js" ;ASL2.0
    ;; XXX: Minified version of <https://github.com/Stuk/jszip>.
    "third_party/catapult/tracing/third_party/jszip" ;Expat or GPL3
    "third_party/catapult/tracing/third_party/mannwhitneyu" ;Expat
    "third_party/catapult/tracing/third_party/oboe" ;BSD-2
    ;; XXX: Minified version of <https://github.com/nodeca/pako>.
    "third_party/catapult/tracing/third_party/pako" ;Expat
    "third_party/ced" ;BSD-3
    "third_party/cld_3" ;ASL2.0
    "third_party/closure_compiler" ;ASL2.0
    "third_party/content_analysis_sdk" ;BSD-3
    "third_party/cpuinfo" ;BSD-2
    "third_party/crashpad" ;ASL2.0
    "third_party/crashpad/crashpad/third_party/lss" ;ASL2.0
    "third_party/crashpad/crashpad/third_party/zlib/zlib_crashpad.h" ;Zlib
    "third_party/crc32c" ;BSD-3
    "third_party/cros_system_api" ;BSD-3
    "third_party/dav1d" ;BSD-2
    "third_party/dawn" ;ASL2.0
    ;; TODO: can likely be unbundled when Vulkan is updated.
    "third_party/dawn/third_party/khronos" ;ASL2.0
    "third_party/dawn/third_party/gn/webgpu-cts" ;BSD-3
    "third_party/devtools-frontend" ;BSD-3
    "third_party/devtools-frontend/src/front_end/third_party/acorn" ;Expat
    "third_party/devtools-frontend/src/front_end/third_party\
/additional_readme_paths.json" ;no explicit license; trivial
    "third_party/devtools-frontend/src/front_end/third_party/axe-core" ;MPL2.0
    "third_party/devtools-frontend/src/front_end/third_party/chromium" ;BSD-3
    "third_party/devtools-frontend/src/front_end/third_party/codemirror" ;Expat
    "third_party/devtools-frontend/src/front_end/third_party/diff" ;ASL2.0
    "third_party/devtools-frontend/src/front_end/third_party/i18n" ;ASL2.0
    "third_party/devtools-frontend/src/front_end/third_party/intl-messageformat" ;BSD-3
    "third_party/devtools-frontend/src/front_end/third_party/lighthouse" ;ASL2.0
    "third_party/devtools-frontend/src/front_end/third_party/lit-html" ;BSD-3
    "third_party/devtools-frontend/src/front_end/third_party/lodash-isequal" ;Expat
    "third_party/devtools-frontend/src/front_end/third_party/marked" ;Expat, BSD-3
    "third_party/devtools-frontend/src/front_end/third_party/puppeteer" ;ASL2.0
    "third_party/devtools-frontend/src/front_end/third_party/wasmparser" ;ASL2.0
    "third_party/devtools-frontend/src/third_party/pyjson5" ;ASL2.0
    "third_party/devtools-frontend/src/third_party/typescript" ;ASL2.0
    "third_party/distributed_point_functions" ;ASL2.0
    "third_party/dom_distiller_js" ;BSD-3
    "third_party/eigen3" ;MPL2.0
    "third_party/emoji-segmenter" ;ASL2.0
    "third_party/farmhash" ;Expat
    "third_party/fdlibm" ;non-copyleft
    "third_party/fft2d" ;non-copyleft
    "third_party/flatbuffers" ;ASL2.0
    "third_party/fusejs" ;ASL2.0
    "third_party/gemmlowp" ;ASL2.0
    "third_party/google_input_tools" ;ASL2.0
    "third_party/google_input_tools/third_party/closure_library" ;ASL2.0
    "third_party/google_input_tools/third_party/closure_library/third_party/closure" ;Expat
    "third_party/googletest" ;BSD-3
    "third_party/harfbuzz-ng" ;Expat
    "third_party/highway" ;ASL2.0
    "third_party/hunspell" ;MPL1.1/GPL2+/LGPL2.1+
    "third_party/iccjpeg" ;IJG
    "third_party/inspector_protocol" ;BSD-3
    "third_party/ipcz" ;BSD-3
    "third_party/jinja2" ;BSD-3
    "third_party/jstemplate" ;ASL2.0
    "third_party/khronos" ;Expat, SGI
    "third_party/leveldatabase" ;BSD-3
    "third_party/libavif" ;BSD-2
    "third_party/libaddressinput" ;ASL2.0
    "third_party/libaom" ;BSD-2 or "Alliance for Open Media Patent License 1.0"
    "third_party/libaom/source/libaom/third_party/fastfeat" ;BSD-3
    "third_party/libaom/source/libaom/third_party/SVT-AV1" ;BSD-3
    "third_party/libaom/source/libaom/third_party/vector" ;Expat
    "third_party/libaom/source/libaom/third_party/x86inc" ;ISC
    "third_party/libjxl" ;ASL2.0
    "third_party/libgav1" ;ASL2.0
    "third_party/libjingle_xmpp" ;BSD-3
    "third_party/libphonenumber" ;ASL2.0
    "third_party/libsecret" ;LGPL2.1+
    "third_party/libsrtp" ;BSD-3
    "third_party/libsync" ;ASL2.0
    "third_party/libudev" ;LGPL2.1+
    "third_party/liburlpattern" ;Expat
    "third_party/libva_protected_content" ;Expat

    ;; FIXME: build/linux/unbundle/libvpx.gn does not work for all users.
    "third_party/libvpx" ;BSD-3
    "third_party/libvpx/source/libvpx/third_party/x86inc" ;Expat

    "third_party/libwebm" ;BSD-3
    "third_party/libxml/chromium" ;BSD-3
    "third_party/libyuv" ;BSD-3
    "third_party/libzip" ;BSD-3
    "third_party/lottie" ;Expat
    "third_party/lss" ;BSD-3
    "third_party/mako" ;Expat
    "third_party/markupsafe" ;BSD-3
    "third_party/mesa_headers" ;Expat, SGI
    "third_party/metrics_proto" ;BSD-3
    "third_party/minigbm" ;BSD-3
    "third_party/modp_b64" ;BSD-3
    "third_party/nasm" ;BSD-2
    "third_party/nearby" ;ASL2.0
    "third_party/node" ;Expat
    "third_party/omnibox_proto" ;BSD-3
    "third_party/one_euro_filter" ;BSD-3
    "third_party/openscreen" ;BSD-3
    "third_party/openscreen/src/third_party/tinycbor" ;Expat
    "third_party/openscreen/src/third_party/mozilla" ;MPL1.1/GPL2+/LGPL2.1+, BSD-3
    "third_party/ots" ;BSD-3
    "third_party/pdfium" ;BSD-3
    "third_party/pdfium/third_party/agg23" ;Expat
    "third_party/pdfium/third_party/base" ;BSD-3
    "third_party/pdfium/third_party/bigint" ;Public domain, BSD-3
    "third_party/pdfium/third_party/libtiff" ;non-copyleft
    "third_party/pdfium/third_party/skia_shared" ;BSD-3
    "third_party/pdfium/third_party/freetype/include/pstables.h" ;FreeType
    "third_party/perfetto" ;ASL2.0
    "third_party/perfetto/protos/third_party/chromium" ;BSD-3
    "third_party/pffft" ;the "FFTPACK" license
    "third_party/ply" ;BSD-3
    "third_party/polymer" ;BSD-3
    "third_party/private_membership" ;ASL2.0
    "third_party/private-join-and-compute" ;ASL2.0
    "third_party/protobuf" ;BSD-3
    "third_party/protobuf/third_party/six" ;Expat
    "third_party/pthreadpool" ;BSD-2
    "third_party/pyjson5" ;ASL2.0
    "third_party/qcms" ;Expat
    "third_party/rnnoise" ;BSD-3
    "third_party/ruy" ;ASL2.0
    "third_party/s2cellid" ;ASL2.0
    "third_party/securemessage" ;ASL2.0
    "third_party/shell-encryption" ;ASL2.0
    "third_party/skia" ;BSD-3
    "third_party/skia/third_party/vulkanmemoryallocator" ;BSD-3, Expat
    "third_party/smhasher" ;Expat, public domain

    ;; FIXME: the snappy "replacement" shim (see replace_gn_files.py below) does
    ;; not declare a library dependency added in M93, causing a link failure.
    "third_party/snappy" ;BSD-3

    "third_party/speech-dispatcher" ;GPL2+
    "third_party/sqlite" ;Public domain
    "third_party/swiftshader" ;ASL2.0
    "third_party/swiftshader/third_party/astc-encoder" ;ASL2.0
    "third_party/swiftshader/third_party/llvm-10.0" ;ASL2.0, with LLVM exception
    "third_party/swiftshader/third_party/llvm-subzero" ;NCSA
    "third_party/swiftshader/third_party/marl" ;ASL2.0
    "third_party/swiftshader/third_party/subzero" ;NCSA
    "third_party/swiftshader/third_party/SPIRV-Headers" ;X11-style
    "third_party/swiftshader/third_party/SPIRV-Tools" ;ASL2.0
    "third_party/tensorflow-text" ;ASL2.0
    "third_party/tflite" ;ASL2.0
    "third_party/tflite/src/third_party/eigen3" ;MPL2.0
    "third_party/tflite/src/third_party/fft2d" ;ASL2.0
    "third_party/ukey2" ;ASL2.0
    "third_party/usb_ids" ;BSD-3
    "third_party/utf" ;Expat
    "third_party/vulkan-deps" ;ASL2.0, BSD-3, Expat
    "third_party/vulkan_memory_allocator" ;Expat
    "third_party/wayland/src/protocol" ;Expat
    "third_party/wayland/stubs" ;BSD-3, Expat
    "third_party/wayland/wayland_scanner_wrapper.py" ;BSD-3
    "third_party/wayland-protocols" ;Expat
    "third_party/web-animations-js" ;ASL2.0
    "third_party/webdriver" ;ASL2.0
    "third_party/webgpu-cts" ;BSD-3
    "third_party/webrtc" ;BSD-3
    "third_party/webrtc/common_audio/third_party/ooura" ;Non-copyleft
    "third_party/webrtc/common_audio/third_party/spl_sqrt_floor" ;Public domain
    "third_party/webrtc/modules/third_party/fft" ;Non-copyleft
    "third_party/webrtc/modules/third_party/g711" ;Public domain
    "third_party/webrtc/modules/third_party/g722" ;Public domain
    "third_party/webrtc/rtc_base/third_party/base64" ;Non-copyleft
    "third_party/webrtc/rtc_base/third_party/sigslot" ;Public domain
    "third_party/widevine/cdm/widevine_cdm_version.h" ;BSD-3
    "third_party/widevine/cdm/widevine_cdm_common.h" ;BSD-3
    "third_party/woff2" ;ASL2.0
    "third_party/wuffs" ;ASL2.0
    "third_party/xcbproto" ;X11
    "third_party/xdg-utils" ;Expat
    "third_party/xnnpack" ;BSD-3

    ;; These are forked components of the X11 keybinding code.
    "third_party/libxcb-keysyms" ;X11
    "third_party/libx11/src/KeyBind.c" ;X11
    "third_party/libx11/src/xkb/XKBBind.c" ;X11
    "third_party/x11proto/keysymdef.h" ;X11

    "third_party/zlib/google" ;BSD-3
    "third_party/zxcvbn-cpp" ;Expat
    "url/third_party/mozilla" ;BSD-3, MPL1.1/GPL2+/LGPL2.1+
    "v8/src/third_party/siphash" ;Public domain
    "v8/src/third_party/utf8-decoder" ;Expat
    "v8/src/third_party/valgrind" ;BSD-4
    "v8/third_party/inspector_protocol" ;BSD-3
    "v8/third_party/v8/builtins")) ;PSFL

(define %blacklisted-files
  ;; 'third_party/blink/perf_tests/resources/svg/HarveyRayner.svg' carries a
  ;; nonfree license according to LICENSES in the same directory.  As we don't
  ;; run the Blink performance tests, just remove everything to save ~70MiB.
  '("third_party/blink/perf_tests"))

(define %chromium-version "108.0.5359.98")
(define %ungoogled-revision (string-append %chromium-version "-1"))
(define %debian-revision "debian/102.0.5005.61-1")
(define %arch-revision "4de5019014aeb77187a517c5ca6db8723d622a40")

(define %ungoogled-origin
  (origin
    (method git-fetch)
    (uri (git-reference (url "https://github.com/Eloston/ungoogled-chromium")
                        (commit %ungoogled-revision)))
    (file-name (git-file-name "ungoogled-chromium" %ungoogled-revision))
    (sha256
     (base32
      "16rc15qsndrsj52p56ma3hg94jslkfy2f91ryr3qss73r2rkjf8j"))))

(define %debian-origin
  (origin
    (method git-fetch)
    (uri (git-reference
          (url "https://salsa.debian.org/chromium-team/chromium.git")
          (commit %debian-revision)))
    (file-name (git-file-name "debian-chromium-patches"
                              (match (string-split %debian-revision #\/)
                                ((_ version) version))))
    (sha256
     (base32
      "1ln6r1qzlr7dsgvcbssvvc34my4mpkwv9hmvlb2dhjncs7isp65j"))))

(define (origin-file origin file)
  (computed-file
   (basename file)
   #~(symlink (string-append #$origin "/" #$file)
              #$output)))

(define (debian-patch name)
  (origin-file %debian-origin (string-append "/debian/patches/" name)))

(define %debian-patches
  (map debian-patch
       '("system/jsoncpp.patch"
         "system/zlib.patch"
         "system/openjpeg.patch")))

(define %arch-patches
  '())

(define %gcc-patches
  '())

(define %reverse-patches
  '())

(define %guix-patches
  (list (local-file
         (assume-valid-file-name
          (search-patch "ungoogled-chromium-extension-search-path.patch")))
        (local-file
         (assume-valid-file-name
          (search-patch "ungoogled-chromium-RUNPATH.patch")))
        (local-file
         (assume-valid-file-name
          (search-patch "ungoogled-chromium-system-ffmpeg.patch")))
        (local-file
         (assume-valid-file-name
          (search-patch "ungoogled-chromium-system-nspr.patch")))))

(define %patches
  (append %debian-patches %arch-patches %guix-patches))

;; This is a source 'snippet' that does the following:
;; *) Applies various patches for unbundling purposes and libstdc++ compatibility.
;; *) Runs the ungoogled patch-, domain substitution-, and scrubbing scripts.
;; *) Prunes all third_party directories that are not explicitly preserved.
;; *) Adjusts "GN" build files such that system libraries are preferred.
(define ungoogled-chromium-snippet
  ;; Note: delay to cope with cyclic module imports at the top level.
  (delay
    #~(begin
        (let ((chromium-dir (getcwd)))
          (set-path-environment-variable
           "PATH" '("bin")
           (list #+patch #+python-wrapper #+xz))

          ;; Apply patches before running the ungoogled scripts because
          ;; domain substitution may break some of the patches.
          (format #t "Applying assorted build fixes...~%")
          (force-output)
          (for-each (lambda (patch)
                      (invoke "patch" "-p1" "--force" "--input"
                              patch "--no-backup-if-mismatch"))
                    '#+%patches)

          ;; These patches are "reversed", i.e. their changes should be undone.
          (for-each (lambda (patch)
                      (invoke "patch" "-Rp1" "-F3" "--force" "--input"
                              patch "--no-backup-if-mismatch"))
                    '#+%reverse-patches)

          (with-directory-excursion #+%ungoogled-origin
            (format #t "Ungooglifying...~%")
            (force-output)
            (invoke "python" "utils/prune_binaries.py" chromium-dir
                    "pruning.list")
            (invoke "python" "utils/patches.py" "apply" chromium-dir
                    "patches")
            (invoke "python" "utils/domain_substitution.py" "apply" "-r"
                    "domain_regex.list" "-f" "domain_substitution.list"
                    "-c" "/tmp/domainscache.tar.gz" chromium-dir))

          ;; Run after the ungoogled scripts to avoid interfering with
          ;; patches or file lists.
          (format #t "Removing blacklisted files...~%")
          (force-output)
          (for-each delete-file-recursively '#$%blacklisted-files)

          (format #t "Pruning third party files...~%")
          (force-output)
          (apply invoke "python"
                 "build/linux/unbundle/remove_bundled_libraries.py"
                 "--do-remove" '#$%preserved-third-party-files)

          (format #t "Replacing GN files...~%")
          (force-output)
          (substitute* "tools/generate_shim_headers/generate_shim_headers.py"
            ;; The "is_official_build" configure option enables certain
            ;; release optimizations like those used in the commercial
            ;; Chrome browser.  Unfortunately it also requires using the
            ;; bundled libraries: lose that restriction.
            (("#if defined\\(OFFICIAL_BUILD\\)")
             "#if 0"))
          (invoke "python" "build/linux/unbundle/replace_gn_files.py"
                  "--system-libraries" "ffmpeg" "flac" "fontconfig"
                  "freetype" "harfbuzz-ng" "icu" "libdrm" "libevent"
                  "libjpeg" "libpng" "libwebp" "libxml" "libxslt"
                  "openh264" "opus" "re2" "zlib")))))

(define opus+custom
  (package/inherit opus
    (name "opus+custom")
    (arguments
     (substitute-keyword-arguments (package-arguments opus)
       ((#:configure-flags flags ''())
        ;; Opus Custom is an optional extension of the Opus
        ;; specification that allows for unsupported frame
        ;; sizes.  Chromium requires that this is enabled.
        `(cons "--enable-custom-modes"
               ,flags))))))

(define-public ungoogled-chromium
  (package
    (name "ungoogled-chromium")
    (version %ungoogled-revision)
    (synopsis "Graphical web browser")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://commondatastorage.googleapis.com"
                                  "/chromium-browser-official/chromium-"
                                  %chromium-version ".tar.xz"))
              (sha256
               (base32
                "07jnhd5y7k4zp2ipz052isw7llagxn8l8rbz8x3jkjz3f5wi7dk0"))
              (modules '((guix build utils)))
              (snippet (force ungoogled-chromium-snippet))))
    (build-system gnu-build-system)
    (arguments
     (list
      #:tests? #f
      #:modules '((guix build gnu-build-system)
                  (guix build utils)
                  (srfi srfi-26))
      #:configure-flags
      ;; See tools/gn/docs/cookbook.md and
      ;; https://www.chromium.org/developers/gn-build-configuration
      ;; for usage.  Run "gn args . --list" in the Release
      ;; directory for an exhaustive list of supported flags.
      ;; (Note: The 'configure' phase will do that for you.)
      #~(list "is_debug=false"
              ;; Use the "official" release optimizations, as opposed to
              ;; a developer build.
              "is_official_build=true"
              "clang_use_chrome_plugins=false"
              "use_custom_libcxx=false"
              "chrome_pgo_phase=0"
              "use_sysroot=false"
              "goma_dir=\"\""
              "enable_nacl=false"
              "use_unofficial_version_number=false"
              "treat_warnings_as_errors=false"
              "use_official_google_api_keys=false"
              "disable_fieldtrial_testing_config=true"
              "safe_browsing_mode=0"
              "enable_mdns=false"
              "enable_reading_list=false"
              "enable_remoting=false"
              "enable_reporting=false"
              "enable_service_discovery=false"
              "enable_vr=false"
              "enable_widevine=false"
              ;; Disable type-checking for the Web UI to avoid a Java dependency.
              "enable_js_type_check=false"
              ;; Disable code using TensorFlow until it has been scrutinized
              ;; by the ungoogled project.
              "build_with_tflite_lib=false"
              ;; Avoid dependency on code formatting tools.
              "blink_enable_generated_code_formatting=false"
              ;; Don't bother building Dawn tests.
              "build_dawn_tests=false"

              ;; Define a custom toolchain that simply looks up CC, AR and
              ;; friends from the environment.
              "custom_toolchain=\"//build/toolchain/linux/unbundle:default\""
              "host_toolchain=\"//build/toolchain/linux/unbundle:default\""

              (string-append "clang_base_path=\""
                             (dirname (dirname (search-input-file %build-inputs
                                                                  "/bin/clang")))
                             "\"")

              ;; Prefer system libraries.
              "use_system_freetype=true"
              "use_system_harfbuzz=true"
              "use_system_lcms2=true"
              "use_system_libdrm=true"
              "use_system_libjpeg=true"
              "use_system_libopenjpeg2=true"
              "use_system_libpng=true"
              "use_system_libwayland=true"
              "use_system_wayland_scanner=true"
              (string-append "system_wayland_scanner_path=\""
                             (search-input-file %build-inputs
                                                "/bin/wayland-scanner")
                             "\"")

              "use_system_zlib=true"
              "use_gnome_keyring=false" ;deprecated by libsecret
              "use_pulseaudio=true"
              "link_pulseaudio=true"
              "icu_use_data_file=false"

              ;; FIXME: Using system protobuf with "is_official_build" causes an
              ;; invalid opcode and "protoc-gen-plugin: Plugin killed by signal 4".
              ;;"perfetto_use_system_protobuf=true"

              ;; VA-API acceleration is currently only supported on x86_64-linux.
              #$@(if (string-prefix? "x86_64" (or (%current-target-system)
                                                  (%current-system)))
                     '("use_vaapi=true")
                     '())

              "media_use_ffmpeg=true"
              "media_use_libvpx=true"
              "media_use_openh264=true"

              ;; Do not artifically restrict formats supported by system ffmpeg.
              "proprietary_codecs=true"
              "ffmpeg_branding=\"Chrome\""

              ;; WebRTC stuff.
              "rtc_use_h264=true"
              "rtc_use_pipewire=true"
              "rtc_link_pipewire=true"
              ;; Don't use bundled sources.
              "rtc_build_json=false"
              (string-append "rtc_jsoncpp_root=\""
                             (search-input-directory %build-inputs
                                                     "include/json")
                             "\"")
              "rtc_build_libevent=false"
              ;; XXX: Use the bundled libvpx for WebRTC because unbundling
              ;; currently fails (see above), and the versions must match.
              "rtc_build_libvpx=true"
              "rtc_build_opus=false"
              "rtc_build_libsrtp=true"  ;FIXME: fails to find headers
              "rtc_build_ssl=true")     ;XXX: requires BoringSSL
      #:phases
      #~(modify-phases %standard-phases
          (add-after 'unpack 'patch-stuff
            (lambda* (#:key inputs #:allow-other-keys)
              (let* ((libopenjp2 (search-input-file inputs "lib/libopenjp2.so"))
                     (openjpeg (dirname (dirname libopenjp2))))
                (substitute* "third_party/pdfium/BUILD.gn"
                  ;; This include path is added by Debians openjpeg patch.
                  (("/usr/include/openjpeg-")
                   (string-append openjpeg "/include/openjpeg-")))

                ;; Adjust minizip header inclusions.
                (substitute* (find-files "third_party/tflite_support\
/src/tensorflow_lite_support/metadata/cc")
                  (("#include \"contrib/minizip/ioapi\\.h\"")
                   ;; This one can be removed for M108 or so.
                   "#include \"minizip/ioapi.h\"")
                  (("third_party/zlib/contrib/minizip/")
                   "minizip/"))

                (substitute*
                    '("base/process/launch_posix.cc"
                      "base/third_party/dynamic_annotations/dynamic_annotations.c"
                      "sandbox/linux/seccomp-bpf/sandbox_bpf.cc"
                      "sandbox/linux/services/credentials.cc"
                      "sandbox/linux/services/namespace_utils.cc"
                      "sandbox/linux/services/syscall_wrappers.cc"
                      "sandbox/linux/syscall_broker/broker_host.cc")
                  (("include \"base/third_party/valgrind/") "include \"valgrind/"))

                (substitute*
                    (append
                     '("media/audio/audio_opus_encoder.h")
                     (find-files (string-append "third_party/webrtc/modules"
                                                "/audio_coding/codecs/opus")))
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
                   "#include \"opus/opus_types.h\"")
                  (("\"third_party/opus/src/include/([a-z_-]+\\.h)\"" _ header)
                   (string-append "<opus/" header ">")))

                (substitute* "third_party/webrtc/rtc_base/strings/json.h"
                  (("#include \"third_party/jsoncpp/")
                   "#include \"json/"))

                ;; Many files try to include ICU headers from "third_party/icu/...".
                ;; Remove the "third_party/" prefix to use system headers instead.
                (substitute* (find-files "chrome" "\\.cc$")
                  (("third_party/icu/source/(common|i18n)/")
                   ""))

                ;; XXX: Should be unnecessary when use_system_lcms2=true.
                (substitute* "third_party/pdfium/core/fxcodec/icc/icc_transform.h"
                  (("include \"third_party/lcms/include/lcms2\\.h\"")
                   "include \"lcms2.h\""))

                (substitute*
                    "third_party/breakpad/breakpad/src/common/linux/libcurl_wrapper.h"
                  (("include \"third_party/curl")
                   "include \"curl"))

                (substitute* '("components/viz/common/gpu/vulkan_context_provider.h"
                               "components/viz/common/resources/resource_format_utils.h"
                               "gpu/config/gpu_util.cc")
                  (("third_party/vulkan_headers/include/") ""))

                (substitute* "third_party/skia/include/private/gpu/vk/SkiaVulkan.h"
                  (("include/third_party/vulkan/") "")))))
          (add-after 'patch-stuff 'add-absolute-references
            (lambda* (#:key inputs #:allow-other-keys)
              (let ((cups-config (search-input-file inputs "/bin/cups-config"))
                    (libnssckbi.so (search-input-file inputs
                                                      "/lib/nss/libnssckbi.so"))
                    (libudev.so.1 (search-input-file inputs "/lib/libudev.so.1"))
                    (libvulkan.so.1 (search-input-file inputs
                                                       "/lib/libvulkan.so.1"))
                    (icd.d (search-input-directory inputs "share/vulkan/icd.d"))
                    (mesa-lib (dirname (search-input-file inputs
                                                          "/lib/libGL.so.1")))
                    (gtk-libs '("libgio-2.0.so.0"
                                "libgdk_pixbuf-2.0.so.0"
                                "libgdk-3.so.0"
                                "libgtk-3.so.0")))
                (for-each (lambda (lib)
                            (substitute* "ui/gtk/gtk_compat.cc"
                              ((lib) (search-input-file
                                      inputs (string-append "lib/" lib)))))
                          gtk-libs)
                (substitute* "printing/cups_config_helper.py"
                  (("cups_config =.*")
                   (string-append "cups_config = '" cups-config "'\n")))
                (substitute* "crypto/nss_util.cc"
                  (("libnssckbi\\.so") libnssckbi.so))
                (substitute* "device/udev_linux/udev1_loader.cc"
                  (("libudev\\.so\\.1") libudev.so.1))

                ;; Patch libvulkan.so everywhere.
                (substitute*
                    '("third_party/swiftshader/include/vulkan/vulkan.hpp"
                      "third_party/vulkan-deps/vulkan-tools\
/src/vulkaninfo/vulkaninfo.h"
                      "third_party/vulkan-deps/vulkan-headers\
/src/include/vulkan/vulkan.hpp"
                      "content/gpu/gpu_sandbox_hook_linux.cc"
                      "ui/ozone/platform/wayland/gpu/vulkan_implementation_wayland.cc"
                      "ui/ozone/platform/drm/gpu/vulkan_implementation_gbm.cc"
                      "ui/ozone/platform/x11/vulkan_implementation_x11.cc"
                      "third_party/skia/tools/sk_app/unix\
/DawnVulkanWindowContext_unix.cpp")
                  (("libvulkan\\.so\\.1") libvulkan.so.1))
                (substitute* "content/gpu/gpu_sandbox_hook_linux.cc"
                  (("/usr/share/vulkan/icd\\.d") icd.d))

                ;; Add the libvulkan directory to dawn built-in search paths.
                (substitute* "third_party/dawn/src/dawn/native/Instance.cpp"
                  (("^([[:blank:]]+)mRuntimeSearchPaths\\.push_back\\(\"\"\\);"
                    all indent)
                   (string-append indent "mRuntimeSearchPaths.push_back(\""
                                  (dirname libvulkan.so.1) "/\");\n" all)))

                (substitute*
                    '("ui/ozone/platform/x11/gl_ozone_glx.cc"
                      "ui/ozone/common/egl_util.cc"
                      "third_party/angle/src/libANGLE/renderer/gl/glx\
/FunctionsGLX.cpp")
                  (("libGL\\.so\\.1")
                   (string-append mesa-lib "/libGL.so.1"))
                  (("libEGL\\.so\\.1")
                   (string-append mesa-lib "/libEGL.so.1"))
                  (("libGLESv2\\.so\\.2")
                   (string-append mesa-lib "/libGLESv2.so.2"))))))
          (add-before 'configure 'prepare-build-environment
            (lambda* (#:key native-inputs inputs #:allow-other-keys)
              (let ((c++ (search-input-directory (or native-inputs inputs)
                                                 "include/c++"))
                    (node (search-input-file (or native-inputs inputs)
                                             "/bin/node")))
                ;; Define the GN toolchain.
                (setenv "AR" "llvm-ar") (setenv "NM" "llvm-nm")
                (setenv "CC" "clang") (setenv "CXX" "clang++")

                ;; TODO: pre-compile instead. Avoids a race condition.
                (setenv "PYTHONDONTWRITEBYTECODE" "1")

                ;; XXX: How portable is this.
                (mkdir-p "third_party/node/linux/node-linux-x64")
                (symlink (dirname node)
                         "third_party/node/linux/node-linux-x64/bin"))))
          (replace 'configure
            (lambda* (#:key configure-flags #:allow-other-keys)
              (let ((args (string-join configure-flags " ")))
                ;; Generate ninja build files.
                (invoke "gn" "gen" "out/Release"
                        (string-append "--args=" args))

                ;; Print the full list of supported arguments as well as
                ;; their current status for convenience.
                (format #t "Dumping configure flags...\n")
                (invoke "gn" "args" "out/Release" "--list"))))
          (add-before 'build 'increase-resource-limits
            (lambda _
              ;; XXX: Chromiums linking step requires a lot of simultaneous file
              ;; accesses.  Having a too low ulimit will result in bogus linker
              ;; errors such as "foo.a: error adding symbols: malformed archive".

              ;; Try increasing the soft resource limit of max open files to 2048,
              ;; or equal to the hard limit, whichever is lower.
              (call-with-values (lambda () (getrlimit 'nofile))
                (lambda (soft hard)
                  (when (and soft (< soft 2048))
                    (if hard
                        (setrlimit 'nofile (min hard 2048) hard)
                        (setrlimit 'nofile 2048 #f))
                    (format #t
                            "increased maximum number of open files from ~d to ~d~%"
                            soft (if hard (min hard 2048) 2048)))))))
          (replace 'build
            (lambda* (#:key (parallel-build? #t) #:allow-other-keys)
              (invoke "ninja" "-C" "out/Release"
                      "-j" (if parallel-build?
                               (number->string (parallel-job-count))
                               "1")
                      "chrome"
                      "chromedriver")))
          (replace 'install
            (lambda* (#:key inputs outputs #:allow-other-keys)
              (let* ((out            (assoc-ref outputs "out"))
                     (bin            (string-append out "/bin"))
                     (exe            (string-append bin "/chromium"))
                     (lib            (string-append out "/lib"))
                     (man            (string-append out "/share/man/man1"))
                     (applications   (string-append out "/share/applications"))
                     (libs           '("chrome_100_percent.pak"
                                       "chrome_200_percent.pak"
                                       "resources.pak"
                                       "v8_context_snapshot.bin"
                                       "chrome_crashpad_handler"

                                       ;; Swiftshader ICD.
                                       "libvk_swiftshader.so"
                                       "vk_swiftshader_icd.json"

                                       ;; Chromium ships its own libGL
                                       ;; implementation called ANGLE.
                                       "libEGL.so" "libGLESv2.so"))
                     (locales        (string-append lib "/locales"))
                     (resources      (string-append lib "/resources"))
                     (preferences
                      ;; This file contains defaults for new user profiles.
                      #$(local-file
                         (search-auxiliary-file
                          "chromium/master-preferences.json")))
                     (gtk (dirname (dirname
                                    (search-input-file inputs "lib/libgtk-3.so"))))
                     (xdg-utils (dirname (search-input-file inputs "bin/xdg-open"))))

                (substitute* '("chrome/app/resources/manpage.1.in"
                               "chrome/installer/linux/common/desktop.template")
                  (("@@MENUNAME@@") "Chromium")
                  (("@@PACKAGE@@") "chromium")
                  (("/usr/bin/@@USR_BIN_SYMLINK_NAME@@") exe))

                (mkdir-p man)
                (copy-file "chrome/app/resources/manpage.1.in"
                           (string-append man "/chromium.1"))

                (mkdir-p applications)
                (copy-file "chrome/installer/linux/common/desktop.template"
                           (string-append applications "/chromium.desktop"))

                (mkdir-p lib)
                (copy-file preferences (string-append lib "/master_preferences"))

                (with-directory-excursion "out/Release"
                  (for-each (cut install-file <> lib) libs)
                  (copy-file "chrome" (string-append lib "/chromium"))

                  (copy-recursively "locales" locales)
                  (copy-recursively "resources" resources)

                  (mkdir-p bin)
                  (symlink "../lib/chromium" exe)
                  (install-file "chromedriver" bin)

                  (for-each (lambda (so)
                              (install-file so (string-append lib "/swiftshader")))
                            (find-files "swiftshader" "\\.so$"))

                  (wrap-program exe
                    ;; Avoid file manager crash.  See <https://bugs.gnu.org/26593>.
                    `("XDG_DATA_DIRS" ":" prefix (,(string-append gtk "/share")))
                    `("PATH" ":" prefix (,xdg-utils))))

                (with-directory-excursion "chrome/app/theme/chromium"
                  (for-each
                   (lambda (size)
                     (let ((icons (string-append out "/share/icons/hicolor/"
                                                 size "x" size "/apps")))
                       (mkdir-p icons)
                       (copy-file (string-append "product_logo_" size ".png")
                                  (string-append icons "/chromium.png"))))
                   '("24" "48" "64" "128" "256")))))))))
    (native-inputs
     (list bison
           clang-15
           gn
           gperf
           lld-as-ld-wrapper-15
           ninja
           node-lts
           pkg-config
           which
           python-beautifulsoup4
           python-html5lib
           python-wrapper
           wayland))
    (inputs
     (list alsa-lib
           atk
           at-spi2-atk
           cups
           curl
           dbus
           expat
           flac
           ffmpeg/chromium
           fontconfig
           fp16
           freetype
           fxdiv
           gdk-pixbuf
           glib
           gtk+
           harfbuzz-5
           icu4c-71
           jsoncpp
           lcms
           libevent
           libffi
           libjpeg-turbo
           libpng
           libva
           libvpx
           libwebp
           libx11
           libxcb
           libxcomposite
           libxcursor
           libxdamage
           libxext
           libxfixes
           libxi
           libxml2
           libxrandr
           libxrender
           libxscrnsaver
           libxslt
           libxtst
           mesa
           minizip
           mit-krb5
           nss
           openh264
           openjpeg                     ;PDFium only
           opus+custom
           pango
           pciutils
           pipewire-0.3
           pulseaudio
           qtbase-5
           re2
           snappy
           speech-dispatcher
           eudev
           valgrind
           vulkan-headers
           vulkan-loader
           wayland
           xdg-utils))
    (native-search-paths
     (list (search-path-specification
            (variable "CHROMIUM_EXTENSION_DIRECTORY")
            (separator #f)              ;single entry
            (files '("share/chromium/extensions")))))

    ;; Building Chromium takes ... a very long time.  On a single core, a busy
    ;; mid-end x86 system may need more than 24 hours to complete the build.
    (properties '((timeout . 144000)    ;40 hours
                  ;; The linking step may take more than an hour on some hardware.
                  (max-silent-time . 7200)
                  (cpe-name . "chrome")))

    (home-page "https://github.com/Eloston/ungoogled-chromium")
    (description
     "Ungoogled-Chromium is the Chromium web browser, with some functionality
disabled in order to protect the users privacy.  This package also includes
the @command{chromedriver} command, which can be useful for automated web
testing.")
    ;; Chromium is developed as BSD-3, but bundles a large number of third-party
    ;; components with other licenses.  For full information, see chrome://credits.
    (license (list license:bsd-3
                   license:bsd-2
                   license:expat
                   license:asl2.0
                   license:mpl1.1
                   license:mpl2.0
                   license:public-domain
                   license:isc
                   (license:non-copyleft "chrome://credits"
                                         "See chrome://credits for more information.")
                   license:lgpl2.1+))))

(define-public ungoogled-chromium/wayland
  (package
    (inherit ungoogled-chromium)
    (name "ungoogled-chromium-wayland")
    (native-inputs '())
    (inputs
     `(("bash" ,bash-minimal)
       ("glibc-locales" ,glibc-utf8-locales)
       ("ungoogled-chromium" ,ungoogled-chromium)))
    (build-system trivial-build-system)
    (arguments
     '(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))
         (let* ((bash (assoc-ref %build-inputs "bash"))
                (chromium (assoc-ref %build-inputs "ungoogled-chromium"))
                (locales (assoc-ref %build-inputs "glibc-locales"))
                (out (assoc-ref %outputs "out"))
                (exe (string-append out "/bin/chromium")))

           ;; Use a Unicode locale so we can substitute the file below.
           (setenv "GUIX_LOCPATH" (string-append locales "/lib/locale"))
           (setlocale LC_ALL "en_US.utf8")

           (mkdir-p (dirname exe))
           (symlink (string-append chromium "/bin/chromedriver")
                    (string-append out "/bin/chromedriver"))

           (call-with-output-file exe
             (lambda (port)
               (format port "#!~a
exec ~a --enable-features=UseOzonePlatform --ozone-platform=wayland \
--enable-features=WebRTCPipeWireCapturer $@"
                       (string-append bash "/bin/bash")
                       (string-append chromium "/bin/chromium"))))
           (chmod exe #o555)

           ;; Provide the manual and .desktop file.
           (copy-recursively (string-append chromium "/share")
                             (string-append out "/share"))
           (substitute* (string-append
                         out "/share/applications/chromium.desktop")
             ((chromium) out))
           #t))))))
