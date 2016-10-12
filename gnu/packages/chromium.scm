;;; GNU Guix --- Functional package management for GNU
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

(define-module (gnu packages chromium)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
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
  ;#:use-module (gnu packages ghostscript) ;lcms
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
  #:use-module (gnu packages mit-krb5)
  #:use-module (gnu packages ninja)
  #:use-module (gnu packages patchutils)
  #:use-module (gnu packages pciutils)
  #:use-module (gnu packages photo)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages protobuf)
  #:use-module (gnu packages pulseaudio)
  #:use-module (gnu packages python)
  #:use-module (gnu packages regex)
  #:use-module (gnu packages serialization)
  #:use-module (gnu packages speech)
  ;#:use-module (gnu packages telephony) ; for libsrtp
  #:use-module (gnu packages tls)
  #:use-module (gnu packages valgrind)
  #:use-module (gnu packages version-control)
  #:use-module (gnu packages video)
  #:use-module (gnu packages xiph)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xdisorg)
  #:use-module (gnu packages xorg))

(define-public chromium
  (package
    (name "chromium")
    ;(version "56.0.2906.0") ; broken
    (version "56.0.2902.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://commondatastorage.googleapis.com/"
                                  "chromium-browser-official/chromium-"
                                  version ".tar.xz"))
              (sha256
               (base32
                "18jv0cy4vbwkmwqwa8pbrgd917pw2447r9zydkkm7v7xjvm3m8l8"
                ;"1pfgb5dnygyxiwfq6ini5s159c178zz7235npaag7k8gcc10ybnz" ; 2906
                ))
       (patches (search-patches
                 ;; Gentoo patches.
                 "chromium-system-ffmpeg-r4.patch"
                 "chromium-system-jinja-r14.patch"
                 ;; Debian patches.
                 "chromium-disable-ad-promo.patch"
                 ;; Ungoogled-chromium patches.
                 "chromium-disable-ipv6-probe.patch"
                 ;; Inox patches.
                 "chromium-disable-gcm-status-check.patch"
                 "chromium-disable-google-url-tracker.patch"
                 "chromium-disable-translation-lang-fetch.patch"
                 "chromium-disable-web-resource-service.patch"
                 ;; Iridium patches.
                 "chromium-disable-battery-status-api.patch"
                 "chromium-disable-missing-api-keys-warning.patch"
                 "chromium-disable-prediction-service.patch"
                 "chromium-increase-rsa-key-length.patch"))
       (modules '((srfi srfi-1)
                  (guix build utils)))
       (snippet
        '(begin
           ;; FIXME: This is an implementation of
           ;; "build/linux/unbundle/remove_bundled_libraries.py".
           ;; Descend into any directory named third_party and delete files
           ;; not ending in .gn or .gni. Unless the file or any parent
           ;; directory has been passed as an argument.
           ;; (let* ((keep-files
           ;;         (map
           ;;          ;; Prepend paths with "./" for comparison with find-files.
           ;;          (lambda (path) (string-append "./" path))
           ;;          (list
           ;;          <paste keep-libs from configure here...>
           ;;          )))
           ;;        ;; Find all third_party folders that is not in keep-files..
           ;;        (third-party-dirs
           ;;         (lset-difference eqv? (find-files "." "^third_party$"
           ;;                                           #:directories? #t)
           ;;                          keep-files))
           ;;        (purge-file?
           ;;         (lambda (path stat)
           ;;           (not (or (string-suffix? ".gn" path)
           ;;                    (string-suffix? ".gni" path)
           ;;                    (member path keep-files)
           ;;                    ;; Preserve directories to prevent a race condition.
           ;;                    (eq? (stat:type stat) 'directory)
           ;;                    ;; Check if parent is in keep-files.
           ;;                    ;; FIXME: need to check *any* parent.
           ;;                    (member (string-join
           ;;                             (reverse (cdr (reverse
           ;;                                            (string-split path #\/))))
           ;;                             "/")
           ;;                            keep-files)))))
           ;;        (delete-non-preserved-files
           ;;         (lambda (dir)
           ;;           (for-each (lambda (path)
           ;;                       (delete-file path))
           ;;                     (find-files dir purge-file? #:directories? #t)))))

           ;;   ;; Finally delete them.
           ;;   (for-each delete-non-preserved-files third-party-dirs))

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
                       '("harfbuzz-ng.gn" . "third_party/harfbuzz-ng/BUILD.gn")
                       '("icu.gn" . "third_party/icu/BUILD.gn")
                       '("libevent.gn" . "base/third_party/libevent/BUILD.gn")
                       '("libjpeg.gn" .
                         "build/secondary/third_party/libjpeg_turbo/BUILD.gn")
                       '("libpng.gn" . "third_party/libpng/BUILD.gn")
                       '("libvpx.gn" . "third_party/libvpx/BUILD.gn")
                       '("libwebp.gn" . "third_party/libwebp/BUILD.gn")
                       '("libxml.gn" . "third_party/libxml/BUILD.gn")
                       '("libxslt.gn" . "third_party/libxslt/BUILD.gn")
                       '("re2.gn" . "third_party/re2/BUILD.gn")
                       '("snappy.gn" . "third_party/snappy/BUILD.gn")
                       '("yasm.gn" . "third_party/yasm/yasm_assemble.gni")
                       '("zlib.gn" . "third_party/zlib/BUILD.gn")))
            #t))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; How?
       #:validate-runpath? #f ; FIXME
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-stuff
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
             ;; XXX fails to compile with system valgrind.
             ;; (substitute*
             ;;     '("v8/src/ia32/cpu-ia32.cc"
             ;;       "v8/src/x64/cpu-x64.cc"
             ;;       "v8/src/x87/cpu-x87.cc")
             ;;   (("include \"src/third_party/valgrind/") "include \"valgrind/"))

             (for-each (lambda (file)
                         (substitute* file
                           ;; These are not in the default include path, so
                           ;; might as well use system headers.
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

             ;; TODO: needs linker flags
             ;; (substitute*
             ;;     '("base/time/time.cc"
             ;;       "base/time/pr_time_unittest.cc")
             ;;   (("include \"base/third_party/nspr") "include \"nspr"))

             (substitute* "chrome/common/chrome_paths.cc"
               (("/usr/share/chromium/extensions")
                ;; TODO: how to add ~/.guix-profile
                "/run/current-system/profile/share/chromium/extensions"))

             (substitute* "breakpad/src/common/linux/libcurl_wrapper.h"
               (("include \"third_party/curl") "include \"curl"))))
         (replace 'configure
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((gn-flags
                    (list
                     ;; See tools/gn/docs/cookbook.md and
                     ;; https://www.chromium.org/developers/gn-build-configuration
                     ;; for usage. Run "./gn args . --list" in the Release
                     ;; directory for an exhaustive list of supported flags.
                     "is_debug=false"
                     "is_clang=false"
                     "use_gold=false"
                     "linux_use_bundled_binutils=false"
                     "use_sysroot=false"
                     "remove_webcore_debug_symbols=true"
                     ;; Don't record build date.
                     "override_build_date=\"01 01 2000 05:00:00\""
                     ;; TODO: This splits the build into smaller shared
                     ;; libraries instead of one massive static one.
                     ;; Causes linking problems.
                     ;"is_component_build=true"

                     ;; Don't fail when using deprecated ffmpeg features.
                     "treat_warnings_as_errors=false"

                     "enable_nacl=false" ; Uses pre-built pnacl toolchain.
                     "use_allocator=\"none\"" ; Don't use tcmalloc.

                     ;; Disable SUID sandbox; not needed with user namespaces.
                     ;; See docs/linux_sandboxing.md.
                     ;; FIXME: UPSTREAM: linking chrome fails without this.
                     ;"compile_suid_client=false"

                     ;; Don't build VR support.
                     "enable_vr_shell=false"

                     ;; Use the experimental vulkan backend.
                     ;;"enable_vulkan=true"

                     ;; Don't install any API keys. Users can still set them
                     ;; in the environment, if they wish to use such features.
                     "use_official_google_api_keys=false"

                     ;; FIXME: The generated "mksnapshot" fails to
                     ;; load libicui18n.
                     "v8_enable_i18n_support=false"

                     ;; There are better FTP clients.
                     ;; FIXME: UPSTREAM: linking fails with this disabled.
                     ;"disable_ftp_support=true"
                     ;; And file managers..
                     ;; FIXME: UPSTREAM: linking fails with this disabled.
                     ;"disable_file_support=true"

                     "use_ozone=false" ; enables cairo and pango
                     "use_alsa=true"
                     "use_cups=true"
                     "use_dbus=true"
                     "use_glib=true"
                     "use_gnome_keyring=false" ; deprecated by libsecret
                     "use_gtk3=true"
                     "use_libpci=true"
                     "use_pulseaudio=true"
                     "use_udev=true"
                     "use_xkbcommon=true"
                     ;; TODO: is this actually useful.
                     "link_pulseaudio=true"
                     ;; TODO: check if this works.
                     ;;"enable_wayland_server=true"

                     ;; Don't allow the Aura UI to access clipboard.
                     "enable_clipboard_aurax11=false"

                     "disable_precompiled_headers=true"
                     ;; Not currently supported on Linux.
                     ;"use_system_sqlite=true"
                     ;; TODO: what does this actually do.
                     "use_system_libjpeg=true"
                     ;; XXX vulcanize still needed with this.
                     ;"use_vulcanize=false"

                     "proprietary_codecs=false"
                     "enable_wifi_display=false"
                     ;; Don't download speech recognition blob on launch.
                     "enable_hotwording=false"
                     ;; Disable DRM support.
                     "enable_widevine=false"
                     ;; Disable extensions for proprietary services.
                     "enable_google_now=false"
                     "enable_hangout_services_extension=false"
                     ;; Don't allow apps to run when the browser is closed.
                     ;; FIXME: UPSTREAM: linking chrome fails without this.
                     ;"enable_background=false"
                     ;; Disable "field trials".
                     "fieldtrial_testing_like_official_build=true"
                     ;; Don't contact a web service to check for internet access.
                     "enable_captive_portal_detection=false"
                     ;; This is a web browser, not a LAN browser.
                     "enable_mdns=false"
                     "enable_service_discovery=false"
                     ;; Disable support for remote desktop apps aka "chromoting".
                     "enable_remoting=false"
                     ;; Disable support for routing media to other devices.
                     ;; FIXME: UPSTREAM: render_view_context_menu.cc
                     ;; "media_router" has not been declared
                     ;"enable_media_router=false"
                     "enable_media_remoting=false"
                     ;; Disable profile sync with external provider.
                     ;; FIXME: UPSTREAM: one_click_signin_dialog_view.cc:
                     ;; "start_sync_callback_ not declared in this scope"
                     ;"enable_one_click_signin=false"
                     ;; Prevent users from shooting their own foot.
                     ;; FIXME: UPSTREAM: pepper_plugin_info.h:20:2: error:
                     ;; "Plugins should be enabled"
                     ;"enable_plugins=false"
                     ;; Disable nanny mode.
                     ;; FIXME: UPSTREAM: supervised_users.h:
                     ;; "Supervised users aren't enabled."
                     ;"enable_supervised_users=false"
                     ;; Don't use an external service to validate URLs.
                     ;; FIXME: UPSTREAM: linking chrome fails with this disabled.
                     ;"safe_browsing_mode=0"

                     ;; TODO: extract pdfium into separate package.
                     ;; See "pdf_is_standalone" flag.
                     "enable_pdf=false"
                     "enable_print_preview=false" ; requires pdf

                     ;; TODO: What do these do.
                     "enable_app_list=false"
                     ;"metrics_use_blimp=true" ; Uh..
                     ;; XXX causes linking problems. Probably wanted anyway.
                     ;"enable_session_service=false"
                     "enable_mojo_media=false"

                     ;; WebRTC. May cause DNS leak, disable for now.
                     ;; https://en.wikipedia.org/wiki/WebRTC#Concerns
                     "enable_webrtc=false"
                     ;; These flags are still evaluated.
                     "rtc_desktop_capture_supported=false"
                     ;"rtc_have_dbus_glib=true"
                     "rtc_use_lto=true"
                     "rtc_use_gtk=true"
                     ;; Use absolute header paths.
                     "rtc_relative_path=false"
                     ;; Don't use bundled libraries.
                     "rtc_build_expat=false"
                     "rtc_build_json=false"
                     "rtc_build_libevent=false"
                     "rtc_build_libjpeg=false"
                     "rtc_build_libsrtp=false"
                     "rtc_build_libvpx=false"
                     "rtc_build_libyuv=false"
                     "rtc_build_openmax_dl=false"
                     "rtc_build_opus=false"
                     "rtc_build_ssl=false"
                     "rtc_build_usrsctp=false"
                     (string-append "rtc_jsoncpp_root=\""
                                    (assoc-ref inputs "jsoncpp")
                                    "/include/jsoncpp/json\"")
                     (string-append "rtc_ssl_root=\""
                                    (assoc-ref inputs "openssl")
                                    "/include/openssl\"")
                     ))
                   (gn-library-path
                    (string-join (map (lambda (name)
                                        (string-append (assoc-ref inputs name)
                                                       "/lib"))
                                      '("glib" "libevent"))
                                 ":"))
                   (keep-libs
                    (list
                     ;; Third party folders that cannot be deleted yet.
                     ;; Stuff in base/ seems mostly used for bootstrapping gn.
                     "base/third_party/dmg_fp"
                     "base/third_party/dynamic_annotations"
                     "base/third_party/icu"
                     "base/third_party/nspr"
                     "base/third_party/superfasthash"
                     "base/third_party/symbolize" ; TODO use system glog
                     "base/third_party/xdg_mime"
                     "base/third_party/libevent"
                     "base/third_party/xdg_user_dirs"
                     "chrome/third_party/mozilla_security_manager"
                     "courgette/third_party"
                     "net/third_party/mozilla_security_manager"
                     "net/third_party/nss"
                     "third_party/WebKit"
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
                     "third_party/ced"
                     "third_party/cld_3"
                     "third_party/cros_system_api"
                     "third_party/dom_distiller_js"
                     "third_party/fips181"
                     "third_party/flatbuffers"
                     "third_party/google_input_tools"
                     "third_party/google_input_tools/third_party/closure_library"
                     (string-append "third_party/google_input_tools/third_party"
                                    "/closure_library/third_party/closure")
                     "third_party/hunspell"
                     "third_party/iccjpeg"
                     "third_party/jstemplate"
                     "third_party/khronos"
                     "third_party/leveldatabase"
                     "third_party/libXNVCtrl"
                     "third_party/libaddressinput"
                     "third_party/libphonenumber"
                     ;; FIXME: needs pkg-config support
                     "third_party/libsecret"
                     ;"third_party/libsrtp"
                     "third_party/libudev"
                     "third_party/libwebm"
                     "third_party/libxml/chromium"
                     "third_party/libyuv"
                     "third_party/lss"
                     "third_party/lzma_sdk"
                     ;; XXX gpu/command_buffer_service/error_state.cc
                     ;; "not declared in this scope" with system mesa.
                     "third_party/mesa"
                     "third_party/modp_b64"
                     "third_party/mt19937ar"
                     "third_party/openmax_dl"
                     "third_party/opus"
                     "third_party/ots"
                     "third_party/polymer"
                     "third_party/protobuf"
                     ;; TODO: Remove when safe_browsing is disabled.
                     "third_party/protobuf/third_party/six"
                     "third_party/qcms"
                     "third_party/sfntly"
                     "third_party/skia"
                     "third_party/smhasher"
                     ;; XXX the sources that include this are generated.
                     "third_party/speech-dispatcher"
                     "third_party/sqlite"
                     "third_party/usb_ids"
                     "third_party/usrsctp"
                     "third_party/web-animations-js"
                     "third_party/webrtc"
                     "third_party/widevine/cdm/widevine_cdm_version.h"
                     "third_party/widevine/cdm/widevine_cdm_common.h"
                     "third_party/woff2"
                     "third_party/x86inc"
                     "third_party/xdg-utils"
                     "third_party/yasm"
                     "third_party/zlib/google"
                     "url/third_party/mozilla"
                     ;; XXX V8 fails to compile with system headers.
                     "v8/src/third_party/valgrind")))

               (setenv "CC" "gcc")
               (setenv "CXX" "g++")
               ;; TODO: pre-compile instead. Avoids a race condition.
               (setenv "PYTHONDONTWRITEBYTECODE" "1")

               (and
                ;; FIXME: implement as source snippet. This traverses
                ;; any "third_party" directory and deletes files that are:
                ;; * not ending with ".gn" or ".gni"; or
                ;; * not explicitly named as argument (folder or file).
                (zero? (apply system* "python"
                              "build/linux/unbundle/remove_bundled_libraries.py"
                              "--do-remove" keep-libs))

                ;; Build the "gn" tool.
                (zero? (system* "python"
                                "tools/gn/bootstrap/bootstrap.py" "-v"
                                "--gn-gen-args" (string-join gn-flags " ")))

                ;; The newly-built "gn" executable is unable to open
                ;; certain libraries, so we give it some help with
                ;; LD_LIBRARY_PATH.
                (with-directory-excursion "out/Release"
                  (wrap-program "gn"
                    `("LD_LIBRARY_PATH" ":" prefix (,gn-library-path))))

                ;; Generate ninja build files.
                (zero? (system* "./out/Release/gn" "gen"
                                ;"--args" (string-join gn-flags " ")
                                "out/Release"))))))
         (replace 'build
           (lambda _
             (zero? (system* "ninja" "-C" "out/Release"
                             "-j" (number->string (parallel-job-count))
                             "chrome"))))
         (replace 'install
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (bin (string-append out "/bin"))
                    (exe (string-append bin "/chromium-browser"))
                    (lib (string-append out "/lib/chromium"))
                    (man (string-append out "/share/man/man1"))
                    (locales (string-append lib "/locales"))
                    (resources (string-append lib "/resources")))

               ;; Can not use find-files here as there are many similar
               ;; files in build-specific subdirectories.
               (for-each (lambda (file)
                           (install-file (string-append "out/Release/" file) lib))
                         '("chrome" "natives_blob.bin" "snapshot_blob.bin"
                           "product_logo_48.png" "resources.pak"
                           "chrome_100_percent.pak" "chrome_200_percent.pak"))

               ;;(install-file "out/Release/icudtl.dat" lib)
               (install-file "out/Release/chrome.1" man)

               (copy-recursively "out/Release/locales" locales)
               (copy-recursively "out/Release/resources" resources)

               (mkdir-p bin)
               (symlink (string-append lib "/chrome") exe)

               ;; Ugh. Can we pass these to LDFLAGS instead?
               (wrap-program exe
                 `("LD_LIBRARY_PATH" ":" prefix
                   ,(map (lambda (input)
                           (string-append (assoc-ref inputs input) "/lib"))
                         '("pango" "glib" "cairo" "libx11" "libxcursor"
                           "libxdamage" "libxext" "libxfixes" "libxrender"
                           "icu4c" "nss" "zlib" "harfbuzz" "libjpeg"
                           "libpng" "libxcb" "libxcomposite" "libxi" "pulseaudio"
                           "libxtst" "nspr" "expat" "libxml2" "fontconfig"
                           "dbus" "libevent" "freetype" "gconf" "libxscrnsaver"
                           "libxrandr" "atk" "gdk-pixbuf" "libwebp" "mesa"
                           "re2" "ffmpeg" "libvpx" "alsa-lib" "flac" "udev"
                           "minizip" "gtk+" "gtk+-2" "libxslt" "snappy"))))
               ;; Wrap it again, now adding "nss/lib/nss"...
               (wrap-program exe
                 `("LD_LIBRARY_PATH" ":" prefix
                   (,(string-append (assoc-ref inputs "nss") "/lib/nss"))))
               #t))))))
    (native-inputs
     `(("bison" ,bison)
       ("git" ,git) ; last_commit_position.py
       ("gperf" ,gperf)
       ("ninja" ,ninja)
       ("pkg-config" ,pkg-config)
       ;("quilt" ,quilt)
       ("which" ,which)
       ("yasm" ,yasm)

       ;; Headers.
       ("curl" ,curl)
       ("opus" ,opus)
       ("valgrind" ,valgrind)

       ("python-beautifulsoup4" ,python2-beautifulsoup4)
       ("python-html5lib" ,python2-html5lib)
       ("python-jinja2" ,python2-jinja2)
       ("python-ply" ,python2-ply)
       ("python-simplejson" ,python2-simplejson)
       ("python-six" ,python-six)
       ("python" ,python-2)))
    (inputs
     `(("alsa-lib" ,alsa-lib)
       ("atk" ,atk)
       ("cups" ,cups)
       ("dbus" ,dbus)
       ;("dbus-glib" ,dbus-glib) ; Include for WebRTC.
       ("udev" ,eudev)
       ("expat" ,expat)
       ("flac" ,flac)
       ("ffmpeg" ,ffmpeg)
       ("fontconfig" ,fontconfig)
       ("freetype" ,freetype)
       ("gconf" ,gconf)
       ("gdk-pixbuf" ,gdk-pixbuf)
       ("glib" ,glib)
       ;("libgnome-keyring" ,libgnome-keyring)
       ("gtk+-2" ,gtk+-2)
       ("gtk+" ,gtk+)
       ("harfbuzz" ,harfbuzz)
       ("icu4c" ,icu4c)
       ("jsoncpp" ,jsoncpp)
       ;("lcms" ,lcms)
       ("libcap" ,libcap)
       ("libevent" ,libevent)
       ("libexif" ,libexif)
       ("libffi" ,libffi)
       ("libjpeg" ,libjpeg-8) ; Patches exist for building with jpeg-9.
       ("libpng" ,libpng)
       ;("libsecret" ,libsecret)
       ;("libsrtp" ,libsrtp)
       ("libusb" ,libusb)
       ("libvpx" ,libvpx)
       ("libwebp" ,libwebp)
       ("libx11" ,libx11)
       ("libxcb" ,libxcb)
       ("libxcomposite" ,libxcomposite)
       ("libxcursor" ,libxcursor)
       ("libxdamage" ,libxdamage)
       ("libxext" ,libxext)
       ("libxfixes" ,libxfixes)
       ("libxi" ,libxi)
       ("libxinerama" ,libxinerama)
       ("libxkbcommon" ,libxkbcommon)
       ("libxml2" ,libxml2)
       ("libxrandr" ,libxrandr)
       ("libxrender" ,libxrender)
       ("libxscrnsaver" ,libxscrnsaver)
       ("libxslt" ,libxslt)
       ("libxtst" ,libxtst)
       ("mesa" ,mesa)
       ("minizip" ,zlib-minizip)
       ("mit-krb5" ,mit-krb5)
       ("nss" ,nss)
       ("openssl" ,openssl)
       ("pango" ,pango)
       ("pciutils" ,pciutils)
       ("protobuf" ,protobuf)
       ("pulseaudio" ,pulseaudio)
       ("re2" ,re2)
       ("snappy" ,snappy)
       ("speech-dispatcher" ,speech-dispatcher)
       ("sqlite" ,sqlite)))
    (home-page "https://www.chromium.org/")
    (synopsis "Graphical web browser")
    (description "Chromium is a popular web browser.  This version
incorporates patches from the @uref{https://github.com/gcarq/inox-patchset,Inox},
@uref{https://iridiumbrowser.de/,Iridium} and
@uref{https://github.com/Eloston/ungoogled-chromium,ungoogled-chromium}
projects for enhanced privacy control.

Warning: Chromium is a fast-moving project and we cannot guarantee that
this browser does not leak user data to third-parties.  If you are
concerned about privacy, use GNU Icecat.")
    ;; TODO: Run tools/licenses.py to check for third-party licenses.
    (license license:bsd-3)))
