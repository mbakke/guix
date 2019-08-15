;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015, 2016, 2017, 2018, 2019 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016, 2017 Marius Bakke <mbakke@fastmail.com>
;;; Copyright © 2016 Hartmut Goebel <h.goebel@crazy-compilers.com>
;;; Copyright © 2018, 2019 Tobias Geerinckx-Rice <me@tobias.gr>
;;; Copyright © 2018 Kei Kebreau <kkebreau@posteo.net>
;;; Copyright © 2018 Mark Meyer <mark@ofosos.org>
;;; Copyright © 2018 Ben Woodcroft <donttrustben@gmail.com>
;;; Copyright © 2018 Fis Trivial <ybbs.daans@hotmail.com>
;;; Copyright © 2018 Julien Lepiller <julien@lepiller.eu>
;;; Copyright © 2018 Björn Höfling <bjoern.hoefling@bjoernhoefling.de>
;;; Copyright © 2019 Nicolas Goaziou <mail@nicolasgoaziou.fr>
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

(define-module (gnu packages machine-learning)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (guix download)
  #:use-module (guix svn-download)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system ocaml)
  #:use-module (guix build-system python)
  #:use-module (guix build-system r)
  #:use-module (guix git-download)
  #:use-module (gnu packages)
  #:use-module (gnu packages adns)
  #:use-module (gnu packages algebra)
  #:use-module (gnu packages audio)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages boost)
  #:use-module (gnu packages check)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages cran)
  #:use-module (gnu packages databases)
  #:use-module (gnu packages dejagnu)
  #:use-module (gnu packages docker)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages graphviz)
  #:use-module (gnu packages gstreamer)
  #:use-module (gnu packages image)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages mpi)
  #:use-module (gnu packages ocaml)
  #:use-module (gnu packages onc-rpc)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages protobuf)
  #:use-module (gnu packages python)
  #:use-module (gnu packages python-web)
  #:use-module (gnu packages python-xyz)
  #:use-module (gnu packages serialization)
  #:use-module (gnu packages sphinx)
  #:use-module (gnu packages statistics)
  #:use-module (gnu packages sqlite)
  #:use-module (gnu packages swig)
  #:use-module (gnu packages time)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages version-control)
  #:use-module (gnu packages web)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xorg)
  #:use-module (ice-9 match))

(define-public fann
  ;; The last release is >100 commits behind, so we package from git.
  (let ((commit "d71d54788bee56ba4cf7522801270152da5209d7"))
    (package
      (name "fann")
      (version (string-append "2.2.0-1." (string-take commit 8)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/libfann/fann.git")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "0ibwpfrjs6q2lijs8slxjgzb2llcl6rk3v2ski4r6215g5jjhg3x"))))
      (build-system cmake-build-system)
      (arguments
       `(#:phases
         (modify-phases %standard-phases
           (replace 'check
             (lambda* (#:key outputs #:allow-other-keys)
               (let* ((out (assoc-ref outputs "out")))
                 (with-directory-excursion (string-append (getcwd) "/tests")
                   (invoke "./fann_tests"))))))))
      (home-page "http://leenissen.dk/fann/wp/")
      (synopsis "Fast Artificial Neural Network")
      (description
       "FANN is a free open source neural network library, which implements
multilayer artificial neural networks in C with support for both fully
connected and sparsely connected networks.")
      (license license:lgpl2.1))))

(define-public libsvm
  (package
    (name "libsvm")
    (version "3.23")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://www.csie.ntu.edu.tw/~cjlin/libsvm/"
                           name "-" version ".tar.gz"))
       (sha256
        (base32 "0jpaq0rr92x38p4nk3gjan79ip67m6p80anb28z1d8601miysyi5"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f                      ; no "check" target
       #:phases (modify-phases %standard-phases
                  (delete 'configure)
                  (replace
                   'install             ; no ‘install’ target
                   (lambda* (#:key outputs #:allow-other-keys)
                     (let* ((out (assoc-ref outputs "out"))
                            (bin (string-append out "/bin/")))
                       (mkdir-p bin)
                       (for-each (lambda (file)
                                   (copy-file file (string-append bin file)))
                                 '("svm-train"
                                   "svm-predict"
                                   "svm-scale")))
                     #t)))))
    (home-page "http://www.csie.ntu.edu.tw/~cjlin/libsvm/")
    (synopsis "Library for Support Vector Machines")
    (description
     "LIBSVM is a machine learning library for support vector
classification, (C-SVC, nu-SVC), regression (epsilon-SVR, nu-SVR) and
distribution estimation (one-class SVM).  It supports multi-class
classification.")
    (license license:bsd-3)))

(define-public python-libsvm
  (package (inherit libsvm)
    (name "python-libsvm")
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f                      ; no "check" target
       #:make-flags '("-C" "python")
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace
          'install                      ; no ‘install’ target
          (lambda* (#:key inputs outputs #:allow-other-keys)
            (let ((site (string-append (assoc-ref outputs "out")
                                       "/lib/python"
                                       (string-take
                                        (string-take-right
                                         (assoc-ref inputs "python") 5) 3)
                                       "/site-packages/")))
              (substitute* "python/svm.py"
                (("../libsvm.so.2") "libsvm.so.2"))
              (mkdir-p site)
              (for-each (lambda (file)
                          (copy-file file (string-append site (basename file))))
                        (find-files "python" "\\.py"))
              (copy-file "libsvm.so.2"
                         (string-append site "libsvm.so.2")))
            #t)))))
    (inputs
     `(("python" ,python)))
    (synopsis "Python bindings of libSVM")))

(define-public ghmm
  ;; The latest release candidate is several years and a couple of fixes have
  ;; been published since.  This is why we download the sources from the SVN
  ;; repository.
  (let ((svn-revision 2341))
    (package
      (name "ghmm")
      (version (string-append "0.9-rc3-0." (number->string svn-revision)))
      (source (origin
                (method svn-fetch)
                (uri (svn-reference
                      (url "http://svn.code.sf.net/p/ghmm/code/trunk")
                      (revision svn-revision)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "0qbq1rqp94l530f043qzp8aw5lj7dng9wq0miffd7spd1ff638wq"))))
      (build-system gnu-build-system)
      (arguments
       `(#:imported-modules (,@%gnu-build-system-modules
                             (guix build python-build-system))
         #:phases
         (modify-phases %standard-phases
           (add-after 'unpack 'enter-dir
             (lambda _ (chdir "ghmm") #t))
           (delete 'check)
           (add-after 'install 'check
             (assoc-ref %standard-phases 'check))
           (add-before 'check 'fix-PYTHONPATH
             (lambda* (#:key inputs outputs #:allow-other-keys)
               (let ((python-version ((@@ (guix build python-build-system)
                                           get-python-version)
                                      (assoc-ref inputs "python"))))
                 (setenv "PYTHONPATH"
                         (string-append (getenv "PYTHONPATH")
                                        ":" (assoc-ref outputs "out")
                                        "/lib/python" python-version
                                        "/site-packages")))
               #t))
           (add-after 'enter-dir 'fix-runpath
             (lambda* (#:key outputs #:allow-other-keys)
               (substitute* "ghmmwrapper/setup.py"
                 (("^(.*)extra_compile_args = \\[" line indent)
                  (string-append indent
                                 "extra_link_args = [\"-Wl,-rpath="
                                 (assoc-ref outputs "out") "/lib\"],\n"
                                 line
                                 "\"-Wl,-rpath="
                                 (assoc-ref outputs "out")
                                 "/lib\", ")))
               #t))
           (add-after 'enter-dir 'disable-broken-tests
             (lambda _
               (substitute* "tests/Makefile.am"
                 ;; GHMM_SILENT_TESTS is assumed to be a command.
                 (("TESTS_ENVIRONMENT.*") "")
                 ;; Do not build broken tests.
                 (("chmm .*") "")
                 (("read_fa .*") "")
                 (("mcmc .*") "")
                 (("label_higher_order_test.*$")
                  "label_higher_order_test\n"))

               ;; These Python unittests are broken as there is no gato.
               ;; See https://sourceforge.net/p/ghmm/support-requests/3/
               (substitute* "ghmmwrapper/ghmmunittests.py"
                 (("^(.*)def (testNewXML|testMultipleTransitionClasses|testNewXML)"
                   line indent)
                  (string-append indent
                                 "@unittest.skip(\"Disabled by Guix\")\n"
                                 line)))
               #t)))))
      (inputs
       `(("python" ,python-2) ; only Python 2 is supported
         ("libxml2" ,libxml2)))
      (native-inputs
       `(("pkg-config" ,pkg-config)
         ("dejagnu" ,dejagnu)
         ("swig" ,swig)
         ("autoconf" ,autoconf)
         ("automake" ,automake)
         ("libtool" ,libtool)))
      (home-page "http://ghmm.org")
      (synopsis "Hidden Markov Model library")
      (description
       "The General Hidden Markov Model library (GHMM) is a C library with
additional Python bindings implementing a wide range of types of @dfn{Hidden
Markov Models} (HMM) and algorithms: discrete, continuous emissions, basic
training, HMM clustering, HMM mixtures.")
      (license license:lgpl2.0+))))

(define-public mcl
  (package
    (name "mcl")
    (version "14.137")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://micans.org/mcl/src/mcl-"
                    (string-replace-substring version "." "-")
                    ".tar.gz"))
              (sha256
               (base32
                "15xlax3z31lsn62vlg94hkm75nm40q4679amnfg13jm8m2bnhy5m"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags (list "--enable-blast")))
    (inputs
     `(("perl" ,perl)))
    (home-page "http://micans.org/mcl/")
    (synopsis "Clustering algorithm for graphs")
    (description
     "The MCL algorithm is short for the @dfn{Markov Cluster Algorithm}, a
fast and scalable unsupervised cluster algorithm for graphs (also known as
networks) based on simulation of (stochastic) flow in graphs.")
    ;; In the LICENCE file and web page it says "The software is licensed
    ;; under the GNU General Public License, version 3.", but in several of
    ;; the source code files it suggests GPL3 or later.
    ;; http://listserver.ebi.ac.uk/pipermail/mcl-users/2016/000376.html
    (license license:gpl3)))

(define-public ocaml-mcl
  (package
    (name "ocaml-mcl")
    (version "12-068oasis4")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/fhcrc/mcl.git")
             (commit version)))
       (file-name (git-file-name name version))
       (sha256
        (base32
         "0009dc3h2jp3qg5val452wngpqnbfyhbcxylghq0mrjqxx0jdq5p"))))
    (build-system ocaml-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'configure 'patch-paths
           (lambda _
             (substitute* "configure"
               (("/bin/sh") (which "sh")))
             (substitute* "setup.ml"
               (("LDFLAGS=-fPIC")
                (string-append "LDFLAGS=-fPIC\"; \"SHELL=" (which "sh")))
               (("-std=c89") "-std=gnu99")

               ;; This is a mutable string, which is no longer supported.  Use
               ;; a byte buffer instead.
               (("String.make \\(String.length s\\)")
                "Bytes.make (String.length s)")

               ;; These two belong together.
               (("OASISString.replace_chars")
                "Bytes.to_string (OASISString.replace_chars")
               ((" s;")
                " s);"))
             (substitute* "myocamlbuild.ml"
               (("std=c89") "std=gnu99"))
             ;; Since we build with a more recent OCaml, we have to use C99 or
             ;; later.  This causes problems with the old C code.
             (substitute* "src/impala/matrix.c"
               (("restrict") "restrict_"))
             #t)))))
    (native-inputs
     `(("ocamlbuild" ,ocamlbuild)))
    (home-page "https://github.com/fhcrc/mcl")
    (synopsis "OCaml wrappers around MCL")
    (description
     "This package provides OCaml bindings for the MCL graph clustering
algorithm.")
    (license license:gpl3)))

(define-public python-mflux-ai
  (package
    (name "python-mflux-ai")
    (version "0.2.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "mflux-ai" version))
              (sha256
               (base32
                "19c5p87h24hxjwydqa7c24wv7mavj6qdh19hw66a0s68ix66d5xg"))))
    (build-system python-build-system)
    (arguments
     `(#:phases (modify-phases %standard-phases
                  (replace 'check
                    (lambda _
                      (setenv "PYTHONPATH"
                              (string-append "./build/lib:"
                                             (or (getenv "PYTHONPATH") "")))
                      (invoke "pytest" "-vv"))))))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-pytest-runner" ,python-pytest-runner)
       ("python-responses" ,python-responses)))
    (propagated-inputs
     `(("python-joblib" ,python-joblib)
       ("python-minio" ,python-minio)
       ("python-requests" ,python-requests)))
    (home-page "https://github.com/AIAScience/mflux-ai-python")
    (synopsis "Python library for mflux.ai")
    (description
     "This package provides a Python interface to the mflux.ai server.")
    ;; XXX: The library has no license information yet.
    (license license:expat)))

(define-public mlflow
  (package
    (name "mlflow")
    (version "1.2.0")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "mlflow" version))
              (sha256
               (base32
                "13jckipp5k67yd1iga6jiwwpds6d35k69lvqnfgw7ds55bz7n5q7"))))
    (build-system python-build-system)
    (arguments
     `(;; FIXME: Tests require Protobuf >= 3.6.0.
       #:tests? #f))
    (propagated-inputs
     `(("python-alembic" ,python-alembic)
       ("python-click" ,python-click)
       ("python-cloudpickle" ,python-cloudpickle)
       ("python-databricks-cli" ,python-databricks-cli)
       ("python-dateutil" ,python-dateutil)
       ("python-docker" ,python-docker-py)
       ("python-entrypoints" ,python-entrypoints)
       ("python-flask" ,python-flask)
       ("python-gitpython" ,python-gitpython)
       ("python-gorilla" ,python-gorilla)
       ("python-gunicorn" ,python-gunicorn)
       ("python-numpy" ,python-numpy)
       ("python-pandas" ,python-pandas)
       ("python-protobuf" ,python-protobuf-next)
       ("python-pyyaml" ,python-pyyaml)
       ("python-querystring-parser" ,python-querystring-parser)
       ("python-requests" ,python-requests)
       ("python-simplejson" ,python-simplejson)
       ("python-six" ,python-six)
       ("python-sqlalchemy" ,python-sqlalchemy)
       ("python-sqlparse" ,python-sqlparse)
       ("python-waitress" ,python-waitress)))
    (home-page "https://mlflow.org/")
    (synopsis "Manage machine learning workflows")
    (description
     "MLflow is a platform to streamline machine learning development,
including tracking experiments, packaging code into reproducible runs, and
sharing and deploying models.  MLflow offers a set of lightweight APIs that
can used with any existing machine learning application or library (TensorFlow,
PyTorch, XGBoost, etc), wherever you currently run ML code (e.g. in notebooks,
standalone applications or the cloud).")
    (license license:asl2.0)))

(define-public randomjungle
  (package
    (name "randomjungle")
    (version "2.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://www.imbs.uni-luebeck.de/fileadmin/files/Software"
             "/randomjungle/randomjungle-" version ".tar_.gz"))
       (patches (search-patches "randomjungle-disable-static-build.patch"))
       (sha256
        (base32
         "12c8rf30cla71swx2mf4ww9mfd8jbdw5lnxd7dxhyw1ygrvg6y4w"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags
       (list "--disable-static"
             (string-append "--with-boost="
                            (assoc-ref %build-inputs "boost")))
       #:phases
       (modify-phases %standard-phases
         (add-before
          'configure 'set-CXXFLAGS
          (lambda _
            (setenv "CXXFLAGS" "-fpermissive ")
            #t)))))
    (inputs
     `(("boost" ,boost)
       ("gsl" ,gsl)
       ("libxml2" ,libxml2)
       ("zlib" ,zlib)))
    (native-inputs
     `(("gfortran" ,gfortran)
       ("gfortran:lib" ,gfortran "lib")))
    ;; Non-portable assembly instructions are used so building fails on
    ;; platforms other than x86_64 or i686.
    (supported-systems '("x86_64-linux" "i686-linux"))
    (home-page "https://www.imbs.uni-luebeck.de/forschung/software/details.html#c224")
    (synopsis "Implementation of the Random Forests machine learning method")
    (description
     "Random Jungle is an implementation of Random Forests.  It is supposed to
analyse high dimensional data.  In genetics, it can be used for analysing big
Genome Wide Association (GWA) data.  Random Forests is a powerful machine
learning method.  Most interesting features are variable selection, missing
value imputation, classifier creation, generalization error estimation and
sample proximities between pairs of cases.")
    (license license:gpl3+)))

(define-public openfst
  (package
    (name "openfst")
    (version "1.7.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://www.openfst.org/twiki/pub/FST/"
                                  "FstDownload/openfst-" version ".tar.gz"))
              (sha256
               (base32
                "0fqgk8195kz21is09gwzwnrg7fr9526bi9mh4apyskapz27pbhr1"))))
    (build-system gnu-build-system)
    (home-page "http://www.openfst.org")
    (synopsis "Library for weighted finite-state transducers")
    (description "OpenFst is a library for constructing, combining,
optimizing, and searching weighted finite-state transducers (FSTs).")
    (license license:asl2.0)))

(define-public shogun
  (package
    (name "shogun")
    (version "6.1.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "ftp://shogun-toolbox.org/shogun/releases/"
             (version-major+minor version)
             "/sources/shogun-" version ".tar.bz2"))
       (sha256
        (base32
         "1rn9skm3nw6hr7mr3lgp2gfqhi7ii0lyxck7qmqnf8avq349s5jp"))
       (modules '((guix build utils)
                  (ice-9 rdelim)))
       (snippet
        '(begin
           ;; Remove non-free sources and files referencing them
           (for-each delete-file
                     (find-files "src/shogun/classifier/svm/"
                                 "SVMLight\\.(cpp|h)"))
           (for-each delete-file
                     (find-files "examples/undocumented/libshogun/"
                                 (string-append
                                  "(classifier_.*svmlight.*|"
                                  "evaluation_cross_validation_locked_comparison).cpp")))
           ;; Remove non-free functions.
           (define (delete-ifdefs file)
             (with-atomic-file-replacement file
               (lambda (in out)
                 (let loop ((line (read-line in 'concat))
                            (skipping? #f))
                   (if (eof-object? line)
                       #t
                       (let ((skip-next?
                              (or (and skipping?
                                       (not (string-prefix?
                                             "#endif //USE_SVMLIGHT" line)))
                                  (string-prefix?
                                   "#ifdef USE_SVMLIGHT" line))))
                         (when (or (not skipping?)
                                   (and skipping? (not skip-next?)))
                           (display line out))
                         (loop (read-line in 'concat) skip-next?)))))))
           (for-each delete-ifdefs
                     (append
                      (find-files "src/shogun/classifier/mkl"
                                  "^MKLClassification\\.cpp")
                      (find-files "src/shogun/classifier/svm"
                                  "^SVMLightOneClass\\.(cpp|h)")
                      (find-files "src/shogun/multiclass"
                                  "^ScatterSVM\\.(cpp|h)")
                      (find-files "src/shogun/kernel/"
                                  "^(Kernel|CombinedKernel|ProductKernel)\\.(cpp|h)")
                      (find-files "src/shogun/regression/svr"
                                  "^(MKLRegression|SVRLight)\\.(cpp|h)")
                      (find-files "src/shogun/transfer/domain_adaptation"
                                  "^DomainAdaptationSVM\\.(cpp|h)")))
           #t))))
    (build-system cmake-build-system)
    (arguments
     '(#:tests? #f ;no check target
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'delete-broken-symlinks
           (lambda _
             (for-each delete-file '("applications/arts/data"
                                     "applications/asp/data"
                                     "applications/easysvm/data"
                                     "applications/msplicer/data"
                                     "applications/ocr/data"
                                     "examples/meta/data"
                                     "examples/undocumented/data"))
             #t))
         (add-after 'unpack 'change-R-target-path
           (lambda* (#:key outputs #:allow-other-keys)
             (substitute* '("src/interfaces/r/CMakeLists.txt"
                            "examples/meta/r/CMakeLists.txt")
               (("\\$\\{R_COMPONENT_LIB_PATH\\}")
                (string-append (assoc-ref outputs "out")
                               "/lib/R/library/")))
             #t))
         (add-after 'unpack 'fix-octave-modules
           (lambda* (#:key outputs #:allow-other-keys)
             (substitute* "src/interfaces/octave/CMakeLists.txt"
               (("^include_directories\\(\\$\\{OCTAVE_INCLUDE_DIRS\\}")
                "include_directories(${OCTAVE_INCLUDE_DIRS} ${OCTAVE_INCLUDE_DIRS}/octave")
               ;; change target directory
               (("\\$\\{OCTAVE_OCT_LOCAL_API_FILE_DIR\\}")
                (string-append (assoc-ref outputs "out")
                               "/share/octave/packages")))
             (substitute* '("src/interfaces/octave/swig_typemaps.i"
                            "src/interfaces/octave/sg_print_functions.cpp")
               ;; "octave/config.h" and "octave/oct-obj.h" deprecated in Octave.
               (("octave/config\\.h") "octave/octave-config.h")
               (("octave/oct-obj.h") "octave/ovl.h"))
             #t))
         (add-after 'unpack 'move-rxcpp
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((rxcpp-dir "shogun/third-party/rxcpp"))
               (mkdir-p rxcpp-dir)
               (install-file (assoc-ref inputs "rxcpp") rxcpp-dir)
               #t)))
         (add-before 'build 'set-HOME
           ;; $HOME needs to be set at some point during the build phase
           (lambda _ (setenv "HOME" "/tmp") #t)))
       #:configure-flags
       (list "-DCMAKE_BUILD_WITH_INSTALL_RPATH=TRUE"
             "-DUSE_SVMLIGHT=OFF" ;disable proprietary SVMLIGHT
             "-DBUILD_META_EXAMPLES=OFF" ;requires unpackaged ctags
             ;;"-DINTERFACE_JAVA=ON" ;requires unpackaged jblas
             ;;"-DINTERFACE_RUBY=ON" ;requires unpackaged ruby-narray
             ;;"-DINTERFACE_PERL=ON" ;"FindPerlLibs" does not exist
             ;;"-DINTERFACE_LUA=ON"  ;fails because lua doesn't build pkgconfig file
             "-DINTERFACE_OCTAVE=ON"
             "-DINTERFACE_PYTHON=ON"
             "-DINTERFACE_R=ON")))
    (inputs
     `(("python" ,python)
       ("numpy" ,python-numpy)
       ("r-minimal" ,r-minimal)
       ("octave" ,octave-cli)
       ("swig" ,swig)
       ("eigen" ,eigen)
       ("hdf5" ,hdf5)
       ("atlas" ,atlas)
       ("arpack" ,arpack-ng)
       ("lapack" ,lapack)
       ("glpk" ,glpk)
       ("libxml2" ,libxml2)
       ("lzo" ,lzo)
       ("zlib" ,zlib)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("rxcpp" ,rxcpp)))
    ;; Non-portable SSE instructions are used so building fails on platforms
    ;; other than x86_64.
    (supported-systems '("x86_64-linux"))
    (home-page "http://shogun-toolbox.org/")
    (synopsis "Machine learning toolbox")
    (description
     "The Shogun Machine learning toolbox provides a wide range of unified and
efficient Machine Learning (ML) methods.  The toolbox seamlessly allows to
combine multiple data representations, algorithm classes, and general purpose
tools.  This enables both rapid prototyping of data pipelines and extensibility
in terms of new algorithms.")
    (license license:gpl3+)))

(define-public rxcpp
  (package
    (name "rxcpp")
    (version "4.1.0")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/ReactiveX/RxCpp.git")
             (commit (string-append "v" version))))
       (sha256
        (base32 "1rdpa3jlc181jd08nk437aar085h28i45s6nzrv65apb3xyyz0ij"))
       (file-name (git-file-name name version))))
    (build-system cmake-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'remove-werror
           (lambda _
             (substitute* (find-files ".")
               (("-Werror") ""))
             #t))
         (replace 'check
           (lambda _
             (invoke "ctest"))))))
    (native-inputs
     `(("catch" ,catch-framework)))
    (home-page "http://reactivex.io/")
    (synopsis "Reactive Extensions for C++")
    (description
     "The Reactive Extensions for C++ (RxCpp) is a library of algorithms for
values-distributed-in-time.  ReactiveX is a library for composing asynchronous
and event-based programs by using observable sequences.

It extends the observer pattern to support sequences of data and/or events and
adds operators that allow you to compose sequences together declaratively while
abstracting away concerns about things like low-level threading,
synchronization, thread-safety, concurrent data structures, and non-blocking
I/O.")
    (license license:asl2.0)))

(define-public r-adaptivesparsity
  (package
    (name "r-adaptivesparsity")
    (version "1.6")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "AdaptiveSparsity" version))
              (sha256
               (base32
                "0imr5m8mll9j6n4icsv6z9rl5kbnwsp9wvzrg7n90nnmcxq2cz91"))))
    (properties
     `((upstream-name . "AdaptiveSparsity")))
    (build-system r-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'link-against-armadillo
           (lambda _
             (substitute* "src/Makevars"
               (("PKG_LIBS=" prefix)
                (string-append prefix "-larmadillo"))))))))
    (propagated-inputs
     `(("r-mass" ,r-mass)
       ("r-matrix" ,r-matrix)
       ("r-rcpp" ,r-rcpp)
       ("r-rcpparmadillo" ,r-rcpparmadillo)))
    (inputs
     `(("armadillo" ,armadillo)))
    (home-page "https://cran.r-project.org/web/packages/AdaptiveSparsity")
    (synopsis "Adaptive sparsity models")
    (description
     "This package implements the Figueiredo machine learning algorithm for
adaptive sparsity and the Wong algorithm for adaptively sparse gaussian
geometric models.")
    (license license:lgpl3+)))

(define-public gemmlowp-for-tensorflow
  ;; The commit hash is taken from "tensorflow/workspace.bzl".
  (let ((commit "38ebac7b059e84692f53e5938f97a9943c120d98")
        (revision "2"))
    (package
      (name "gemmlowp")
      (version (git-version "0" revision commit))
      (source (origin
                (method url-fetch)
                (uri (string-append "https://mirror.bazel.build/"
                                    "github.com/google/gemmlowp/archive/"
                                    commit ".zip"))
                (file-name (string-append "gemmlowp-" version ".zip"))
                (sha256
                 (base32
                  "0n56s2g8hrssm4w8qj1v58gfm56a04n9v992ixkmvk6zjiralzxq"))))
      (build-system cmake-build-system)
      (arguments
       `(#:configure-flags
         (list ,@(match (%current-system)
                   ((or "x86_64-linux" "i686-linux")
                    '("-DCMAKE_CXX_FLAGS=-msse2"))
                   (_ '())))
         #:phases
         (modify-phases %standard-phases
           ;; This directory contains the CMakeLists.txt.
           (add-after 'unpack 'chdir
             (lambda _ (chdir "contrib") #t))
           ;; There is no install target
           (replace 'install
             (lambda* (#:key outputs #:allow-other-keys)
               (let* ((out (assoc-ref outputs "out"))
                      (lib (string-append out "/lib/"))
                      (inc (string-append out "/include/")))
                 (install-file "../build/libeight_bit_int_gemm.so" lib)
                 (for-each (lambda (dir)
                             (let ((target (string-append inc "/" dir)))
                               (mkdir-p target)
                               (for-each (lambda (h)
                                           (install-file h target))
                                         (find-files (string-append "../" dir)
                                                     "\\.h$"))))
                           '("meta" "profiling" "public" "fixedpoint"
                             "eight_bit_int_gemm" "internal"))
                 #t))))))
      (native-inputs
       `(("unzip" ,unzip)))
      (home-page "https://github.com/google/gemmlowp")
      (synopsis "Small self-contained low-precision GEMM library")
      (description
       "This is a small self-contained low-precision @dfn{general matrix
multiplication} (GEMM) library.  It is not a full linear algebra library.
Low-precision means that the input and output matrix entries are integers on
at most 8 bits.  To avoid overflow, results are internally accumulated on more
than 8 bits, and at the end only some significant 8 bits are kept.")
      (license license:asl2.0))))

(define-public dlib
  (package
    (name "dlib")
    (version "19.7")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://dlib.net/files/dlib-" version ".tar.bz2"))
              (sha256
               (base32
                "1mljz02kwkrbggyncxv5fpnyjdybw2qihaacb3js8yfkw12vwpc2"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  ;; Delete ~13MB of bundled dependencies.
                  (delete-file-recursively "dlib/external")
                  (delete-file-recursively "docs/dlib/external")
                  #t))))
    (build-system cmake-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'disable-asserts
           (lambda _
             ;; config.h recommends explicitly enabling or disabling asserts
             ;; when building as a shared library. By default neither is set.
             (substitute* "dlib/config.h"
               (("^//#define DLIB_DISABLE_ASSERTS") "#define DLIB_DISABLE_ASSERTS"))
             #t))
         (add-after 'disable-asserts 'disable-failing-tests
           (lambda _
             ;; One test times out on MIPS, so we need to disable it.
             ;; Others are flaky on some platforms.
             (let* ((system ,(or (%current-target-system)
                                 (%current-system)))
                    (disabled-tests (cond
                                     ((string-prefix? "mips64" system)
                                      '("object_detector" ; timeout
                                        "data_io"))
                                     ((string-prefix? "armhf" system)
                                      '("learning_to_track"))
                                     ((string-prefix? "i686" system)
                                      '("optimization"))
                                     (else '()))))
               (for-each
                (lambda (test)
                  (substitute* "dlib/test/makefile"
                    (((string-append "SRC \\+= " test "\\.cpp")) "")))
                disabled-tests)
               #t)))
         (replace 'check
           (lambda _
             ;; No test target, so we build and run the unit tests here.
             (let ((test-dir (string-append "../dlib-" ,version "/dlib/test")))
               (with-directory-excursion test-dir
                 (invoke "make" "-j" (number->string (parallel-job-count)))
                 (invoke "./dtest" "--runall"))
               #t)))
         (add-after 'install 'delete-static-library
           (lambda* (#:key outputs #:allow-other-keys)
             (delete-file (string-append (assoc-ref outputs "out")
                                         "/lib/libdlib.a"))
             #t)))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ;; For tests.
       ("libnsl" ,libnsl)))
    (inputs
     `(("giflib" ,giflib)
       ("lapack" ,lapack)
       ("libjpeg" ,libjpeg)
       ("libpng" ,libpng)
       ("libx11" ,libx11)
       ("openblas" ,openblas)
       ("zlib" ,zlib)))
    (synopsis
     "Toolkit for making machine learning and data analysis applications in C++")
    (description
     "Dlib is a modern C++ toolkit containing machine learning algorithms and
tools.  It is used in both industry and academia in a wide range of domains
including robotics, embedded devices, mobile phones, and large high performance
computing environments.")
    (home-page "http://dlib.net")
    (license license:boost1.0)))

(define-public python-scikit-learn
  (package
    (name "python-scikit-learn")
    (version "0.20.3")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/scikit-learn/scikit-learn.git")
             (commit version)))
       (file-name (git-file-name name version))
       (sha256
        (base32
         "08aaby5zphfxy83mggg35bwyka7wk91l2qijh8kk0bl08dikq8dl"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'build 'build-ext
           (lambda _ (invoke "python" "setup.py" "build_ext" "--inplace") #t))
         (replace 'check
           (lambda _
             ;; Restrict OpenBLAS threads to prevent segfaults while testing!
             (setenv "OPENBLAS_NUM_THREADS" "1")

             ;; Some tests require write access to $HOME.
             (setenv "HOME" "/tmp")

             (invoke "pytest" "sklearn" "-m" "not network")))
         (add-before 'reset-gzip-timestamps 'make-files-writable
           (lambda* (#:key outputs #:allow-other-keys)
             ;; Make sure .gz files are writable so that the
             ;; 'reset-gzip-timestamps' phase can do its work.
             (let ((out (assoc-ref outputs "out")))
               (for-each make-file-writable
                         (find-files out "\\.gz$"))
               #t))))))
    (inputs
     `(("openblas" ,openblas)))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-pandas" ,python-pandas) ;for tests
       ("python-cython" ,python-cython)))
    (propagated-inputs
     `(("python-numpy" ,python-numpy)
       ("python-scipy" ,python-scipy)))
    (home-page "http://scikit-learn.org/")
    (synopsis "Machine Learning in Python")
    (description
     "Scikit-learn provides simple and efficient tools for data mining and
data analysis.")
    (license license:bsd-3)))

(define-public python2-scikit-learn
  (package-with-python2 python-scikit-learn))

(define-public python-autograd
  (let* ((commit "442205dfefe407beffb33550846434baa90c4de7")
         (revision "0")
         (version (git-version "0.0.0" revision commit)))
    (package
      (name "python-autograd")
      (home-page "https://github.com/HIPS/autograd")
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url home-page)
                      (commit commit)))
                (sha256
                 (base32
                  "189sv2xb0mwnjawa9z7mrgdglc1miaq93pnck26r28fi1jdwg0z4"))
                (file-name (git-file-name name version))))
      (version version)
      (build-system python-build-system)
      (native-inputs
       `(("python-nose" ,python-nose)
         ("python-pytest" ,python-pytest)))
      (propagated-inputs
       `(("python-future" ,python-future)
         ("python-numpy" ,python-numpy)))
      (arguments
       `(#:phases (modify-phases %standard-phases
                    (replace 'check
                      (lambda _
                        (invoke "py.test" "-v"))))))
      (synopsis "Efficiently computes derivatives of NumPy code")
      (description "Autograd can automatically differentiate native Python and
NumPy code.  It can handle a large subset of Python's features, including loops,
ifs, recursion and closures, and it can even take derivatives of derivatives
of derivatives.  It supports reverse-mode differentiation
(a.k.a. backpropagation), which means it can efficiently take gradients of
scalar-valued functions with respect to array-valued arguments, as well as
forward-mode differentiation, and the two can be composed arbitrarily.  The
main intended application of Autograd is gradient-based optimization.")
      (license license:expat))))

(define-public python2-autograd
  (package-with-python2 python-autograd))

(define-public lightgbm
  (package
    (name "lightgbm")
    (version "2.0.12")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/Microsoft/LightGBM/archive/v"
                    version ".tar.gz"))
              (sha256
               (base32
                "132zf0yk0545mg72hyzxm102g3hpb6ixx9hnf8zd2k55gas6cjj1"))
              (file-name (string-append name "-" version ".tar.gz"))))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-nose" ,python-nose)))
    (inputs
     `(("openmpi" ,openmpi)))
    (propagated-inputs
     `(("python-numpy" ,python-numpy)
       ("python-scipy" ,python-scipy)))
    (arguments
     `(#:configure-flags
       '("-DUSE_MPI=ON")
       #:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda* (#:key outputs #:allow-other-keys)
             (with-directory-excursion ,(string-append "../LightGBM-" version)
               (invoke "pytest" "tests/c_api_test/test_.py")))))))
    (build-system cmake-build-system)
    (home-page "https://github.com/Microsoft/LightGBM")
    (synopsis "Gradient boosting framework based on decision tree algorithms")
    (description "LightGBM is a gradient boosting framework that uses tree
based learning algorithms.  It is designed to be distributed and efficient with
the following advantages:

@itemize
@item Faster training speed and higher efficiency
@item Lower memory usage
@item Better accuracy
@item Parallel and GPU learning supported (not enabled in this package)
@item Capable of handling large-scale data
@end itemize\n")
    (license license:expat)))

(define-public vowpal-wabbit
  ;; Language bindings not included.
  (package
    (name "vowpal-wabbit")
    (version "8.5.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/JohnLangford/vowpal_wabbit/archive/"
                    version ".tar.gz"))
              (sha256
               (base32
                "0clp2kb7rk5sckhllxjr5a651awf4s8dgzg4659yh4hf5cqnf0gr"))
              (file-name (string-append name "-" version ".tar.gz"))))
    (inputs
     `(("boost" ,boost)
       ("zlib" ,zlib)))
    (arguments
     `(#:configure-flags
       (list (string-append "--with-boost="
                            (assoc-ref %build-inputs "boost")))))
    (build-system gnu-build-system)
    (home-page "https://github.com/JohnLangford/vowpal_wabbit")
    (synopsis "Fast machine learning library for online learning")
    (description "Vowpal Wabbit is a machine learning system with techniques
such as online, hashing, allreduce, reductions, learning2search, active, and
interactive learning.")
    (license license:bsd-3)))

(define-public python2-fastlmm
  (package
    (name "python2-fastlmm")
    (version "0.2.21")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "fastlmm" version ".zip"))
       (sha256
        (base32
         "1q8c34rpmwkfy3r4d5172pzdkpfryj561897z9r3x22gq7813x1m"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f ; some test files are missing
       #:python ,python-2)) ; only Python 2.7 is supported
    (propagated-inputs
     `(("python2-numpy" ,python2-numpy)
       ("python2-scipy" ,python2-scipy)
       ("python2-matplotlib" ,python2-matplotlib)
       ("python2-pandas" ,python2-pandas)
       ("python2-scikit-learn" ,python2-scikit-learn)
       ("python2-pysnptools" ,python2-pysnptools)))
    (native-inputs
     `(("unzip" ,unzip)
       ("python2-cython" ,python2-cython)
       ("python2-mock" ,python2-mock)
       ("python2-nose" ,python2-nose)))
    (home-page "http://research.microsoft.com/en-us/um/redmond/projects/mscompbio/fastlmm/")
    (synopsis "Perform genome-wide association studies on large data sets")
    (description
     "FaST-LMM, which stands for Factored Spectrally Transformed Linear Mixed
Models, is a program for performing both single-SNP and SNP-set genome-wide
association studies (GWAS) on extremely large data sets.")
    (license license:asl2.0)))

;; There have been no proper releases yet.
(define-public kaldi
  (let ((commit "2f95609f0bb085bd3a1dc5eb0a39f3edea59e606")
        (revision "1"))
    (package
      (name "kaldi")
      (version (git-version "0" revision commit))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/kaldi-asr/kaldi.git")
                      (commit commit)))
                (file-name (git-file-name name version))
                (sha256
                 (base32
                  "082qh3pfi7hvncylp4xsmkfahbd7gb0whdfa4rwrx7fxk9rdh3kz"))))
      (build-system gnu-build-system)
      (arguments
       `(#:test-target "test"
         #:phases
         (modify-phases %standard-phases
           (add-after 'unpack 'chdir
             (lambda _ (chdir "src") #t))
           (replace 'configure
             (lambda* (#:key build system inputs outputs #:allow-other-keys)
               (when (not (or (string-prefix? "x86_64" system)
                              (string-prefix? "i686" system)))
                 (substitute* "makefiles/linux_openblas.mk"
                   (("-msse -msse2") "")))
               (substitute* "makefiles/default_rules.mk"
                 (("/bin/bash") (which "bash")))
               (substitute* "Makefile"
                 (("ext_depend: check_portaudio")
                  "ext_depend:"))
               (substitute* '("online/Makefile"
                              "onlinebin/Makefile"
                              "gst-plugin/Makefile")
                 (("../../tools/portaudio/install")
                  (assoc-ref inputs "portaudio")))

               ;; This `configure' script doesn't support variables passed as
               ;; arguments, nor does it support "prefix".
               (let ((out (assoc-ref outputs "out"))
                     (openblas (assoc-ref inputs "openblas"))
                     (openfst (assoc-ref inputs "openfst")))
                 (substitute* "configure"
                   (("check_for_slow_expf;") "")
                   ;; This affects the RPATH and also serves as the installation
                   ;; directory.
                   (("KALDILIBDIR=`pwd`/lib")
                    (string-append "KALDILIBDIR=" out "/lib")))
                 (mkdir-p out) ; must exist
                 (setenv "CONFIG_SHELL" (which "bash"))
                 (setenv "OPENFST_VER" ,(package-version openfst))
                 (invoke "./configure"
                         "--use-cuda=no"
                         "--shared"
                         (string-append "--openblas-root=" openblas)
                         (string-append "--fst-root=" openfst)))))
           (add-after 'build 'build-ext-and-gstreamer-plugin
             (lambda _
               (invoke "make" "-C" "online" "depend")
               (invoke "make" "-C" "online")
               (invoke "make" "-C" "onlinebin" "depend")
               (invoke "make" "-C" "onlinebin")
               (invoke "make" "-C" "gst-plugin" "depend")
               (invoke "make" "-C" "gst-plugin")
               #t))
           ;; TODO: also install the executables.
           (replace 'install
             (lambda* (#:key outputs #:allow-other-keys)
               (let* ((out (assoc-ref outputs "out"))
                      (inc (string-append out "/include"))
                      (lib (string-append out "/lib")))
                 (mkdir-p lib)
                 ;; The build phase installed symlinks to the actual
                 ;; libraries.  Install the actual targets.
                 (for-each (lambda (file)
                             (let ((target (readlink file)))
                               (delete-file file)
                               (install-file target lib)))
                           (find-files lib "\\.so"))
                 ;; Install headers
                 (for-each (lambda (file)
                             (let ((target-dir (string-append inc "/" (dirname file))))
                               (install-file file target-dir)))
                           (find-files "." "\\.h"))
                 (install-file "gst-plugin/libgstonlinegmmdecodefaster.so"
                               (string-append lib "/gstreamer-1.0"))
                 #t))))))
      (inputs
       `(("alsa-lib" ,alsa-lib)
         ("gfortran" ,gfortran "lib")
         ("glib" ,glib)
         ("gstreamer" ,gstreamer)
         ("jack" ,jack-1)
         ("openblas" ,openblas)
         ("openfst" ,openfst)
         ("portaudio" ,portaudio)
         ("python" ,python)))
      (native-inputs
       `(("glib" ,glib "bin")             ; glib-genmarshal
         ("grep" ,grep)
         ("sed" ,sed)
         ("pkg-config" ,pkg-config)
         ("which" ,which)))
      (home-page "https://kaldi-asr.org/")
      (synopsis "Speech recognition toolkit")
      (description "Kaldi is an extensible toolkit for speech recognition
written in C++.")
      (license license:asl2.0))))

(define-public gst-kaldi-nnet2-online
  (let ((commit "617e43e73c7cc45eb9119028c02bd4178f738c4a")
        (revision "1"))
    (package
      (name "gst-kaldi-nnet2-online")
      (version (git-version "0" revision commit))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/alumae/gst-kaldi-nnet2-online.git")
                      (commit commit)))
                (file-name (git-file-name name version))
                (sha256
                 (base32
                  "0xh3w67b69818s6ib02ara4lw7wamjdmh4jznvkpzrs4skbs9jx9"))))
      (build-system gnu-build-system)
      (arguments
       `(#:tests? #f                    ; there are none
         #:make-flags
         (list (string-append "SHELL="
                              (assoc-ref %build-inputs "bash") "/bin/bash")
               (string-append "KALDI_ROOT="
                              (assoc-ref %build-inputs "kaldi-src"))
               (string-append "KALDILIBDIR="
                              (assoc-ref %build-inputs "kaldi") "/lib")
               "KALDI_FLAVOR=dynamic")
         #:phases
         (modify-phases %standard-phases
           (add-after 'unpack 'chdir
             (lambda _ (chdir "src") #t))
           (replace 'configure
             (lambda* (#:key inputs #:allow-other-keys)
               (let ((glib (assoc-ref inputs "glib")))
                 (setenv "CXXFLAGS" "-std=c++11 -fPIC")
                 (setenv "CPLUS_INCLUDE_PATH"
                         (string-append glib "/include/glib-2.0:"
                                        glib "/lib/glib-2.0/include:"
                                        (assoc-ref inputs "gstreamer")
                                        "/include/gstreamer-1.0:"
                                        (getenv "CPLUS_INCLUDE_PATH"))))
               (substitute* "Makefile"
                 (("include \\$\\(KALDI_ROOT\\)/src/kaldi.mk") "")
                 (("\\$\\(error Cannot find") "#"))))
           (add-before 'build 'build-depend
             (lambda* (#:key make-flags #:allow-other-keys)
               (apply invoke "make" "depend" make-flags)))
           (replace 'install
             (lambda* (#:key outputs #:allow-other-keys)
               (let* ((out (assoc-ref outputs "out"))
                      (lib (string-append out "/lib/gstreamer-1.0")))
                 (install-file "libgstkaldinnet2onlinedecoder.so" lib)
                 #t))))))
      (inputs
       `(("glib" ,glib)
         ("gstreamer" ,gstreamer)
         ("jansson" ,jansson)
         ("openfst" ,openfst)
         ("kaldi" ,kaldi)))
      (native-inputs
       `(("bash" ,bash)
         ("glib:bin" ,glib "bin")       ; glib-genmarshal
         ("kaldi-src" ,(package-source kaldi))
         ("pkg-config" ,pkg-config)))
      (home-page "https://kaldi-asr.org/")
      (synopsis "Gstreamer plugin for decoding speech")
      (description "This package provides a GStreamer plugin that wraps
Kaldi's @code{SingleUtteranceNnet2Decoder}.  It requires iVector-adapted DNN
acoustic models.  The iVectors are adapted to the current audio stream
automatically.")
      (license license:asl2.0))))

(define-public kaldi-gstreamer-server
  (let ((commit "1735ba49c5dc0ebfc184e45105fc600cd9f1f508")
        (revision "1"))
    (package
      (name "kaldi-gstreamer-server")
      (version (git-version "0" revision commit))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/alumae/kaldi-gstreamer-server.git")
                      (commit commit)))
                (file-name (git-file-name name version))
                (sha256
                 (base32
                  "0j701m7lbwmzqxsfanj882v7881hrbmpqybbczbxqpcbg8q34w0k"))))
      (build-system gnu-build-system)
      (arguments
       `(#:tests? #f ; there are no tests that can be run automatically
         #:modules ((guix build utils)
                    (guix build gnu-build-system)
                    (srfi srfi-26))
         #:phases
         (modify-phases %standard-phases
           (delete 'configure)
           (replace 'build
             (lambda* (#:key outputs #:allow-other-keys)
               ;; Disable hash randomization to ensure the generated .pycs
               ;; are reproducible.
               (setenv "PYTHONHASHSEED" "0")
               (with-directory-excursion "kaldigstserver"
                 (for-each (lambda (file)
                             (apply invoke
                                    `("python"
                                      "-m" "compileall"
                                      "-f" ; force rebuild
                                      ,file)))
                           (find-files "." "\\.py$")))
               #t))
           (replace 'install
             (lambda* (#:key inputs outputs #:allow-other-keys)
               (let* ((out (assoc-ref outputs "out"))
                      (bin (string-append out "/bin"))
                      (share (string-append out "/share/kaldi-gstreamer-server/")))
                 ;; Install Python files
                 (with-directory-excursion "kaldigstserver"
                   (for-each (cut install-file <> share)
                             (find-files "." ".*")))

                 ;; Install sample configuration files
                 (for-each (cut install-file <> share)
                           (find-files "." "\\.yaml"))

                 ;; Install executables
                 (mkdir-p bin)
                 (let* ((server (string-append bin "/kaldi-gst-server"))
                        (client (string-append bin "/kaldi-gst-client"))
                        (worker (string-append bin "/kaldi-gst-worker"))
                        (PYTHONPATH (getenv "PYTHONPATH"))
                        (GST_PLUGIN_PATH (string-append
                                          (assoc-ref inputs "gst-kaldi-nnet2-online")
                                          "/lib/gstreamer-1.0:${GST_PLUGIN_PATH}"))
                        (wrap (lambda (wrapper what)
                                (with-output-to-file wrapper
                                  (lambda _
                                    (format #t
                                            "#!~a
export PYTHONPATH=~a
export GST_PLUGIN_PATH=~a
exec ~a ~a/~a \"$@\"~%"
                                            (which "bash") PYTHONPATH GST_PLUGIN_PATH
                                            (which "python") share what)))
                                (chmod wrapper #o555))))
                   (for-each wrap
                             (list server client worker)
                             (list "master_server.py"
                                   "client.py"
                                   "worker.py")))
                 #t))))))
      (inputs
       `(("gst-kaldi-nnet2-online" ,gst-kaldi-nnet2-online)
         ("python2" ,python-2)
         ("python2-futures" ,python2-futures)
         ("python2-pygobject" ,python2-pygobject)
         ("python2-pyyaml" ,python2-pyyaml)
         ("python2-tornado" ,python2-tornado)
         ("python2-ws4py" ,python2-ws4py-for-kaldi-gstreamer-server)))
      (home-page "https://github.com/alumae/kaldi-gstreamer-server")
      (synopsis "Real-time full-duplex speech recognition server")
      (description "This is a real-time full-duplex speech recognition server,
based on the Kaldi toolkit and the GStreamer framework and implemented in
Python.")
      (license license:bsd-2))))

(define-public grpc
  (package
    (name "grpc")
    (version "1.16.1")
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "https://github.com/grpc/grpc.git")
                    (commit (string-append "v" version))))
              (file-name (git-file-name name version))
              (sha256
               (base32
                "1jimqz3115f9pli5w6ik9wi7mjc7ix6y7yrq4a1ab9fc3dalj7p2"))))
    (build-system cmake-build-system)
    (arguments
     `(#:tests? #f ; no test target
       #:configure-flags
       (list "-DgRPC_ZLIB_PROVIDER=package"
             "-DgRPC_CARES_PROVIDER=package"
             "-DgRPC_SSL_PROVIDER=package"
             "-DgRPC_PROTOBUF_PROVIDER=package")))
    (inputs
     `(("c-ares" ,c-ares-next)
       ("openssl" ,openssl)
       ("zlib" ,zlib)))
    (native-inputs
     `(("protobuf" ,protobuf-next)
       ("python" ,python-wrapper)))
    (home-page "https://grpc.io")
    (synopsis "High performance universal RPC framework")
    (description "gRPC is a modern open source high performance @dfn{Remote
Procedure Call} (RPC) framework that can run in any environment.  It can
efficiently connect services in and across data centers with pluggable support
for load balancing, tracing, health checking and authentication.  It is also
applicable in last mile of distributed computing to connect devices, mobile
applications and browsers to backend services.")
    (license license:asl2.0)))

;; Note that Tensorflow includes a "third_party" directory, which seems to not
;; only contain modified subsets of upstream library source code, but also
;; adapter headers provided by Google (such as the fft.h header, which is not
;; part of the upstream project code).  The Tensorflow code includes headers
;; from the "third_party" directory.  It does not look like we can replace
;; these headers with unmodified upstream files, so we keep them.
(define-public tensorflow
  (package
    (name "tensorflow")
    (version "1.9.0")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/tensorflow/tensorflow.git")
             (commit (string-append "v" version))))
       (file-name (string-append "tensorflow-" version "-checkout"))
       (sha256
        (base32
         "0a9kwha395g3wgxfwln5j8vn9nkspmd75xldrlqdq540w996g8xa"))))
    (build-system cmake-build-system)
    (arguments
     `(#:tests? #f                      ; no "check" target
       #:build-type "Release"
       #:configure-flags
       (let ((protobuf (assoc-ref %build-inputs "protobuf"))
             (protobuf:native (assoc-ref %build-inputs "protobuf:native"))
             (jsoncpp (assoc-ref %build-inputs "jsoncpp"))
             (snappy (assoc-ref %build-inputs "snappy"))
             (sqlite (assoc-ref %build-inputs "sqlite")))
         (list
          ;; Use protobuf from Guix
          (string-append "-Dprotobuf_STATIC_LIBRARIES="
                         protobuf "/lib/libprotobuf.so")
          (string-append "-DPROTOBUF_PROTOC_EXECUTABLE="
                         protobuf:native "/bin/protoc")

          ;; Use snappy from Guix
          (string-append "-Dsnappy_STATIC_LIBRARIES="
                         snappy "/lib/libsnappy.so")
          ;; Yes, this is not actually the include directory but a prefix...
          (string-append "-Dsnappy_INCLUDE_DIR=" snappy)

          ;; Use jsoncpp from Guix
          (string-append "-Djsoncpp_STATIC_LIBRARIES="
                         jsoncpp "/lib/libjsoncpp.so")
          ;; Yes, this is not actually the include directory but a prefix...
          (string-append "-Djsoncpp_INCLUDE_DIR=" jsoncpp)

          ;; Use sqlite from Guix
          (string-append "-Dsqlite_STATIC_LIBRARIES="
                         sqlite "/lib/libsqlite.a")

          ;; Use system libraries wherever possible.  Currently, this
          ;; only affects zlib.
          "-Dsystemlib_ALL=ON"
          "-Dtensorflow_ENABLE_POSITION_INDEPENDENT_CODE=ON"
          "-Dtensorflow_BUILD_SHARED_LIB=ON"
          "-Dtensorflow_OPTIMIZE_FOR_NATIVE_ARCH=OFF"
          "-Dtensorflow_ENABLE_SSL_SUPPORT=OFF"
          "-Dtensorflow_BUILD_CONTRIB_KERNELS=OFF"))
       #:make-flags
       (list "CC=gcc")
       #:modules ((ice-9 ftw)
                  (guix build utils)
                  (guix build cmake-build-system))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'set-source-file-times-to-1980
           ;; At the end of the tf_python_build_pip_package target, a ZIP
           ;; archive should be generated via bdist_wheel, but it fails with
           ;; "ZIP does not support timestamps before 1980".  Luckily,
           ;; SOURCE_DATE_EPOCH is respected, which we set to some time in
           ;; 1980.
           (lambda _ (setenv "SOURCE_DATE_EPOCH" "315532800") #t))
         ;; See https://github.com/tensorflow/tensorflow/issues/20517#issuecomment-406373913
         (add-after 'unpack 'python3.7-compatibility
           (lambda _
             (substitute* '("tensorflow/python/eager/pywrap_tfe_src.cc"
                            "tensorflow/python/lib/core/ndarray_tensor.cc"
                            "tensorflow/python/lib/core/py_func.cc")
               (("PyUnicode_AsUTF8") "(char *)PyUnicode_AsUTF8"))
             (substitute* "tensorflow/c/eager/c_api.h"
               (("unsigned char async")
                "unsigned char is_async"))

             ;; Remove dependency on tensorboard, a complicated but probably
             ;; optional package.
             (substitute* "tensorflow/tools/pip_package/setup.py"
               ((".*'tensorboard >.*") ""))
             #t))
         (add-after 'python3.7-compatibility 'chdir
           (lambda _ (chdir "tensorflow/contrib/cmake") #t))
         (add-after 'chdir 'disable-downloads
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* (find-files "external" "\\.cmake$")
               (("GIT_REPOSITORY.*") "")
               (("GIT_TAG.*") "")
               (("PREFIX ")
                "DOWNLOAD_COMMAND \"\"\nPREFIX "))

             ;; Use packages from Guix
             (let ((grpc (assoc-ref inputs "grpc")))
               (substitute* "CMakeLists.txt"
                 ;; Sqlite
                 (("include\\(sqlite\\)") "")
                 (("\\$\\{sqlite_STATIC_LIBRARIES\\}")
                  (string-append (assoc-ref inputs "sqlite")
                                 "/lib/libsqlite3.so"))
                 (("sqlite_copy_headers_to_destination") "")

                 ;; PNG
                 (("include\\(png\\)") "")
                 (("\\$\\{png_STATIC_LIBRARIES\\}")
                  (string-append (assoc-ref inputs "libpng")
                                 "/lib/libpng16.so"))
                 (("png_copy_headers_to_destination") "")

                 ;; JPEG
                 (("include\\(jpeg\\)") "")
                 (("\\$\\{jpeg_STATIC_LIBRARIES\\}")
                  (string-append (assoc-ref inputs "libjpeg")
                                 "/lib/libjpeg.so"))
                 (("jpeg_copy_headers_to_destination") "")

                 ;; GIF
                 (("include\\(gif\\)") "")
                 (("\\$\\{gif_STATIC_LIBRARIES\\}")
                  (string-append (assoc-ref inputs "giflib")
                                 "/lib/libgif.so"))
                 (("gif_copy_headers_to_destination") "")

                 ;; lmdb
                 (("include\\(lmdb\\)") "")
                 (("\\$\\{lmdb_STATIC_LIBRARIES\\}")
                  (string-append (assoc-ref inputs "lmdb")
                                 "/lib/liblmdb.so"))
                 (("lmdb_copy_headers_to_destination") "")

                 ;; Protobuf
                 (("include\\(protobuf\\)") "")
                 (("protobuf_copy_headers_to_destination") "")
                 (("^ +protobuf") "")

                 ;; gRPC
                 (("include\\(grpc\\)")
                  "find_package(grpc REQUIRED NAMES gRPC)")
                 (("list\\(APPEND tensorflow_EXTERNAL_DEPENDENCIES grpc\\)") "")

                 ;; Eigen
                 (("include\\(eigen\\)")
                  (string-append "find_package(eigen REQUIRED NAMES Eigen3)
set(eigen_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/external/eigen_archive "
                                 (assoc-ref inputs "eigen") "/include/eigen3)"))
                 (("^ +eigen") "")

                 ;; snappy
                 (("include\\(snappy\\)")
                  "add_definitions(-DTF_USE_SNAPPY)")
                 (("list\\(APPEND tensorflow_EXTERNAL_DEPENDENCIES snappy\\)") "")

                 ;; jsoncpp
                 (("include\\(jsoncpp\\)") "")
                 (("^ +jsoncpp") ""))

               (substitute* "tf_core_framework.cmake"
                 ((" grpc") "")
                 (("\\$\\{GRPC_BUILD\\}/grpc_cpp_plugin")
                  (which "grpc_cpp_plugin"))
                 ;; Link with gRPC libraries
                 (("add_library\\(tf_protos_cc.*" m)
                  (string-append m
                                 (format #f "\ntarget_link_libraries(tf_protos_cc PRIVATE \
~a/lib/libgrpc++_unsecure.a \
~a/lib/libgrpc_unsecure.a \
~a/lib/libaddress_sorting.a \
~a/lib/libgpr.a \
~a//lib/libcares.so
)\n"
                                         grpc grpc grpc grpc
                                         (assoc-ref inputs "c-ares"))))))
             (substitute* "tf_tools.cmake"
               (("add_dependencies\\(\\$\\{proto_text.*") ""))
             ;; Remove dependency on bundled grpc
             (substitute* "tf_core_distributed_runtime.cmake"
               (("tf_core_cpu grpc") "tf_core_cpu"))

             ;; This directory is a dependency of many targets.
             (mkdir-p "protobuf")
             #t))
         (add-after 'configure 'unpack-third-party-sources
           (lambda* (#:key inputs #:allow-other-keys)
             ;; This is needed to configure bundled packages properly.
             (setenv "CONFIG_SHELL" (which "bash"))
             (for-each
              (lambda (name)
                (let* ((what  (assoc-ref inputs (string-append name "-src")))
                       (name* (string-map (lambda (c)
                                            (if (char=? c #\-)
                                                #\_ c)) name))
                       (where (string-append "../build/" name* "/src/" name*)))
                  (cond
                   ((string-suffix? ".zip" what)
                    (mkdir-p where)
                    (with-directory-excursion where
                      (invoke "unzip" what)))
                   ((string-suffix? ".tar.gz" what)
                    (mkdir-p where)
                    (invoke "tar" "xf" what
                            "-C" where "--strip-components=1"))
                   (else
                    (let ((parent (dirname where)))
                      (mkdir-p parent)
                      (with-directory-excursion parent
                        (when (file-exists? name*)
                          (delete-file-recursively name*))
                        (copy-recursively what name*)
                        (map make-file-writable
                             (find-files name* ".*"))))))))
              (list "boringssl"
                    "cub"
                    "double-conversion"
                    "farmhash"
                    "fft2d"
                    "highwayhash"
                    "nsync"
                    "re2"))

             (rename-file "../build/cub/src/cub/cub-1.8.0/"
                          "../build/cub/src/cub/cub/")
             #t))
         (add-after 'unpack 'fix-python-build
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (mkdir-p "protobuf-src")
             (invoke "tar" "xf" (assoc-ref inputs "protobuf:src")
                     "-C" "protobuf-src" "--strip-components=1")
             (mkdir-p "eigen-src")
             (invoke "tar" "xf" (assoc-ref inputs "eigen:src")
                     "-C" "eigen-src" "--strip-components=1")

             (substitute* "tensorflow/contrib/cmake/tf_python.cmake"
               ;; Ensure that all Python dependencies can be found at build time.
               (("PYTHONPATH=\\$\\{CMAKE_CURRENT_BINARY_DIR\\}/tf_python" m)
                (string-append m ":" (getenv "PYTHONPATH")))
               ;; Take protobuf source files from our source package.
               (("\\$\\{CMAKE_CURRENT_BINARY_DIR\\}/protobuf/src/protobuf/src/google")
                (string-append (getcwd) "/protobuf-src/src/google")))

             (substitute* '("tensorflow/contrib/cmake/tf_shared_lib.cmake"
                            "tensorflow/contrib/cmake/tf_python.cmake")
               ;; Take Eigen source files from our source package.
               (("\\$\\{CMAKE_CURRENT_BINARY_DIR\\}/eigen/src/eigen/")
                (string-append (getcwd) "/eigen-src/"))
               ;; Take Eigen headers from our own package.
               (("\\$\\{CMAKE_CURRENT_BINARY_DIR\\}/external/eigen_archive")
                (string-append (assoc-ref inputs "eigen") "/include/eigen3")))

             ;; Correct the RUNPATH of ops libraries generated for Python.
             ;; TODO: this doesn't work :(
             ;; /gnu/store/...-tensorflow-1.9.0/lib/python3.7/site-packages/tensorflow/contrib/seq2seq/python/ops/lib_beam_search_ops.so:
             ;; warning: RUNPATH contains bogus entries: ("/tmp/guix-build-tensorflow-1.9.0.drv-0/source/tensorflow/contrib/build")
             ;; /gnu/store/...-tensorflow-1.9.0/lib/python3.7/site-packages/tensorflow/contrib/seq2seq/python/ops/lib_beam_search_ops.so:
             ;; error: depends on 'libpywrap_tensorflow_internal.so', which
             ;; cannot be found in RUNPATH ...
             (substitute* "tensorflow/contrib/cmake/tf_cc_ops.cmake"
               (("set_target_properties.*")
                (string-append "set_target_properties(${_AT_TARGET} PROPERTIES \
COMPILE_FLAGS ${target_compile_flags} \
INSTALL_RPATH_USE_LINK_PATH TRUE \
INSTALL_RPATH " (assoc-ref outputs "out") "/lib)\n")))
             #t))
         (add-after 'build 'build-pip-package
           (lambda* (#:key outputs #:allow-other-keys)
             (setenv "LDFLAGS"
                     (string-append "-Wl,-rpath="
                                    (assoc-ref outputs "out") "/lib"))
             (invoke "make" "tf_python_build_pip_package")
             #t))
         (add-after 'build-pip-package 'install-python
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out"))
                   (wheel (car (find-files "../build/tf_python/dist/" "\\.whl$"))))
               (invoke "python" "-m" "pip" "install" wheel
                       (string-append "--prefix=" out))

               ;; XXX: broken RUNPATH, see fix-python-build phase.
               (delete-file
                (string-append
                 out "/lib/python3.7/site-packages/tensorflow/contrib/"
                 "seq2seq/python/ops/lib_beam_search_ops.so"))
               #t))))))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("protobuf:native" ,protobuf-next) ; protoc
       ("protobuf:src" ,(package-source protobuf-next))
       ("eigen:src" ,(package-source eigen-for-tensorflow))
       ;; The commit hashes and URLs for third-party source code are taken
       ;; from "tensorflow/workspace.bzl".
       ("boringssl-src"
        ,(let ((commit "ee7aa02")
               (revision "1"))
           (origin
             (method git-fetch)
             (uri (git-reference
                   (url "https://boringssl.googlesource.com/boringssl")
                   (commit commit)))
             (file-name (string-append "boringssl-0-" revision
                                       (string-take commit 7)
                                       "-checkout"))
             (sha256
              (base32
               "1jf693q0nw0adsic6cgmbdx6g7wr4rj4vxa8j1hpn792fqhd8wgw")))))
       ("cub-src"
        ,(let ((version "1.8.0"))
           (origin
             (method url-fetch)
             (uri (string-append "https://mirror.bazel.build/github.com/NVlabs/"
                                 "cub/archive/" version ".zip"))
             (file-name (string-append "cub-" version ".zip"))
             (sha256
              (base32
               "1hsqikqridb90dkxkjr2918dcry6pfh46ccnwrzawl56aamhdykb")))))
       ("double-conversion-src"
        ,(let ((commit "5664746")
               (revision "1"))
           (origin
             (method git-fetch)
             (uri (git-reference
                   (url "https://github.com/google/double-conversion.git")
                   (commit commit)))
             (file-name
              (git-file-name "double-conversion"
                             (string-append "0-" revision "."
                                            (string-take commit 7))))
             (sha256
              (base32
               "1h5lppqqxcvdg5jq42i5msgwx20ryij3apvmndflngrgdpc04gn1")))))
       ("farmhash-src"
        ,(let ((commit "816a4ae622e964763ca0862d9dbd19324a1eaf45"))
           (origin
             (method url-fetch)
             (uri (string-append
                   "https://mirror.bazel.build/github.com/google/farmhash/archive/"
                   commit ".tar.gz"))
             (file-name (string-append "farmhash-0-" (string-take commit 7)
                                       ".tar.gz"))
             (sha256
              (base32
               "185b2xdxl4d4cnsnv6abg8s22gxvx8673jq2yaq85bz4cdy58q35")))))
       ;; The license notice on the home page at
       ;; http://www.kurims.kyoto-u.ac.jp/~ooura/fft.html says:
       ;;   Copyright Takuya OOURA, 1996-2001
       ;;
       ;;   You may use, copy, modify and distribute this code for any purpose
       ;;   (include commercial use) and without fee. Please refer to this
       ;;   package when you modify this code.
       ;;
       ;; We take the identical tarball from the Bazel mirror, because the URL
       ;; at the home page is not versioned and might change.
       ("fft2d-src"
        ,(origin
           (method url-fetch)
           (uri "https://mirror.bazel.build/www.kurims.kyoto-u.ac.jp/~ooura/fft.tgz")
           (file-name "fft2d.tar.gz")
           (sha256
            (base32
             "15jjkfvhqvl2c0753d2di8hz0pyzn598g74wqy79awdrf1y67fsj"))))
       ("highwayhash-src"
        ,(let ((commit "be5edafc2e1a455768e260ccd68ae7317b6690ee")
               (revision "1"))
           (origin
             (method git-fetch)
             (uri (git-reference
                   (url "https://github.com/google/highwayhash.git")
                   (commit commit)))
             (file-name (string-append "highwayhash-0-" revision
                                       (string-take commit 7)
                                       "-checkout"))
             (sha256
              (base32
               "154jwf98cyy54hldr94pgjn85zynly3abpnc1avmb8a18lzwjyb6")))))
       ("nsync-src"
        ,(let ((version "0559ce013feac8db639ee1bf776aca0325d28777")
               (revision "1"))
           (origin
             (method url-fetch)
             (uri (string-append "https://mirror.bazel.build/"
                                 "github.com/google/nsync/archive/"
                                 version ".tar.gz"))
             (file-name (string-append "nsync-0." revision
                                       "-" (string-take version 7)
                                       ".tar.gz"))
             (sha256
              (base32
               "0qdkyqym34x739mmzv97ah5r7ph462v5xkxqxvidmcfqbi64b132")))))
       ("re2-src"
        ,(let ((commit "e7efc48")
               (revision "1"))
           (origin
             (method git-fetch)
             (uri (git-reference
                   (url "https://github.com/google/re2")
                   (commit commit)))
             (file-name (string-append "re2-0-" revision
                                       (string-take commit 7)
                                       "-checkout"))
             (sha256
              (base32
               "161g9841rjfsy5pn52fcis0s9hdr7rxvb06pad38j5rppfihvign")))))
       ("googletest" ,googletest)
       ("swig" ,swig)
       ("unzip" ,unzip)))
    (propagated-inputs
     `(("python-absl-py" ,python-absl-py)
       ("python-astor" ,python-astor)
       ("python-gast" ,python-gast)
       ("python-grpcio" ,python-grpcio)
       ("python-numpy" ,python-numpy)
       ("python-protobuf" ,python-protobuf-next)
       ("python-six" ,python-six)
       ("python-termcolo" ,python-termcolor)
       ("python-wheel" ,python-wheel)))
    (inputs
     `(("c-ares" ,c-ares-next)
       ("eigen" ,eigen-for-tensorflow)
       ("gemmlowp" ,gemmlowp-for-tensorflow)
       ("lmdb" ,lmdb)
       ("libjpeg" ,libjpeg)
       ("libpng" ,libpng)
       ("giflib" ,giflib)
       ("grpc" ,grpc)
       ("jsoncpp" ,jsoncpp-for-tensorflow)
       ("snappy" ,snappy)
       ("sqlite" ,sqlite)
       ("protobuf" ,protobuf-next)
       ("python" ,python-wrapper)
       ("zlib" ,zlib)))
    (home-page "https://tensorflow.org")
    (synopsis "Machine learning framework")
    (description
     "TensorFlow is a flexible platform for building and training machine
learning models.  It provides a library for high performance numerical
computation and includes high level Python APIs, including both a sequential
API for beginners that allows users to build models quickly by plugging
together building blocks and a subclassing API with an imperative style for
advanced research.")
    (license license:asl2.0)))

(define-public python-iml
  (package
    (name "python-iml")
    (version "0.6.2")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "iml" version))
       (sha256
        (base32
         "1k8szlpm19rcwcxdny9qdm3gmaqq8akb4xlvrzyz8c2d679aak6l"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("ipython" ,python-ipython)
       ("nose" ,python-nose)
       ("numpy" ,python-numpy)
       ("pandas" ,python-pandas)
       ("scipy" ,python-scipy)))
    (home-page "http://github.com/interpretable-ml/iml")
    (synopsis "Interpretable Machine Learning (iML) package")
    (description "Interpretable ML (iML) is a set of data type objects,
visualizations, and interfaces that can be used by any method designed to
explain the predictions of machine learning models (or really the output of
any function).  It currently contains the interface and IO code from the Shap
project, and it will potentially also do the same for the Lime project.")
    (license license:expat)))

(define-public python-keras-applications
  (package
    (name "python-keras-applications")
    (version "1.0.8")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Keras_Applications" version))
       (sha256
        (base32
         "1rcz31ca4axa6kzhjx4lwqxbg4wvlljkj8qj9a7p9sfd5fhzjyam"))))
    (build-system python-build-system)
    ;; The tests require Keras, but this package is needed to build Keras.
    (arguments '(#:tests? #f))
    (propagated-inputs
     `(("python-h5py" ,python-h5py)
       ("python-numpy" ,python-numpy)))
    (native-inputs
     `(("python-pytest" ,python-pytest)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-pytest-pep8" ,python-pytest-pep8)
       ("python-pytest-xdist" ,python-pytest-xdist)))
    (home-page "https://github.com/keras-team/keras-applications")
    (synopsis "Reference implementations of popular deep learning models")
    (description
     "This package provides reference implementations of popular deep learning
models for use with the Keras deep learning framework.")
    (license license:expat)))

(define-public python-keras-preprocessing
  (package
    (name "python-keras-preprocessing")
    (version "1.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Keras_Preprocessing" version))
       (sha256
        (base32
         "1r98nm4k1svsqjyaqkfk23i31bl1kcfcyp7094yyj3c43phfp3as"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-numpy" ,python-numpy)
       ("python-six" ,python-six)))
    (native-inputs
     `(("python-pandas" ,python-pandas)
       ("python-pillow" ,python-pillow)
       ("python-pytest" ,python-pytest)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-pytest-xdist" ,python-pytest-xdist)
       ("tensorflow" ,tensorflow)))
    (home-page "https://github.com/keras-team/keras-preprocessing/")
    (synopsis "Data preprocessing and augmentation for deep learning models")
    (description
     "Keras Preprocessing is the data preprocessing and data augmentation
module of the Keras deep learning library.  It provides utilities for working
with image data, text data, and sequence data.")
    (license license:expat)))

(define-public python-keras
  (package
    (name "python-keras")
    (version "2.2.4")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "Keras" version))
       (sha256
        (base32
         "1j8bsqzh49vjdxy6l1k4iwax5vpjzniynyd041xjavdzvfii1dlh"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'remove-tests-for-unavailable-features
           (lambda _
             (delete-file "keras/backend/theano_backend.py")
             (delete-file "keras/backend/cntk_backend.py")
             (delete-file "tests/keras/backend/backend_test.py")

             ;; FIXME: This doesn't work because Tensorflow is missing the
             ;; coder ops library.
             (delete-file "tests/keras/test_callbacks.py")
             #t))
         (replace 'check
           (lambda _
             ;; These tests attempt to download data files from the internet.
             (delete-file "tests/integration_tests/test_datasets.py")
             (delete-file "tests/integration_tests/imagenet_utils_test.py")

             (setenv "PYTHONPATH"
                     (string-append (getcwd) "/build/lib:"
                                    (getenv "PYTHONPATH")))
             (invoke "py.test" "-v"
                     "-p" "no:cacheprovider"
                     "--ignore" "keras/utils"))))))
    (propagated-inputs
     `(("python-h5py" ,python-h5py)
       ("python-keras-applications" ,python-keras-applications)
       ("python-keras-preprocessing" ,python-keras-preprocessing)
       ("python-numpy" ,python-numpy)
       ("python-pydot" ,python-pydot)
       ("python-pyyaml" ,python-pyyaml)
       ("python-scipy" ,python-scipy)
       ("python-six" ,python-six)
       ("tensorflow" ,tensorflow)
       ("graphviz" ,graphviz)))
    (native-inputs
     `(("python-pandas" ,python-pandas)
       ("python-pytest" ,python-pytest)
       ("python-pytest-cov" ,python-pytest-cov)
       ("python-pytest-pep8" ,python-pytest-pep8)
       ("python-pytest-timeout" ,python-pytest-timeout)
       ("python-pytest-xdist" ,python-pytest-xdist)
       ("python-sphinx" ,python-sphinx)
       ("python-requests" ,python-requests)))
    (home-page "https://github.com/keras-team/keras")
    (synopsis "High-level deep learning framework")
    (description "Keras is a high-level neural networks API, written in Python
and capable of running on top of TensorFlow.  It was developed with a focus on
enabling fast experimentation.  Use Keras if you need a deep learning library
that:

@itemize
@item Allows for easy and fast prototyping (through user friendliness,
  modularity, and extensibility).
@item Supports both convolutional networks and recurrent networks, as well as
  combinations of the two.
@item Runs seamlessly on CPU and GPU.
@end itemize\n")
    (license license:expat)))
