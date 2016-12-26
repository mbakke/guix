;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015 Vicente Vera Parra <vicentemvp@gmail.com>
;;; Copyright © 2016 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Pjotr Prins <pjotr.guix@thebird.nl>
;;; Copyright © 2016 Roel Janssen <roel@gnu.org>
;;; Copyright © 2016 Ben Woodcroft <donttrustben@gmail.com>
;;; Copyright © 2016 Raoul Bonnal <ilpuccio.febo@gmail.com>
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

(define-module (gnu packages statistics)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix utils)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system r)
  #:use-module (guix build-system python)
  #:use-module (gnu packages)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages gettext)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages haskell)
  #:use-module (gnu packages icu4c)
  #:use-module (gnu packages image)
  #:use-module (gnu packages java)
  #:use-module (gnu packages machine-learning)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages pcre)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages ssh)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages base)
  #:use-module (gnu packages web)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages zip)
  #:use-module (srfi srfi-1))


(define-public pspp
  (package
    (name "pspp")
    (version "0.10.2")
    (source
     (origin
      (method url-fetch)
      (uri (string-append "mirror://gnu/pspp/pspp-"
                          version ".tar.gz"))
      (sha256
       (base32
        "1afsq0a3iij64qacczvwhk81qg0q5rfqm055y5h9ls28d6paqz7p"))))
    (build-system gnu-build-system)
    (inputs
     `(("cairo" ,cairo)
       ("gettext" ,gettext-minimal)
       ("gsl" ,gsl)
       ("libxml2" ,libxml2)
       ("pango" ,pango)
       ("readline" ,readline)
       ("gtk" ,gtk+)
       ("gtksourceview" ,gtksourceview)
       ("zlib" ,zlib)))
    (native-inputs
     `(("glib" ,glib "bin")             ;for glib-genmarshal
       ("perl" ,perl)
       ("pkg-config" ,pkg-config)))
    (home-page "http://www.gnu.org/software/pspp/")
    (synopsis "Statistical analysis")
    (description
     "GNU PSPP is a statistical analysis program.  It can perform
descriptive statistics, T-tests, linear regression and non-parametric tests.
It features both a graphical interface as well as command-line input.  PSPP
is designed to interoperate with Gnumeric, LibreOffice and OpenOffice.  Data
can be imported from spreadsheets, text files and database sources and it can
be output in text, PostScript, PDF or HTML.")
    (license license:gpl3+)))

(define-public r
  (package
    (name "r")
    (version "3.3.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://cran/src/base/R-"
                                  (version-prefix version 1) "/R-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0k2i9qdd83g09fcpls2198q4ykxkii5skczb514gnx7mx4hsv56j"))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags
       (list (string-append "LDFLAGS=-Wl,-rpath="
                            (assoc-ref %outputs "out")
                            "/lib/R/lib"))
       #:phases
       (modify-phases %standard-phases
         (add-before 'configure 'patch-uname
           (lambda* (#:key inputs #:allow-other-keys)
             (let ((uname-bin (string-append (assoc-ref inputs "coreutils")
                                             "/bin/uname")))
               (substitute* "src/scripts/R.sh.in"
                 (("uname") uname-bin)))
             #t))
         (add-before
          'configure 'set-default-pager
          ;; Set default pager to "cat", because otherwise it is "false",
          ;; making "help()" print nothing at all.
          (lambda _ (setenv "PAGER" "cat") #t))
         (add-before 'check 'set-timezone
          ;; Some tests require the timezone to be set.
          (lambda* (#:key inputs #:allow-other-keys)
            (setenv "TZ" "UTC")
            (setenv "TZDIR"
                    (string-append (assoc-ref inputs "tzdata")
                                   "/share/zoneinfo"))
            #t))
         (add-after 'build 'make-info
          (lambda _ (zero? (system* "make" "info"))))
         (add-after 'build 'install-info
          (lambda _ (zero? (system* "make" "install-info")))))
       #:configure-flags
       '("--with-cairo"
         "--with-blas=-lopenblas"
         "--with-libpng"
         "--with-jpeglib"
         "--with-libtiff"
         "--with-ICU"
         "--enable-R-shlib"
         "--enable-BLAS-shlib"
         "--with-system-zlib"
         "--with-system-bzlib"
         "--with-system-pcre"
         "--with-system-tre"
         "--with-system-xz")))
    ;; R has some support for Java.  When the JDK is available at configure
    ;; time environment variables pointing to the JDK will be recorded under
    ;; $R_HOME/etc and ./tools/getsp.java will be compiled which is used by "R
    ;; CMD javareconf".  "R CMD javareconf" appears to only be used to update
    ;; the recorded environment variables in $R_HOME/etc.  Refer to
    ;; https://cran.r-project.org/doc/manuals/r-release/R-admin.html#Java-support
    ;; for additional information.

    ;; As the JDK is a rather large input with only very limited effects on R,
    ;; we decided to drop it.
    (native-inputs
     `(("bzip2" ,bzip2)
       ("perl" ,perl)
       ("pkg-config" ,pkg-config)
       ("texinfo" ,texinfo) ; for building HTML manuals
       ("which" ,which) ; for tests/Examples/base-Ex.R
       ("xz" ,xz)))
    (inputs
     `(;; We need not only cairo here, but pango to ensure that tests for the
       ;; "cairo" bitmapType plotting backend succeed.
       ("pango" ,pango)
       ("coreutils" ,coreutils)
       ("curl" ,curl)
       ("tzdata" ,tzdata)
       ("openblas" ,openblas)
       ("gfortran" ,gfortran)
       ("icu4c" ,icu4c)
       ("libjpeg" ,libjpeg)
       ("libpng" ,libpng)
       ("libtiff" ,libtiff)
       ("libxt" ,libxt)
       ("pcre" ,pcre)
       ("readline" ,readline)
       ("zlib" ,zlib)))
    (native-search-paths
     (list (search-path-specification
            (variable "R_LIBS_SITE")
            (files (list "site-library/")))))
    (home-page "http://www.r-project.org/")
    (synopsis "Environment for statistical computing and graphics")
    (description
     "R is a language and environment for statistical computing and graphics.
It provides a variety of statistical techniques, such as linear and nonlinear
modeling, classical statistical tests, time-series analysis, classification
and clustering.  It also provides robust support for producing
publication-quality data plots.  A large amount of 3rd-party packages are
available, greatly increasing its breadth and scope.")
    (license license:gpl3+)))

(define-public r-bit
  (package
    (name "r-bit")
    (version "1.1-12")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "bit" version))
       (sha256
        (base32
         "0a6ig6nnjzq80r2ll4hc74za3xwzbzig6wlyb4dby0knzf3iqa6f"))))
    (build-system r-build-system)
    (home-page "http://ff.r-forge.r-project.org")
    (synopsis "Class for vectors of 1-bit booleans")
    (description
     "This package provides bitmapped vectors of booleans (no @code{NA}s),
coercion from and to logicals, integers and integer subscripts, fast boolean
operators and fast summary statistics.  With @code{bit} class vectors of true
binary booleans, @code{TRUE} and @code{FALSE} can be stored with 1 bit only.")
    (license license:gpl2)))

(define-public r-bit64
  (package
    (name "r-bit64")
    (version "0.9-5")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "bit64" version))
       (sha256
        (base32
         "0fz5m3fhvxgwjl76maag7yn0zdw24rx34gy6v77378fajag9yllg"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-bit" ,r-bit)))
    (home-page "http://ff.r-forge.r-project.org/")
    (synopsis "S3 class for vectors of 64 bit integers")
    (description
     "The bit64 package provides serializable S3 atomic 64 bit (signed)
integers that can be used in vectors, matrices, arrays and @code{data.frames}.
Methods are available for coercion from and to logicals, integers, doubles,
characters and factors as well as many elementwise and summary functions.
Many fast algorithmic operations such as @code{match} and @code{order} support
interactive data exploration and manipulation and optionally leverage
caching.")
    (license license:gpl2)))

(define-public r-colorspace
  (package
    (name "r-colorspace")
    (version "1.2-7")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "colorspace" version))
       (sha256
        (base32 "0flw97iwwpkxy6si9cn982jhl61wb1rxi3r0nz2xxf0c3fzw18d5"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/colorspace")
    (synopsis "Color space manipulation")
    (description
     "This package carries out a mapping between assorted color spaces
including RGB, HSV, HLS, CIEXYZ, CIELUV, HCL (polar CIELUV), CIELAB and polar
CIELAB.  Qualitative, sequential, and diverging color palettes based on HCL
colors are provided.")
    (license license:bsd-3)))

(define-public r-dichromat
  (package
    (name "r-dichromat")
    (version "2.0-0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "dichromat" version))
       (sha256
        (base32 "1l8db1nk29ccqg3mkbafvfiw0775iq4gapysf88xq2zp6spiw59i"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/dichromat")
    (synopsis "Color schemes for dichromats")
    (description
     "Dichromat collapses red-green or green-blue distinctions to simulate the
effects of different types of color-blindness.")
    (license license:gpl2+)))

(define-public r-digest
  (package
    (name "r-digest")
    (version "0.6.10")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "digest" version))
       (sha256
        (base32 "07825781nl85gx3pqskc04ywgs0f874qj9z2nyrwz7h0aqks0l8c"))))
    (build-system r-build-system)
    ;; Vignettes require r-knitr, which requires r-digest, so we have to
    ;; disable them and the tests.
    (arguments
     `(#:tests? #f
       #:configure-flags (list "--no-build-vignettes")))
    (home-page "http://dirk.eddelbuettel.com/code/digest.html")
    (synopsis "Create cryptographic hash digests of R objects")
    (description
     "This package contains an implementation of a function 'digest()' for the
creation of hash digests of arbitrary R objects (using the md5, sha-1,
sha-256, crc32, xxhash and murmurhash algorithms) permitting easy comparison
of R language objects, as well as a function 'hmac()' to create hash-based
message authentication code.

Please note that this package is not meant to be deployed for cryptographic
purposes for which more comprehensive (and widely tested) libraries such as
OpenSSL should be used.")
    (license license:gpl2+)))

(define-public r-estimability
  (package
    (name "r-estimability")
    (version "1.1-1")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "estimability" version))
              (sha256
               (base32
                "049adh8i0ad0m0qln2ylqdxcs5v2q9zfignn2a50r5f93ip2ay6w"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/estimability")
    (synopsis "Tools for assessing estimability of linear predictions")
    (description "Provides tools for determining estimability of linear
functions of regression coefficients, and 'epredict' methods that handle
non-estimable cases correctly.")
    (license license:gpl2+)))

(define-public r-gtable
  (package
    (name "r-gtable")
    (version "0.1.2")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "gtable" version))
       (sha256
        (base32 "0k9hfj6r5y238gqh92s3cbdn34biczx3zfh79ix5xq0c5vkai2xh"))))
    (build-system r-build-system)
    (home-page "https://cran.r-project.org/web/packages/gtable")
    (synopsis "R library to arrange grobs in tables")
    (description
     "Gtable is a collection of tools to make it easier to work with
\"tables\" of grobs.")
    (license license:gpl2+)))

(define-public r-pheatmap
  (package
    (name "r-pheatmap")
    (version "1.0.8")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "pheatmap" version))
       (sha256
        (base32
         "1ik0k69kb4n7xl3bkx4p09kw08ri93855zcsxq1c668171jqfiji"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-gtable" ,r-gtable)
       ("r-rcolorbrewer" ,r-rcolorbrewer)
       ("r-scales" ,r-scales)))
    (home-page
     "http://cran.r-project.org/web/packages/pheatmap")
    (synopsis "Pretty heatmaps")
    (description
     "This package provides an implementation of heatmaps that offers more
control over dimensions and appearance.")
    (license license:gpl2+)))

(define-public r-labeling
  (package
    (name "r-labeling")
    (version "0.3")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "labeling" version))
       (sha256
        (base32 "13sk7zrrrzry6ky1bp8mmnzcl9jhvkig8j4id9nny7z993mnk00d"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/labeling")
    (synopsis "Axis labeling algorithms")
    (description "The labeling package provides a range of axis labeling
algorithms.")
    (license license:expat)))

(define-public r-magrittr
  (package
    (name "r-magrittr")
    (version "1.5")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "magrittr" version))
       (sha256
        (base32 "1s1ar6rag8m277qcqmdp02gn4awn9bdj9ax0r8s32i59mm1mki05"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/magrittr/index.html")
    (synopsis "A forward-pipe operator for R")
    (description
     "Magrittr provides a mechanism for chaining commands with a new
forward-pipe operator, %>%.  This operator will forward a value, or the result
of an expression, into the next function call/expression.  There is flexible
support for the type of right-hand side expressions.  For more information,
see package vignette.  To quote Rene Magritte, \"Ceci n'est pas un pipe.\"")
    (license license:expat)))

(define-public r-munsell
  (package
    (name "r-munsell")
    (version "0.4.3")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "munsell" version))
       (sha256
        (base32 "0jdxlbjslkzaqgp058da1cgm85qvqi09wpcgpvp4hvwnmy83qz1r"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-colorspace" ,r-colorspace)))
    (home-page "http://cran.r-project.org/web/packages/munsell")
    (synopsis "Munsell colour system")
    (description
     "The Munsell package contains Functions for exploring and using the
Munsell colour system.")
    (license license:expat)))

(define-public r-rcpp
  (package
    (name "r-rcpp")
    (version "0.12.7")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "Rcpp" version))
       (sha256
        (base32 "1ipid4yfqp1k5c70f7bz7izzq63srmrcxhiqrnyilk2wgrvd7ypb"))))
    (build-system r-build-system)
    (home-page "http://www.rcpp.org")
    (synopsis "Seamless R and C++ Integration")
    (description
     "The Rcpp package provides R functions as well as C++ classes which offer
a seamless integration of R and C++.  Many R data types and objects can be
mapped back and forth to C++ equivalents which facilitates both writing of new
code as well as easier integration of third-party libraries.  Documentation
about Rcpp is provided by several vignettes included in this package, via the
'Rcpp Gallery' site at <http://gallery.rcpp.org>, the paper by Eddelbuettel
and Francois (2011, JSS), and the book by Eddelbuettel (2013, Springer); see
'citation(\"Rcpp\")' for details on these last two.")
    (license license:gpl2+)))

(define-public r-matrix
  (package
    (name "r-matrix")
    (version "1.2-7.1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "Matrix" version))
       (sha256
        (base32
         "09rd51na9spz0lm1lylkfhw43w7c922b83m4jsggmpg3pbd6dssa"))))
    (properties `((upstream-name . "Matrix")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-lattice" ,r-lattice)))
    (home-page "http://Matrix.R-forge.R-project.org/")
    (synopsis "Sparse and dense matrix classes and methods")
    (description
     "This package provides classes and methods for dense and sparse matrices
and operations on them using LAPACK and SuiteSparse.")
    (license license:gpl2+)))

(define-public r-mgcv
  (package
   (name "r-mgcv")
   (version "1.8-15")
   (source
    (origin
     (method url-fetch)
     (uri (cran-uri "mgcv" version))
     (sha256
      (base32
       "05xzmsx51y92c0r0yihac8m9d3v1sqnn8ahcgm3q75j8z6zybsjs"))))
   (build-system r-build-system)
   (home-page "http://cran.r-project.org/web/packages/mgcv")
   (synopsis "Mixed generalised additive model computation")
   (description
    "GAMs, GAMMs and other generalized ridge regression with multiple smoothing
parameter estimation by GCV, REML or UBRE/AIC.  The library includes a
@code{gam()} function, a wide variety of smoothers, JAGS support and
distributions beyond the exponential family.")
   (license license:gpl2+)))

(define-public r-permute
  (package
   (name "r-permute")
   (version "0.9-4")
   (source
    (origin
     (method url-fetch)
     (uri (cran-uri "permute" version))
     (sha256
      (base32
       "1w8wzk1fg9q7wvisnfp2js70dg0m9wi12gkdhpyngpbdcgssahd5"))))
   (build-system r-build-system)
   ;; Tests do not run correctly, but running them properly would entail a
   ;; circular dependency with vegan.
   (home-page "https://github.com/gavinsimpson/permute")
   (synopsis "Functions for Generating Restricted Permutations of Data")
   (description
    "This package provides a set of restricted permutation designs for freely
exchangeable, line transects (time series), spatial grid designs and permutation
of blocks (groups of samples).  @code{permute} also allows split-plot designs,
in which the whole-plots or split-plots or both can be freely exchangeable.")
   (license license:gpl2+)))

(define-public r-plyr
  (package
    (name "r-plyr")
    (version "1.8.4")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "plyr" version))
       (sha256
        (base32 "1igar5pcjqh0jyxv0z3jah8rz617vfa86vw0r5c7c031b7bj5db0"))))
    (build-system r-build-system)
    (native-inputs `(("r-rcpp" ,r-rcpp)))
    (home-page "http://had.co.nz/plyr")
    (synopsis "Tools for Splitting, Applying and Combining Data")
    (description
     "Plyr is a set of tools that solves a common set of problems: you need to
break a big problem down into manageable pieces, operate on each piece and
then put all the pieces back together.  For example, you might want to fit a
model to each spatial location or time point in your study, summarise data by
panels or collapse high-dimensional arrays to simpler summary statistics.")
    (license license:expat)))

(define-public r-proto
  (package
    (name "r-proto")
    (version "1.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "proto" version))
       (sha256
        (base32 "1l843p8vckjckdhgv37ngv47fga5jzy0n00pmipvp05nnaixk54j"))))
    (build-system r-build-system)
    (home-page "https://github.com/hadley/proto")
    (synopsis "Prototype object-based programming")
    (description
     "Proto is an object oriented system using object-based, also called
prototype-based, rather than class-based object oriented ideas.")
    (license license:gpl2+)))

(define-public r-rcolorbrewer
  (package
    (name "r-rcolorbrewer")
    (version "1.1-2")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "RColorBrewer" version))
       (sha256
        (base32 "1pfcl8z1pnsssfaaz9dvdckyfnnc6rcq56dhislbf571hhg7isgk"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/RColorBrewer")
    (synopsis "ColorBrewer palettes")
    (description
     "This package provides color schemes for maps (and other graphics)
designed by Cynthia Brewer as described at http://colorbrewer2.org")
    ;; Includes code licensed under bsd-4
    (license license:asl2.0)))

(define-public r-sendmailr
  (package
    (name "r-sendmailr")
    (version "1.2-1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "sendmailR" version))
       (sha256
        (base32
         "0z7ipywnzgkhfvl4zb2fjwl1xq7b5wib296vn9c9qgbndj6b1zh4"))))
    (properties `((upstream-name . "sendmailR")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-base64enc" ,r-base64enc)))
    (home-page
     "http://cran.r-project.org/web/packages/sendmailR")
    (synopsis "Send email using R")
    (description
     "This package contains a simple SMTP client which provides a portable
solution for sending email, including attachments, from within R.")
    (license license:gpl2+)))

(define-public r-stringi
  (package
    (name "r-stringi")
    (version "1.1.2")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "stringi" version))
       (sha256
        (base32
         "13i1p6j8mx31hsw2s4c2phm2llrrdakzixkm6i0axsxprri722z5"))))
    (build-system r-build-system)
    (inputs `(("icu4c" ,icu4c)))
    (native-inputs `(("pkg-config" ,pkg-config)))
    (home-page "http://stringi.rexamine.com/")
    (synopsis "Character string processing facilities")
    (description
     "This package allows for fast, correct, consistent, portable, as well as
convenient character string/text processing in every locale and any native
encoding.  Owing to the use of the ICU library, the package provides R users
with platform-independent functions known to Java, Perl, Python, PHP, and Ruby
programmers.  Among available features there are: pattern searching
 (e.g.  via regular expressions), random string generation, string collation,
transliteration, concatenation, date-time formatting and parsing, etc.")
    (license license:bsd-3)))

(define-public r-stringr
  (package
    (name "r-stringr")
    (version "1.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "stringr" version))
       (sha256
        (base32 "0css5j4psl80br75chg6s1s3ipzf89f71bnbys34flp9yghg1cfc"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-magrittr" ,r-magrittr)
       ("r-stringi" ,r-stringi)))
    (home-page "https://github.com/hadley/stringr")
    (synopsis "Simple, consistent wrappers for common string operations")
    (description
     "Stringr is a consistent, simple and easy to use set of wrappers around
the fantastic 'stringi' package.  All function and argument names (and
positions) are consistent, all functions deal with \"NA\"'s and zero length
vectors in the same way, and the output from one function is easy to feed into
the input of another.")
    (license license:gpl2+)))

(define-public r-reshape2
  (package
    (name "r-reshape2")
    (version "1.4.2")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "reshape2" version))
       (sha256
        (base32 "0swvjmc9f8cvkrsz463cp6snd8bncbv6q8yrfrb4rgkr0dhq6dvd"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-plyr" ,r-plyr)
       ("r-rcpp" ,r-rcpp)
       ("r-stringr" ,r-stringr)))
    (home-page "https://github.com/hadley/reshape")
    (synopsis "Flexibly reshape data: a reboot of the \"reshape\" package")
    (description
     "Reshape2 is an R library to flexibly restructure and aggregate data
using just two functions: melt and dcast (or acast).")
    (license license:expat)))

(define-public r-scales
  (package
    (name "r-scales")
    (version "0.4.0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "scales" version))
       (sha256
        (base32 "19y6q4j8vpmc73dnn4ncp5wj44gri7m77ys3z2rn3crrcc9zc7l5"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-dichromat" ,r-dichromat)
       ("r-labeling" ,r-labeling)
       ("r-munsell" ,r-munsell)
       ("r-plyr" ,r-plyr)
       ("r-rcolorbrewer" ,r-rcolorbrewer)
       ("r-rcpp" ,r-rcpp)))
    (home-page "https://github.com/hadley/scales")
    (synopsis "Scale functions for visualization")
    (description
     "This package provides graphical scales that map data to aesthetics, and
provides methods for automatically determining breaks and labels for axes and
legends.")
    (license license:expat)))

(define-public r-ggplot2
  (package
    (name "r-ggplot2")
    (version "2.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "ggplot2" version))
       (sha256
        (base32 "0s9rvp0f736ji6p9xpxq54agxf95pjkql4sj7ag0hv2xhnp27hzj"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-digest" ,r-digest)
       ("r-gtable" ,r-gtable)
       ("r-plyr" ,r-plyr)
       ("r-proto" ,r-proto)
       ("r-reshape2" ,r-reshape2)
       ("r-scales" ,r-scales)
       ("r-svglite" ,r-svglite)))
    (home-page "http://ggplot2.org")
    (synopsis "An implementation of the grammar of graphics")
    (description
     "Ggplot2 is an implementation of the grammar of graphics in R.  It
combines the advantages of both base and lattice graphics: conditioning and
shared axes are handled automatically, and you can still build up a plot step
by step from multiple data sources.  It also implements a sophisticated
multidimensional conditioning system and a consistent interface to map data to
aesthetic attributes.")
    (license license:gpl2+)))

(define-public r-gdtools
  (package
    (name "r-gdtools")
    (version "0.1.1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "gdtools" version))
       (sha256
        (base32
         "1l9d759x9s4ddz51sls8kcjps2i9kwfbc72dnagrdavh82h0al8n"))))
    (build-system r-build-system)
    (native-inputs
     `(("r-rcpp" ,r-rcpp)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("cairo" ,cairo)))
    (propagated-inputs
     `(("r-withr" ,r-withr)))
    (home-page "http://cran.r-project.org/web/packages/gdtools")
    (synopsis "Utilities for graphical rendering")
    (description
     "The @code{gdtools} package provides functionalities to get font metrics
and to generate base64 encoded string from raster matrix.")
    (license license:gpl3)))

(define-public r-svglite
  (package
    (name "r-svglite")
    (version "1.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "svglite" version))
       (sha256
        (base32
         "11ryicjglfi6jvkk4jgg5kra42qbs5z2zid7jjhlslpjcljfwc70"))))
    (build-system r-build-system)
    (native-inputs  `(("r-rcpp" ,r-rcpp)))
    (propagated-inputs
     `(("r-bh" ,r-bh)
       ("r-gdtools" ,r-gdtools)))
    (home-page "https://github.com/hadley/svglite")
    (synopsis "SVG graphics device")
    (description
     "@code{svglite} is a graphics device that produces clean
@dfn{SVG} (Scalable Vector Graphics) output, suitable for use on the web, or
hand editing.  Compared to the built-in @code{svg()}, @code{svglite} is
considerably faster, produces smaller files, and leaves text as is.")
    (license license:gpl2+)))

(define-public r-assertthat
  (package
    (name "r-assertthat")
    (version "0.1")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "assertthat" version))
              (sha256
               (base32
                "0dwsqajyglfscqilj843qfqn1ndbqpswa7b4l1d633qjk9d68qqk"))))
    (build-system r-build-system)
    (home-page "https://github.com/hadley/assertthat")
    (synopsis "Easy pre and post assertions")
    (description
     "Assertthat is an extension to stopifnot() that makes it easy to declare
the pre and post conditions that your code should satisfy, while also
producing friendly error messages so that your users know what they've done
wrong.")
    (license license:gpl3+)))

(define-public r-lazyeval
  (package
    (name "r-lazyeval")
    (version "0.2.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "lazyeval" version))
              (sha256
               (base32
                "1jwdz40nznlc44hpjli7h98gnpa4d98ifggmj7z88h84n9aqywqk"))))
    (build-system r-build-system)
    (home-page "https://github.com/hadley/lazyeval")
    (synopsis "Lazy (non-standard) evaluation in R")
    (description
     "This package provides the tools necessary to do non-standard
evaluation (NSE) in R.")
    (license license:gpl3+)))

(define-public r-dbi
  (package
    (name "r-dbi")
    (version "0.5-1")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "DBI" version))
              (sha256
               (base32
                "1idwm9lkmz6ns6h0vvgml18mg0k7vjqiv9p5svrdcmx7r1rirpdi"))))
    (build-system r-build-system)
    (home-page "https://github.com/rstats-db/DBI")
    (synopsis "R database interface")
    (description
     "The DBI package provides a database interface (DBI) definition for
communication between R and relational database management systems.  All
classes in this package are virtual and need to be extended by the various
R/DBMS implementations.")
    (license license:lgpl2.0+)))

(define-public r-bh
  (package
    (name "r-bh")
    (version "1.60.0-2")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "BH" version))
              (sha256
               (base32
                "136497fng9bcvrf8favpj8inz96pxdwp1rrb2k00sxjxjbgawhg4"))))
    (build-system r-build-system)
    (home-page "https://github.com/eddelbuettel/bh")
    (synopsis "R package providing subset of Boost headers")
    (description
     "This package aims to provide the most useful subset of Boost libraries
for template use among CRAN packages.")
    (license license:boost1.0)))

(define-public r-evaluate
  (package
    (name "r-evaluate")
    (version "0.10")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "evaluate" version))
              (sha256
               (base32
                "0mwna7rjyrmc76651a1fm7c76ippdsc2wsp3sj3iwb1c73mvlqv1"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-stringr" ,r-stringr)))
    (home-page "https://github.com/hadley/evaluate")
    (synopsis "Parsing and evaluation tools for R")
    (description
     "This package provides tools that allow you to recreate the parsing,
evaluation and display of R code, with enough information that you can
accurately recreate what happens at the command line.  The tools can easily be
adapted for other output formats, such as HTML or LaTeX.")
    (license license:gpl3+)))

(define-public r-formatr
  (package
    (name "r-formatr")
    (version "1.4")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "formatR" version))
              (sha256
               (base32
                "1fvynq0fj1r9grg9vvfdh5fl2riv6qki9f2rfpyvbvqq3xxpmi3f"))))
    (build-system r-build-system)
    (home-page "http://yihui.name/formatR")
    (synopsis "Format R code automatically")
    (description
     "This package provides a function to format R source code.  Spaces and
indent will be added to the code automatically, and comments will be preserved
under certain conditions, so that R code will be more human-readable and tidy.
There is also a Shiny app as a user interface in this package.")
    (license license:gpl3+)))

(define-public r-highr
  (package
    (name "r-highr")
    (version "0.6")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "highr" version))
              (sha256
               (base32
                "0n9v44dxdy5fhkdmpbpa2p78whyd9z3rhhy42ipdz5m5vsr55qa3"))))
    (build-system r-build-system)
    (home-page "https://github.com/yihui/highr")
    (synopsis "Syntax highlighting for R source code")
    (description
     "This package provides syntax highlighting for R source code.  Currently
it supports LaTeX and HTML output.  Source code of other languages is
supported via Andre Simon's highlight package.")
    (license license:gpl3+)))

(define-public r-mime
  (package
    (name "r-mime")
    (version "0.5")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "mime" version))
              (sha256
               (base32
                "0i91m3ivaja1k33jwcvz16pfjypkci27awm8glil7sxhmwaj3izw"))))
    (build-system r-build-system)
    (home-page "https://github.com/yihui/mime")
    (synopsis "R package to map filenames to MIME types")
    (description
     "This package guesses the MIME type from a filename extension using the
data derived from /etc/mime.types in UNIX-type systems.")
    (license license:gpl2)))

(define-public r-markdown
  (package
    (name "r-markdown")
    (version "0.7.7")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "markdown" version))
              (sha256
               (base32
                "00j1hlib3il50azs2vlcyhi0bjpx1r50mxr9w9dl5g1bwjjc71hb"))))
    (build-system r-build-system)
    ;; Skip check phase because the tests require the r-knitr package to be
    ;; installed. This prevents installation failures. Knitr normally
    ;; shouldn't be available since r-markdown is a dependency of the r-knitr
    ;; package.
    (arguments `(#:tests? #f))
    (propagated-inputs
     `(("r-mime" ,r-mime)))
    (home-page "https://github.com/rstudio/markdown")
    (synopsis "Markdown rendering for R")
    (description
     "This package provides R bindings to the Sundown Markdown rendering
library (https://github.com/vmg/sundown).  Markdown is a plain-text formatting
syntax that can be converted to XHTML or other formats.")
    (license license:gpl2)))

(define-public r-yaml
  (package
    (name "r-yaml")
    (version "2.1.13")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "yaml" version))
              (sha256
               (base32
                "18kz5mfn7qpif5pn91w4vbrc5bkycsj85vwm5wxwzjlb02i9mxi6"))))
    (build-system r-build-system)
    (home-page "https://cran.r-project.org/web/packages/yaml/")
    (synopsis "Methods to convert R data to YAML and back")
    (description
     "This package implements the libyaml YAML 1.1 parser and
emitter (http://pyyaml.org/wiki/LibYAML) for R.")
    (license license:bsd-3)))

(define-public r-knitr
  (package
    (name "r-knitr")
    (version "1.14")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "knitr" version))
              (sha256
               (base32
                "1v0s0knb294p7a2xkwy35bhg0w8p3qcgyphd748sj86hh8a30vds"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-evaluate" ,r-evaluate)
       ("r-digest" ,r-digest)
       ("r-formatr" ,r-formatr)
       ("r-highr" ,r-highr)
       ("r-markdown" ,r-markdown)
       ("r-stringr" ,r-stringr)
       ("r-yaml" ,r-yaml)))
    (home-page "http://yihui.name/knitr/")
    (synopsis "General-purpose package for dynamic report generation in R")
    (description
     "This package provides a general-purpose tool for dynamic report
generation in R using Literate Programming techniques.")
    ;; The code is released under any version of the GPL.  As it is used by
    ;; r-markdown which is available under GPLv2 only, we have chosen GPLv2+
    ;; here.
    (license license:gpl2+)))

(define-public r-knitrbootstrap
  (package
    (name "r-knitrbootstrap")
    (version "1.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "knitrBootstrap" version))
       (sha256
        (base32
         "0pshn2slzqwpryklslsxwh1dmqcnwv6bwi7yfm6m342wjybpk0wl"))))
    (properties `((upstream-name . "knitrBootstrap")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-knitr" ,r-knitr)
       ("r-rmarkdown" ,r-rmarkdown)))
    (home-page "https://github.com/jimhester/knitrBootstrap")
    (synopsis "Knitr bootstrap framework")
    (description
     "This package provides a framework to create Bootstrap 3 HTML reports
from knitr Rmarkdown.")
    (license license:expat)))

(define-public r-microbenchmark
  (package
    (name "r-microbenchmark")
    (version "1.4-2.1")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "microbenchmark" version))
              (sha256
               (base32
                "0qn5r1a6qidghcisc2hpbdmj62pnixc3zz6p4ipk8mvakf0hdsvg"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-ggplot2" ,r-ggplot2)))
    (home-page "https://cran.r-project.org/web/packages/microbenchmark/")
    (synopsis "Accurate timing functions for R")
    (description
     "This package provides infrastructure to accurately measure and compare
the execution time of R expressions.")
    (license license:bsd-2)))

(define-public r-codetools
  (package
    (name "r-codetools")
    (version "0.2-14")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "codetools" version))
              (sha256
               (base32
                "0y9r4m2b8xgavr89sc179knzwpz54xljbc1dinpq2q07i4xn0397"))))
    (build-system r-build-system)
    (home-page "https://cran.r-project.org/web/packages/codetools/index.html")
    (synopsis "Code analysis tools for R")
    (description "This package provides code analysis tools for R.")
    (license license:gpl3+)))

(define-public r-pryr
  (package
    (name "r-pryr")
    (version "0.1.2")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "pryr" version))
              (sha256
               (base32
                "1in350a8hxwf580afavasvn3jc7x2p1b7nlwmj1scakfz74vghk5"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-stringr" ,r-stringr)
       ("r-codetools" ,r-codetools)))
    (native-inputs
     `(("r-rcpp" ,r-rcpp)))
    (home-page "https://github.com/hadley/pryr")
    (synopsis "Tools for computing on the R language")
    (description
     "This package provides useful tools to pry back the covers of R and
understand the language at a deeper level.")
    (license license:gpl2)))

(define-public r-memoise
  (package
    (name "r-memoise")
    (version "1.0.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "memoise" version))
              (sha256
               (base32
                "0sq2dhpvxy17v1baj256r0jnygdy3m5a8x4zh6vhv29957qnq6zx"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-digest" ,r-digest)))
    (home-page "http://github.com/hadley/memoise")
    (synopsis "Memoise functions for R")
    (description
     "This R package allows to cache the results of a function so that when
you call it again with the same arguments it returns the pre-computed value.")
    (license license:expat)))

(define-public r-crayon
  (package
    (name "r-crayon")
    (version "1.3.2")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "crayon" version))
              (sha256
               (base32
                "0s2yam18slph7xsw4pyc9f92gdyf609r5w92yax69zh57kb7asws"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-memoise" ,r-memoise)))
    (home-page "https://github.com/gaborcsardi/crayon")
    (synopsis "Colored terminal output for R")
    (description
     "Colored terminal output on terminals that support ANSI color and
highlight codes.  It also works in Emacs ESS.  ANSI color support is
automatically detected.  Colors and highlighting can be combined and nested.
New styles can also be created easily.  This package was inspired by the
\"chalk\" JavaScript project.")
    (license license:expat)))

(define-public r-praise
  (package
    (name "r-praise")
    (version "1.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "praise" version))
       (sha256
        (base32
         "1gfyypnvmih97p2r0php9qa39grzqpsdbq5g0fdsbpq5zms5w0sw"))))
    (build-system r-build-system)
    (home-page "https://github.com/gaborcsardi/praise")
    (synopsis "Functions to praise users")
    (description
     "This package provides template functions to assist in building friendly
R packages that praise their users.")
    (license license:expat)))

(define-public r-testthat
  (package
    (name "r-testthat")
    (version "1.0.2")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "testthat" version))
              (sha256
               (base32
                "0pj1r01x4ny4capr83dfa19hi5i2sjjxky99schzip8zrq5dzxqf"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-digest" ,r-digest)
       ("r-crayon" ,r-crayon)
       ("r-magrittr" ,r-magrittr)
       ("r-praise" ,r-praise)
       ("r-r6" ,r-r6)))
    (home-page "https://github.com/hadley/testthat")
    (synopsis "Unit testing for R")
    (description
     "This package provides a unit testing system for R designed to be fun,
flexible and easy to set up.")
    (license license:expat)))

(define-public r-r6
  (package
    (name "r-r6")
    (version "2.2.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "R6" version))
              (sha256
               (base32
                "1ir51pb0y6yj05qaxsflk4a6hv8n73cwlb0qajcskbrz632dsyvx"))))
    (build-system r-build-system)
    (home-page "https://github.com/wch/R6/")
    (synopsis "Classes with reference semantics in R")
    (description
     "The R6 package allows the creation of classes with reference semantics,
similar to R's built-in reference classes.  Compared to reference classes, R6
classes are simpler and lighter-weight, and they are not built on S4 classes
so they do not require the methods package.  These classes allow public and
private members, and they support inheritance, even when the classes are
defined in different packages.")
    (license license:expat)))

(define-public r-tibble
  (package
    (name "r-tibble")
    (version "1.2")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "tibble" version))
       (sha256
        (base32
         "011i352ylq9b4xfcj7h10h7qsqd9qkc1rzc0pr1gf8qjb788p2pd"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-assertthat" ,r-assertthat)
       ("r-lazyeval" ,r-lazyeval)
       ("r-rcpp" ,r-rcpp)))
    (home-page "https://github.com/hadley/tibble")
    (synopsis "Simple data frames")
    (description
     "This package provides a @code{tbl_df} class that offers better checking
and printing capabilities than traditional data frames.")
    (license license:expat)))

(define-public r-dplyr
  (package
    (name "r-dplyr")
    (version "0.5.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "dplyr" version))
              (sha256
               (base32
                "0ks5cklb03laqf5ygcw986g1lv7wk1ipvypjlha8xly2y4lvilwk"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-assertthat" ,r-assertthat)
       ("r-r6" ,r-r6)
       ("r-magrittr" ,r-magrittr)
       ("r-lazyeval" ,r-lazyeval)
       ("r-dbi" ,r-dbi)
       ("r-tibble" ,r-tibble)))
    (native-inputs
     `(("r-rcpp" ,r-rcpp)
       ("r-bh" ,r-bh)))
    (home-page "https://github.com/hadley/dplyr")
    (synopsis "Tools for working with data frames in R")
    (description
     "dplyr is the next iteration of plyr.  It is focussed on tools for
working with data frames.  It has three main goals: 1) identify the most
important data manipulation tools needed for data analysis and make them easy
to use in R; 2) provide fast performance for in-memory data by writing key
pieces of code in C++; 3) use the same code interface to work with data no
matter where it is stored, whether in a data frame, a data table or
database.")
    (license license:expat)))

(define-public r-acepack
  (package
    (name "r-acepack")
    (version "1.4.1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "acepack" version))
       (sha256
        (base32
         "1f98rpfjmhd92rdc3j004plyfpjailz6j0ycysbac0kgj83haxc2"))))
    (build-system r-build-system)
    (inputs
     `(("gfortran" ,gfortran)))
    (home-page "http://cran.r-project.org/web/packages/acepack")
    (synopsis "Functions for regression transformations")
    (description
     "This package provides ACE and AVAS methods for choosing regression
transformations.")
    (license license:expat)))

(define-public r-cluster
  (package
    (name "r-cluster")
    (version "2.0.5")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "cluster" version))
       (sha256
        (base32
         "1bkvqmv8h2c423q9ag2afb6s9j2vcdlxsf559zzbimraphrr2c2b"))))
    (build-system r-build-system)
    (inputs
     `(("gfortran" ,gfortran)))
    (home-page "http://cran.r-project.org/web/packages/cluster")
    (synopsis "Methods for data cluster analysis")
    (description
     "This package provides tools that are useful in finding groups in data.
It is based on the methods described in Kaufman and Rousseeuw (1990) \"Finding
Groups in Data\".")
    (license license:gpl2+)))

(define-public r-foreign
  (package
    (name "r-foreign")
    (version "0.8-67")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "foreign" version))
       (sha256
        (base32
         "1mcrm2pydimbyjhkrw5h380bifj1jhwzifph1xgh90asf3lvd1xd"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/foreign")
    (synopsis "Read data stored by other statistics software in R")
    (description
     "This package provides functions for reading and writing data stored by
some versions of Epi Info, Minitab, S, SAS, SPSS, Stata, Systat and Weka, and
for reading and writing some dBase files.")
    (license license:gpl2+)))

(define-public r-formula
  (package
    (name "r-formula")
    (version "1.2-1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "Formula" version))
       (sha256
        (base32
         "02in5325zzrqbhlygx6s0dinj6ymw845q70y56frqacv25ayzcax"))))
    (properties `((upstream-name . "Formula")))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/Formula")
    (synopsis "Extended model formulas")
    (description
     "This package provides a new class @code{Formula}, which extends the base
class @code{formula}.  It supports extended formulas with multiple parts of
regressors on the right-hand side and/or multiple responses on the left-hand
side.")
    (license (list license:gpl2+ license:gpl3+))))

(define-public r-locfit
  (package
    (name "r-locfit")
    (version "1.5-9.1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "locfit" version))
       (sha256
        (base32
         "0lafrmq1q7x026m92h01hc9cjjiximqqi3v1g2hw7ai9vf7i897m"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/locfit")
    (synopsis "Local regression, likelihood and density estimation")
    (description
     "This package provides functions used for local regression, likelihood
and density estimation.")
    (license (list license:gpl2+ license:gpl3+))))

(define-public r-chron
  (package
    (name "r-chron")
    (version "2.3-47")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "chron" version))
              (sha256
               (base32
                "1xj50kk8b8mbjpszp8i0wbripb5a4b36jcscwlbyap8n4487g34s"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/chron")
    (synopsis "Chronological R objects which can handle dates and times")
    (description
     "This package provides chronological R objects which can handle dates and
times.")
    (license license:gpl2)))

(define-public r-data-table
  (package
    (name "r-data-table")
    (version "1.9.6")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "data.table" version))
              (sha256
               (base32
                "0vi3zplpxqbg78z9ifjfs1kl2i8qhkqxr7l9ysp2663kq54w6x3g"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-chron" ,r-chron)))
    (home-page "https://github.com/Rdatatable/data.table/wiki")
    (synopsis "Enhanced version of data.frame R object")
    (description
     "The R package @code{data.table} is an extension of @code{data.frame}
providing functions for fast aggregation of large data (e.g. 100GB in RAM),
fast ordered joins, fast add/modify/delete of columns by group, column listing
and fast file reading.")
    (license license:gpl3+)))

(define-public r-xtable
  (package
    (name "r-xtable")
    (version "1.8-2")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "xtable" version))
       (sha256
        (base32
         "0398qkpvlw3dv0myz4mjcyqwpwc2m31l127r8vdzwc71wb6s28qn"))))
    (build-system r-build-system)
    (native-inputs
     `(("r-knitr" ,r-knitr)))
    (home-page "http://xtable.r-forge.r-project.org/")
    (synopsis "Export R tables to LaTeX or HTML")
    (description
     "This package provides tools to export R data as LaTeX and HTML tables.")
    (license license:gpl2+)))

(define-public python-patsy
  (package
    (name "python-patsy")
    (version "0.4.1")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "patsy" version ".zip"))
              (sha256
               (base32
                "1m6knyq8hbqlx242y4da02j0x86j4qggs1j7q186w3jv0j0c476w"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check (lambda _ (zero? (system* "nosetests" "-v")))))))
    (propagated-inputs
     `(("python-numpy" ,python-numpy)
       ("python-scipy" ,python-scipy)
       ("python-six" ,python-six)))
    (native-inputs
     `(("python-nose" ,python-nose)
       ("unzip" ,unzip)))
    (home-page "https://github.com/pydata/patsy")
    (synopsis "Describe statistical models and build design matrices")
    (description
     "Patsy is a Python package for describing statistical models and for
building design matrices.")
    ;; The majority of the code is distributed under BSD-2.  The module
    ;; patsy.compat contains code derived from the Python standard library,
    ;; and is covered by the PSFL.
    (license (list license:bsd-2 license:psfl))))

(define-public python2-patsy
  (package-with-python2 python-patsy))

(define-public python-statsmodels
  (package
    (name "python-statsmodels")
    (version "0.6.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://pypi.python.org/packages/source/"
                           "s/statsmodels/statsmodels-" version ".tar.gz"))
       (sha256
        (base32
         "0xn67sqr0cc1lmlhzm71352hrb4hw7g318p5ff5q97pc98vl8kmy"))
       (patches (search-patches "python-statsmodels-fix-tests.patch"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; tests must be run after installation
         (delete 'check)
         (add-after 'unpack 'set-matplotlib-backend-to-agg
          (lambda _
            ;; Set the matplotlib backend to Agg to avoid problems using the
            ;; GTK backend without a display.
            (substitute* (find-files "statsmodels/graphics/tests" "\\.py")
              (("import matplotlib\\.pyplot as plt" line)
               (string-append "import matplotlib;matplotlib.use('Agg');"
                              line)))
            #t))
         (add-after 'install 'check
           (lambda* (#:key inputs outputs #:allow-other-keys)
             ;; Make installed package available for running the tests
             (add-installed-pythonpath inputs outputs)
             (with-directory-excursion "/tmp"
               (zero? (system* "nosetests"
                               "--stop"
                               "-v" "statsmodels"))))))))
    (propagated-inputs
     `(("python-numpy" ,python-numpy)
       ("python-scipy" ,python-scipy)
       ("python-pandas" ,python-pandas)
       ("python-patsy" ,python-patsy)
       ("python-matplotlib" ,python-matplotlib)))
    (native-inputs
     `(("python-cython" ,python-cython)
       ("python-nose" ,python-nose)
       ("python-sphinx" ,python-sphinx)))
    (home-page "http://statsmodels.sourceforge.net/")
    (synopsis "Statistical modeling and econometrics in Python")
    (description
     "Statsmodels is a Python package that provides a complement to scipy for
statistical computations including descriptive statistics and estimation and
inference for statistical models.")
    (license license:bsd-3)))

(define-public python2-statsmodels
  (let ((stats (package-with-python2 python-statsmodels)))
    (package (inherit stats)
      (propagated-inputs
       `(("python2-pytz" ,python2-pytz)
         ("python2-numpy" ,python2-numpy)
         ("python2-scipy" ,python2-scipy)
         ("python2-pandas" ,python2-pandas)
         ("python2-patsy" ,python2-patsy)
         ("python2-matplotlib" ,python2-matplotlib))))))

(define-public r-coda
  (package
    (name "r-coda")
    (version "0.18-1")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "coda" version))
              (sha256
               (base32
                "03sc780734zj2kqcm8lkyvf76fql0jbfhkblpn8l58zmb6cqi958"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-lattice" ,r-lattice)))
    (home-page "http://cran.r-project.org/web/packages/coda")
    (synopsis "This is a package for Output Analysis and Diagnostics for MCMC")
    (description "This package provides functions for summarizing and plotting
the output from Markov Chain Monte Carlo (MCMC) simulations, as well as
diagnostic tests of convergence to the equilibrium distribution of the Markov
chain.")
    (license license:gpl2+)))

(define-public r-ade4
  (package
    (name "r-ade4")
    (version "1.7-4")
    (source
      (origin
        (method url-fetch)
        (uri (cran-uri "ade4" version))
        (sha256
          (base32
            "17sbicash7z4b63dlrbaf8xx2pbwh62vykzvhdjs43h8jkl881y7"))))
    (build-system r-build-system)
    (home-page "http://pbil.univ-lyon1.fr/ADE-4")
    (synopsis "Multivariate data analysis and graphical display")
    (description
     "The ade4 package contains data analysis functions to analyze ecological
and environmental data in the framework of Euclidean exploratory methods.")
    (license license:gpl2+)))

(define-public r-xml2
  (package
    (name "r-xml2")
    (version "1.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "xml2" version))
       (sha256
        (base32
         "0f2alsrk3yykznbhnz4pcsg9mb72cv607vbapqx5kqfv39772kgr"))))
    (build-system r-build-system)
    (inputs
     `(("libxml2" ,libxml2)))
    (propagated-inputs
     `(("r-rcpp" ,r-rcpp)
       ("r-bh" ,r-bh)))
    (home-page "https://github.com/hadley/xml2")
    (synopsis "Parse XML with R")
    (description
     "This package provides a simple, consistent interface to working with XML
files in R.  It is built on top of the libxml2 C library.")
    (license license:gpl2+)))

(define-public r-multitaper
  (package
    (name "r-multitaper")
    (version "1.0-12")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "multitaper" version))
       (sha256
        (base32
         "011qpkwpjclfc24y2qqigmdnikqwdnanflfhihigh5b5k7qwgm5j"))))
    (build-system r-build-system)
    (native-inputs
     `(("gfortran" ,gfortran)))
    (home-page "http://github.com/wesleyburr/multitaper/")
    (synopsis "Multitaper spectral analysis tools")
    (description
     "This package implements multitaper spectral estimation
techniques using prolate spheroidal sequences (Slepians) and sine
tapers for time series analysis.  It includes an adaptive weighted
multitaper spectral estimate, a coherence estimate, Thomson's Harmonic
F-test, and complex demodulation.  The Slepians sequences are
generated efficiently using a tridiagonal matrix solution, and
jackknifed confidence intervals are available for most estimates.")
    (license license:gpl2+)))

(define-public r-rversions
  (package
    (name "r-rversions")
    (version "1.0.3")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "rversions" version))
              (sha256
               (base32
                "0i2gi05nrvknr7g89rbppkswyfcwwd4r9gp75fdfhpah8sgq1l11"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-curl" ,r-curl)
       ("r-xml2" ,r-xml2)))
    (home-page "https://github.com/metacran/rversions")
    (synopsis "Query R versions, including 'r-release' and 'r-oldrel'")
    (description
     "This package provides functions to query the main R repository to find
the versions that @code{r-release} and @code{r-oldrel} refer to, and also all
previous R versions and their release dates.")
    (license license:expat)))

(define-public r-whisker
  (package
    (name "r-whisker")
    (version "0.3-2")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "whisker" version))
              (sha256
               (base32
                "0z4cn115gxcl086d6bnqr8afi67b6a7xqg6ivmk3l4ng1x8kcj28"))))
    (build-system r-build-system)
    (home-page "http://github.com/edwindj/whisker")
    (synopsis "Logicless mustache templating for R")
    (description
     "This package provides logicless templating, with a syntax that is not
limited to R.")
    (license license:gpl3+)))

(define-public r-backports
  (package
    (name "r-backports")
    (version "1.0.4")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "backports" version))
       (sha256
        (base32
         "0fssh5rnnvpp8wm0ml9gk765idwrgj07xyxpkhpidl9zwydxzif2"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/backports")
    (synopsis "Reimplementations of functions introduced since R 3.0.0")
    (description
     "Provides implementations of functions which have been introduced in R
since version 3.0.0.  The backports are conditionally exported which results
in R resolving the function names to the version shipped with R (if available)
and uses the implemented backports as fallback.  This way package developers
can make use of the new functions without worrying about the minimum required
R version.")
    (license license:gpl2+)))

(define-public r-checkmate
  (package
    (name "r-checkmate")
    (version "1.8.2")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "checkmate" version))
       (sha256
        (base32
         "1zqcggl9m7slvc0q6zyhssdypb7jzf3l9byl5vxh1qdwjiw2y64g"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-backports" ,r-backports)))
    (home-page "https://github.com/mllg/checkmate")
    (synopsis "Fast and versatile argument checks")
    (description
     "This package provides tests and assertions to perform frequent argument
checks.  A substantial part of the package was written in C to minimize any
worries about execution time overhead.")
    (license license:bsd-3)))

(define-public r-bbmisc
  (package
    (name "r-bbmisc")
    (version "1.10")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "BBmisc" version))
       (sha256
        (base32
         "0cw2mhw7qhdrx91zzd5iwyh7ch9fy4wxga8j63731q6sxr1airjl"))))
    (properties `((upstream-name . "BBmisc")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-checkmate" ,r-checkmate)))
    (home-page "https://github.com/berndbischl/BBmisc")
    (synopsis "Miscellaneous functions for R package development")
    (description
     "This package provides miscellaneous helper functions for the development
of R packages.")
    (license license:bsd-3)))

(define-public r-fail
  (package
    (name "r-fail")
    (version "1.3")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "fail" version))
       (sha256
        (base32
         "0vfm6kmpmgsamda5p0sl771kbnsscan31l2chzssyw93kwmams7d"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-bbmisc" ,r-bbmisc)
       ("r-checkmate" ,r-checkmate)))
    (home-page "https://github.com/mllg/fail")
    (synopsis "File abstraction interface layer (FAIL)")
    (description
     "This package provides a more comfortable interface to work with R data
or source files in a key-value fashion.")
    (license license:bsd-3)))

(define-public r-batchjobs
  (package
    (name "r-batchjobs")
    (version "1.6")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "BatchJobs" version))
       (sha256
        (base32
         "1kb99024jih5bycc226bl4jyvbbl1sg72q3m2wnlshl7s8p6vva0"))))
    (properties `((upstream-name . "BatchJobs")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-bbmisc" ,r-bbmisc)
       ("r-brew" ,r-brew)
       ("r-checkmate" ,r-checkmate)
       ("r-dbi" ,r-dbi)
       ("r-digest" ,r-digest)
       ("r-fail" ,r-fail)
       ("r-rsqlite" ,r-rsqlite)
       ("r-sendmailr" ,r-sendmailr)
       ("r-stringr" ,r-stringr)))
    (home-page "https://github.com/tudo-r/BatchJobs")
    (synopsis "Batch computing with R")
    (description
     "This package provides @code{Map}, @code{Reduce} and @code{Filter}
variants to generate jobs on batch computing systems like PBS/Torque, LSF,
SLURM and Sun Grid Engine.  Multicore and SSH systems are also supported.")
    (license license:bsd-2)))

(define-public r-brew
  (package
    (name "r-brew")
    (version "1.0-6")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "brew" version))
              (sha256
               (base32
                "1vghazbcha8gvkwwcdagjvzx6yl8zm7kgr0i9wxr4jng06d1l3fp"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/brew")
    (synopsis "Templating framework for report generation")
    (description
     "The brew package implements a templating framework for mixing text and R
code for report generation.  The template syntax is similar to PHP, Ruby's erb
module, Java Server Pages, and Python's psp module.")
    (license license:gpl2+)))

(define-public r-roxygen2
  (package
    (name "r-roxygen2")
    (version "5.0.1")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "roxygen2" version))
              (sha256
               (base32
                "19gblyrrn29msbpawcb1hn5m1rshiqwxy0lby0vf92rm13fmsxcz"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-brew" ,r-brew)
       ("r-digest" ,r-digest)
       ("r-rcpp" ,r-rcpp)
       ("r-stringi" ,r-stringi)
       ("r-stringr" ,r-stringr)))
    (home-page "https://github.com/klutometis/roxygen")
    (synopsis "In-source documentation system for R")
    (description
     "Roxygen2 is a Doxygen-like in-source documentation system for Rd,
collation, and NAMESPACE files.")
    (license license:gpl2+)))

(define-public r-openssl
  (package
    (name "r-openssl")
    (version "0.9.5")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "openssl" version))
       (sha256
        (base32
         "1lal8mmcwjhhln10mfi96ipv3d364k0wiviiln220wvhddcpr9pp"))))
    (build-system r-build-system)
    (inputs
     `(("openssl" ,openssl)))
    (home-page "https://github.com/jeroenooms/openssl")
    (synopsis "Toolkit for encryption, signatures and certificates")
    (description
     "This package provides R bindings to OpenSSL libssl and libcrypto, plus
custom SSH pubkey parsers.  It supports RSA, DSA and NIST curves P-256, P-384
and P-521.  Cryptographic signatures can either be created and verified
manually or via x509 certificates.  AES block cipher is used in CBC mode for
symmetric encryption; RSA for asymmetric (public key) encryption.  High-level
envelope functions combine RSA and AES for encrypting arbitrary sized data.
Other utilities include key generators, hash functions (md5, sha1, sha256,
etc), base64 encoder, a secure random number generator, and @code{bignum} math
methods for manually performing crypto calculations on large multibyte
integers.")
    (license license:expat)))

(define-public r-httr
  (package
    (name "r-httr")
    (version "1.2.1")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "httr" version))
              (sha256
               (base32
                "03kkjlhyvvi5znwaxfm6cmdsg3q7ivwsvkzgabhjdj2jxs80pfg7"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-curl" ,r-curl)
       ("r-digest" ,r-digest)
       ("r-jsonlite" ,r-jsonlite)
       ("r-openssl" ,r-openssl)
       ("r-mime" ,r-mime)
       ("r-r6" ,r-r6)
       ("r-stringr" ,r-stringr)))
    (home-page "https://github.com/hadley/httr")
    (synopsis "Tools for working with URLs and HTTP")
    (description
     "The aim of httr is to provide a wrapper for RCurl customised to the
demands of modern web APIs.  It provides useful tools for working with HTTP
organised by HTTP verbs (@code{GET()}, @code{POST()}, etc).  Configuration
functions make it easy to control additional request components.")
    (license license:expat)))

(define-public r-git2r
  (package
    (name "r-git2r")
    (version "0.15.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "git2r" version))
              (sha256
               (base32
                "1rpdf85wy9fp456ypvbhl3p9whkb7kgl0n7rkqxd2bhvyzkvjak8"))))
    (build-system r-build-system)
    ;; This R package contains modified sources of libgit2.  This modified
    ;; version of libgit2 is built as the package is built.  Hence libgit2 is
    ;; not among the inputs of this package.
    (inputs
     `(("libssh2" ,libssh2)
       ("openssl" ,openssl)
       ("zlib" ,zlib)))
    (home-page "https://github.com/ropensci/git2r")
    (synopsis "Access Git repositories with R")
    (description
     "This package provides an R interface to the libgit2 library, which is a
pure C implementation of the Git core methods.")
    ;; GPLv2 only with linking exception.
    (license license:gpl2)))

(define-public r-rstudioapi
  (package
    (name "r-rstudioapi")
    (version "0.6")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "rstudioapi" version))
              (sha256
               (base32
                "1zkvz72z6nw0xc8bhb21y5x1nk6avijs0w8n4vsbvw9sn76wc96s"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/rstudioapi")
    (synopsis "Safely access the RStudio API")
    (description
     "This package provides functions to access the RStudio API and provide
informative error messages when it's not available.")
    (license license:expat)))

(define-public r-devtools
  (package
    (name "r-devtools")
    (version "1.12.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "devtools" version))
              (sha256
               (base32
                "16l18szmj482vf3dvl2fqwwa4zaqylmic1pk7dwh428cp0d86mzi"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-curl" ,r-curl)
       ("r-digest" ,r-digest)
       ("r-evaluate" ,r-evaluate)
       ("r-git2r" ,r-git2r)
       ("r-httr" ,r-httr)
       ("r-jsonlite" ,r-jsonlite)
       ("r-memoise" ,r-memoise)
       ("r-roxygen2" ,r-roxygen2)
       ("r-rstudioapi" ,r-rstudioapi)
       ("r-rversions" ,r-rversions)
       ("r-whisker" ,r-whisker)
       ("r-withr" ,r-withr)))
    (home-page "https://github.com/hadley/devtools")
    (synopsis "Tools to make developing R packages easier")
    (description "The devtools package is a collection of package development
tools to simplify the devolpment of R packages.")
    (license license:gpl2+)))

(define-public r-withr
  (package
    (name "r-withr")
    (version "1.0.2")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "withr" version))
              (sha256
               (base32
                "042z8nmqqilgrvhmbqrjc05qys3gzwq1rqy2wxp2bi5d41859493"))))
    (build-system r-build-system)
    (home-page "https://github.com/jimhester/withr")
    (synopsis "Run code with temporarily modified global state")
    (description
     "This package provides a set of functions to run R code in an environment
in which global state has been temporarily modified.  Many of these functions
were originally a part of the r-devtools package.")
    (license license:gpl2+)))

(define-public r-hms
  (package
    (name "r-hms")
    (version "0.2")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "hms" version))
       (sha256
        (base32
         "0ln1dc26mkl5pc26vvyf01d35x75q6cjaj39cccxp67chbwbdlds"))))
    (build-system r-build-system)
    (home-page "https://github.com/rstats-db/hms")
    (synopsis "Pretty time of day")
    (description
     "This package implements an S3 class for storing and formatting
time-of-day values, based on the @code{difftime} class.")
    (license license:gpl3+)))

(define-public r-readr
  (package
    (name "r-readr")
    (version "1.0.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "readr" version))
              (sha256
               (base32
                "0xji0dbal6xcxnsmjj678fw29n7wrj45wrd5ng99yhqqijcm9f6g"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-curl" ,r-curl)
       ("r-rcpp" ,r-rcpp)
       ("r-hms" ,r-hms)
       ("r-tibble" ,r-tibble)
       ("r-r6" ,r-r6)
       ("r-bh" ,r-bh)))
    (home-page "https://github.com/hadley/readr")
    (synopsis "Read tabular data")
    (description
     "This package provides functions to read flat or tabular text files from
disk (or a connection).")
    (license license:gpl2+)))

(define-public r-plotrix
  (package
    (name "r-plotrix")
    (version "3.6-3")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "plotrix" version))
              (sha256
               (base32
                "0h97jra8zqssi9j4i0psa6c7ya49ya8jd2qc18lc61a4s2yn8w91"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/plotrix")
    (synopsis "Various plotting functions")
    (description
     "This package provides lots of plotting, various labeling, axis and color
scaling functions for R.")
    (license license:gpl2+)))

(define-public r-gridbase
  (package
    (name "r-gridbase")
    (version "0.4-7")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "gridBase" version))
              (sha256
               (base32
                "09jzw4rzwf2y5lcz7b16mb68pn0fqigv34ff7lr6w3yi9k91i1xy"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/gridBase")
    (synopsis "Integration of base and grid graphics")
    (description
     "This package provides an integration of base and grid graphics for R.")
    (license license:gpl2+)))

(define-public r-lattice
  (package
    (name "r-lattice")
    (version "0.20-34")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "lattice" version))
              (sha256
               (base32
                "0615h69czr73k47whhzimf1qxv5qk0cabcrkljwhyrn6m6piq6ja"))))
    (build-system r-build-system)
    (home-page "http://lattice.r-forge.r-project.org/")
    (synopsis "High-level data visualization system")
    (description
     "The lattice package provides a powerful and elegant high-level data
visualization system inspired by Trellis graphics, with an emphasis on
multivariate data.  Lattice is sufficient for typical graphics needs, and is
also flexible enough to handle most nonstandard requirements.")
    (license license:gpl2+)))

(define-public r-latticeextra
  (package
    (name "r-latticeextra")
    (version "0.6-28")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "latticeExtra" version))
       (sha256
        (base32
         "1hkyqsa7klk5glj9y1hg3rxr5qilqw8h0017zc4c3nps7lr9a1kq"))))
    (properties `((upstream-name . "latticeExtra")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-lattice" ,r-lattice)
       ("r-rcolorbrewer" ,r-rcolorbrewer)))
    (home-page "http://latticeextra.r-forge.r-project.org/")
    (synopsis "Extra graphical utilities based on lattice")
    (description
     "Building on the infrastructure provided by the lattice package, this
package provides several new high-level graphics functions and methods, as
well as additional utilities such as panel and axis annotation functions.")
    (license license:gpl2+)))

(define-public r-rcpparmadillo
  (package
    (name "r-rcpparmadillo")
    (version "0.7.500.0.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "RcppArmadillo" version))
              (sha256
               (base32
                "06qb6877c5qd8lvnc4b27z8fwb5r5pyylkj0g6kj1rn868zkh5ps"))
              (modules '((guix build utils)))
              ;; Remove bundled armadillo sources
              (snippet
               '(begin
                  (delete-file-recursively "inst/include/armadillo_bits")
                  (delete-file "inst/include/armadillo")))))
    (properties `((upstream-name . "RcppArmadillo")))
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
     `(("r-rcpp" ,r-rcpp)
       ("armadillo" ,armadillo-for-rcpparmadillo)))
    (home-page "https://github.com/RcppCore/RcppArmadillo")
    (synopsis "Rcpp integration for the Armadillo linear algebra library")
    (description
     "Armadillo is a templated C++ linear algebra library that aims towards a
good balance between speed and ease of use.  Integer, floating point and
complex numbers are supported, as well as a subset of trigonometric and
statistics functions.  Various matrix decompositions are provided through
optional integration with LAPACK and ATLAS libraries.  This package includes
the header files from the templated Armadillo library.")
    ;; Armadillo is licensed under the MPL 2.0, while RcppArmadillo (the Rcpp
    ;; bindings to Armadillo) is licensed under the GNU GPL version 2 or
    ;; later, as is the rest of 'Rcpp'.
    (license license:gpl2+)))

(define-public r-bitops
  (package
    (name "r-bitops")
    (version "1.0-6")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "bitops" version))
              (sha256
               (base32
                "176nr5wpnkavn5z0yy9f7d47l37ndnn2w3gv854xav8nnybi6wwv"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/bitops")
    (synopsis "Bitwise operations")
    (description
     "This package provides functions for bitwise operations on integer
vectors.")
    (license license:gpl2+)))

(define-public r-catools
  (package
    (name "r-catools")
    (version "1.17.1")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "caTools" version))
              (sha256
               (base32
                "1x4szsn2qmbzpyjfdaiz2q7jwhap2gky9wq0riah74q0pzz76ank"))))
    (properties `((upstream-name . "caTools")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-bitops" ,r-bitops)))
    (home-page "http://cran.r-project.org/web/packages/caTools")
    (synopsis "Various tools including functions for moving window statistics")
    (description
     "This package contains several basic utility functions including:
moving (rolling, running) window statistic functions, read/write for GIF and
ENVI binary files, fast calculation of AUC, LogitBoost classifier, base64
encoder/decoder, round-off-error-free sum and cumsum, etc.")
    (license license:gpl3+)))

(define-public r-rmarkdown
  (package
    (name "r-rmarkdown")
    (version "1.1")
    (source
      (origin
        (method url-fetch)
        (uri (cran-uri "rmarkdown" version))
        (sha256
          (base32
            "1czvkaz1ji3jyj6qrvbswisqs9d05ljqc4vjkfdrf6hygix7azd0"))))
    (properties `((upstream-name . "rmarkdown")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-catools" ,r-catools)
       ("r-evaluate" ,r-evaluate)
       ("r-tibble" ,r-tibble)
       ("r-htmltools" ,r-htmltools)
       ("r-jsonlite" ,r-jsonlite)
       ("r-base64enc" ,r-base64enc)
       ("r-knitr" ,r-knitr)
       ("r-yaml" ,r-yaml)
       ("ghc-pandoc" ,ghc-pandoc)))
    (home-page "http://rmarkdown.rstudio.com")
    (synopsis "Convert R Markdown documents into a variety of formats")
    (description
     "This package provides tools to convert R Markdown documents into a
variety of formats.")
    (license license:gpl3+)))

(define-public r-gtable
  (package
    (name "r-gtable")
    (version "0.2.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "gtable" version))
              (sha256
               (base32
                "0vz7073m0a2q12qzzihrfh5c2kx5jqi5l7z470fxmwqghdllh7l0"))))
    (properties `((upstream-name . "gtable")))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/gtable")
    (synopsis "Arrange grobs in tables")
    (description
     "This package provides tools to make it easier to work with tables of
grobs.")
    (license license:gpl2+)))

(define-public r-gridextra
  (package
    (name "r-gridextra")
    (version "2.2.1")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "gridExtra" version))
              (sha256
               (base32
                "0638ihwl00j76ivaxxhxvi8z573lwy1jym3srr78mx6dbdd4bzj4"))))
    (properties `((upstream-name . "gridExtra")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-gtable" ,r-gtable)))
    (native-inputs
     `(("r-knitr" ,r-knitr))) ;for building vignettes
    (home-page "https://github.com/baptiste/gridextra")
    (synopsis "Miscellaneous functions for \"Grid\" graphics")
    (description
     "This package provides a number of user-level functions to work with
@code{grid} graphics, notably to arrange multiple grid-based plots on a page,
and draw tables.")
    (license license:gpl2+)))

(define-public r-rsqlite
  (package
    (name "r-rsqlite")
    (version "1.0.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "RSQLite" version))
              (sha256
               (base32
                "08b1syv8z887gxiw8i09dpqh0zisfb6ihq6qqr01zipvkahzq34f"))))
    (properties `((upstream-name . "RSQLite")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-dbi" ,r-dbi)))
    (home-page "https://github.com/rstats-db/RSQLite")
    (synopsis "SQLite interface for R")
    (description
     "This package embeds the SQLite database engine in R and provides an
interface compliant with the DBI package.  The source for the SQLite
engine (version 3.8.6) is included.")
    (license license:lgpl2.0+)))

(define-public r-rcurl
  (package
    (name "r-rcurl")
    (version "1.95-0.1.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://www.bioconductor.org/packages/"
                                  "release/extra/src/"
                                  "contrib/RCurl_" version ".tar.gz"))
              (sha256
               (base32
                "0l7qi45jxlf898n0jazabnam1yyczvqfdknd00bdirhhiplpd1sc"))))
    (properties `((upstream-name . "RCurl")))
    (build-system r-build-system)
    (inputs
     `(("libcurl" ,curl)))
    (propagated-inputs
     `(("r-bitops" ,r-bitops)))
    (home-page "http://www.omegahat.org/RCurl")
    (synopsis "General network client interface for R")
    (description
     "The package allows one to compose general HTTP requests and provides
convenient functions to fetch URIs, GET and POST forms, etc. and process the
results returned by the Web server.  This provides a great deal of control
over the HTTP/FTP/... connection and the form of the request while providing a
higher-level interface than is available just using R socket connections.
Additionally, the underlying implementation is robust and extensive,
supporting FTP/FTPS/TFTP (uploads and downloads), SSL/HTTPS, telnet, dict,
ldap, and also supports cookies, redirects, authentication, etc.")
    (license license:bsd-3)))

(define-public r-xml
  (package
    (name "r-xml")
    (version "3.98-1.4")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "XML" version))
              (sha256
               (base32
                "09hiy5a875v2fhsgrsfymrwccn9249wnnsr6ck2slrig65svq2lw"))))
    (properties
     `((upstream-name . "XML")))
    (build-system r-build-system)
    (inputs
     `(("libxml2" ,libxml2)))
    (propagated-inputs
     `(("r-rcurl" ,r-rcurl)))
    (home-page "http://www.omegahat.org/RSXML")
    (synopsis "Tools for parsing and generating XML within R")
    (description
     "Many approaches for both reading and creating XML (and HTML)
documents (including DTDs), both local and accessible via HTTP or FTP.  Also
offers access to an XPath \"interpreter\".")
    (license license:bsd-2)))

(define-public r-xnomial
  (package
    (name "r-xnomial")
    (version "1.0.4")
    (source
     (origin (method url-fetch)
             (uri (cran-uri "XNomial" version))
             (sha256
              (base32
               "1mwx302576rmsjllbq2clfxilm3hkyp5bw0wmwqbn0kgv5wpy8z6"))))
    (properties (quasiquote ((upstream-name . "XNomial"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/XNomial")
    (synopsis "Goodness-of-Fit test for multinomial data")
    (description
     "This package provides an exact Goodness-of-Fit test for
multinomial data with fixed probabilities.  It can be used to
determine whether a set of counts fits a given expected ratio.  To see
whether a set of observed counts fits an expectation, one can examine
all possible outcomes with @code{xmulti()} or a random sample of them
with @code{xmonte()} and find the probability of an observation
deviating from the expectation by at least as much as the observed.
As a measure of deviation from the expected, one can use the
log-likelihood ratio, the multinomial probability, or the classic
chi-square statistic.  A histogram of the test statistic can also be
plotted and compared with the asymptotic curve.")
    (license (list license:gpl2+ license:gpl3+))))

(define-public r-lambda-r
  (package
    (name "r-lambda-r")
    (version "1.1.9")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "lambda.r" version))
              (sha256
               (base32
                "1j6287iqvs3ill6r5g6ksf5809qp0l0nf20ib8266m1r09lc9j14"))))
    (properties `((upstream-name . "lambda.r")))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/lambda.r")
    (synopsis "Functional programming extension for R")
    (description
     "This package provides a language extension to efficiently write
functional programs in R.  Syntax extensions include multi-part function
definitions, pattern matching, guard statements, built-in (optional) type
safety.")
    (license license:lgpl3+)))

(define-public r-futile-options
  (package
    (name "r-futile-options")
    (version "1.0.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "futile.options" version))
              (sha256
               (base32
                "1hp82h6xqq5cck67h7lpf22n3j7mg3v1mla5y5ivnzrrb7iyr17f"))))
    (properties
     `((upstream-name . "futile.options")))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/futile.options")
    (synopsis "Options management framework")
    (description
     "The futile.options subsystem provides an easy user-defined options
management system that is properly scoped.  This means that options created
via @code{futile.options} are fully self-contained and will not collide with
options defined in other packages.")
    (license license:lgpl3+)))

(define-public r-futile-logger
  (package
    (name "r-futile-logger")
    (version "1.4.3")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "futile.logger" version))
              (sha256
               (base32
                "1r3nayk0z9n1svbf8640vw90dal5q07nkn0gv4bnva3pbzb352sy"))))
    (properties `((upstream-name . "futile.logger")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-futile-options" ,r-futile-options)
       ("r-lambda-r" ,r-lambda-r)))
    (home-page "http://cran.r-project.org/web/packages/futile.logger")
    (synopsis "Logging utility for R")
    (description
     "This package provides a simple yet powerful logging utility.  Based
loosely on log4j, futile.logger takes advantage of R idioms to make logging a
convenient and easy to use replacement for @code{cat} and @code{print}
statements.")
    (license license:lgpl3+)))

(define-public r-segmented
  (package
    (name "r-segmented")
    (version "0.5-1.4")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "segmented" version))
       (sha256
        (base32
         "1740cvx2q4v23g4q0zkvg50s5bv8jcrlzzhm7fac4xn0riwmzp5i"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/segmented")
    (synopsis "Regression models with breakpoints estimation")
    (description
     "Given a regression model, segmented updates the model by adding one or
more segmented (i.e., piecewise-linear) relationships.  Several variables with
multiple breakpoints are allowed.")
    (license (list license:gpl2+ license:gpl3+))))

(define-public r-snow
  (package
    (name "r-snow")
    (version "0.4-2")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "snow" version))
              (sha256
               (base32
                "1mxbrkpnmq32x4wd0194d541661yvfrrjlr3lsf7qq53ms3h21zf"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/snow")
    (synopsis "Support for simple parallel computing in R")
    (description
     "The snow package provides support for simple parallel computing on a
network of workstations using R.  A master R process calls @code{makeCluster}
to start a cluster of worker processes; the master process then uses functions
such as @code{clusterCall} and @code{clusterApply} to execute R code on the
worker processes and collect and return the results on the master.")
    (license (list license:gpl2+ license:gpl3+))))

(define-public r-sparsem
  (package
    (name "r-sparsem")
    (version "1.72")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "SparseM" version))
              (sha256
               (base32
                "0zpb1swn9xjkb22sky10ixff7vqfiz9m36nkbc1qqbm9frcldnka"))))
    (properties
     `((upstream-name . "SparseM")))
    (inputs
     `(("gfortran" ,gfortran)))
    (build-system r-build-system)
    (home-page "http://www.econ.uiuc.edu/~roger/research/sparse/sparse.html")
    (synopsis "Sparse linear algebra")
    (description
     "This package provides some basic linear algebra functionality for sparse
matrices.  It includes Cholesky decomposition and backsolving as well as
standard R subsetting and Kronecker products.")
    (license license:gpl2+)))

(define-public r-iterators
  (package
    (name "r-iterators")
    (version "1.0.8")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "iterators" version))
       (sha256
        (base32
         "1f057pabs7ss9h1n244can26qsi5n2k3salrdk0b0vkphlrs4kmf"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/iterators")
    (synopsis "Iterator construct for R")
    (description
     "This package provides support for iterators, which allow a programmer to
traverse through all the elements of a vector, list, or other collection of
data.")
    (license license:asl2.0)))

(define-public r-codetools
  (package
    (name "r-codetools")
    (version "0.2-15")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "codetools" version))
       (sha256
        (base32
         "0h7sjmvvsi35041jp47cxhsqzgf1y8jrw6fxii7n26i8g7nrh1sf"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/codetools")
    (synopsis "Code analysis tools for R")
    (description "This package provides code analysis tools for R to check R
code for possible problems.")
    (license (list license:gpl2+ license:gpl3+))))

(define-public r-foreach
  (package
    (name "r-foreach")
    (version "1.4.3")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "foreach" version))
       (sha256
        (base32
         "10aqsd3rxz03s1qdb6gsb1cj89mj4vmh491zfpin4skj1xvkzw0y"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-codetools" ,r-codetools)
       ("r-iterators" ,r-iterators)))
    (home-page "http://cran.r-project.org/web/packages/foreach")
    (synopsis "Foreach looping construct for R")
    (description
     "This package provides support for the @code{foreach} looping construct.
@code{foreach} is an idiom that allows for iterating over elements in a
collection, without the use of an explicit loop counter.  This package in
particular is intended to be used for its return value, rather than for its
side effects.  In that sense, it is similar to the standard @code{lapply}
function, but doesn't require the evaluation of a function.  Using
@code{foreach} without side effects also facilitates executing the loop in
parallel.")
    (license license:asl2.0)))

(define-public r-doparallel
  (package
    (name "r-doparallel")
    (version "1.0.10")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "doParallel" version))
       (sha256
        (base32
         "1mddx25l25pw9d0csnx2q203dbg5hbrhkr1f08kw0p02a1lln0kh"))))
    (properties `((upstream-name . "doParallel")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-foreach" ,r-foreach)
       ("r-iterators" ,r-iterators)))
    (home-page "http://cran.r-project.org/web/packages/doParallel")
    (synopsis "Foreach parallel adaptor for the 'parallel' package")
    (description
     "This package provides a parallel backend for the @code{%dopar%} function
using the parallel package.")
    (license license:gpl2+)))

(define-public r-domc
  (package
    (name "r-domc")
    (version "1.3.4")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "doMC" version))
       (sha256
        (base32
         "0y47jl6g4f83r14pj8bafdzq1phj7bxy5dwyz3k43d2rr8phk8bn"))))
    (properties `((upstream-name . "doMC")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-foreach" ,r-foreach)
       ("r-iterators" ,r-iterators)))
    (home-page "http://cran.r-project.org/web/packages/doMC")
    (synopsis "Foreach parallel adaptor for the 'parallel' package")
    (description
     "This package provides a parallel backend for the @code{%dopar%} function
using the multicore functionality of the parallel package.")
    (license license:gpl2+)))

(define-public r-dt
  (package
    (name "r-dt")
    (version "0.2")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "DT" version))
              (sha256
               (base32
                "1g86p0jcjqi2ph5rhm45jkzibsa6yfcj8n5cg3giy90sqgjzkdx1"))))
    (properties
     `((upstream-name . "DT")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-htmltools" ,r-htmltools)
       ("r-htmlwidgets" ,r-htmlwidgets)
       ("r-magrittr" ,r-magrittr)))
    (home-page "http://rstudio.github.io/DT")
    (synopsis "R wrapper of the DataTables JavaScript library")
    (description
     "This package allows for data objects in R to be rendered as HTML tables
using the JavaScript library 'DataTables' (typically via R Markdown or Shiny).
The 'DataTables' library has been included in this R package.")
    ;; The DT package as a whole is distributed under GPLv3.  The DT package
    ;; inludes other software components under different licenses:
    ;;
    ;;   * Expat: jQuery, jquery.highlight.js, DataTables
    ;;   * ASL2.0: selectize.js
    ;;   * WTFPL: noUiSlider
    (license (list license:gpl3
                   license:expat
                   license:asl2.0
                   (license:non-copyleft "http://www.wtfpl.net/txt/copying/")))))

(define-public r-base64enc
  (package
    (name "r-base64enc")
    (version "0.1-3")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "base64enc" version))
              (sha256
               (base32
                "13b89fhg1nx7zds82a0biz847ixphg9byf5zl2cw9kab6s56v1bd"))))
    (build-system r-build-system)
    (home-page "http://www.rforge.net/base64enc")
    (synopsis "Tools for Base64 encoding")
    (description
     "This package provides tools for handling Base64 encoding.  It is more
flexible than the orphaned \"base64\" package.")
    (license license:gpl2+)))

(define-public r-irlba
  (package
    (name "r-irlba")
    (version "2.1.2")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "irlba" version))
       (sha256
        (base32
         "1qbcn0ix85pmk296jhpi419kvh06vxm5cq24yk013ps3g7fyi0si"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/irlba")
    (synopsis "Methods for eigendecomposition of large matrices")
    (description
     "This package provides fast and memory efficient methods for truncated
singular and eigenvalue decompositions, as well as for principal component
analysis of large sparse or dense matrices.")
    (license (list license:gpl2+ license:gpl3+))))

(define-public r-glmnet
  (package
   (name "r-glmnet")
   (version "2.0-5")
   (source
    (origin
     (method url-fetch)
     (uri (cran-uri "glmnet" version))
     (sha256
      (base32
       "1cbpzmbv837fvq88rgn6mgzgr9f1wqp9fg8gh2kkmngvr1957a9c"))))
   (build-system r-build-system)
    (inputs
     `(("gfortran" ,gfortran)))
   (propagated-inputs
    `(("r-foreach" ,r-foreach)))
   (home-page "http://www.jstatsoft.org/v33/i01")
   (synopsis "Lasso and elastic-net regularized generalized linear models")
   (description
    "The glmnet package provides efficient procedures for fitting the entire
lasso or elastic-net regularization path for linear and Poisson regression, as
well as logistic, multinomial, Cox, multiple-response Gaussian and grouped
multinomial models.  The algorithm uses cyclical coordinate descent in a
path-wise fashion.")
   (license license:gpl2+)))

(define-public r-pkgmaker
  (package
    (name "r-pkgmaker")
    (version "0.22")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "pkgmaker" version))
       (sha256
        (base32
         "0vrqnd3kg6liqvpbd969jjsdx0f0rvmmxgdbwwrp6xfmdg0pib8r"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-codetools" ,r-codetools)
       ("r-digest" ,r-digest)
       ("r-registry" ,r-registry)
       ("r-stringr" ,r-stringr)
       ("r-xtable" ,r-xtable)))
    (home-page "https://renozao.github.io/pkgmaker")
    (synopsis "Package development utilities")
    (description
     "This package provides some low-level utilities to use for R package
development.  It currently provides managers for multiple package specific
options and registries, vignette, unit test and bibtex related utilities.")
    (license license:gpl2+)))

 (define-public r-registry
   (package
     (name "r-registry")
     (version "0.3")
     (source
      (origin
        (method url-fetch)
        (uri (cran-uri "registry" version))
        (sha256
         (base32
          "0c7lscfxncwwd8zp46h2xfw9gw14dypqv6m2kx85xjhjh0xw99aq"))))
     (build-system r-build-system)
     (home-page "http://cran.r-project.org/web/packages/registry")
     (synopsis "Infrastructure for R package registries")
     (description
      "This package provides a generic infrastructure for creating and using R
package registries.")
     (license license:gpl2+)))

(define-public r-rngtools
  (package
    (name "r-rngtools")
    (version "1.2.4")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "rngtools" version))
       (sha256
        (base32
         "1fcgfqrrb48z37xgy8sffx91p9irp39yqzxv7nqp1x2hnwsrh097"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-digest" ,r-digest)
       ("r-pkgmaker" ,r-pkgmaker)
       ("r-stringr" ,r-stringr)))
    (home-page "https://renozao.github.io/rngtools")
    (synopsis "Utility functions for working with random number generators")
    (description
     "This package contains a set of functions for working with Random Number
Generators (RNGs).  In particular, it defines a generic S4 framework for
getting/setting the current RNG, or RNG data that are embedded into objects
for reproducibility.  Notably, convenient default methods greatly facilitate
the way current RNG settings can be changed.")
    (license license:gpl3+)))

(define-public r-rtsne
  (package
    (name "r-rtsne")
    (version "0.11")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "Rtsne" version))
       (sha256
        (base32
         "0zi4nxgpiv1gpdmcnqdhz5kymzp8m5xj02zpf290p1yyydl76bhy"))))
    (properties `((upstream-name . "Rtsne")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-rcpp" ,r-rcpp)))
    (home-page "https://github.com/jkrijthe/Rtsne")
    (synopsis "T-distributed stochastic neighbor embedding")
    (description
     "This package provides an R wrapper around the fast T-distributed
Stochastic Neighbor Embedding using a Barnes-Hut implementation.")
    ;; The declared license for this package is BSD-3, but it also includes
    ;; code licensed under BSD-4.
    (license (list license:bsd-3 license:bsd-4))))

(define-public r-e1071
  (package
    (name "r-e1071")
    (version "1.6-7")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "e1071" version))
       (sha256
        (base32
         "1069qwj9gsjq6par2cgfah8nn5x2w38830761x1f7mqpmk0gnj3h"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/e1071")
    (synopsis "Miscellaneous functions for probability theory")
    (description
     "This package provides functions for latent class analysis, short time
Fourier transform, fuzzy clustering, support vector machines, shortest path
computation, bagged clustering, naive Bayes classifier, and more.")
    (license license:gpl2+)))

(define-public r-bigmemory-sri
  (package
    (name "r-bigmemory-sri")
    (version "0.1.3")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "bigmemory.sri" version))
       (sha256
        (base32 "0mg14ilwdkd64q2ri9jdwnk7mp55dqim7xfifrs65sdsv1934h2m"))))
    (properties
     `((upstream-name . "bigmemory.sri")))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/bigmemory.sri")
    (synopsis "Shared resource interface for the bigmemory package")
    (description "This package provides a shared resource interface for the
bigmemory and synchronicity packages.")
    ;; Users can choose either LGPLv3 or ASL2.0.
    (license (list license:lgpl3 license:asl2.0))))

(define-public r-synchronicity
  (package
    (name "r-synchronicity")
    (version "1.1.9.1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "synchronicity" version))
       (sha256
        (base32
         "0d9skpwmsnkn4xb3f2kgyyv8bhdi0r9p1kj3cvi0s92fjjnpi00c"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-bh" ,r-bh)
       ("r-bigmemory-sri" ,r-bigmemory-sri)
       ("r-rcpp" ,r-rcpp)))
    (home-page "http://www.bigmemory.org")
    (synopsis "Boost mutex functionality in R")
    (description "This package provides support for synchronization
via mutexes and may eventually support interprocess communication and
message passing.")
    ;; Users can choose either LGPLv3 or ASL2.0.
    (license (list license:lgpl3 license:asl2.0))))

(define-public r-bigmemory
  (package
    (name "r-bigmemory")
    (version "4.5.19")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "bigmemory" version))
       (sha256
        (base32
         "191gbzca557kpk7mdsg716vfyqpr7j5din6qb8hin4g1nkzzwmg6"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-bh" ,r-bh)
       ("r-rcpp" ,r-rcpp)
       ("r-bigmemory-sri" ,r-bigmemory-sri)
       ("r-r-utils" ,r-r-utils)))
    (home-page "http://www.bigmemory.org")
    (synopsis "Manage large matrices with shared memory or memory-mapped files")
    (description "This package provides methods to create, store, access, and
manipulate large matrices.  Matrices are allocated to shared memory and may use
memory-mapped files.")
    ;; Users can choose either LGPLv3 or ASL2.0.
    (license (list license:lgpl3 license:asl2.0))))

(define-public r-nmf
  (package
    (name "r-nmf")
    (version "0.20.6")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "NMF" version))
       (sha256
        (base32
         "0mmh9bz0zjwd8h9jplz4rq3g94npaqj8s4px51vcv47csssd9k6z"))))
    (properties `((upstream-name . "NMF")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-cluster" ,r-cluster)
       ("r-bigmemory" ,r-bigmemory)
       ("r-synchronicity" ,r-synchronicity)
       ("r-colorspace" ,r-colorspace)
       ("r-digest" ,r-digest)
       ("r-doparallel" ,r-doparallel)
       ("r-foreach" ,r-foreach)
       ("r-ggplot2" ,r-ggplot2)
       ("r-gridbase" ,r-gridbase)
       ("r-pkgmaker" ,r-pkgmaker)
       ("r-rcolorbrewer" ,r-rcolorbrewer)
       ("r-registry" ,r-registry)
       ("r-reshape2" ,r-reshape2)
       ("r-rngtools" ,r-rngtools)
       ("r-stringr" ,r-stringr)))
    (home-page "http://renozao.github.io/NMF")
    (synopsis "Algorithms and framework for nonnegative matrix factorization")
    (description
     "This package provides a framework to perform Non-negative Matrix
Factorization (NMF).  The package implements a set of already published
algorithms and seeding methods, and provides a framework to test, develop and
plug new or custom algorithms.  Most of the built-in algorithms have been
optimized in C++, and the main interface function provides an easy way of
performing parallel computations on multicore machines.")
    (license license:gpl2+)))

(define-public r-igraph
  (package
    (name "r-igraph")
    (version "1.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "igraph" version))
       (sha256
        (base32
         "00jnm8v3kvxpxav5klld2z2nnkcpj4sdwv4ksipddy5mp04ysr6w"))))
    (build-system r-build-system)
    (native-inputs
     `(("gfortran" ,gfortran)))
    (inputs
     `(("gmp" ,gmp)
       ("libxml2" ,libxml2)))
    (propagated-inputs
     `(("r-irlba" ,r-irlba)
       ("r-magrittr" ,r-magrittr)
       ("r-nmf" ,r-nmf)))
    (home-page "http://igraph.org")
    (synopsis "Network analysis and visualization")
    (description
     "This package provides routines for simple graphs and network analysis.
It can handle large graphs very well and provides functions for generating
random and regular graphs, graph visualization, centrality methods and much
more.")
    (license license:gpl2+)))

(define-public r-r-methodss3
  (package
    (name "r-r-methodss3")
    (version "1.7.1")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "R.methodsS3" version))
              (sha256
               (base32
                "11z6v2i7jl647wxi9p5z66yvfnnqv6s7fxqmz7w2gkb6j8wl1f24"))))
    (properties `((upstream-name . "R.methodsS3")))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/R.methodsS3")
    (synopsis "S3 methods simplified")
    (description
     "This package provides methods that simplify the setup of S3 generic
functions and S3 methods.  Major effort has been made in making definition of
methods as simple as possible with a minimum of maintenance for package
developers.  For example, generic functions are created automatically, if
missing, and naming conflict are automatically solved, if possible.  The
method @code{setMethodS3()} is a good start for those who in the future may
want to migrate to S4.")
    (license license:lgpl2.1+)))

(define-public r-r-oo
  (package
    (name "r-r-oo")
    (version "1.21.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "R.oo" version))
              (sha256
               (base32
                "0723gxjazgqq7v3lwnl7axw3brzcnizvhbd71ijkkv8mz31fwp34"))))
    (properties `((upstream-name . "R.oo")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-r-methodss3" ,r-r-methodss3)))
    (home-page "https://github.com/HenrikBengtsson/R.oo")
    (synopsis "R object-oriented programming with or without references")
    (description
     "This package provides methods and classes for object-oriented
programming in R with or without references.  Large effort has been made on
making definition of methods as simple as possible with a minimum of
maintenance for package developers.")
    (license license:lgpl2.1+)))

(define-public r-r-utils
  (package
    (name "r-r-utils")
    (version "2.4.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "R.utils" version))
              (sha256
               (base32
                "0cn0wlmgwclmqak05825wrk9q894xa4qjqa7rn0i9p4ss7k6vifj"))))
    (properties `((upstream-name . "R.utils")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-r-methodss3" ,r-r-methodss3)
       ("r-r-oo" ,r-r-oo)))
    (home-page "https://github.com/HenrikBengtsson/R.utils")
    (synopsis "Various programming utilities")
    (description
     "This package provides utility functions useful when programming and
developing R packages.")
    (license license:lgpl2.1+)))

(define-public r-r-cache
  (package
    (name "r-r-cache")
    (version "0.12.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "R.cache" version))
              (sha256
               (base32
                "006x52w9r8phw5hgqmyp0bz8z42vn8p5yibibnzi1sfa1xlw8iyx"))))
    (properties `((upstream-name . "R.cache")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-digest" ,r-digest)
       ("r-r-methodss3" ,r-r-methodss3)
       ("r-r-oo" ,r-r-oo)
       ("r-r-utils" ,r-r-utils)))
    (home-page "https://github.com/HenrikBengtsson/R.cache")
    (synopsis "Light-weight caching of objects and results")
    (description
     "This package provides methods for caching or memoization of objects and
results.  With this package, any R object can be cached in a key-value storage
where the key can be an arbitrary set of R objects.  The cache memory is
persistent (on the file system).")
    (license license:lgpl2.1+)))

(define-public r-r-rsp
  (package
    (name "r-r-rsp")
    (version "0.30.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "R.rsp" version))
              (sha256
               (base32
                "1ssykygqkxzx9qblxhavxlf2z6r5bhk0s47yw1dllfiyc8zy7jv2"))))
    (properties `((upstream-name . "R.rsp")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-r-cache" ,r-r-cache)
       ("r-r-methodss3" ,r-r-methodss3)
       ("r-r-oo" ,r-r-oo)
       ("r-r-utils" ,r-r-utils)))
    (home-page "https://github.com/HenrikBengtsson/R.rsp")
    (synopsis "Dynamic generation of scientific reports")
    (description
     "The RSP markup language provides a powerful markup for controlling the
content and output of LaTeX, HTML, Markdown, AsciiDoc, Sweave and knitr
documents (and more), e.g. @code{Today's date is <%=Sys.Date()%>}.  Contrary
to many other literate programming languages, with RSP it is straightforward
to loop over mixtures of code and text sections, e.g.  in month-by-month
summaries.  RSP has also several preprocessing directives for incorporating
static and dynamic contents of external files (local or online) among other
things.  RSP is ideal for self-contained scientific reports and R package
vignettes.")
    (license license:lgpl2.1+)))

(define-public r-mvtnorm
  (package
    (name "r-mvtnorm")
    (version "1.0-5")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "mvtnorm" version))
              (sha256
               (base32
                "1pc1mi2h063gh4a40009xk5j6pf5bm4274i5kycln38dixsry3yh"))))
    (build-system r-build-system)
    (inputs
     `(("gfortran" ,gfortran)))
    (home-page "http://mvtnorm.R-forge.R-project.org")
    (synopsis "Package for multivariate normal and t-distributions")
    (description "This package can compute multivariate normal and
t-probabilities, quantiles, random deviates and densities.")
    (license license:gpl2)))

(define-public r-matrixstats
  (package
    (name "r-matrixstats")
    (version "0.51.0")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "matrixStats" version))
              (sha256
               (base32
                "0bsalx605kgb9nl7mfnq1qinkyd9s97p8plymsyfja1gmcnjrcpj"))))
    (properties `((upstream-name . "matrixStats")))
    (build-system r-build-system)
    (native-inputs
     `(("r-r-rsp" ,r-r-rsp))) ;used to build vignettes
    (home-page "https://github.com/HenrikBengtsson/matrixStats")
    (synopsis "Methods applying to vectors and matrix rows and columns")
    (description
     "This package provides methods operating on rows and columns of matrices,
e.g.  @code{rowMedians()}, @code{rowRanks()}, and @code{rowSds()}.  There are
also some vector-based methods, e.g. @code{binMeans()}, @code{madDiff()} and
@code{weightedMedians()}.  All methods have been optimized for speed and
memory usage.")
    (license license:artistic2.0)))

(define-public r-viridis
  (package
    (name "r-viridis")
    (version "0.3.4")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "viridis" version))
              (sha256
               (base32
                "1a9hqn2pccpc51vh8ghw698ni6xzdnp8v0n8kgjh51nlz5hhc87j"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-ggplot2" ,r-ggplot2)
       ("r-gridextra" ,r-gridextra)))
    (home-page "https://github.com/sjmgarnier/viridis")
    (synopsis "Matplotlib default color map")
    (description
     "This package is a port of the new @url{matplotlib,
http://matplotlib.org/} color maps (@code{viridis}--the default--,
@code{magma}, @code{plasma}, and @code{inferno}) to R.  These color maps are
designed in such a way that they will analytically be perfectly
perceptually-uniform, both in regular form and also when converted to
black-and-white.  They are also designed to be perceived by readers with the
most common form of color blindness.")
    (license license:x11)))

(define-public r-viridislite
  (package
    (name "r-viridislite")
    (version "0.1.3")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "viridisLite" version))
       (sha256
        (base32
         "1b0fhj8i1m9jsz91gzag60k7vy7kk5xkdg31rc3h3spq96l66psp"))))
    (properties `((upstream-name . "viridisLite")))
    (build-system r-build-system)
    (home-page "https://github.com/sjmgarnier/viridisLite")
    (synopsis "Default color maps from matplotlib")
    (description
     "This package is a port of the new @code{matplotlib} color maps ('viridis',
'magma', 'plasma' and 'inferno') to R.  matplotlib is a popular plotting
library for Python.  These color maps are designed in such a way that they
will analytically be perfectly perceptually-uniform, both in regular form and
also when converted to black-and-white.  They are also designed to be
perceived by readers with the most common form of color blindness.  This is
the 'lite' version of the more complete @code{viridis} package.")
    (license license:expat)))

(define-public r-tidyr
  (package
    (name "r-tidyr")
    (version "0.6.0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "tidyr" version))
       (sha256
        (base32
         "1bpwbphgl43ym433b0nrshwhr7pprmj1wkpkamdzix1zvf9dcbc2"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-dplyr" ,r-dplyr)
       ("r-lazyeval" ,r-lazyeval)
       ("r-magrittr" ,r-magrittr)
       ("r-rcpp" ,r-rcpp)
       ("r-stringi" ,r-stringi)))
    (home-page "https://github.com/hadley/tidyr")
    (synopsis "Tidy data with `spread()` and `gather()` functions")
    (description
     "tidyr is a reframing of the reshape2 package designed to accompany the
tidy data framework, and to work hand-in-hand with magrittr and dplyr to build
a solid pipeline for data analysis.  It is designed specifically for tidying
data, not the general reshaping that reshape2 does, or the general aggregation
that reshape did.  In particular, built-in methods only work for data frames,
and tidyr provides no margins or aggregation.")
    (license license:expat)))

(define-public r-hexbin
  (package
    (name "r-hexbin")
    (version "1.27.1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "hexbin" version))
       (sha256
        (base32
         "0xi6fbf1fvyn2gffr052n3viibqzpr3603sgi4xaminbzja4syjh"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-lattice" ,r-lattice)))
    (native-inputs
     `(("gfortran" ,gfortran)))
    (home-page "http://github.com/edzer/hexbin")
    (synopsis "Hexagonal binning routines")
    (description
     "This package provides binning and plotting functions for hexagonal bins.
It uses and relies on grid graphics and formal (S4) classes and methods.")
    (license license:gpl2+)))

(define-public r-purrr
  (package
    (name "r-purrr")
    (version "0.2.2")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "purrr" version))
       (sha256
        (base32
         "0lss8q733nv7s154wargm6vnxq55qygnxakib8xdj4jv0y86sxc3"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-bh" ,r-bh)
       ("r-dplyr" ,r-dplyr)
       ("r-lazyeval" ,r-lazyeval)
       ("r-magrittr" ,r-magrittr)
       ("r-rcpp" ,r-rcpp)))
    (home-page "https://github.com/hadley/purrr")
    (synopsis "Functional programming tools")
    (description
     "This package completes R's functional programming tools with missing
features present in other programming languages.")
    (license license:gpl3+)))

(define-public r-plotly
  (package
    (name "r-plotly")
    (version "4.5.2")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "plotly" version))
              (sha256
               (base32
                "08shs0qhy9js0fpj3d4rzfbwmw11ki3z5vg8jszfm6m69mfkgzw1"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-base64enc" ,r-base64enc)
       ("r-digest" ,r-digest)
       ("r-dplyr" ,r-dplyr)
       ("r-ggplot2" ,r-ggplot2)
       ("r-hexbin" ,r-hexbin)
       ("r-htmlwidgets" ,r-htmlwidgets)
       ("r-httr" ,r-httr)
       ("r-jsonlite" ,r-jsonlite)
       ("r-lazyeval" ,r-lazyeval)
       ("r-magrittr" ,r-magrittr)
       ("r-purrr" ,r-purrr)
       ("r-scales" ,r-scales)
       ("r-tibble" ,r-tibble)
       ("r-tidyr" ,r-tidyr)
       ("r-viridislite" ,r-viridislite)))
    (home-page "https://plot.ly/r")
    (synopsis "Create interactive web graphics")
    (description
     "This package enables the translation of ggplot2 graphs to an interactive
web-based version and/or the creation of custom web-based visualizations
directly from R.  Once uploaded to a plotly account, plotly graphs (and the
data behind them) can be viewed and modified in a web browser.")
    (license license:x11)))

(define-public r-biased-urn
  (package
   (name "r-biased-urn")
   (version "1.07")
   (source
    (origin
     (method url-fetch)
     (uri (cran-uri "BiasedUrn" version))
     (sha256
      (base32
       "13i2lgfnjhlbbm2yxfc2l5hswqw6x03pwba5csjmirv8kpjw4xr3"))))
   (properties `((upstream-name . "BiasedUrn")))
   (build-system r-build-system)
   (home-page "http://www.agner.org/random/")
   (synopsis "Biased urn model distributions")
   (description
    "This package provides statistical models of biased sampling in the form
of univariate and multivariate noncentral hypergeometric distributions,
including Wallenius' noncentral hypergeometric distribution and Fisher's
noncentral hypergeometric distribution (also called extended hypergeometric
distribution).")
   (license license:gpl3+)))

(define-public r-rematch
  (package
    (name "r-rematch")
    (version "1.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "rematch" version))
       (sha256
        (base32
         "0y3mshvpvz9csmq8hk8jbabx4nxlv5sckvfzvm6920ndg34xw2d4"))))
    (build-system r-build-system)
    (home-page "https://github.com/MangoTheCat/rematch")
    (synopsis "Match regular expressions with a nicer API")
    (description
     "This package provides a small wrapper on @code{regexpr} to extract the
matches and captured groups from the match of a regular expression to a
character vector.")
    (license license:expat)))

(define-public r-cellranger
  (package
    (name "r-cellranger")
    (version "1.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "cellranger" version))
       (sha256
        (base32
         "16fgi3annn34c3cxi0pxf62mmmmxi21hp0zzlv7bkfsjqy4g4f2x"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-rematch" ,r-rematch)
       ("r-tibble" ,r-tibble)))
    (home-page "https://github.com/rsheets/cellranger")
    (synopsis "Translate spreadsheet cell ranges to rows and columns")
    (description
     "This package provides helper functions to work with spreadsheets and the
@code{A1:D10} style of cell range specification.")
    (license license:expat)))

(define-public r-googlesheets
  (package
    (name "r-googlesheets")
    (version "0.2.1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "googlesheets" version))
       (sha256
        (base32
         "0ps13h1cv7fj5dh8s4nvwi64wnnyqdsadcaa4iizq1c5s615cwk3"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-cellranger" ,r-cellranger)
       ("r-dplyr" ,r-dplyr)
       ("r-httr" ,r-httr)
       ("r-jsonlite" ,r-jsonlite)
       ("r-purrr" ,r-purrr)
       ("r-readr" ,r-readr)
       ("r-stringr" ,r-stringr)
       ("r-tidyr" ,r-tidyr)
       ("r-xml2" ,r-xml2)))
    (home-page "https://github.com/jennybc/googlesheets")
    (synopsis "Manage Google spreadsheets from R")
    (description "This package provides tools to interact with Google Sheets
from within R.")
    (license license:expat)))

(define-public r-spams
  (package
    (name "r-spams")
    (version "2.5-svn2014-07-04")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://gforge.inria.fr/frs/download.php/33815/"
                           "spams-R-v" version ".tar.gz"))
       (sha256
        (base32
         "1k459jg9a334slkw31w63l4d39xszjzsng7dv5j1mp78zifz7hvx"))))
    (build-system r-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'chdir
           (lambda _ (chdir "spams") #t))
         ;; Since R 3.3.0 including R headers inside of an extern "C" block
         ;; causes C headers to be included, which results in a lot of
         ;; duplicate definitions.  This can be avoided by defining
         ;; NO_C_HEADERS before including the R headers.
         (add-after 'chdir 'patch-use-of-R-headers
           (lambda _
             (substitute* "src/spams.cpp"
               (("#include <R.h>" line)
                (string-append "#define NO_C_HEADERS\n" line)))
             #t))
         ;; This looks like a syntax error.
         (add-after 'chdir 'patch-isnan
           (lambda _
             (substitute* '"src/spams/linalg/linalg.h"
               (("if isnan\\(lambda\\) \\{")
                "if (isnan(lambda)) {"))
             #t)))))
    (home-page "http://spams-devel.gforge.inria.fr")
    (synopsis "Toolbox for solving sparse estimation problems")
    (description "SPAMS (SPArse Modeling Software) is an optimization toolbox
for solving various sparse estimation problems.  It includes tools for the
following problems:

@enumerate
@item Dictionary learning and matrix factorization (NMF, sparse @dfn{principle
 component analysis} (PCA), ...)
@item Solving sparse decomposition problems with LARS, coordinate descent,
 OMP, SOMP, proximal methods
@item Solving structured sparse decomposition problems (l1/l2, l1/linf, sparse
 group lasso, tree-structured regularization, structured sparsity with
 overlapping groups,...).
@end enumerate\n")
    (license license:gpl3+)))

(define-public r-rpart
  (package
    (name "r-rpart")
    (version "4.1-10")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "rpart" version))
       (sha256
        (base32
         "119dvh2cpab4vq9blvbkil5hgq6w018amiwlda3ii0fki39axpf5"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/rpart")
    (synopsis "Recursive partitioning and regression trees")
    (description
     "This package provides recursive partitioning functions for
classification, regression and survival trees.")
    (license (list license:gpl2+ license:gpl3+))))

(define-public r-survival
  (package
    (name "r-survival")
    (version "2.40-1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "survival" version))
       (sha256
        (base32
         "10pf0kq0g66k5rgizrvh29mq3r84acljw2jgrv5yp6z38xw23mci"))))
    (build-system r-build-system)
    (home-page "https://github.com/therneau/survival")
    (synopsis "Survival analysis")
    (description
     "This package contains the core survival analysis routines, including
definition of Surv objects, Kaplan-Meier and Aalen-Johansen (multi-state)
curves, Cox models, and parametric accelerated failure time models.")
    (license license:lgpl2.0+)))

(define-public r-hmisc
  (package
    (name "r-hmisc")
    (version "4.0-0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "Hmisc" version))
       (sha256
        (base32
         "0azxmg9h9c456biydc0wpi9xhljmd37m8bv0zaadbvc93g7x0l4b"))))
    (properties `((upstream-name . "Hmisc")))
    (build-system r-build-system)
    (native-inputs
     `(("gfortran" ,gfortran)))
    (propagated-inputs
     `(("r-acepack" ,r-acepack)
       ("r-cluster" ,r-cluster)
       ("r-data-table" ,r-data-table)
       ("r-foreign" ,r-foreign)
       ("r-formula" ,r-formula)
       ("r-ggplot2" ,r-ggplot2)
       ("r-gridextra" ,r-gridextra)
       ("r-gtable" ,r-gtable)
       ("r-lattice" ,r-lattice)
       ;; Hmisc needs survival >= 2.40.1, so it cannot use the survival
       ;; package that comes with R 3.3.1.
       ("r-survival" ,r-survival)
       ("r-latticeextra" ,r-latticeextra)
       ("r-htmltable" ,r-htmltable)
       ("r-htmltools" ,r-htmltools)
       ("r-viridis" ,r-viridis)
       ("r-nnet" ,r-nnet)
       ("r-rpart" ,r-rpart)))
    (home-page "http://biostat.mc.vanderbilt.edu/Hmisc")
    (synopsis "Miscellaneous data analysis and graphics functions")
    (description
     "This package contains many functions useful for data analysis,
high-level graphics, utility operations, functions for computing sample size
and power, importing and annotating datasets, imputing missing values,
advanced table making, variable clustering, character string manipulation,
conversion of R objects to LaTeX code, and recoding variables.")
    (license license:gpl2+)))

(define-public r-runit
  (package
    (name "r-runit")
    (version "0.4.31")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "RUnit" version))
       (sha256
        (base32
         "1jqr871jkll2xmk7wk5hv1z3a36hyn2ibgivw7bwk4b346940xlx"))))
    (properties `((upstream-name . "RUnit")))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/RUnit")
    (synopsis "R unit test framework")
    (description
     "This package provides R functions implementing a standard unit testing
framework, with additional code inspection and report generation tools.")
    (license license:gpl2+)))

(define-public r-dynamictreecut
  (package
    (name "r-dynamictreecut")
    (version "1.63-1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "dynamicTreeCut" version))
       (sha256
        (base32
         "1fadbql7g5r2vvlkr89nlrjxwp4yx4xrdqmv077qvmnx9vv0f4w3"))))
    (properties `((upstream-name . "dynamicTreeCut")))
    (build-system r-build-system)
    (home-page
     "http://www.genetics.ucla.edu/labs/horvath/CoexpressionNetwork/BranchCutting/")
    (synopsis "Detect clusters in hierarchical clustering dendrograms")
    (description
     "This package contains methods for the detection of clusters in
hierarchical clustering dendrograms.")
    (license license:gpl2+)))

(define-public r-preprocesscore
  (package
    (name "r-preprocesscore")
    (version "1.36.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "preprocessCore" version))
       (sha256
        (base32
         "1n8y12q7145f385gm2k3c6y3vwvin7jlb47la4mnl7mar6pq9kmp"))))
    (properties
     `((upstream-name . "preprocessCore")))
    (build-system r-build-system)
    (home-page "https://github.com/bmbolstad/preprocessCore")
    (synopsis "Collection of pre-processing functions")
    (description
     "This package provides a library of core pre-processing and normalization
routines.")
    (license license:lgpl2.0+)))

(define-public r-fastcluster
  (package
    (name "r-fastcluster")
    (version "1.1.20")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "fastcluster" version))
       (sha256
        (base32
         "0rlbxhh894znf10x0xgkv9dzpibgq9jw5aqpgviccdnxc2c5hwid"))))
    (build-system r-build-system)
    (home-page "http://danifold.net/fastcluster.html")
    (synopsis "Fast hierarchical clustering routines")
    (description
     "This package implements fast hierarchical, agglomerative clustering
routines.  Part of the functionality is designed as drop-in replacement for
existing routines: @code{linkage()} in the SciPy package
@code{scipy.cluster.hierarchy}, @code{hclust()} in R's @code{stats} package,
and the @code{flashClust} package.  It provides the same functionality with
the benefit of a much faster implementation.  Moreover, there are
memory-saving routines for clustering of vector data, which go beyond what the
existing packages provide.")
    (license license:bsd-2)))

(define-public r-sfsmisc
  (package
    (name "r-sfsmisc")
    (version "1.1-0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "sfsmisc" version))
       (sha256
        (base32
         "0580piv4n1nispl3pa8nfjjfnb8iwaqky2dzdy0aqnxrxgrhqhvz"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/sfsmisc")
    (synopsis "Utilities from \"Seminar fuer Statistik\" ETH Zurich")
    (description
     "This package provides useful utilities from Seminar fuer Statistik ETH
Zurich, including many that are related to graphics.")
    (license license:gpl2+)))

(define-public r-gtools
  (package
    (name "r-gtools")
    (version "3.5.0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "gtools" version))
       (sha256
        (base32
         "1xknwk9xlsj027pg0nwiizigcrsc84hdrig0jn0cgcyxj8dabdl6"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/gtools")
    (synopsis "Various R programming tools")
    (description
     "This package contains a collection of various functions to assist in R
programming, such as tools to assist in developing, updating, and maintaining
R and R packages, calculating the logit and inverse logit transformations,
tests for whether a value is missing, empty or contains only @code{NA} and
@code{NULL} values, and many more.")
    (license license:gpl2)))

(define-public r-gdata
  (package
    (name "r-gdata")
    (version "2.17.0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "gdata" version))
       (sha256
        (base32
         "0kiy3jbcszlpmarg311spdsfi5pn89wgy742dxsbzxk8907fr5w0"))))
    (build-system r-build-system)
    (inputs
     `(("perl" ,perl)))
    (propagated-inputs
     `(("r-gtools" ,r-gtools)))
    (home-page "http://cran.r-project.org/web/packages/gdata")
    (synopsis "Various R programming tools for data manipulation")
    (description
     "This package provides various R programming tools for data manipulation,
including:

@itemize
@item medical unit conversions
@item combining objects
@item character vector operations
@item factor manipulation
@item obtaining information about R objects
@item manipulating MS-Excel formatted files
@item generating fixed-width format files
@item extricating components of date and time objects
@item operations on columns of data frames
@item matrix operations
@item operations on vectors and data frames
@item value of last evaluated expression
@item wrapper for @code{sample} that ensures consistent behavior for
  both scalar and vector arguments
@end itemize\n")
    (license license:gpl2+)))

(define-public r-gplots
  (package
    (name "r-gplots")
    (version "3.0.1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "gplots" version))
       (sha256
        (base32
         "02nb8n3s7c1zxq2s7ycaq2ys72y7mzirxrwj954h6gdc4x1zhg9l"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-catools" ,r-catools)
       ("r-gdata" ,r-gdata)
       ("r-gtools" ,r-gtools)
       ("r-kernsmooth" ,r-kernsmooth)))
    (home-page "http://cran.r-project.org/web/packages/gplots")
    (synopsis "Various R programming tools for plotting data")
    (description
     "This package provides various R programming tools for plotting data,
including:

@itemize
@item calculating and plotting locally smoothed summary function
@item enhanced versions of standard plots
@item manipulating colors
@item calculating and plotting two-dimensional data summaries
@item enhanced regression diagnostic plots
@item formula-enabled interface to @code{stats::lowess} function
@item displaying textual data in plots
@item baloon plots
@item plotting \"Venn\" diagrams
@item displaying Open-Office style plots
@item plotting multiple data on same region, with separate axes
@item plotting means and confidence intervals
@item spacing points in an x-y plot so they don't overlap
@end itemize\n")
    (license license:gpl2+)))

(define-public r-rocr
  (package
    (name "r-rocr")
    (version "1.0-7")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "ROCR" version))
       (sha256
        (base32
         "1jay8cm7lgq56i967vm5c2hgaxqkphfpip0gn941li3yhh7p3vz7"))))
    (properties `((upstream-name . "ROCR")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-gplots" ,r-gplots)))
    (home-page "http://rocr.bioinf.mpi-sb.mpg.de/")
    (synopsis "Visualizing the performance of scoring classifiers")
    (description
     "ROCR is a flexible tool for creating cutoff-parameterized 2D performance
curves by freely combining two from over 25 performance measures (new
performance measures can be added using a standard interface).  Curves from
different cross-validation or bootstrapping runs can be averaged by different
methods, and standard deviations, standard errors or box plots can be used to
visualize the variability across the runs.  The parameterization can be
visualized by printing cutoff values at the corresponding curve positions, or
by coloring the curve according to cutoff.  All components of a performance
plot can be quickly adjusted using a flexible parameter dispatching
mechanism.")
    (license license:gpl2+)))

(define-public r-kernsmooth
  (package
    (name "r-kernsmooth")
    (version "2.23-15")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "KernSmooth" version))
       (sha256
        (base32
         "1xhha8kw10jv8pv8b61hb5in9qiw3r2a9kdji3qlm991s4zd4wlb"))))
    (properties `((upstream-name . "KernSmooth")))
    (build-system r-build-system)
    (inputs
     `(("gfortran" ,gfortran)))
    (home-page "http://cran.r-project.org/web/packages/KernSmooth")
    (synopsis "Functions for kernel smoothing")
    (description
     "This package provides functions for kernel smoothing (and density
estimation) corresponding to the book: Wand, M.P.  and Jones, M.C. (1995)
\"Kernel Smoothing\".")
    ;; Unlimited use and distribution
    (license (license:non-copyleft "file://LICENSE.note"))))

(define-public r-zoo
  (package
    (name "r-zoo")
    (version "1.7-13")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "zoo" version))
              (sha256
               (base32
                "0m67bnrg7r1jxvs9p7rpa430szp5qfp65r056yb8bivpc16jd98c"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-lattice" ,r-lattice)))
    (home-page "http://zoo.R-Forge.R-project.org/")
    (synopsis "S3 infrastructure for regular and irregular time series")
    (description "This package contains an S3 class with methods for totally
ordered indexed observations.  It is particularly aimed at irregular time
series of numeric vectors/matrices and factors.")
    (license license:gpl2+)))

(define-public r-ztable
  (package
    (name "r-ztable")
    (version "0.1.5")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "ztable" version))
              (sha256
               (base32
                "1jfqnqy9544gfvz3bsb48v4177nwp4b4n9l2743asq8sbq305b5r"))))
    (build-system r-build-system)
    (home-page "http://cran.r-project.org/web/packages/ztable")
    (synopsis "Zebra-striped tables in LaTeX and HTML formats for R")
    (description
     "This package provides functions to make zebra-striped tables (tables
with alternating row colors) in LaTeX and HTML formats easily from
@code{data.frame}, @code{matrix}, @code{lm}, @code{aov}, @code{anova},
@code{glm}, @code{coxph}, @code{nls}, @code{fitdistr}, @code{mytable} and
@code{cbind.mytable} objects.")
    (license license:gpl2+)))
