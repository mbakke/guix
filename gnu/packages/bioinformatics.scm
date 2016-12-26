;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2014, 2015, 2016 Ricardo Wurmus <rekado@elephly.net>
;;; Copyright © 2015, 2016 Ben Woodcroft <donttrustben@gmail.com>
;;; Copyright © 2015, 2016 Pjotr Prins <pjotr.guix@thebird.nl>
;;; Copyright © 2015 Andreas Enge <andreas@enge.fr>
;;; Copyright © 2016 Roel Janssen <roel@gnu.org>
;;; Copyright © 2016 Efraim Flashner <efraim@flashner.co.il>
;;; Copyright © 2016 Marius Bakke <mbakke@fastmail.com>
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

(define-module (gnu packages bioinformatics)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix hg-download)
  #:use-module (guix build-system ant)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system cmake)
  #:use-module (guix build-system perl)
  #:use-module (guix build-system python)
  #:use-module (guix build-system r)
  #:use-module (guix build-system ruby)
  #:use-module (guix build-system trivial)
  #:use-module (gnu packages)
  #:use-module (gnu packages autotools)
  #:use-module (gnu packages algebra)
  #:use-module (gnu packages base)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages boost)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages cpio)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages documentation)
  #:use-module (gnu packages datastructures)
  #:use-module (gnu packages file)
  #:use-module (gnu packages flex)
  #:use-module (gnu packages gawk)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages gd)
  #:use-module (gnu packages gtk)
  #:use-module (gnu packages glib)
  #:use-module (gnu packages groff)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages haskell)
  #:use-module (gnu packages image)
  #:use-module (gnu packages imagemagick)
  #:use-module (gnu packages java)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages logging)
  #:use-module (gnu packages machine-learning)
  #:use-module (gnu packages man)
  #:use-module (gnu packages maths)
  #:use-module (gnu packages mpi)
  #:use-module (gnu packages ncurses)
  #:use-module (gnu packages pcre)
  #:use-module (gnu packages parallel)
  #:use-module (gnu packages pdf)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages popt)
  #:use-module (gnu packages protobuf)
  #:use-module (gnu packages python)
  #:use-module (gnu packages readline)
  #:use-module (gnu packages ruby)
  #:use-module (gnu packages serialization)
  #:use-module (gnu packages statistics)
  #:use-module (gnu packages tbb)
  #:use-module (gnu packages tex)
  #:use-module (gnu packages texinfo)
  #:use-module (gnu packages textutils)
  #:use-module (gnu packages time)
  #:use-module (gnu packages tls)
  #:use-module (gnu packages vim)
  #:use-module (gnu packages web)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages xorg)
  #:use-module (gnu packages zip)
  #:use-module (srfi srfi-1))

(define-public aragorn
  (package
    (name "aragorn")
    (version "1.2.38")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://mbio-serv2.mbioekol.lu.se/ARAGORN/Downloads/aragorn"
                    version ".tgz"))
              (sha256
               (base32
                "09i1rg716smlbnixfm7q1ml2mfpaa2fpn3hwjg625ysmfwwy712b"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; there are no tests
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'build
                  (lambda _
                    (zero? (system* "gcc"
                                    "-O3"
                                    "-ffast-math"
                                    "-finline-functions"
                                    "-o"
                                    "aragorn"
                                    (string-append "aragorn" ,version ".c")))))
         (replace 'install
                  (lambda* (#:key outputs #:allow-other-keys)
                    (let* ((out (assoc-ref outputs "out"))
                           (bin (string-append out "/bin"))
                           (man (string-append out "/share/man/man1")))
                      (mkdir-p bin)
                      (copy-file "aragorn"
                                 (string-append bin "/aragorn"))
                      (mkdir-p man)
                      (copy-file "aragorn.1"
                                 (string-append man "/aragorn.1")))
                    #t)))))
    (home-page "http://mbio-serv2.mbioekol.lu.se/ARAGORN")
    (synopsis "Detect tRNA, mtRNA and tmRNA genes in nucleotide sequences")
    (description
     "Aragorn identifies transfer RNA, mitochondrial RNA and
transfer-messenger RNA from nucleotide sequences, based on homology to known
tRNA consensus sequences and RNA structure.  It also outputs the secondary
structure of the predicted RNA.")
    (license license:gpl2)))

(define-public bamm
  (package
    (name "bamm")
    (version "1.7.3")
    (source (origin
              (method url-fetch)
              ;; BamM is not available on pypi.
              (uri (string-append
                    "https://github.com/Ecogenomics/BamM/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1f35yxp4pc8aadsvbpg6r4kg2jh4fkjci0iby4iyljm6980sac0s"))
              (modules '((guix build utils)))
              (snippet
               `(begin
                  ;; Delete bundled htslib.
                  (delete-file-recursively "c/htslib-1.3.1")
                  #t))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2 ; BamM is Python 2 only.
       ;; Do not use bundled libhts.  Do use the bundled libcfu because it has
       ;; been modified from its original form.
       #:configure-flags
       (let ((htslib (assoc-ref %build-inputs "htslib")))
         (list "--with-libhts-lib" (string-append htslib "/lib")
               "--with-libhts-inc" (string-append htslib "/include/htslib")))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'autogen
           (lambda _
             (with-directory-excursion "c"
               (let ((sh (which "sh")))
                 ;; Use autogen so that 'configure' works.
                 (substitute* "autogen.sh" (("/bin/sh") sh))
                 (setenv "CONFIG_SHELL" sh)
                 (substitute* "configure" (("/bin/sh") sh))
                 (zero? (system* "./autogen.sh"))))))
         (delete 'build)
         ;; Run tests after installation so compilation only happens once.
         (delete 'check)
         (add-after 'install 'wrap-executable
           (lambda* (#:key outputs #:allow-other-keys)
            (let* ((out  (assoc-ref outputs "out"))
                   (path (getenv "PATH")))
              (wrap-program (string-append out "/bin/bamm")
                `("PATH" ":" prefix (,path))))
            #t))
         (add-after 'wrap-executable 'post-install-check
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (setenv "PATH"
                     (string-append (assoc-ref outputs "out")
                                    "/bin:"
                                    (getenv "PATH")))
             (setenv "PYTHONPATH"
                     (string-append
                      (assoc-ref outputs "out")
                      "/lib/python"
                      (string-take (string-take-right
                                    (assoc-ref inputs "python") 5) 3)
                      "/site-packages:"
                      (getenv "PYTHONPATH")))
             ;; There are 2 errors printed, but they are safe to ignore:
             ;; 1) [E::hts_open_format] fail to open file ...
             ;; 2) samtools view: failed to open ...
             (zero? (system* "nosetests")))))))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("libtool" ,libtool)
       ("zlib" ,zlib)
       ("python-nose" ,python2-nose)
       ("python-pysam" ,python2-pysam)))
    (inputs
     `(("htslib" ,htslib)
       ("samtools" ,samtools)
       ("bwa" ,bwa)
       ("grep" ,grep)
       ("sed" ,sed)
       ("coreutils" ,coreutils)))
    (propagated-inputs
     `(("python-numpy" ,python2-numpy)))
    (home-page "http://ecogenomics.github.io/BamM/")
    (synopsis "Metagenomics-focused BAM file manipulator")
    (description
     "BamM is a C library, wrapped in python, to efficiently generate and
parse BAM files, specifically for the analysis of metagenomic data.  For
instance, it implements several methods to assess contig-wise read coverage.")
    (license license:lgpl3+)))

(define-public bamtools
  (package
    (name "bamtools")
    (version "2.3.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/pezmaster31/bamtools/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1brry29bw2xr2l9pqn240rkqwayg85b8qq78zk2zs6nlspk4d018"))))
    (build-system cmake-build-system)
    (arguments
     `(#:tests? #f ;no "check" target
       #:phases
       (modify-phases %standard-phases
         (add-before
          'configure 'set-ldflags
          (lambda* (#:key outputs #:allow-other-keys)
            (setenv "LDFLAGS"
                    (string-append
                     "-Wl,-rpath="
                     (assoc-ref outputs "out") "/lib/bamtools")))))))
    (inputs `(("zlib" ,zlib)))
    (home-page "https://github.com/pezmaster31/bamtools")
    (synopsis "C++ API and command-line toolkit for working with BAM data")
    (description
     "BamTools provides both a C++ API and a command-line toolkit for handling
BAM files.")
    (license license:expat)))

(define-public bcftools
  (package
    (name "bcftools")
    (version "1.3.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/samtools/bcftools/releases/download/"
                    version "/bcftools-" version ".tar.bz2"))
              (sha256
               (base32
                "095ry68vmz9q5s1scjsa698dhgyvgw5aicz24c19iwfbai07mhqj"))
              (modules '((guix build utils)))
              (snippet
               ;; Delete bundled htslib.
               '(delete-file-recursively "htslib-1.3.1"))))
    (build-system gnu-build-system)
    (arguments
     `(#:test-target "test"
       #:make-flags
       (list
        "USE_GPL=1"
        (string-append "prefix=" (assoc-ref %outputs "out"))
        (string-append "HTSDIR=" (assoc-ref %build-inputs "htslib") "/include")
        (string-append "HTSLIB=" (assoc-ref %build-inputs "htslib") "/lib/libhts.a")
        (string-append "BGZIP=" (assoc-ref %build-inputs "htslib") "/bin/bgzip")
        (string-append "TABIX=" (assoc-ref %build-inputs "htslib") "/bin/tabix"))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'patch-Makefile
           (lambda _
             (substitute* "Makefile"
               ;; Do not attempt to build htslib.
               (("^include \\$\\(HTSDIR\\)/htslib\\.mk") "")
               ;; Link against GSL cblas.
               (("-lcblas") "-lgslcblas"))
             #t))
         (delete 'configure)
         (add-before 'check 'patch-tests
           (lambda _
             (substitute* "test/test.pl"
               (("/bin/bash") (which "bash")))
             #t)))))
    (native-inputs
     `(("htslib" ,htslib)
       ("perl" ,perl)))
    (inputs
     `(("gsl" ,gsl)
       ("zlib" ,zlib)))
    (home-page "https://samtools.github.io/bcftools/")
    (synopsis "Utilities for variant calling and manipulating VCFs and BCFs")
    (description
     "BCFtools is a set of utilities that manipulate variant calls in the
Variant Call Format (VCF) and its binary counterpart BCF.  All commands work
transparently with both VCFs and BCFs, both uncompressed and BGZF-compressed.")
    ;; The sources are dual MIT/GPL, but becomes GPL-only when USE_GPL=1.
    (license (list license:gpl3+ license:expat))))

(define-public bedops
  (package
    (name "bedops")
    (version "2.4.14")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/bedops/bedops/archive/v"
                                  version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1kqbac547wyqma81cyky9n7mkgikjpsfd3nnmcm6hpqwanqgh10v"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f
       #:make-flags (list (string-append "BINDIR=" %output "/bin"))
       #:phases
       (alist-cons-after
         'unpack 'unpack-tarballs
         (lambda _
           ;; FIXME: Bedops includes tarballs of minimally patched upstream
           ;; libraries jansson, zlib, and bzip2.  We cannot just use stock
           ;; libraries because at least one of the libraries (zlib) is
           ;; patched to add a C++ function definition (deflateInit2cpp).
           ;; Until the Bedops developers offer a way to link against system
           ;; libraries we have to build the in-tree copies of these three
           ;; libraries.

           ;; See upstream discussion:
           ;; https://github.com/bedops/bedops/issues/124

           ;; Unpack the tarballs to benefit from shebang patching.
           (with-directory-excursion "third-party"
             (and (zero? (system* "tar" "xvf" "jansson-2.6.tar.bz2"))
                  (zero? (system* "tar" "xvf" "zlib-1.2.7.tar.bz2"))
                  (zero? (system* "tar" "xvf" "bzip2-1.0.6.tar.bz2"))))
           ;; Disable unpacking of tarballs in Makefile.
           (substitute* "system.mk/Makefile.linux"
             (("^\tbzcat .*") "\t@echo \"not unpacking\"\n")
             (("\\./configure") "CONFIG_SHELL=bash ./configure"))
           (substitute* "third-party/zlib-1.2.7/Makefile.in"
             (("^SHELL=.*$") "SHELL=bash\n")))
         (alist-delete 'configure %standard-phases))))
    (home-page "https://github.com/bedops/bedops")
    (synopsis "Tools for high-performance genomic feature operations")
    (description
     "BEDOPS is a suite of tools to address common questions raised in genomic
studies---mostly with regard to overlap and proximity relationships between
data sets.  It aims to be scalable and flexible, facilitating the efficient
and accurate analysis and management of large-scale genomic data.

BEDOPS provides tools that perform highly efficient and scalable Boolean and
other set operations, statistical calculations, archiving, conversion and
other management of genomic data of arbitrary scale.  Tasks can be easily
split by chromosome for distributing whole-genome analyses across a
computational cluster.")
    (license license:gpl2+)))

(define-public bedtools
  (package
    (name "bedtools")
    (version "2.26.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/arq5x/bedtools2/archive/v"
                                  version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0xvri5hnp2iim1cx6mcd5d9f102p5ql41x69rd6106x1c17pinqm"))))
    (build-system gnu-build-system)
    (native-inputs `(("python" ,python-2)))
    (inputs `(("samtools" ,samtools)
              ("zlib" ,zlib)))
    (arguments
     '(#:test-target "test"
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((bin (string-append (assoc-ref outputs "out") "/bin/")))
               (for-each (lambda (file)
                           (install-file file bin))
                         (find-files "bin" ".*")))
             #t)))))
    (home-page "https://github.com/arq5x/bedtools2")
    (synopsis "Tools for genome analysis and arithmetic")
    (description
     "Collectively, the bedtools utilities are a swiss-army knife of tools for
a wide-range of genomics analysis tasks.  The most widely-used tools enable
genome arithmetic: that is, set theory on the genome.  For example, bedtools
allows one to intersect, merge, count, complement, and shuffle genomic
intervals from multiple files in widely-used genomic file formats such as BAM,
BED, GFF/GTF, VCF.")
    (license license:gpl2)))

;; Later releases of bedtools produce files with more columns than
;; what Ribotaper expects.
(define-public bedtools-2.18
  (package (inherit bedtools)
    (name "bedtools")
    (version "2.18.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/arq5x/bedtools2/"
                                  "archive/v" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "05vrnr8yp7swfagshzpgqmzk1blnwnq8pq5pckzi1m26w98d63vf"))))))

(define-public ribotaper
  (package
    (name "ribotaper")
    (version "1.3.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://ohlerlab.mdc-berlin.de/"
                                  "files/RiboTaper/RiboTaper_Version_"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0ykjbps1y3z3085q94npw8i9x5gldc6shy8vlc08v76zljsm07hv"))))
    (build-system gnu-build-system)
    (inputs
     `(("bedtools" ,bedtools-2.18)
       ("samtools" ,samtools-0.1)
       ("r" ,r)
       ("r-foreach" ,r-foreach)
       ("r-xnomial" ,r-xnomial)
       ("r-domc" ,r-domc)
       ("r-multitaper" ,r-multitaper)
       ("r-seqinr" ,r-seqinr)))
    (home-page "https://ohlerlab.mdc-berlin.de/software/RiboTaper_126/")
    (synopsis "Define translated ORFs using ribosome profiling data")
    (description
     "Ribotaper is a method for defining translated @dfn{open reading
frames} (ORFs) using ribosome profiling (ribo-seq) data.  This package
provides the Ribotaper pipeline.")
    (license license:gpl3+)))

(define-public bioawk
  (package
    (name "bioawk")
    (version "1.0")
    (source (origin
      (method url-fetch)
      (uri (string-append "https://github.com/lh3/bioawk/archive/v"
                          version ".tar.gz"))
      (file-name (string-append name "-" version ".tar.gz"))
      (sha256
       (base32 "1daizxsk17ahi9n58fj8vpgwyhzrzh54bzqhanjanp88kgrz7gjw"))))
    (build-system gnu-build-system)
    (inputs
     `(("zlib" ,zlib)))
    (native-inputs
     `(("bison" ,bison)))
    (arguments
     `(#:tests? #f ; There are no tests to run.
       ;; Bison must generate files, before other targets can build.
       #:parallel-build? #f
       #:phases
       (modify-phases %standard-phases
         (delete 'configure) ; There is no configure phase.
         (replace 'install
          (lambda* (#:key outputs #:allow-other-keys)
            (let* ((out (assoc-ref outputs "out"))
                   (bin  (string-append out "/bin"))
                   (man (string-append out "/share/man/man1")))
              (mkdir-p man)
              (copy-file "awk.1" (string-append man "/bioawk.1"))
              (install-file "bioawk" bin)))))))
    (home-page "https://github.com/lh3/bioawk")
    (synopsis "AWK with bioinformatics extensions")
    (description "Bioawk is an extension to Brian Kernighan's awk, adding the
support of several common biological data formats, including optionally gzip'ed
BED, GFF, SAM, VCF, FASTA/Q and TAB-delimited formats with column names.  It
also adds a few built-in functions and a command line option to use TAB as the
input/output delimiter.  When the new functionality is not used, bioawk is
intended to behave exactly the same as the original BWK awk.")
    (license license:x11)))

(define-public python2-pybedtools
  (package
    (name "python2-pybedtools")
    (version "0.6.9")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://pypi.python.org/packages/source/p/pybedtools/pybedtools-"
                    version ".tar.gz"))
              (sha256
               (base32
                "1ldzdxw1p4y3g2ignmggsdypvqkcwqwzhdha4rbgpih048z5p4an"))))
    (build-system python-build-system)
    (arguments `(#:python ,python-2)) ; no Python 3 support
    (inputs
     `(("python-matplotlib" ,python2-matplotlib)))
    (propagated-inputs
     `(("bedtools" ,bedtools)
       ("samtools" ,samtools)))
    (native-inputs
     `(("python-cython" ,python2-cython)
       ("python-pyyaml" ,python2-pyyaml)
       ("python-nose" ,python2-nose)))
    (home-page "https://pythonhosted.org/pybedtools/")
    (synopsis "Python wrapper for BEDtools programs")
    (description
     "pybedtools is a Python wrapper for Aaron Quinlan's BEDtools programs,
which are widely used for genomic interval manipulation or \"genome algebra\".
pybedtools extends BEDTools by offering feature-level manipulations from with
Python.")
    (license license:gpl2+)))

(define-public python-biom-format
  (package
   (name "python-biom-format")
   (version "2.1.5")
   (source
    (origin
     (method url-fetch)
     ;; Use GitHub as source because PyPI distribution does not contain
     ;; test data: https://github.com/biocore/biom-format/issues/693
     (uri (string-append "https://github.com/biocore/biom-format/archive/"
                         version ".tar.gz"))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32
       "1n25w3p1rixbpac8iysmzcja6m4ip5r6sz19l8y6wlwi49hxn278"))))
   (build-system python-build-system)
   (propagated-inputs
    `(("python-numpy" ,python-numpy)
      ("python-scipy" ,python-scipy)
      ("python-future" ,python-future)
      ("python-click" ,python-click)
      ("python-h5py" ,python-h5py)))
   (home-page "http://www.biom-format.org")
   (synopsis "Biological Observation Matrix (BIOM) format utilities")
   (description
    "The BIOM file format is designed to be a general-use format for
representing counts of observations e.g. operational taxonomic units, KEGG
orthology groups or lipid types, in one or more biological samples
e.g. microbiome samples, genomes, metagenomes.")
   (license license:bsd-3)
   (properties `((python2-variant . ,(delay python2-biom-format))))))

(define-public python2-biom-format
  (let ((base (package-with-python2 (strip-python2-variant python-biom-format))))
    (package
      (inherit base)
      (arguments
       `(#:phases
         (modify-phases %standard-phases
           ;; Do not require the unmaintained pyqi library.
           (add-after 'unpack 'remove-pyqi
             (lambda _
               (substitute* "setup.py"
                 (("install_requires.append\\(\"pyqi\"\\)") "pass"))
               #t)))
         ,@(package-arguments base))))))

(define-public bioperl-minimal
  (let* ((inputs `(("perl-module-build" ,perl-module-build)
                   ("perl-data-stag" ,perl-data-stag)
                   ("perl-libwww" ,perl-libwww)
                   ("perl-uri" ,perl-uri)))
         (transitive-inputs
          (map (compose package-name cadr)
               (delete-duplicates
                (concatenate
                 (map (compose package-transitive-target-inputs cadr) inputs))))))
    (package
      (name "bioperl-minimal")
      (version "1.7.0")
      (source
       (origin
         (method url-fetch)
         (uri (string-append "https://github.com/bioperl/bioperl-live/"
                             "archive/release-"
                             (string-map (lambda (c)
                                           (if (char=? c #\.)
                                               #\- c)) version)
                             ".tar.gz"))
         (sha256
          (base32
           "12phgpxwgkqflkwfb9dcqg7a31dpjlfhar8wcgv0aj5ln4akfz06"))))
      (build-system perl-build-system)
      (arguments
       `(#:phases
         (modify-phases %standard-phases
           (add-after
            'install 'wrap-programs
            (lambda* (#:key outputs #:allow-other-keys)
              ;; Make sure all executables in "bin" find the required Perl
              ;; modules at runtime.  As the PERL5LIB variable contains also
              ;; the paths of native inputs, we pick the transitive target
              ;; inputs from %build-inputs.
              (let* ((out  (assoc-ref outputs "out"))
                     (bin  (string-append out "/bin/"))
                     (path (string-join
                            (cons (string-append out "/lib/perl5/site_perl")
                                  (map (lambda (name)
                                         (assoc-ref %build-inputs name))
                                       ',transitive-inputs))
                            ":")))
                (for-each (lambda (file)
                            (wrap-program file
                              `("PERL5LIB" ":" prefix (,path))))
                          (find-files bin "\\.pl$"))
                #t))))))
      (inputs inputs)
      (native-inputs
       `(("perl-test-most" ,perl-test-most)))
      (home-page "http://search.cpan.org/dist/BioPerl")
      (synopsis "Bioinformatics toolkit")
      (description
       "BioPerl is the product of a community effort to produce Perl code which
is useful in biology.  Examples include Sequence objects, Alignment objects
and database searching objects.  These objects not only do what they are
advertised to do in the documentation, but they also interact - Alignment
objects are made from the Sequence objects, Sequence objects have access to
Annotation and SeqFeature objects and databases, Blast objects can be
converted to Alignment objects, and so on.  This means that the objects
provide a coordinated and extensible framework to do computational biology.")
      (license (package-license perl)))))

(define-public python-biopython
  (package
    (name "python-biopython")
    (version "1.68")
    (source (origin
              (method url-fetch)
              ;; use PyPi rather than biopython.org to ease updating
              (uri (pypi-uri "biopython" version))
              (sha256
               (base32
                "07qc7nz0k77y8hf8s18rscvibvm91zw0kkq7ylrhisf8vp8hkp6i"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'check 'set-home
           ;; Some tests require a home directory to be set.
           (lambda _ (setenv "HOME" "/tmp") #t)))))
    (propagated-inputs
     `(("python-numpy" ,python-numpy)))
    (home-page "http://biopython.org/")
    (synopsis "Tools for biological computation in Python")
    (description
     "Biopython is a set of tools for biological computation including parsers
for bioinformatics files into Python data structures; interfaces to common
bioinformatics programs; a standard sequence class and tools for performing
common operations on them; code to perform data classification; code for
dealing with alignments; code making it easy to split up parallelizable tasks
into separate processes; and more.")
    (license (license:non-copyleft "http://www.biopython.org/DIST/LICENSE"))))

(define-public python2-biopython
  (package-with-python2 python-biopython))

;; An outdated version of biopython is required for seqmagick, see
;; https://github.com/fhcrc/seqmagick/issues/59
;; When that issue has been resolved this package should be removed.
(define python2-biopython-1.66
  (package
    (inherit python2-biopython)
    (version "1.66")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "biopython" version))
              (sha256
               (base32
                "1gdv92593klimg22icf5j9by7xiq86jnwzkpz4abaa05ylkdf6hp"))))))

(define-public bpp-core
  ;; The last release was in 2014 and the recommended way to install from source
  ;; is to clone the git repository, so we do this.
  ;; http://biopp.univ-montp2.fr/wiki/index.php/Main_Page
  (let ((commit "7d8bced0d1a87291ea8dd7046b7fb5ff9c35c582"))
    (package
      (name "bpp-core")
      (version (string-append "2.2.0-1." (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "http://biopp.univ-montp2.fr/git/bpp-core")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "10djsq5vlnkilv436gnmh4irpk49v29pa69r6xiryg32xmvn909j"))))
      (build-system cmake-build-system)
      (arguments
       `(#:parallel-build? #f))
      (inputs
       `(("gcc" ,gcc-5))) ; Compilation of bpp-phyl fails with GCC 4.9 so we
                          ; compile all of the bpp packages with GCC 5.
      (home-page "http://biopp.univ-montp2.fr")
      (synopsis "C++ libraries for Bioinformatics")
      (description
       "Bio++ is a set of C++ libraries for Bioinformatics, including sequence
analysis, phylogenetics, molecular evolution and population genetics.  It is
Object Oriented and is designed to be both easy to use and computer efficient.
Bio++ intends to help programmers to write computer expensive programs, by
providing them a set of re-usable tools.")
      (license license:cecill-c))))

(define-public bpp-phyl
  ;; The last release was in 2014 and the recommended way to install from source
  ;; is to clone the git repository, so we do this.
  ;; http://biopp.univ-montp2.fr/wiki/index.php/Main_Page
  (let ((commit "0c07167b629f68b569bf274d1ad0c4af83276ae2"))
    (package
      (name "bpp-phyl")
      (version (string-append "2.2.0-1." (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "http://biopp.univ-montp2.fr/git/bpp-phyl")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "1ssjgchzwj3iai26kyly7gwkdv8sk59nqhkb1wpap3sf5m6kyllh"))))
      (build-system cmake-build-system)
      (arguments
       `(#:parallel-build? #f
         ;; If out-of-source, test data is not copied into the build directory
         ;; so the tests fail.
         #:out-of-source? #f))
      (inputs
       `(("bpp-core" ,bpp-core)
         ("bpp-seq" ,bpp-seq)
         ;; GCC 4.8 fails due to an 'internal compiler error', so we use a more
         ;; modern GCC.
         ("gcc" ,gcc-5)))
      (home-page "http://biopp.univ-montp2.fr")
      (synopsis "Bio++ phylogenetic Library")
      (description
       "Bio++ is a set of C++ libraries for Bioinformatics, including sequence
analysis, phylogenetics, molecular evolution and population genetics.  This
library provides phylogenetics-related modules.")
      (license license:cecill-c))))

(define-public bpp-popgen
  ;; The last release was in 2014 and the recommended way to install from source
  ;; is to clone the git repository, so we do this.
  ;; http://biopp.univ-montp2.fr/wiki/index.php/Main_Page
  (let ((commit "e472bac9b1a148803895d747cd6d0c5904f85d9f"))
    (package
      (name "bpp-popgen")
      (version (string-append "2.2.0-1." (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "http://biopp.univ-montp2.fr/git/bpp-popgen")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "0yn82dzn1n5629nzja68xfrhi655709rjanyryb36vzkmymy6dw5"))))
      (build-system cmake-build-system)
      (arguments
       `(#:parallel-build? #f
         #:tests? #f)) ; There are no tests.
      (inputs
       `(("bpp-core" ,bpp-core)
         ("bpp-seq" ,bpp-seq)
         ("gcc" ,gcc-5)))
      (home-page "http://biopp.univ-montp2.fr")
      (synopsis "Bio++ population genetics library")
      (description
       "Bio++ is a set of C++ libraries for Bioinformatics, including sequence
analysis, phylogenetics, molecular evolution and population genetics.  This
library provides population genetics-related modules.")
      (license license:cecill-c))))

(define-public bpp-seq
  ;; The last release was in 2014 and the recommended way to install from source
  ;; is to clone the git repository, so we do this.
  ;; http://biopp.univ-montp2.fr/wiki/index.php/Main_Page
  (let ((commit "6cfa07965ce152e5598a89df2fa80a75973bfa33"))
    (package
      (name "bpp-seq")
      (version (string-append "2.2.0-1." (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "http://biopp.univ-montp2.fr/git/bpp-seq")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "1nys5jq7jqvdg40d91wsmj3q2yzy4276cp7sp44n67p468f27zf2"))))
      (build-system cmake-build-system)
      (arguments
       `(#:parallel-build? #f
         ;; If out-of-source, test data is not copied into the build directory
         ;; so the tests fail.
         #:out-of-source? #f))
      (inputs
       `(("bpp-core" ,bpp-core)
         ("gcc" ,gcc-5))) ; Use GCC 5 as per 'bpp-core'.
      (home-page "http://biopp.univ-montp2.fr")
      (synopsis "Bio++ sequence library")
      (description
       "Bio++ is a set of C++ libraries for Bioinformatics, including sequence
analysis, phylogenetics, molecular evolution and population genetics.  This
library provides sequence-related modules.")
      (license license:cecill-c))))

(define-public bppsuite
  ;; The last release was in 2014 and the recommended way to install from source
  ;; is to clone the git repository, so we do this.
  ;; http://biopp.univ-montp2.fr/wiki/index.php/Main_Page
  (let ((commit "c516147f57aa50961121cd505bed52cd7603698b"))
    (package
      (name "bppsuite")
      (version (string-append "2.2.0-1." (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "http://biopp.univ-montp2.fr/git/bppsuite")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "1y87pxvw0jxjizhq2dr9g2r91md45k1p9ih2sl1yy1y3p934l2kb"))))
      (build-system cmake-build-system)
      (arguments
       `(#:parallel-build? #f
         #:tests? #f)) ; There are no tests.
      (native-inputs
       `(("groff" ,groff)
         ("man-db" ,man-db)
         ("texinfo" ,texinfo)))
      (inputs
       `(("bpp-core" ,bpp-core)
         ("bpp-seq" ,bpp-seq)
         ("bpp-phyl" ,bpp-phyl)
         ("bpp-phyl" ,bpp-popgen)
         ("gcc" ,gcc-5)))
      (home-page "http://biopp.univ-montp2.fr")
      (synopsis "Bioinformatics tools written with the Bio++ libraries")
      (description
       "Bio++ is a set of C++ libraries for Bioinformatics, including sequence
analysis, phylogenetics, molecular evolution and population genetics.  This
package provides command line tools using the Bio++ library.")
      (license license:cecill-c))))

(define-public blast+
  (package
    (name "blast+")
    (version "2.4.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "ftp://ftp.ncbi.nlm.nih.gov/blast/executables/blast+/"
                    version "/ncbi-blast-" version "+-src.tar.gz"))
              (sha256
               (base32
                "14n9jik6vhiwjd3m7bach4xj1pzfn0szbsbyfxybd9l9cc43b6mb"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  ;; Remove bundled bzip2 and zlib
                  (delete-file-recursively "c++/src/util/compress/bzip2")
                  (delete-file-recursively "c++/src/util/compress/zlib")
                  (substitute* "c++/src/util/compress/Makefile.in"
                    (("bzip2 zlib api") "api"))
                  ;; Remove useless msbuild directory
                  (delete-file-recursively
                   "c++/src/build-system/project_tree_builder/msbuild")
                  #t))))
    (build-system gnu-build-system)
    (arguments
     `(;; There are three(!) tests for this massive library, and all fail with
       ;; "unparsable timing stats".
       ;; ERR [127] --  [util/regexp] test_pcre.sh     (unparsable timing stats)
       ;; ERR [127] --  [serial/datatool] datatool.sh     (unparsable timing stats)
       ;; ERR [127] --  [serial/datatool] datatool_xml.sh     (unparsable timing stats)
       #:tests? #f
       #:out-of-source? #t
       #:parallel-build? #f ; not supported
       #:phases
       (modify-phases %standard-phases
         (add-before
          'configure 'set-HOME
          ;; $HOME needs to be set at some point during the configure phase
          (lambda _ (setenv "HOME" "/tmp") #t))
         (add-after
          'unpack 'enter-dir
          (lambda _ (chdir "c++") #t))
         (add-after
          'enter-dir 'fix-build-system
          (lambda _
            (define (which* cmd)
              (cond ((string=? cmd "date")
                     ;; make call to "date" deterministic
                     "date -d @0")
                    ((which cmd)
                     => identity)
                    (else
                     (format (current-error-port)
                             "WARNING: Unable to find absolute path for ~s~%"
                             cmd)
                     #f)))

            ;; Rewrite hardcoded paths to various tools
            (substitute* (append '("src/build-system/configure.ac"
                                   "src/build-system/configure"
                                   "scripts/common/impl/if_diff.sh"
                                   "scripts/common/impl/run_with_lock.sh"
                                   "src/build-system/Makefile.configurables.real"
                                   "src/build-system/Makefile.in.top"
                                   "src/build-system/Makefile.meta.gmake=no"
                                   "src/build-system/Makefile.meta.in"
                                   "src/build-system/Makefile.meta_l"
                                   "src/build-system/Makefile.meta_p"
                                   "src/build-system/Makefile.meta_r"
                                   "src/build-system/Makefile.mk.in"
                                   "src/build-system/Makefile.requirements"
                                   "src/build-system/Makefile.rules_with_autodep.in")
                                 (find-files "scripts/common/check" "\\.sh$"))
              (("(/usr/bin/|/bin/)([a-z][-_.a-z]*)" all dir cmd)
               (or (which* cmd) all)))

            (substitute* (find-files "src/build-system" "^config.*")
              (("LN_S=/bin/\\$LN_S") (string-append "LN_S=" (which "ln")))
              (("^PATH=.*") ""))

            ;; rewrite "/var/tmp" in check script
            (substitute* "scripts/common/check/check_make_unix.sh"
              (("/var/tmp") "/tmp"))

            ;; do not reset PATH
            (substitute* (find-files "scripts/common/impl/" "\\.sh$")
              (("^ *PATH=.*") "")
              (("action=/bin/") "action=")
              (("export PATH") ":"))
            #t))
         (replace
          'configure
          (lambda* (#:key inputs outputs #:allow-other-keys)
            (let ((out     (assoc-ref outputs "out"))
                  (lib     (string-append (assoc-ref outputs "lib") "/lib"))
                  (include (string-append (assoc-ref outputs "include")
                                          "/include/ncbi-tools++")))
              ;; The 'configure' script doesn't recognize things like
              ;; '--enable-fast-install'.
              (zero? (system* "./configure.orig"
                              (string-append "--with-build-root=" (getcwd) "/build")
                              (string-append "--prefix=" out)
                              (string-append "--libdir=" lib)
                              (string-append "--includedir=" include)
                              (string-append "--with-bz2="
                                             (assoc-ref inputs "bzip2"))
                              (string-append "--with-z="
                                             (assoc-ref inputs "zlib"))
                              ;; Each library is built twice by default, once
                              ;; with "-static" in its name, and again
                              ;; without.
                              "--without-static"
                              "--with-dll"))))))))
    (outputs '("out"       ;  19 MB
               "lib"       ; 203 MB
               "include")) ;  32 MB
    (inputs
     `(("bzip2" ,bzip2)
       ("zlib" ,zlib)))
    (native-inputs
     `(("cpio" ,cpio)))
    (home-page "http://blast.ncbi.nlm.nih.gov")
    (synopsis "Basic local alignment search tool")
    (description
     "BLAST is a popular method of performing a DNA or protein sequence
similarity search, using heuristics to produce results quickly.  It also
calculates an “expect value” that estimates how many matches would have
occurred at a given score by chance, which can aid a user in judging how much
confidence to have in an alignment.")
    ;; Most of the sources are in the public domain, with the following
    ;; exceptions:
    ;;   * Expat:
    ;;     * ./c++/include/util/bitset/
    ;;     * ./c++/src/html/ncbi_menu*.js
    ;;   * Boost license:
    ;;     * ./c++/include/util/impl/floating_point_comparison.hpp
    ;;   * LGPL 2+:
    ;;     * ./c++/include/dbapi/driver/odbc/unix_odbc/
    ;;   * ASL 2.0:
    ;;     * ./c++/src/corelib/teamcity_*
    (license (list license:public-domain
                   license:expat
                   license:boost1.0
                   license:lgpl2.0+
                   license:asl2.0))))

(define-public bless
  (package
    (name "bless")
    (version "1p02")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/bless-ec/bless.v"
                                  version ".tgz"))
              (sha256
               (base32
                "0rm0gw2s18dqwzzpl3c2x1z05ni2v0xz5dmfk3d33j6g4cgrlrdd"))
              (modules '((guix build utils)))
              (snippet
               `(begin
                  ;; Remove bundled boost, pigz, zlib, and .git directory
                  ;; FIXME: also remove bundled sources for murmurhash3 and
                  ;; kmc once packaged.
                  (delete-file-recursively "boost")
                  (delete-file-recursively "pigz")
                  (delete-file-recursively "google-sparsehash")
                  (delete-file-recursively "zlib")
                  (delete-file-recursively ".git")
                  #t))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f ;no "check" target
       #:make-flags
       (list (string-append "ZLIB="
                            (assoc-ref %build-inputs "zlib")
                            "/lib/libz.a")
             (string-append "LDFLAGS="
                            (string-join '("-lboost_filesystem"
                                           "-lboost_system"
                                           "-lboost_iostreams"
                                           "-lz"
                                           "-fopenmp"
                                           "-std=c++11"))))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'do-not-build-bundled-pigz
          (lambda* (#:key inputs outputs #:allow-other-keys)
            (substitute* "Makefile"
              (("cd pigz/pigz-2.3.3; make") ""))
            #t))
         (add-after 'unpack 'patch-paths-to-executables
          (lambda* (#:key inputs outputs #:allow-other-keys)
            (substitute* "parse_args.cpp"
              (("kmc_binary = .*")
               (string-append "kmc_binary = \""
                              (assoc-ref outputs "out")
                              "/bin/kmc\";"))
              (("pigz_binary = .*")
               (string-append "pigz_binary = \""
                              (assoc-ref inputs "pigz")
                              "/bin/pigz\";")))
            #t))
         (replace 'install
          (lambda* (#:key outputs #:allow-other-keys)
            (let ((bin (string-append (assoc-ref outputs "out") "/bin/")))
              (for-each (lambda (file)
                          (install-file file bin))
                        '("bless" "kmc/bin/kmc"))
              #t)))
         (delete 'configure))))
    (native-inputs
     `(("perl" ,perl)))
    (inputs
     `(("openmpi" ,openmpi)
       ("boost" ,boost)
       ("sparsehash" ,sparsehash)
       ("pigz" ,pigz)
       ("zlib" ,zlib)))
    (supported-systems '("x86_64-linux"))
    (home-page "http://sourceforge.net/p/bless-ec/wiki/Home/")
    (synopsis "Bloom-filter-based error correction tool for NGS reads")
    (description
     "@dfn{Bloom-filter-based error correction solution for high-throughput
sequencing reads} (BLESS) uses a single minimum-sized bloom filter is a
correction tool for genomic reads produced by @dfn{Next-generation
sequencing} (NGS).  BLESS produces accurate correction results with much less
memory compared with previous solutions and is also able to tolerate a higher
false-positive rate.  BLESS can extend reads like DNA assemblers to correct
errors at the end of reads.")
    (license license:gpl3+)))

(define-public bowtie
  (package
    (name "bowtie")
    (version "2.2.9")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/BenLangmead/bowtie2/archive/v"
                                  version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1vp5db8i7is57iwjybcdg18f5ivyzlj5g1ix1nlvxainzivhz55g"))
              (modules '((guix build utils)))
              (snippet
               '(substitute* "Makefile"
                  ;; replace BUILD_HOST and BUILD_TIME for deterministic build
                  (("-DBUILD_HOST=.*") "-DBUILD_HOST=\"\\\"guix\\\"\"")
                  (("-DBUILD_TIME=.*") "-DBUILD_TIME=\"\\\"0\\\"\"")))))
    (build-system gnu-build-system)
    (inputs `(("perl" ,perl)
              ("perl-clone" ,perl-clone)
              ("perl-test-deep" ,perl-test-deep)
              ("perl-test-simple" ,perl-test-simple)
              ("python" ,python-2)
              ("tbb" ,tbb)))
    (arguments
     '(#:make-flags
       (list "allall"
             "WITH_TBB=1"
             (string-append "prefix=" (assoc-ref %outputs "out")))
       #:phases
       (alist-delete
        'configure
        (alist-replace
         'check
         (lambda* (#:key outputs #:allow-other-keys)
           (system* "perl"
                    "scripts/test/simple_tests.pl"
                    "--bowtie2=./bowtie2"
                    "--bowtie2-build=./bowtie2-build"))
         %standard-phases))))
    (home-page "http://bowtie-bio.sourceforge.net/bowtie2/index.shtml")
    (synopsis "Fast and sensitive nucleotide sequence read aligner")
    (description
     "Bowtie 2 is a fast and memory-efficient tool for aligning sequencing
reads to long reference sequences.  It is particularly good at aligning reads
of about 50 up to 100s or 1,000s of characters, and particularly good at
aligning to relatively long (e.g. mammalian) genomes.  Bowtie 2 indexes the
genome with an FM Index to keep its memory footprint small: for the human
genome, its memory footprint is typically around 3.2 GB.  Bowtie 2 supports
gapped, local, and paired-end alignment modes.")
    (supported-systems '("x86_64-linux"))
    (license license:gpl3+)))

(define-public tophat
  (package
    (name "tophat")
    (version "2.1.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://ccb.jhu.edu/software/tophat/downloads/tophat-"
                    version ".tar.gz"))
              (sha256
               (base32
                "168zlzykq622zbgkh90a90f1bdgsxkscq2zxzbj8brq80hbjpyp7"))
              (patches (search-patches "tophat-build-with-later-seqan.patch"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  ;; Remove bundled SeqAn and samtools
                  (delete-file-recursively "src/SeqAn-1.3")
                  (delete-file-recursively "src/samtools-0.1.18")
                  #t))))
    (build-system gnu-build-system)
    (arguments
     '(#:parallel-build? #f ; not supported
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'use-system-samtools
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "src/Makefile.in"
               (("(noinst_LIBRARIES = )\\$\\(SAMLIB\\)" _ prefix) prefix)
               (("\\$\\(SAMPROG\\): \\$\\(SAMLIB\\)") "")
               (("SAMPROG = samtools_0\\.1\\.18") "")
               (("\\$\\(samtools_0_1_18_SOURCES\\)") "")
               (("am__EXEEXT_1 = samtools_0\\.1\\.18\\$\\(EXEEXT\\)") ""))
             (substitute* '("src/common.cpp"
                            "src/tophat.py")
               (("samtools_0.1.18") (which "samtools")))
             (substitute* '("src/common.h"
                            "src/bam2fastx.cpp")
               (("#include \"bam.h\"") "#include <samtools/bam.h>")
               (("#include \"sam.h\"") "#include <samtools/sam.h>"))
             (substitute* '("src/bwt_map.h"
                            "src/map2gtf.h"
                            "src/align_status.h")
               (("#include <bam.h>") "#include <samtools/bam.h>")
               (("#include <sam.h>") "#include <samtools/sam.h>"))
             #t)))))
    (inputs
     `(("boost" ,boost)
       ("bowtie" ,bowtie)
       ("samtools" ,samtools-0.1)
       ("ncurses" ,ncurses)
       ("python" ,python-2)
       ("perl" ,perl)
       ("zlib" ,zlib)
       ("seqan" ,seqan)))
    (home-page "http://ccb.jhu.edu/software/tophat/index.shtml")
    (synopsis "Spliced read mapper for RNA-Seq data")
    (description
     "TopHat is a fast splice junction mapper for nucleotide sequence
reads produced by the RNA-Seq method.  It aligns RNA-Seq reads to
mammalian-sized genomes using the ultra high-throughput short read
aligner Bowtie, and then analyzes the mapping results to identify
splice junctions between exons.")
    ;; TopHat is released under the Boost Software License, Version 1.0
    ;; See https://github.com/infphilo/tophat/issues/11#issuecomment-121589893
    (license license:boost1.0)))

(define-public bwa
  (package
    (name "bwa")
    (version "0.7.12")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/bio-bwa/bwa-"
                                  version ".tar.bz2"))
              (sha256
               (base32
                "1330dpqncv0px3pbhjzz1gwgg39kkcv2r9qp2xs0sixf8z8wl7bh"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f ;no "check" target
       #:phases
       (alist-replace
        'install
        (lambda* (#:key outputs #:allow-other-keys)
          (let ((bin (string-append
                      (assoc-ref outputs "out") "/bin"))
                (doc (string-append
                      (assoc-ref outputs "out") "/share/doc/bwa"))
                (man (string-append
                      (assoc-ref outputs "out") "/share/man/man1")))
            (install-file "bwa" bin)
            (install-file "README.md" doc)
            (install-file "bwa.1" man)))
        ;; no "configure" script
        (alist-delete 'configure %standard-phases))))
    (inputs `(("zlib" ,zlib)))
    ;; Non-portable SSE instructions are used so building fails on platforms
    ;; other than x86_64.
    (supported-systems '("x86_64-linux"))
    (home-page "http://bio-bwa.sourceforge.net/")
    (synopsis "Burrows-Wheeler sequence aligner")
    (description
     "BWA is a software package for mapping low-divergent sequences against a
large reference genome, such as the human genome.  It consists of three
algorithms: BWA-backtrack, BWA-SW and BWA-MEM.  The first algorithm is
designed for Illumina sequence reads up to 100bp, while the rest two for
longer sequences ranged from 70bp to 1Mbp.  BWA-MEM and BWA-SW share similar
features such as long-read support and split alignment, but BWA-MEM, which is
the latest, is generally recommended for high-quality queries as it is faster
and more accurate.  BWA-MEM also has better performance than BWA-backtrack for
70-100bp Illumina reads.")
    (license license:gpl3+)))

(define-public bwa-pssm
  (package (inherit bwa)
    (name "bwa-pssm")
    (version "0.5.11")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/pkerpedjiev/bwa-pssm/"
                                  "archive/" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "02p7mpbs4mlxmn84g2x4ghak638vbj4lqix2ipx5g84pz9bhdavg"))))
    (build-system gnu-build-system)
    (inputs
     `(("gdsl" ,gdsl)
       ("zlib" ,zlib)
       ("perl" ,perl)))
    (home-page "http://bwa-pssm.binf.ku.dk/")
    (synopsis "Burrows-Wheeler transform-based probabilistic short read mapper")
    (description
     "BWA-PSSM is a probabilistic short genomic sequence read aligner based on
the use of @dfn{position specific scoring matrices} (PSSM).  Like many of the
existing aligners it is fast and sensitive.  Unlike most other aligners,
however, it is also adaptible in the sense that one can direct the alignment
based on known biases within the data set.  It is coded as a modification of
the original BWA alignment program and shares the genome index structure as
well as many of the command line options.")
    (license license:gpl3+)))

(define-public python2-bx-python
  (package
    (name "python2-bx-python")
    (version "0.7.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://pypi.python.org/packages/source/b/bx-python/bx-python-"
                    version ".tar.gz"))
              (sha256
               (base32
                "0ld49idhc5zjdvbhvjq1a2qmpjj7h5v58rqr25dzmfq7g34b50xh"))
              (modules '((guix build utils)))
              (snippet
               '(substitute* "setup.py"
                  ;; remove dependency on outdated "distribute" module
                  (("^from distribute_setup import use_setuptools") "")
                  (("^use_setuptools\\(\\)") "")))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f ;tests fail because test data are not included
       #:python ,python-2))
    (inputs
     `(("python-numpy" ,python2-numpy)
       ("zlib" ,zlib)))
    (native-inputs
     `(("python-nose" ,python2-nose)))
    (home-page "http://bitbucket.org/james_taylor/bx-python/")
    (synopsis "Tools for manipulating biological data")
    (description
     "bx-python provides tools for manipulating biological data, particularly
multiple sequence alignments.")
    (license license:expat)))

(define-public python-pysam
  (package
    (name "python-pysam")
    (version "0.9.1.4")
    (source (origin
              (method url-fetch)
              ;; Test data is missing on PyPi.
              (uri (string-append
                    "https://github.com/pysam-developers/pysam/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0y41ssbg6nvn2jgcbnrvkzblpjcwszaiv1rgyd8dwzjkrbfsgsmc"))
              (modules '((guix build utils)))
              (snippet
               ;; Drop bundled htslib. TODO: Also remove samtools and bcftools.
               '(delete-file-recursively "htslib"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'build 'set-flags
           (lambda* (#:key inputs #:allow-other-keys)
             (setenv "HTSLIB_MODE" "external")
             (setenv "HTSLIB_LIBRARY_DIR"
                     (string-append (assoc-ref inputs "htslib") "/lib"))
             (setenv "HTSLIB_INCLUDE_DIR"
                     (string-append (assoc-ref inputs "htslib") "/include"))
             (setenv "LDFLAGS" "-lncurses")
             (setenv "CFLAGS" "-D_CURSES_LIB=1")
             #t))
         (delete 'check)
         (add-after 'install 'check
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (setenv "PYTHONPATH"
                     (string-append
                      (getenv "PYTHONPATH")
                      ":" (assoc-ref outputs "out")
                      "/lib/python"
                      (string-take (string-take-right
                                    (assoc-ref inputs "python") 5) 3)
                      "/site-packages"))
             ;; Step out of source dir so python does not import from CWD.
             (chdir "tests")
             (setenv "HOME" "/tmp")
             (and (zero? (system* "make" "-C" "pysam_data"))
                  (zero? (system* "make" "-C" "cbcf_data"))
                  (zero? (system* "nosetests" "-v"))))))))
    (propagated-inputs
     `(("htslib"            ,htslib))) ; Included from installed header files.
    (inputs
     `(("ncurses"           ,ncurses)
       ("zlib"              ,zlib)))
    (native-inputs
     `(("python-cython"     ,python-cython)
       ;; Dependencies below are are for tests only.
       ("samtools"          ,samtools)
       ("bcftools"          ,bcftools)
       ("python-nose"       ,python-nose)))
    (home-page "https://github.com/pysam-developers/pysam")
    (synopsis "Python bindings to the SAMtools C API")
    (description
     "Pysam is a Python module for reading and manipulating files in the
SAM/BAM format.  Pysam is a lightweight wrapper of the SAMtools C API.  It
also includes an interface for tabix.")
    (license license:expat)))

(define-public python2-pysam
  (package-with-python2 python-pysam))

(define-public python-twobitreader
  (package
    (name "python-twobitreader")
    (version "3.1.4")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "twobitreader" version))
              (sha256
               (base32
                "1q8wnj2kga9nz1lwc4w7qv52smfm536hp6mc8w6s53lhyj0mpi22"))))
    (build-system python-build-system)
    (arguments
     '(;; Tests are not distributed in the PyPi release.
       ;; TODO Try building from the Git repo or asking the upstream maintainer
       ;; to distribute the tests on PyPi.
       #:tests? #f))
    (native-inputs
     `(("python-sphinx" ,python-sphinx)))
    (home-page "https://github.com/benjschiller/twobitreader")
    (synopsis "Python library for reading .2bit files")
    (description
     "twobitreader is a Python library for reading .2bit files as used by the
UCSC genome browser.")
    (license license:artistic2.0)))

(define-public python2-twobitreader
  (package-with-python2 python-twobitreader))

(define-public python-plastid
  (package
    (name "python-plastid")
    (version "0.4.6")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "plastid" version))
              (sha256
               (base32
                "1sqkz5d3b9kf688mp7k771c87ins42j7j0whmkb49cb3fsg8s8lj"))))
    (build-system python-build-system)
    (arguments
     ;; Some test files are not included.
     `(#:tests? #f))
    (propagated-inputs
     `(("python-numpy" ,python-numpy)
       ("python-scipy" ,python-scipy)
       ("python-pandas" ,python-pandas)
       ("python-pysam" ,python-pysam)
       ("python-matplotlib" ,python-matplotlib)
       ("python-biopython" ,python-biopython)
       ("python-twobitreader" ,python-twobitreader)
       ("python-termcolor" ,python-termcolor)))
    (native-inputs
     `(("python-cython" ,python-cython)
       ("python-nose" ,python-nose)))
    (home-page "https://github.com/joshuagryphon/plastid")
    (synopsis "Python library for genomic analysis")
    (description
     "plastid is a Python library for genomic analysis – in particular,
high-throughput sequencing data – with an emphasis on simplicity.")
    (license license:bsd-3)))

(define-public python2-plastid
  (package-with-python2 python-plastid))

(define-public cd-hit
  (package
    (name "cd-hit")
    (version "4.6.5")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/weizhongli/cdhit"
                                  "/releases/download/V" version
                                  "/cd-hit-v" version "-2016-0304.tar.gz"))
              (sha256
               (base32
                "15db0hq38yyifwqx9b6l34z14jcq576dmjavhj8a426c18lvnhp3"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; there are no tests
       #:make-flags
       ;; Executables are copied directly to the PREFIX.
       (list (string-append "PREFIX=" (assoc-ref %outputs "out") "/bin"))
       #:phases
       (modify-phases %standard-phases
         ;; No "configure" script
         (delete 'configure)
         ;; Remove sources of non-determinism
         (add-after 'unpack 'be-timeless
           (lambda _
             (substitute* "cdhit-utility.c++"
               ((" \\(built on \" __DATE__ \"\\)") ""))
             (substitute* "cdhit-common.c++"
               (("__DATE__") "\"0\"")
               (("\", %s, \" __TIME__ \"\\\\n\", date") ""))
             #t))
         ;; The "install" target does not create the target directory
         (add-before 'install 'create-target-dir
           (lambda* (#:key outputs #:allow-other-keys)
             (mkdir-p (string-append (assoc-ref outputs "out") "/bin"))
             #t)))))
    (inputs
     `(("perl" ,perl)))
    (home-page "http://weizhongli-lab.org/cd-hit/")
    (synopsis "Cluster and compare protein or nucleotide sequences")
    (description
     "CD-HIT is a program for clustering and comparing protein or nucleotide
sequences.  CD-HIT is designed to be fast and handle extremely large
databases.")
    ;; The manual says: "It can be copied under the GNU General Public License
    ;; version 2 (GPLv2)."
    (license license:gpl2)))

(define-public clipper
  (package
    (name "clipper")
    (version "1.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/YeoLab/clipper/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0pflmsvhbf8izbgwhbhj1i7349sw1f55qpqj8ljmapp16hb0p0qi"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  ;; remove unnecessary setup dependency
                  (substitute* "setup.py"
                    (("setup_requires = .*") ""))
                  (for-each delete-file
                            '("clipper/src/peaks.so"
                              "clipper/src/readsToWiggle.so"))
                  (delete-file-recursively "dist/")
                  #t))))
    (build-system python-build-system)
    (arguments `(#:python ,python-2)) ; only Python 2 is supported
    (inputs
     `(("htseq" ,htseq)
       ("python-pybedtools" ,python2-pybedtools)
       ("python-cython" ,python2-cython)
       ("python-scikit-learn" ,python2-scikit-learn)
       ("python-matplotlib" ,python2-matplotlib)
       ("python-pandas" ,python2-pandas)
       ("python-pysam" ,python2-pysam)
       ("python-numpy" ,python2-numpy)
       ("python-scipy" ,python2-scipy)))
    (native-inputs
     `(("python-mock" ,python2-mock)   ; for tests
       ("python-pytz" ,python2-pytz))) ; for tests
    (home-page "https://github.com/YeoLab/clipper")
    (synopsis "CLIP peak enrichment recognition")
    (description
     "CLIPper is a tool to define peaks in CLIP-seq datasets.")
    (license license:gpl2)))

(define-public codingquarry
  (package
    (name "codingquarry")
    (version "2.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "mirror://sourceforge/codingquarry/CodingQuarry_v"
                    version ".tar.gz"))
              (sha256
               (base32
                "0115hkjflsnfzn36xppwf9h9avfxlavr43djqmshkkzbgjzsz60i"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f ; no "check" target
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (bin (string-append out "/bin"))
                    (doc (string-append out "/share/doc/codingquarry")))
               (install-file "INSTRUCTIONS.pdf" doc)
               (copy-recursively "QuarryFiles"
                                 (string-append out "/QuarryFiles"))
               (install-file "CodingQuarry" bin)
               (install-file "CufflinksGTF_to_CodingQuarryGFF3.py" bin)))))))
    (inputs `(("openmpi" ,openmpi)))
    (native-search-paths
     (list (search-path-specification
            (variable "QUARRY_PATH")
            (files '("QuarryFiles")))))
    (native-inputs `(("python" ,python-2))) ; Only Python 2 is supported
    (synopsis "Fungal gene predictor")
    (description "CodingQuarry is a highly accurate, self-training GHMM fungal
gene predictor designed to work with assembled, aligned RNA-seq transcripts.")
    (home-page "https://sourceforge.net/projects/codingquarry/")
    (license license:gpl3+)))

(define-public couger
  (package
    (name "couger")
    (version "1.8.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://couger.oit.duke.edu/static/assets/COUGER"
                    version ".zip"))
              (sha256
               (base32
                "04p2b14nmhzxw5h72mpzdhalv21bx4w9b87z0wpw0xzxpysyncmq"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (delete 'build)
         (replace
          'install
          (lambda* (#:key outputs #:allow-other-keys)
            (let ((out (assoc-ref outputs "out")))
              (copy-recursively "src" (string-append out "/src"))
              (mkdir (string-append out "/bin"))
              ;; Add "src" directory to module lookup path.
              (substitute* "couger"
                (("from argparse")
                 (string-append "import sys\nsys.path.append(\""
                                out "\")\nfrom argparse")))
              (copy-file "couger" (string-append out "/bin/couger")))
            #t))
         (add-after
          'install 'wrap-program
          (lambda* (#:key inputs outputs #:allow-other-keys)
            ;; Make sure 'couger' runs with the correct PYTHONPATH.
            (let* ((out (assoc-ref outputs "out"))
                   (path (getenv "PYTHONPATH")))
              (wrap-program (string-append out "/bin/couger")
                `("PYTHONPATH" ":" prefix (,path))))
            #t)))))
    (inputs
     `(("python" ,python-2)
       ("python2-pillow" ,python2-pillow)
       ("python2-numpy" ,python2-numpy)
       ("python2-scipy" ,python2-scipy)
       ("python2-matplotlib" ,python2-matplotlib)))
    (propagated-inputs
     `(("r" ,r)
       ("libsvm" ,libsvm)
       ("randomjungle" ,randomjungle)))
    (native-inputs
     `(("unzip" ,unzip)))
    (home-page "http://couger.oit.duke.edu")
    (synopsis "Identify co-factors in sets of genomic regions")
    (description
     "COUGER can be applied to any two sets of genomic regions bound by
paralogous TFs (e.g., regions derived from ChIP-seq experiments) to identify
putative co-factors that provide specificity to each TF.  The framework
determines the genomic targets uniquely-bound by each TF, and identifies a
small set of co-factors that best explain the in vivo binding differences
between the two TFs.

COUGER uses classification algorithms (support vector machines and random
forests) with features that reflect the DNA binding specificities of putative
co-factors.  The features are generated either from high-throughput TF-DNA
binding data (from protein binding microarray experiments), or from large
collections of DNA motifs.")
    (license license:gpl3+)))

(define-public clustal-omega
  (package
    (name "clustal-omega")
    (version "1.2.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://www.clustal.org/omega/clustal-omega-"
                    version ".tar.gz"))
              (sha256
               (base32
                "02ibkx0m0iwz8nscg998bh41gg251y56cgh86bvyrii5m8kjgwqf"))))
    (build-system gnu-build-system)
    (inputs
     `(("argtable" ,argtable)))
    (home-page "http://www.clustal.org/omega/")
    (synopsis "Multiple sequence aligner for protein and DNA/RNA")
    (description
     "Clustal-Omega is a general purpose multiple sequence alignment (MSA)
program for protein and DNA/RNA.  It produces high quality MSAs and is capable
of handling data-sets of hundreds of thousands of sequences in reasonable
time.")
    (license license:gpl2+)))

(define-public crossmap
  (package
    (name "crossmap")
    (version "0.2.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/crossmap/CrossMap-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "07y179f63d7qnzdvkqcziwk9bs3k4zhp81q392fp1hwszjdvy22f"))
              ;; This patch has been sent upstream already and is available
              ;; for download from Sourceforge, but it has not been merged.
              (patches (search-patches "crossmap-allow-system-pysam.patch"))
              (modules '((guix build utils)))
              ;; remove bundled copy of pysam
              (snippet
               '(delete-file-recursively "lib/pysam"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:phases
       (alist-cons-after
        'unpack 'set-env
        (lambda _ (setenv "CROSSMAP_USE_SYSTEM_PYSAM" "1"))
        %standard-phases)))
    (inputs
     `(("python-numpy" ,python2-numpy)
       ("python-pysam" ,python2-pysam)
       ("zlib" ,zlib)))
    (native-inputs
     `(("python-cython" ,python2-cython)
       ("python-nose" ,python2-nose)))
    (home-page "http://crossmap.sourceforge.net/")
    (synopsis "Convert genome coordinates between assemblies")
    (description
     "CrossMap is a program for conversion of genome coordinates or annotation
files between different genome assemblies.  It supports most commonly used
file formats including SAM/BAM, Wiggle/BigWig, BED, GFF/GTF, VCF.")
    (license license:gpl2+)))

(define-public cufflinks
  (package
    (name "cufflinks")
    (version "2.2.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://cole-trapnell-lab.github.io/"
                                  "cufflinks/assets/downloads/cufflinks-"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1bnm10p8m7zq4qiipjhjqb24csiqdm1pwc8c795z253r2xk6ncg8"))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags
       (list
        ;; The includes for "eigen" are located in a subdirectory.
        (string-append "EIGEN_CPPFLAGS="
                       "-I" (assoc-ref %build-inputs "eigen")
                       "/include/eigen3/")
        ;; Cufflinks must be linked with various boost libraries.
        (string-append "LDFLAGS="
                       (string-join '("-lboost_system"
                                      "-lboost_serialization"
                                      "-lboost_thread"))))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-search-for-bam
          (lambda _
            (substitute* '("ax_bam.m4"
                           "configure"
                           "src/hits.h")
              (("<bam/sam\\.h>") "<samtools/sam.h>")
              (("<bam/bam\\.h>") "<samtools/bam.h>")
              (("<bam/version\\.hpp>") "<samtools/version.h>"))
            #t)))
       #:configure-flags
       (list (string-append "--with-bam="
                            (assoc-ref %build-inputs "samtools")))))
    (inputs
     `(("eigen" ,eigen)
       ("samtools" ,samtools-0.1)
       ("htslib" ,htslib)
       ("boost" ,boost)
       ("python" ,python-2)
       ("zlib" ,zlib)))
    (home-page "http://cole-trapnell-lab.github.io/cufflinks/")
    (synopsis "Transcriptome assembly and RNA-Seq expression analysis")
    (description
     "Cufflinks assembles RNA transcripts, estimates their abundances,
and tests for differential expression and regulation in RNA-Seq
samples.  It accepts aligned RNA-Seq reads and assembles the
alignments into a parsimonious set of transcripts.  Cufflinks then
estimates the relative abundances of these transcripts based on how
many reads support each one, taking into account biases in library
preparation protocols.")
    (license license:boost1.0)))

(define-public cutadapt
  (package
    (name "cutadapt")
    (version "1.12")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/marcelm/cutadapt/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "19smhh6444ikn4jlmyhvffw4m5aw7yg07rqsk7arg8dkwyga1i4v"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         ;; The tests must be run after installation.
         (delete 'check)
         (add-after 'install 'check
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (setenv "PYTHONPATH"
                     (string-append
                      (getenv "PYTHONPATH")
                      ":" (assoc-ref outputs "out")
                      "/lib/python"
                      (string-take (string-take-right
                                    (assoc-ref inputs "python") 5) 3)
                      "/site-packages"))
             (zero? (system* "nosetests" "-P" "tests")))))))
    (inputs
     `(("python-xopen" ,python-xopen)))
    (native-inputs
     `(("python-cython" ,python-cython)
       ("python-nose" ,python-nose)))
    (home-page "https://cutadapt.readthedocs.io/en/stable/")
    (synopsis "Remove adapter sequences from nucleotide sequencing reads")
    (description
     "Cutadapt finds and removes adapter sequences, primers, poly-A tails and
other types of unwanted sequence from high-throughput sequencing reads.")
    (license license:expat)))

(define-public libbigwig
  (package
    (name "libbigwig")
    (version "0.1.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/dpryan79/libBigWig/"
                                  "archive/" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "098rjh35pi4a9q83n8wiwvyzykjqj6l8q189p1xgfw4ghywdlvw1"))))
    (build-system gnu-build-system)
    (arguments
     `(#:test-target "test"
       #:make-flags
       (list "CC=gcc"
             (string-append "prefix=" (assoc-ref %outputs "out")))
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (add-before 'check 'disable-curl-test
           (lambda _
             (substitute* "Makefile"
               (("./test/testRemote.*") ""))
             #t))
         ;; This has been fixed with the upstream commit 4ff6959cd8a0, but
         ;; there has not yet been a release containing this change.
         (add-before 'install 'create-target-dirs
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (mkdir-p (string-append out "/lib"))
               (mkdir-p (string-append out "/include"))
               #t))))))
    (inputs
     `(("zlib" ,zlib)
       ("curl" ,curl)))
    (native-inputs
     `(("doxygen" ,doxygen)))
    (home-page "https://github.com/dpryan79/libBigWig")
    (synopsis "C library for handling bigWig files")
    (description
     "This package provides a C library for parsing local and remote BigWig
files.")
    (license license:expat)))

(define-public python-pybigwig
  (package
    (name "python-pybigwig")
    (version "0.2.5")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pyBigWig" version))
              (sha256
               (base32
                "0yrpdxg3y0sny25x4w22lv1k47jzccqjmg7j4bp0hywklvp0hg7d"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  ;; Delete bundled libBigWig sources
                  (delete-file-recursively "libBigWig")))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'link-with-libBigWig
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* "setup.py"
               (("libs=\\[") "libs=[\"BigWig\", "))
             #t)))))
    (inputs
     `(("libbigwig" ,libbigwig)
       ("zlib" ,zlib)
       ("curl" ,curl)))
    (home-page "https://github.com/dpryan79/pyBigWig")
    (synopsis "Access bigWig files in Python using libBigWig")
    (description
     "This package provides Python bindings to the libBigWig library for
accessing bigWig files.")
    (license license:expat)))

(define-public python2-pybigwig
  (package-with-python2 python-pybigwig))

(define-public python-dendropy
  (package
    (name "python-dendropy")
    (version "4.1.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "DendroPy" version))
       (sha256
        (base32
         "1jfz7gp18wph311w1yygbvjanb3n5mdqal439bb6myw41dwb5m63"))
       ;; There are two known test failures that will be fixed in the next
       ;; release after 4.1.0.
       ;; https://github.com/jeetsukumaran/DendroPy/issues/48
       (patches (search-patches
                 "python-dendropy-exclude-failing-tests.patch"))))
    (build-system python-build-system)
    (home-page "http://packages.python.org/DendroPy/")
    (synopsis "Library for phylogenetics and phylogenetic computing")
    (description
     "DendroPy is a library for phylogenetics and phylogenetic computing: reading,
writing, simulation, processing and manipulation of phylogenetic
trees (phylogenies) and characters.")
    (license license:bsd-3)
    (properties `((python2-variant . ,(delay python2-dendropy))))))

(define-public python2-dendropy
  (let ((base (package-with-python2 (strip-python2-variant python-dendropy))))
    (package
      (inherit base)
      ;; Do not use same source as 'python-dendropy' because the patched
      ;; failing tests do not occur on Python 2.
      (source
       (origin
         (method url-fetch)
         (uri (pypi-uri "DendroPy" (package-version base)))
         (sha256
          (base32
           "1jfz7gp18wph311w1yygbvjanb3n5mdqal439bb6myw41dwb5m63"))))
      (arguments
       `(#:python ,python-2
         #:phases
           (modify-phases %standard-phases
             (replace 'check
               ;; There is currently a test failure that only happens on some
               ;; systems, and only using "setup.py test"
               (lambda _ (zero? (system* "nosetests")))))))
      (native-inputs `(("python2-nose" ,python2-nose)
                       ,@(package-native-inputs base))))))


(define-public deeptools
  (package
    (name "deeptools")
    (version "2.1.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/fidelram/deepTools/"
                                  "archive/" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1nmfin0zjdby3vay3r4flvz94dr6qjhj41ax4yz3vx13j6wz8izd"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2))
    (inputs
     `(("python-scipy" ,python2-scipy)
       ("python-numpy" ,python2-numpy)
       ("python-numpydoc" ,python2-numpydoc)
       ("python-matplotlib" ,python2-matplotlib)
       ("python-bx-python" ,python2-bx-python)
       ("python-pysam" ,python2-pysam)
       ("python-pybigwig" ,python2-pybigwig)))
    (native-inputs
     `(("python-mock" ,python2-mock)   ;for tests
       ("python-pytz" ,python2-pytz))) ;for tests
    (home-page "https://github.com/fidelram/deepTools")
    (synopsis "Tools for normalizing and visualizing deep-sequencing data")
    (description
     "DeepTools addresses the challenge of handling the large amounts of data
that are now routinely generated from DNA sequencing centers.  To do so,
deepTools contains useful modules to process the mapped reads data to create
coverage files in standard bedGraph and bigWig file formats.  By doing so,
deepTools allows the creation of normalized coverage files or the comparison
between two files (for example, treatment and control).  Finally, using such
normalized and standardized files, multiple visualizations can be created to
identify enrichments with functional annotations of the genome.")
    (license license:gpl3+)))

(define-public diamond
  (package
    (name "diamond")
    (version "0.8.29")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/bbuchfink/diamond/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1mnhj7y13pk2bhfichjma5aw8ssdiqyria61ip1kps6facqlal3z"))))
    (build-system cmake-build-system)
    (arguments
     '(#:tests? #f ; no "check" target
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'remove-native-compilation
           (lambda _
             (substitute* "CMakeLists.txt" (("-march=native") ""))
             #t)))))
    (inputs
     `(("zlib" ,zlib)))
    (home-page "https://github.com/bbuchfink/diamond")
    (synopsis "Accelerated BLAST compatible local sequence aligner")
    (description
     "DIAMOND is a BLAST-compatible local aligner for mapping protein and
translated DNA query sequences against a protein reference database (BLASTP
and BLASTX alignment mode).  The speedup over BLAST is up to 20,000 on short
reads at a typical sensitivity of 90-99% relative to BLAST depending on the
data and settings.")
    ;; diamond fails to build on other platforms
    ;; https://github.com/bbuchfink/diamond/issues/18
    (supported-systems '("x86_64-linux"))
    (license (license:non-copyleft "file://src/COPYING"
                                   "See src/COPYING in the distribution."))))

(define-public discrover
  (package
    (name "discrover")
    (version "1.6.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/maaskola/discrover/archive/"
                           version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0rah9ja4m0rl5mldd6vag9rwrivw1zrqxssfq8qx64m7961fp68k"))))
    (build-system cmake-build-system)
    (arguments `(#:tests? #f)) ; there are no tests
    (inputs
     `(("boost" ,boost)
       ("cairo" ,cairo)))
    (native-inputs
     `(("texlive" ,texlive)
       ("imagemagick" ,imagemagick)))
    (home-page "http://dorina.mdc-berlin.de/public/rajewsky/discrover/")
    (synopsis "Discover discriminative nucleotide sequence motifs")
    (description "Discrover is a motif discovery method to find binding sites
of nucleic acid binding proteins.")
    (license license:gpl3+)))

(define-public eigensoft
  (let ((revision "1")
        (commit "b14d1e202e21e532536ff8004f0419cd5e259dc7"))
    (package
      (name "eigensoft")
      (version (string-append "6.1.2-"
                              revision "."
                              (string-take commit 9)))
      (source
       (origin
         (method git-fetch)
         (uri (git-reference
               (url "https://github.com/DReichLab/EIG.git")
               (commit commit)))
         (file-name (string-append "eigensoft-" commit "-checkout"))
         (sha256
          (base32
           "0f5m6k2j5c16xc3xbywcs989xyc26ncy1zfzp9j9n55n9r4xcaiq"))
         (modules '((guix build utils)))
         ;; Remove pre-built binaries.
         (snippet '(begin
                     (delete-file-recursively "bin")
                     (mkdir "bin")
                     #t))))
      (build-system gnu-build-system)
      (arguments
       `(#:tests? #f                    ; There are no tests.
         #:make-flags '("CC=gcc")
         #:phases
         (modify-phases %standard-phases
           ;; There is no configure phase, but the Makefile is in a
           ;; sub-directory.
           (replace 'configure
             (lambda _
               (chdir "src")
               ;; The link flags are incomplete.
               (substitute* "Makefile"
                 (("-lgsl") "-lgsl -lm -llapack -llapacke -lpthread"))
               #t))
           ;; The provided install target only copies executables to
           ;; the "bin" directory in the build root.
           (add-after 'install 'actually-install
             (lambda* (#:key outputs #:allow-other-keys)
               (let* ((out (assoc-ref outputs "out"))
                      (bin  (string-append out "/bin")))
                 (for-each (lambda (file)
                             (install-file file bin))
                           (find-files "../bin" ".*"))
                 #t))))))
      (inputs
       `(("gsl" ,gsl)
         ("lapack" ,lapack)
         ("openblas" ,openblas)
         ("perl" ,perl)
         ("gfortran" ,gfortran "lib")))
      (home-page "https://github.com/DReichLab/EIG")
      (synopsis "Tools for population genetics")
      (description "The EIGENSOFT package provides tools for population
genetics and stratification correction.  EIGENSOFT implements methods commonly
used in population genetics analyses such as PCA, computation of Tracy-Widom
statistics, and finding related individuals in structured populations.  It
comes with a built-in plotting script and supports multiple file formats and
quantitative phenotypes.")
      ;; The license of the eigensoft tools is Expat, but since it's
      ;; linking with the GNU Scientific Library (GSL) the effective
      ;; license is the GPL.
      (license license:gpl3+))))

(define-public edirect
  (package
    (name "edirect")
    (version "4.10")
    (source (origin
              (method url-fetch)
              (uri (string-append "ftp://ftp.ncbi.nlm.nih.gov/entrez/entrezdirect/"
                                  "versions/2016-05-03/edirect.tar.gz"))
              (sha256
               (base32
                "15zsprak5yh8c1yrz4r1knmb5s8qcmdid4xdhkh3lqcv64l60hli"))))
    (build-system perl-build-system)
    (arguments
     `(#:tests? #f ;no "check" target
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (delete 'build)
         (replace 'install
                  (lambda* (#:key outputs #:allow-other-keys)
                    (let ((target (string-append (assoc-ref outputs "out")
                                                 "/bin")))
                      (mkdir-p target)
                      (copy-file "edirect.pl"
                                 (string-append target "/edirect.pl"))
                      #t)))
         (add-after
          'install 'wrap-program
          (lambda* (#:key inputs outputs #:allow-other-keys)
            ;; Make sure 'edirect.pl' finds all perl inputs at runtime.
            (let* ((out (assoc-ref outputs "out"))
                   (path (getenv "PERL5LIB")))
              (wrap-program (string-append out "/bin/edirect.pl")
                `("PERL5LIB" ":" prefix (,path)))))))))
    (inputs
     `(("perl-html-parser" ,perl-html-parser)
       ("perl-encode-locale" ,perl-encode-locale)
       ("perl-file-listing" ,perl-file-listing)
       ("perl-html-tagset" ,perl-html-tagset)
       ("perl-html-tree" ,perl-html-tree)
       ("perl-http-cookies" ,perl-http-cookies)
       ("perl-http-date" ,perl-http-date)
       ("perl-http-message" ,perl-http-message)
       ("perl-http-negotiate" ,perl-http-negotiate)
       ("perl-lwp-mediatypes" ,perl-lwp-mediatypes)
       ("perl-lwp-protocol-https" ,perl-lwp-protocol-https)
       ("perl-net-http" ,perl-net-http)
       ("perl-uri" ,perl-uri)
       ("perl-www-robotrules" ,perl-www-robotrules)
       ("perl" ,perl)))
    (home-page "http://www.ncbi.nlm.nih.gov/books/NBK179288/")
    (synopsis "Tools for accessing the NCBI's set of databases")
    (description
     "Entrez Direct (EDirect) is a method for accessing the National Center
for Biotechnology Information's (NCBI) set of interconnected
databases (publication, sequence, structure, gene, variation, expression,
etc.) from a terminal.  Functions take search terms from command-line
arguments.  Individual operations are combined to build multi-step queries.
Record retrieval and formatting normally complete the process.

EDirect also provides an argument-driven function that simplifies the
extraction of data from document summaries or other results that are returned
in structured XML format.  This can eliminate the need for writing custom
software to answer ad hoc questions.")
    (license license:public-domain)))

(define-public exonerate
  (package
    (name "exonerate")
    (version "2.4.0")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append
         "http://ftp.ebi.ac.uk/pub/software/vertebrategenomics/exonerate/"
         "exonerate-" version ".tar.gz"))
       (sha256
        (base32
         "0hj0m9xygiqsdxvbg79wq579kbrx1mdrabi2bzqz2zn9qwfjcjgq"))))
    (build-system gnu-build-system)
    (arguments
     `(#:parallel-build? #f)) ; Building in parallel fails on some machines.
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("glib" ,glib)))
    (home-page
     "https://www.ebi.ac.uk/about/vertebrate-genomics/software/exonerate")
    (synopsis "Generic tool for biological sequence alignment")
    (description
     "Exonerate is a generic tool for pairwise sequence comparison.  It allows
the alignment of sequences using a many alignment models, either exhaustive
dynamic programming or a variety of heuristics.")
    (license license:gpl3)))

(define-public express
  (package
    (name "express")
    (version "1.5.1")
    (source (origin
              (method url-fetch)
              (uri
               (string-append
                "http://bio.math.berkeley.edu/eXpress/downloads/express-"
                version "/express-" version "-src.tgz"))
              (sha256
               (base32
                "03rczxd0gjp2l1jxcmjfmf5j94j77zqyxa6x063zsc585nj40n0c"))))
    (build-system cmake-build-system)
    (arguments
     `(#:tests? #f ;no "check" target
       #:phases
       (alist-cons-after
        'unpack 'use-shared-boost-libs-and-set-bamtools-paths
        (lambda* (#:key inputs #:allow-other-keys)
          (substitute* "CMakeLists.txt"
            (("set\\(Boost_USE_STATIC_LIBS ON\\)")
             "set(Boost_USE_STATIC_LIBS OFF)")
            (("\\$\\{CMAKE_CURRENT_SOURCE_DIR\\}/bamtools/include")
             (string-append (assoc-ref inputs "bamtools") "/include/bamtools")))
          (substitute* "src/CMakeLists.txt"
            (("\\$\\{CMAKE_CURRENT_SOURCE_DIR\\}/\\.\\./bamtools/lib")
             (string-append (assoc-ref inputs "bamtools") "/lib/bamtools")))
          #t)
        %standard-phases)))
    (inputs
     `(("boost" ,boost)
       ("bamtools" ,bamtools)
       ("protobuf" ,protobuf)
       ("zlib" ,zlib)))
    (home-page "http://bio.math.berkeley.edu/eXpress")
    (synopsis "Streaming quantification for high-throughput genomic sequencing")
    (description
     "eXpress is a streaming tool for quantifying the abundances of a set of
target sequences from sampled subsequences.  Example applications include
transcript-level RNA-Seq quantification, allele-specific/haplotype expression
analysis (from RNA-Seq), transcription factor binding quantification in
ChIP-Seq, and analysis of metagenomic data.")
    (license license:artistic2.0)))

(define-public express-beta-diversity
  (package
   (name "express-beta-diversity")
   (version "1.0.7")
   (source (origin
             (method url-fetch)
             (uri
              (string-append
               "https://github.com/dparks1134/ExpressBetaDiversity/archive/v"
               version ".tar.gz"))
             (file-name (string-append name "-" version ".tar.gz"))
             (sha256
              (base32
               "1djvdlmqvjf6h0zq7w36y8cl5cli6rgj86x65znl48agnwmzxfxr"))))
   (build-system gnu-build-system)
   (arguments
    `(#:phases
      (modify-phases %standard-phases
        (delete 'configure)
        (add-before 'build 'enter-source (lambda _ (chdir "source") #t))
        (replace 'check
                 (lambda _ (zero? (system* "../bin/ExpressBetaDiversity"
                                           "-u"))))
        (add-after 'check 'exit-source (lambda _ (chdir "..") #t))
        (replace 'install
                 (lambda* (#:key outputs #:allow-other-keys)
                   (let ((bin (string-append (assoc-ref outputs "out")
                                             "/bin")))
                     (mkdir-p bin)
                     (copy-file "scripts/convertToEBD.py"
                                (string-append bin "/convertToEBD.py"))
                     (copy-file "bin/ExpressBetaDiversity"
                                (string-append bin "/ExpressBetaDiversity"))
                     #t))))))
   (inputs
    `(("python" ,python-2)))
   (home-page "http://kiwi.cs.dal.ca/Software/ExpressBetaDiversity")
   (synopsis "Taxon- and phylogenetic-based beta diversity measures")
   (description
    "Express Beta Diversity (EBD) calculates ecological beta diversity
(dissimilarity) measures between biological communities.  EBD implements a
variety of diversity measures including those that make use of phylogenetic
similarity of community members.")
   (license license:gpl3+)))

(define-public fasttree
  (package
   (name "fasttree")
   (version "2.1.9")
   (source (origin
             (method url-fetch)
             (uri (string-append
                   "http://www.microbesonline.org/fasttree/FastTree-"
                   version ".c"))
             (sha256
              (base32
               "0ljvvw8i1als1wbfzvrf15c3ii2vw9db20a259g6pzg34xyyb97k"))))
   (build-system gnu-build-system)
   (arguments
    `(#:tests? #f ; no "check" target
      #:phases
      (modify-phases %standard-phases
        (delete 'unpack)
        (delete 'configure)
        (replace 'build
          (lambda* (#:key source #:allow-other-keys)
            (and (zero? (system* "gcc"
                                 "-O3"
                                 "-finline-functions"
                                 "-funroll-loops"
                                 "-Wall"
                                 "-o"
                                 "FastTree"
                                 source
                                 "-lm"))
                 (zero? (system* "gcc"
                                 "-DOPENMP"
                                 "-fopenmp"
                                 "-O3"
                                 "-finline-functions"
                                 "-funroll-loops"
                                 "-Wall"
                                 "-o"
                                 "FastTreeMP"
                                 source
                                 "-lm")))))
        (replace 'install
          (lambda* (#:key outputs #:allow-other-keys)
            (let ((bin (string-append (assoc-ref outputs "out")
                                      "/bin")))
              (mkdir-p bin)
              (copy-file "FastTree"
                         (string-append bin "/FastTree"))
              (copy-file "FastTreeMP"
                         (string-append bin "/FastTreeMP"))
              #t))))))
   (home-page "http://www.microbesonline.org/fasttree")
   (synopsis "Infers approximately-maximum-likelihood phylogenetic trees")
   (description
    "FastTree can handle alignments with up to a million of sequences in a
reasonable amount of time and memory.  For large alignments, FastTree is
100-1,000 times faster than PhyML 3.0 or RAxML 7.")
   (license license:gpl2+)))

(define-public fastx-toolkit
  (package
    (name "fastx-toolkit")
    (version "0.0.14")
    (source (origin
              (method url-fetch)
              (uri
               (string-append
                "https://github.com/agordon/fastx_toolkit/releases/download/"
                version "/fastx_toolkit-" version ".tar.bz2"))
              (sha256
               (base32
                "01jqzw386873sr0pjp1wr4rn8fsga2vxs1qfmicvx1pjr72007wy"))))
    (build-system gnu-build-system)
    (inputs
     `(("libgtextutils" ,libgtextutils)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "http://hannonlab.cshl.edu/fastx_toolkit/")
    (synopsis "Tools for FASTA/FASTQ file preprocessing")
    (description
     "The FASTX-Toolkit is a collection of command line tools for Short-Reads
FASTA/FASTQ files preprocessing.

Next-Generation sequencing machines usually produce FASTA or FASTQ files,
containing multiple short-reads sequences.  The main processing of such
FASTA/FASTQ files is mapping the sequences to reference genomes.  However, it
is sometimes more productive to preprocess the files before mapping the
sequences to the genome---manipulating the sequences to produce better mapping
results.  The FASTX-Toolkit tools perform some of these preprocessing tasks.")
    (license license:agpl3+)))

(define-public flexbar
  (package
    (name "flexbar")
    (version "2.5")
    (source (origin
              (method url-fetch)
              (uri
               (string-append "mirror://sourceforge/flexbar/"
                              version "/flexbar_v" version "_src.tgz"))
              (sha256
               (base32
                "13jaykc3y1x8y5nn9j8ljnb79s5y51kyxz46hdmvvjj6qhyympmf"))))
    (build-system cmake-build-system)
    (arguments
     `(#:configure-flags (list
                          (string-append "-DFLEXBAR_BINARY_DIR="
                                         (assoc-ref %outputs "out")
                                         "/bin/"))
       #:phases
       (alist-replace
        'check
        (lambda* (#:key outputs #:allow-other-keys)
          (setenv "PATH" (string-append
                          (assoc-ref outputs "out") "/bin:"
                          (getenv "PATH")))
          (chdir "../flexbar_v2.5_src/test")
          (zero? (system* "bash" "flexbar_validate.sh")))
        (alist-delete 'install %standard-phases))))
    (inputs
     `(("tbb" ,tbb)
       ("zlib" ,zlib)))
    (native-inputs
     `(("pkg-config" ,pkg-config)
       ("seqan" ,seqan)))
    (home-page "http://flexbar.sourceforge.net")
    (synopsis "Barcode and adapter removal tool for sequencing platforms")
    (description
     "Flexbar preprocesses high-throughput nucleotide sequencing data
efficiently.  It demultiplexes barcoded runs and removes adapter sequences.
Moreover, trimming and filtering features are provided.  Flexbar increases
read mapping rates and improves genome and transcriptome assemblies.  It
supports next-generation sequencing data in fasta/q and csfasta/q format from
Illumina, Roche 454, and the SOLiD platform.")
    (license license:gpl3)))

(define-public fraggenescan
  (package
    (name "fraggenescan")
    (version "1.20")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "mirror://sourceforge/fraggenescan/"
                       "FragGeneScan" version ".tar.gz"))
       (sha256
        (base32 "1zzigqmvqvjyqv4945kv6nc5ah2xxm1nxgrlsnbzav3f5c0n0pyj"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (add-before 'build 'patch-paths
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (string-append (assoc-ref outputs "out")))
                    (share (string-append out "/share/fraggenescan/")))
               (substitute* "run_FragGeneScan.pl"
                 (("system\\(\"rm")
                  (string-append "system(\"" (which "rm")))
                 (("system\\(\"mv")
                  (string-append "system(\"" (which "mv")))
                 ;; This script and other programs expect the training files
                 ;; to be in the non-standard location bin/train/XXX. Change
                 ;; this to be share/fraggenescan/train/XXX instead.
                 (("^\\$train.file = \\$dir.*")
                  (string-append "$train_file = \""
                                 share
                                 "train/\".$FGS_train_file;")))
               (substitute* "run_hmm.c"
                 (("^  strcat\\(train_dir, \\\"train/\\\"\\);")
                  (string-append "  strcpy(train_dir, \"" share "/train/\");")))
               (substitute* "post_process.pl"
                 (("^my \\$dir = substr.*")
                  (string-append "my $dir = \"" share "\";"))))
             #t))
         (replace 'build
           (lambda _ (and (zero? (system* "make" "clean"))
                          (zero? (system* "make" "fgs")))))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (string-append (assoc-ref outputs "out")))
                    (bin (string-append out "/bin/"))
                    (share (string-append out "/share/fraggenescan/train")))
               (install-file "run_FragGeneScan.pl" bin)
               (install-file "FragGeneScan" bin)
               (install-file "FGS_gff.py" bin)
               (install-file "post_process.pl" bin)
               (copy-recursively "train" share))))
         (delete 'check)
         (add-after 'install 'post-install-check
           ;; In lieu of 'make check', run one of the examples and check the
           ;; output files gets created.
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (string-append (assoc-ref outputs "out")))
                    (bin (string-append out "/bin/")))
               (and (zero? (system* (string-append bin "run_FragGeneScan.pl")
                             "-genome=./example/NC_000913.fna"
                             "-out=./test2"
                             "-complete=1"
                             "-train=complete"))
                    (file-exists? "test2.faa")
                    (file-exists? "test2.ffn")
                    (file-exists? "test2.gff")
                    (file-exists? "test2.out"))))))))
    (inputs
     `(("perl" ,perl)
       ("python" ,python-2))) ;not compatible with python 3.
    (home-page "https://sourceforge.net/projects/fraggenescan/")
    (synopsis "Finds potentially fragmented genes in short reads")
    (description
     "FragGeneScan is a program for predicting bacterial and archaeal genes in
short and error-prone DNA sequencing reads.  It can also be applied to predict
genes in incomplete assemblies or complete genomes.")
    ;; GPL3+ according to private correspondense with the authors.
    (license license:gpl3+)))

(define-public fxtract
  (let ((util-commit "776ca85a18a47492af3794745efcb4a905113115"))
    (package
      (name "fxtract")
      (version "2.3")
      (source
       (origin
         (method url-fetch)
         (uri (string-append
               "https://github.com/ctSkennerton/fxtract/archive/"
               version ".tar.gz"))
         (file-name (string-append "ctstennerton-util-"
                                   (string-take util-commit 7)
                                   "-checkout"))
         (sha256
          (base32
           "0275cfdhis8517hm01is62062swmi06fxzifq7mr3knbbxjlaiwj"))))
      (build-system gnu-build-system)
      (arguments
       `(#:make-flags (list
                       (string-append "PREFIX=" (assoc-ref %outputs "out"))
                       "CC=gcc")
         #:test-target "fxtract_test"
         #:phases
         (modify-phases %standard-phases
           (delete 'configure)
           (add-before 'build 'copy-util
             (lambda* (#:key inputs #:allow-other-keys)
               (rmdir "util")
               (copy-recursively (assoc-ref inputs "ctskennerton-util") "util")
               #t))
           ;; Do not use make install as this requires additional dependencies.
           (replace 'install
             (lambda* (#:key outputs #:allow-other-keys)
               (let* ((out (assoc-ref outputs "out"))
                      (bin (string-append out"/bin")))
                 (install-file "fxtract" bin)
                 #t))))))
      (inputs
       `(("pcre" ,pcre)
         ("zlib" ,zlib)))
      (native-inputs
       ;; ctskennerton-util is licensed under GPL2.
       `(("ctskennerton-util"
          ,(origin
             (method git-fetch)
             (uri (git-reference
                   (url "https://github.com/ctSkennerton/util.git")
                   (commit util-commit)))
             (file-name (string-append
                         "ctstennerton-util-" util-commit "-checkout"))
             (sha256
              (base32
               "0cls1hd4vgj3f36fpzzg4xc77d6f3hpc60cbpfmn2gdr7ykzzad7"))))))
      (home-page "https://github.com/ctSkennerton/fxtract")
      (synopsis "Extract sequences from FASTA and FASTQ files")
      (description
       "Fxtract extracts sequences from a protein or nucleotide fastx (FASTA
or FASTQ) file given a subsequence.  It uses a simple substring search for
basic tasks but can change to using POSIX regular expressions, PCRE, hash
lookups or multi-pattern searching as required.  By default fxtract looks in
the sequence of each record but can also be told to look in the header,
comment or quality sections.")
      ;; 'util' requires SSE instructions.
      (supported-systems '("x86_64-linux"))
      (license license:expat))))

(define-public grit
  (package
    (name "grit")
    (version "2.0.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/nboley/grit/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "157in84dj70wimbind3x7sy1whs3h57qfgcnj2s6lrd38fbrb7mj"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2
       #:phases
       (alist-cons-after
        'unpack 'generate-from-cython-sources
        (lambda* (#:key inputs outputs #:allow-other-keys)
          ;; Delete these C files to force fresh generation from pyx sources.
          (delete-file "grit/sparsify_support_fns.c")
          (delete-file "grit/call_peaks_support_fns.c")
          (substitute* "setup.py"
            (("Cython.Setup") "Cython.Build")
            ;; Add numpy include path to fix compilation
            (("pyx\", \\]")
             (string-append "pyx\", ], include_dirs = ['"
                            (assoc-ref inputs "python-numpy")
                            "/lib/python2.7/site-packages/numpy/core/include/"
                            "']"))) #t)
        %standard-phases)))
    (inputs
     `(("python-scipy" ,python2-scipy)
       ("python-numpy" ,python2-numpy)
       ("python-pysam" ,python2-pysam)
       ("python-networkx" ,python2-networkx)))
    (native-inputs
     `(("python-cython" ,python2-cython)))
    (home-page "http://grit-bio.org")
    (synopsis "Tool for integrative analysis of RNA-seq type assays")
    (description
     "GRIT is designed to use RNA-seq, TES, and TSS data to build and quantify
full length transcript models.  When none of these data sources are available,
GRIT can be run by providing a candidate set of TES or TSS sites.  In
addition, GRIT can merge in reference junctions and gene boundaries.  GRIT can
also be run in quantification mode, where it uses a provided GTF file and just
estimates transcript expression.")
    (license license:gpl3+)))

(define-public hisat
  (package
    (name "hisat")
    (version "0.1.4")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://ccb.jhu.edu/software/hisat/downloads/hisat-"
                    version "-beta-source.zip"))
              (sha256
               (base32
                "1k381ydranqxp09yf2y7w1d0chz5d59vb6jchi89hbb0prq19lk5"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ;no check target
       #:make-flags '("allall"
                      ;; Disable unsupported `popcnt' instructions on
                      ;; architectures other than x86_64
                      ,@(if (string-prefix? "x86_64"
                                            (or (%current-target-system)
                                                (%current-system)))
                            '()
                            '("POPCNT_CAPABILITY=0")))
       #:phases
       (alist-cons-after
        'unpack 'patch-sources
        (lambda _
          ;; XXX Cannot use snippet because zip files are not supported
          (substitute* "Makefile"
            (("^CC = .*$") "CC = gcc")
            (("^CPP = .*$") "CPP = g++")
            ;; replace BUILD_HOST and BUILD_TIME for deterministic build
            (("-DBUILD_HOST=.*") "-DBUILD_HOST=\"\\\"guix\\\"\"")
            (("-DBUILD_TIME=.*") "-DBUILD_TIME=\"\\\"0\\\"\""))
          (substitute* '("hisat-build" "hisat-inspect")
            (("/usr/bin/env") (which "env"))))
        (alist-replace
         'install
         (lambda* (#:key outputs #:allow-other-keys)
           (let ((bin (string-append (assoc-ref outputs "out") "/bin/")))
             (for-each (lambda (file)
                         (install-file file bin))
                       (find-files
                        "."
                        "hisat(-(build|align|inspect)(-(s|l)(-debug)*)*)*$"))))
         (alist-delete 'configure %standard-phases)))))
    (native-inputs
     `(("unzip" ,unzip)))
    (inputs
     `(("perl" ,perl)
       ("python" ,python)
       ("zlib" ,zlib)))
    ;; Non-portable SSE instructions are used so building fails on platforms
    ;; other than x86_64.
    (supported-systems '("x86_64-linux"))
    (home-page "http://ccb.jhu.edu/software/hisat/index.shtml")
    (synopsis "Hierarchical indexing for spliced alignment of transcripts")
    (description
     "HISAT is a fast and sensitive spliced alignment program for mapping
RNA-seq reads.  In addition to one global FM index that represents a whole
genome, HISAT uses a large set of small FM indexes that collectively cover the
whole genome.  These small indexes (called local indexes) combined with
several alignment strategies enable effective alignment of RNA-seq reads, in
particular, reads spanning multiple exons.")
    (license license:gpl3+)))

(define-public hmmer
  (package
    (name "hmmer")
    (version "3.1b2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://eddylab.org/software/hmmer"
                    (version-prefix version 1) "/"
                    version "/hmmer-" version ".tar.gz"))
              (sha256
               (base32
                "0djmgc0pfli0jilfx8hql1axhwhqxqb8rxg2r5rg07aw73sfs5nx"))))
    (build-system gnu-build-system)
    (native-inputs `(("perl" ,perl)))
    (home-page "http://hmmer.org/")
    (synopsis "Biosequence analysis using profile hidden Markov models")
    (description
     "HMMER is used for searching sequence databases for homologs of protein
sequences, and for making protein sequence alignments.  It implements methods
using probabilistic models called profile hidden Markov models (profile
HMMs).")
    (license (list license:gpl3+
                   ;; The bundled library 'easel' is distributed
                   ;; under The Janelia Farm Software License.
                   (license:non-copyleft
                    "file://easel/LICENSE"
                    "See easel/LICENSE in the distribution.")))))

(define-public htseq
  (package
    (name "htseq")
    (version "0.6.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://pypi.python.org/packages/source/H/HTSeq/HTSeq-"
                    version ".tar.gz"))
              (sha256
               (base32
                "1i85ppf2j2lj12m0x690qq5nn17xxk23pbbx2c83r8ayb5wngzwv"))))
    (build-system python-build-system)
    (arguments `(#:python ,python-2)) ; only Python 2 is supported
    ;; Numpy needs to be propagated when htseq is used as a Python library.
    (propagated-inputs
     `(("python-numpy" ,python2-numpy)))
    (inputs
     `(("python-pysam" ,python2-pysam)))
    (home-page "http://www-huber.embl.de/users/anders/HTSeq/")
    (synopsis "Analysing high-throughput sequencing data with Python")
    (description
     "HTSeq is a Python package that provides infrastructure to process data
from high-throughput sequencing assays.")
    (license license:gpl3+)))

(define-public java-htsjdk
  (package
    (name "java-htsjdk")
    (version "1.129")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/samtools/htsjdk/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0asdk9b8jx2ij7yd6apg9qx03li8q7z3ml0qy2r2qczkra79y6fw"))
              (modules '((guix build utils)))
              ;; remove build dependency on git
              (snippet '(substitute* "build.xml"
                          (("failifexecutionfails=\"true\"")
                           "failifexecutionfails=\"false\"")))))
    (build-system ant-build-system)
    (arguments
     `(#:tests? #f ; test require Internet access
       #:make-flags
       (list (string-append "-Ddist=" (assoc-ref %outputs "out")
                            "/share/java/htsjdk/"))
       #:build-target "all"
       #:phases
       (modify-phases %standard-phases
         ;; The build phase also installs the jars
         (delete 'install))))
    (home-page "http://samtools.github.io/htsjdk/")
    (synopsis "Java API for high-throughput sequencing data (HTS) formats")
    (description
     "HTSJDK is an implementation of a unified Java library for accessing
common file formats, such as SAM and VCF, used for high-throughput
sequencing (HTS) data.  There are also an number of useful utilities for
manipulating HTS data.")
    (license license:expat)))

(define-public htslib
  (package
    (name "htslib")
    (version "1.3.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/samtools/htslib/releases/download/"
                    version "/htslib-" version ".tar.bz2"))
              (sha256
               (base32
                "1rja282fwdc25ql6izkhdyh8ppw8x2fs0w0js78zgkmqjlikmma9"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after
          'unpack 'patch-tests
          (lambda _
            (substitute* "test/test.pl"
              (("/bin/bash") (which "bash")))
            #t)))))
    (inputs
     `(("zlib" ,zlib)))
    (native-inputs
     `(("perl" ,perl)))
    (home-page "http://www.htslib.org")
    (synopsis "C library for reading/writing high-throughput sequencing data")
    (description
     "HTSlib is a C library for reading/writing high-throughput sequencing
data.  It also provides the bgzip, htsfile, and tabix utilities.")
    ;; Files under cram/ are released under the modified BSD license;
    ;; the rest is released under the Expat license
    (license (list license:expat license:bsd-3))))

(define-public idr
  (package
    (name "idr")
    (version "2.0.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/nboley/idr/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1k3x44biak00aiv3hpm1yd6nn4hhp7n0qnbs3zh2q9sw7qr1qj5r"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after
          'install 'wrap-program
          (lambda* (#:key inputs outputs #:allow-other-keys)
            (let* ((out (assoc-ref outputs "out"))
                   (python-version (string-take (string-take-right
                                                 (assoc-ref inputs "python") 5) 3))
                   (path (string-join
                          (map (lambda (name)
                                 (string-append (assoc-ref inputs name)
                                                "/lib/python" python-version
                                                "/site-packages"))
                               '("python-scipy"
                                 "python-numpy"
                                 "python-matplotlib"))
                          ":")))
              (wrap-program (string-append out "/bin/idr")
                `("PYTHONPATH" ":" prefix (,path))))
            #t)))))
    (inputs
     `(("python-scipy" ,python-scipy)
       ("python-numpy" ,python-numpy)
       ("python-matplotlib" ,python-matplotlib)))
    (native-inputs
     `(("python-cython" ,python-cython)))
    (home-page "https://github.com/nboley/idr")
    (synopsis "Tool to measure the irreproducible discovery rate (IDR)")
    (description
     "The IDR (Irreproducible Discovery Rate) framework is a unified approach
to measure the reproducibility of findings identified from replicate
experiments and provide highly stable thresholds based on reproducibility.")
    (license license:gpl3+)))

(define-public jellyfish
  (package
    (name "jellyfish")
    (version "2.2.4")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/gmarcais/Jellyfish/"
                                  "releases/download/v" version
                                  "/jellyfish-" version ".tar.gz"))
              (sha256
               (base32
                "0a6xnynqy2ibfbfz86b9g2m2dgm7f1469pmymkpam333gi3p26nk"))))
    (build-system gnu-build-system)
    (outputs '("out"      ;for library
               "ruby"     ;for Ruby bindings
               "python")) ;for Python bindings
    (arguments
     `(#:configure-flags
       (list (string-append "--enable-ruby-binding="
                            (assoc-ref %outputs "ruby"))
             (string-append "--enable-python-binding="
                            (assoc-ref %outputs "python")))
       #:phases
       (modify-phases %standard-phases
         (add-before 'check 'set-SHELL-variable
           (lambda _
             ;; generator_manager.hpp either uses /bin/sh or $SHELL
             ;; to run tests.
             (setenv "SHELL" (which "bash"))
             #t)))))
    (native-inputs
     `(("bc" ,bc)
       ("time" ,time)
       ("ruby" ,ruby)
       ("python" ,python-2)))
    (synopsis "Tool for fast counting of k-mers in DNA")
    (description
     "Jellyfish is a tool for fast, memory-efficient counting of k-mers in
DNA.  A k-mer is a substring of length k, and counting the occurrences of all
such substrings is a central step in many analyses of DNA sequence.  Jellyfish
is a command-line program that reads FASTA and multi-FASTA files containing
DNA sequences.  It outputs its k-mer counts in a binary format, which can be
translated into a human-readable text format using the @code{jellyfish dump}
command, or queried for specific k-mers with @code{jellyfish query}.")
    (home-page "http://www.genome.umd.edu/jellyfish.html")
    ;; From their website: JELLYFISH runs on 64-bit Intel-compatible processors
    (supported-systems '("x86_64-linux"))
    ;; The combined work is published under the GPLv3 or later.  Individual
    ;; files such as lib/jsoncpp.cpp are released under the Expat license.
    (license (list license:gpl3+ license:expat))))

(define-public khmer
  (package
    (name "khmer")
    (version "2.0")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "khmer" version))
       (sha256
        (base32
         "0wb05shqh77v00256qlm68vbbx3kl76fyzihszbz5nhanl4ni33a"))
       (patches (search-patches "khmer-use-libraries.patch"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'set-paths
           (lambda* (#:key inputs outputs #:allow-other-keys)
             ;; Delete bundled libraries.
             (delete-file-recursively "third-party/zlib")
             (delete-file-recursively "third-party/bzip2")
             ;; Replace bundled seqan.
             (let* ((seqan-all "third-party/seqan")
                    (seqan-include (string-append
                                    seqan-all "/core/include")))
               (delete-file-recursively seqan-all)
               (copy-recursively (string-append (assoc-ref inputs "seqan")
                                                "/include/seqan")
                          (string-append seqan-include "/seqan")))
             ;; We do not replace the bundled MurmurHash as the canonical
             ;; repository for this code 'SMHasher' is unsuitable for
             ;; providing a library.  See
             ;; https://lists.gnu.org/archive/html/guix-devel/2016-06/msg00977.html
             #t))
         (add-after 'unpack 'set-cc
           (lambda _
             (setenv "CC" "gcc")
             #t))
         ;; It is simpler to test after installation.
         (delete 'check)
         (add-after 'install 'post-install-check
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let ((out (assoc-ref outputs "out")))
               (setenv "PATH"
                       (string-append
                        (getenv "PATH")
                        ":"
                        (assoc-ref outputs "out")
                        "/bin"))
               (setenv "PYTHONPATH"
                       (string-append
                        (getenv "PYTHONPATH")
                        ":"
                        out
                        "/lib/python"
                        (string-take (string-take-right
                                      (assoc-ref inputs "python") 5) 3)
                        "/site-packages"))
               (with-directory-excursion "build"
                 (zero? (system* "nosetests" "khmer" "--attr"
                                 "!known_failing")))))))))
    (native-inputs
     `(("seqan" ,seqan)
       ("python-nose" ,python-nose)))
    (inputs
     `(("zlib" ,zlib)
       ("bzip2" ,bzip2)
       ("python-screed" ,python-screed)
       ("python-bz2file" ,python-bz2file)))
    (home-page "https://khmer.readthedocs.org/")
    (synopsis "K-mer counting, filtering and graph traversal library")
    (description "The khmer software is a set of command-line tools for
working with DNA shotgun sequencing data from genomes, transcriptomes,
metagenomes and single cells.  Khmer can make de novo assemblies faster, and
sometimes better.  Khmer can also identify and fix problems with shotgun
data.")
    ;; When building on i686, armhf and mips64el, we get the following error:
    ;; error: ['khmer', 'khmer.tests', 'oxli'] require 64-bit operating system
    (supported-systems '("x86_64-linux"))
    (license license:bsd-3)))

(define-public macs
  (package
    (name "macs")
    (version "2.1.0.20151222")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "MACS2" version))
              (sha256
               (base32
                "1r2hcz6irhcq7lwbafjks98jbn34hv05avgbdjnp6w6mlfjkf8x5"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2 ; only compatible with Python 2.7
       #:tests? #f)) ; no test target
    (inputs
     `(("python-numpy" ,python2-numpy)))
    (home-page "http://github.com/taoliu/MACS/")
    (synopsis "Model based analysis for ChIP-Seq data")
    (description
     "MACS is an implementation of a ChIP-Seq analysis algorithm for
identifying transcript factor binding sites named Model-based Analysis of
ChIP-Seq (MACS).  MACS captures the influence of genome complexity to evaluate
the significance of enriched ChIP regions and it improves the spatial
resolution of binding sites through combining the information of both
sequencing tag position and orientation.")
    (license license:bsd-3)))

(define-public mafft
  (package
    (name "mafft")
    (version "7.305")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://mafft.cbrc.jp/alignment/software/mafft-" version
                    "-without-extensions-src.tgz"))
              (file-name (string-append name "-" version ".tgz"))
              (sha256
               (base32
                "0ziim7g58n3z8gppsa713f5fxprl60ldj3xck186z0n9dpp06i8r"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; no automated tests, though there are tests in the read me
       #:make-flags (let ((out (assoc-ref %outputs "out")))
                      (list (string-append "PREFIX=" out)
                            (string-append "BINDIR="
                                           (string-append out "/bin"))))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'enter-dir
           (lambda _ (chdir "core") #t))
         (add-after 'enter-dir 'patch-makefile
           (lambda _
             ;; on advice from the MAFFT authors, there is no need to
             ;; distribute mafft-profile, mafft-distance, or
             ;; mafft-homologs.rb as they are too "specialised".
             (substitute* "Makefile"
               ;; remove mafft-homologs.rb from SCRIPTS
               (("^SCRIPTS = mafft mafft-homologs.rb")
                "SCRIPTS = mafft")
               ;; remove mafft-homologs from MANPAGES
               (("^MANPAGES = mafft.1 mafft-homologs.1")
                "MANPAGES = mafft.1")
               ;; remove mafft-distance from PROGS
               (("^PROGS = dvtditr dndfast7 dndblast sextet5 mafft-distance")
                "PROGS = dvtditr dndfast7 dndblast sextet5")
               ;; remove mafft-profile from PROGS
               (("splittbfast disttbfast tbfast mafft-profile 2cl mccaskillwrap")
                "splittbfast disttbfast tbfast f2cl mccaskillwrap")
               (("^rm -f mafft-profile mafft-profile.exe") "#")
               (("^rm -f mafft-distance mafft-distance.exe") ")#")
               ;; do not install MAN pages in libexec folder
               (("^\t\\$\\(INSTALL\\) -m 644 \\$\\(MANPAGES\\) \
\\$\\(DESTDIR\\)\\$\\(LIBDIR\\)") "#"))
             #t))
         (add-after 'enter-dir 'patch-paths
           (lambda* (#:key inputs #:allow-other-keys)
             (substitute* '("pairash.c"
                            "mafft.tmpl")
               (("perl") (which "perl"))
               (("([\"`| ])awk" _ prefix)
                (string-append prefix (which "awk")))
               (("grep") (which "grep")))
             #t))
         (delete 'configure)
         (add-after 'install 'wrap-programs
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (bin (string-append out "/bin"))
                    (path (string-append
                           (assoc-ref %build-inputs "coreutils") "/bin:")))
               (for-each (lambda (file)
                           (wrap-program file
                             `("PATH" ":" prefix (,path))))
                         (find-files bin)))
             #t)))))
    (inputs
     `(("perl" ,perl)
       ("ruby" ,ruby)
       ("gawk" ,gawk)
       ("grep" ,grep)
       ("coreutils" ,coreutils)))
    (home-page "http://mafft.cbrc.jp/alignment/software/")
    (synopsis "Multiple sequence alignment program")
    (description
     "MAFFT offers a range of multiple alignment methods for nucleotide and
protein sequences.  For instance, it offers L-INS-i (accurate; for alignment
of <~200 sequences) and FFT-NS-2 (fast; for alignment of <~30,000
sequences).")
    (license (license:non-copyleft
              "http://mafft.cbrc.jp/alignment/software/license.txt"
              "BSD-3 with different formatting"))))

(define-public mash
  (package
    (name "mash")
    (version "1.1.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/marbl/mash/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "08znbvqq5xknfhmpp3wcj574zvi4p7i8zifi67c9qw9a6ikp42fj"))
              (modules '((guix build utils)))
              (snippet
               ;; Delete bundled kseq.
               ;; TODO: Also delete bundled murmurhash and open bloom filter.
               '(delete-file "src/mash/kseq.h"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; No tests.
       #:configure-flags
       (list
        (string-append "--with-capnp=" (assoc-ref %build-inputs "capnproto"))
        (string-append "--with-gsl=" (assoc-ref %build-inputs "gsl")))
       #:make-flags (list "CC=gcc")
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-includes
           (lambda _
             (substitute* '("src/mash/Sketch.cpp" "src/mash/CommandFind.cpp")
               (("^#include \"kseq\\.h\"")
                "#include \"htslib/kseq.h\""))
             #t))
         (add-before 'configure 'autoconf
           (lambda _ (zero? (system* "autoconf")))))))
    (native-inputs
     `(("autoconf" ,autoconf)
       ;; Capnproto and htslib are statically embedded in the final
       ;; application. Therefore we also list their licenses, below.
       ("capnproto" ,capnproto)
       ("htslib" ,htslib)))
    (inputs
     `(("gsl" ,gsl)
       ("zlib" ,zlib)))
    (supported-systems '("x86_64-linux"))
    (home-page "https://mash.readthedocs.io")
    (synopsis "Fast genome and metagenome distance estimation using MinHash")
    (description "Mash is a fast sequence distance estimator that uses the
MinHash algorithm and is designed to work with genomes and metagenomes in the
form of assemblies or reads.")
    (license (list license:bsd-3          ; Mash
                   license:expat          ; HTSlib and capnproto
                   license:public-domain  ; MurmurHash 3
                   license:cpl1.0))))     ; Open Bloom Filter

(define-public metabat
  ;; We package from a git commit because compilation of the released version
  ;; fails.
  (let ((commit "cbdca756993e66ae57e50a27970595dda9cbde1b"))
    (package
      (name "metabat")
      (version (string-append "0.32.4-1." (string-take commit 8)))
      (source
       (origin
         (method git-fetch)
         (uri (git-reference
               (url "https://bitbucket.org/berkeleylab/metabat.git")
               (commit commit)))
         (file-name (string-append name "-" version))
         (sha256
          (base32
           "0byia8nsip6zvc4ha0qkxkxxyjf4x7jcvy48q2dvb0pzr989syzr"))
         (patches (search-patches "metabat-remove-compilation-date.patch"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-includes
           (lambda _
             (substitute* "src/BamUtils.h"
               (("^#include \"bam/bam\\.h\"")
                "#include \"samtools/bam.h\"")
               (("^#include \"bam/sam\\.h\"")
                "#include \"samtools/sam.h\""))
             (substitute* "src/KseqReader.h"
               (("^#include \"bam/kseq\\.h\"")
                "#include \"htslib/kseq.h\""))
             #t))
         (add-after 'unpack 'fix-scons
            (lambda* (#:key inputs #:allow-other-keys)
              (substitute* "SConstruct"
                (("^htslib_dir = 'samtools'")
                 (string-append "hitslib_dir = '"
                                (assoc-ref inputs "htslib")
                                "'"))
                (("^samtools_dir = 'samtools'")
                 (string-append "samtools_dir = '"
                                (assoc-ref inputs "htslib")
                                "'"))
                (("^findStaticOrShared\\('bam', hts_lib")
                 (string-append "findStaticOrShared('bam', '"
                                (assoc-ref inputs "samtools")
                                "/lib'"))
                ;; Do not distribute README.
                (("^env\\.Install\\(idir_prefix, 'README\\.md'\\)") ""))
              #t))
         (delete 'configure)
         (replace 'build
                  (lambda* (#:key inputs outputs #:allow-other-keys)
                    (mkdir (assoc-ref outputs "out"))
                    (zero? (system* "scons"
                                    (string-append
                                     "PREFIX="
                                     (assoc-ref outputs "out"))
                                    (string-append
                                     "BOOST_ROOT="
                                     (assoc-ref inputs "boost"))
                                    "install"))))
         ;; Check and install are carried out during build phase.
         (delete 'check)
         (delete 'install))))
    (inputs
     `(("zlib" ,zlib)
       ("perl" ,perl)
       ("samtools" ,samtools)
       ("htslib" ,htslib)
       ("boost" ,boost)))
    (native-inputs
     `(("scons" ,scons)))
    (home-page "https://bitbucket.org/berkeleylab/metabat")
    (synopsis
     "Reconstruction of single genomes from complex microbial communities")
    (description
     "Grouping large genomic fragments assembled from shotgun metagenomic
sequences to deconvolute complex microbial communities, or metagenome binning,
enables the study of individual organisms and their interactions.  MetaBAT is
an automated metagenome binning software, which integrates empirical
probabilistic distances of genome abundance and tetranucleotide frequency.")
   (license (license:non-copyleft "file://license.txt"
                                  "See license.txt in the distribution.")))))

(define-public minced
  (package
    (name "minced")
    (version "0.2.0")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/ctSkennerton/minced/archive/"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0wxmlsapxfpxfd3ps9636h7i2xy6la8i42mwh0j2lsky63h63jp1"))))
    (build-system gnu-build-system)
    (arguments
     `(#:test-target "test"
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (add-before 'check 'fix-test
           (lambda _
             ;; Fix test for latest version.
             (substitute* "t/Aquifex_aeolicus_VF5.expected"
               (("minced:0.1.6") "minced:0.2.0"))
             #t))
         (replace 'install ; No install target.
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (bin (string-append out "/bin"))
                    (wrapper (string-append bin "/minced")))
               ;; Minced comes with a wrapper script that tries to figure out where
               ;; it is located before running the JAR. Since these paths are known
               ;; to us, we build our own wrapper to avoid coreutils dependency.
               (install-file "minced.jar" bin)
               (with-output-to-file wrapper
                 (lambda _
                   (display
                    (string-append
                     "#!" (assoc-ref inputs "bash") "/bin/sh\n\n"
                     (assoc-ref inputs "jre") "/bin/java -jar "
                     bin "/minced.jar \"$@\"\n"))))
               (chmod wrapper #o555)))))))
    (native-inputs
     `(("jdk" ,icedtea "jdk")))
    (inputs
     `(("bash" ,bash)
       ("jre" ,icedtea "out")))
    (home-page "https://github.com/ctSkennerton/minced")
    (synopsis "Mining CRISPRs in Environmental Datasets")
    (description
     "MinCED is a program to find Clustered Regularly Interspaced Short
Palindromic Repeats (CRISPRs) in DNA sequences.  It can be used for
unassembled metagenomic reads, but is mainly designed for full genomes and
assembled metagenomic sequence.")
    (license license:gpl3+)))

(define-public miso
  (package
    (name "miso")
    (version "0.5.3")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://pypi.python.org/packages/source/m/misopy/misopy-"
                    version ".tar.gz"))
              (sha256
               (base32
                "0x446867az8ir0z8c1vjqffkp0ma37wm4sylixnkhgawllzx8v5w"))
              (modules '((guix build utils)))
              (snippet
               '(substitute* "setup.py"
                  ;; Use setuptools, or else the executables are not
                  ;; installed.
                  (("distutils.core") "setuptools")
                  ;; use "gcc" instead of "cc" for compilation
                  (("^defines")
                   "cc.set_executables(
compiler='gcc',
compiler_so='gcc',
linker_exe='gcc',
linker_so='gcc -shared'); defines")))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2 ; only Python 2 is supported
       #:tests? #f)) ; no "test" target
    (inputs
     `(("samtools" ,samtools)
       ("python-numpy" ,python2-numpy)
       ("python-pysam" ,python2-pysam)
       ("python-scipy" ,python2-scipy)
       ("python-matplotlib" ,python2-matplotlib)))
    (native-inputs
     `(("python-mock" ,python2-mock)   ;for tests
       ("python-pytz" ,python2-pytz))) ;for tests
    (home-page "http://genes.mit.edu/burgelab/miso/index.html")
    (synopsis "Mixture of Isoforms model for RNA-Seq isoform quantitation")
    (description
     "MISO (Mixture-of-Isoforms) is a probabilistic framework that quantitates
the expression level of alternatively spliced genes from RNA-Seq data, and
identifies differentially regulated isoforms or exons across samples.  By
modeling the generative process by which reads are produced from isoforms in
RNA-Seq, the MISO model uses Bayesian inference to compute the probability
that a read originated from a particular isoform.")
    (license license:gpl2)))

(define-public muscle
  (package
    (name "muscle")
    (version "3.8.1551")
    (source (origin
              (method url-fetch/tarbomb)
              (file-name (string-append name "-" version))
              (uri (string-append
                    "http://www.drive5.com/muscle/muscle_src_"
                    version ".tar.gz"))
              (sha256
               (base32
                "0bj8kj7sdizy3987zx6w7axihk40fk8rn76mpbqqjcnd64i5a367"))))
    (build-system gnu-build-system)
    (arguments
     `(#:make-flags (list "LDLIBS = -lm")
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'check
           ;; There are no tests, so just test if it runs.
           (lambda _ (zero? (system* "./muscle" "-version"))))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (bin (string-append out "/bin")))
               (install-file "muscle" bin)))))))
    (home-page "http://www.drive5.com/muscle")
    (synopsis "Multiple sequence alignment program")
    (description
     "MUSCLE aims to be a fast and accurate multiple sequence alignment
program for nucleotide and protein sequences.")
    ;; License information found in 'muscle -h' and usage.cpp.
    (license license:public-domain)))

(define-public newick-utils
  ;; There are no recent releases so we package from git.
  (let ((commit "da121155a977197cab9fbb15953ca1b40b11eb87"))
    (package
      (name "newick-utils")
      (version (string-append "1.6-1." (string-take commit 8)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/tjunier/newick_utils.git")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "1hkw21rq1mwf7xp0rmbb2gqc0i6p11108m69i7mr7xcjl268pxnb"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'autoconf
           (lambda _ (zero? (system* "autoreconf" "-vif")))))))
    (inputs
     ;; XXX: TODO: Enable Lua and Guile bindings.
     ;; https://github.com/tjunier/newick_utils/issues/13
     `(("libxml2" ,libxml2)
       ("flex" ,flex)
       ("bison" ,bison)))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("libtool" ,libtool)))
    (synopsis "Programs for working with newick format phylogenetic trees")
    (description
     "Newick-utils is a suite of utilities for processing phylogenetic trees
in Newick format.  Functions include re-rooting, extracting subtrees,
trimming, pruning, condensing, drawing (ASCII graphics or SVG).")
    (home-page "https://github.com/tjunier/newick_utils")
    (license license:bsd-3))))

(define-public orfm
  (package
    (name "orfm")
    (version "0.6.1")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/wwood/OrfM/releases/download/v"
                    version "/orfm-" version ".tar.gz"))
              (sha256
               (base32
                "19hwp13n82isdvk16710l9m35cmzf0q3fsrcn3r8c5r67biiz39s"))))
    (build-system gnu-build-system)
    (inputs `(("zlib" ,zlib)))
    (native-inputs
     `(("ruby-bio-commandeer" ,ruby-bio-commandeer)
       ("ruby-rspec" ,ruby-rspec)
       ("ruby" ,ruby)))
    (synopsis "Simple and not slow open reading frame (ORF) caller")
    (description
     "An ORF caller finds stretches of DNA that, when translated, are not
interrupted by stop codons.  OrfM finds and prints these ORFs.")
    (home-page "https://github.com/wwood/OrfM")
    (license license:lgpl3+)))

(define-public python2-pbcore
  (package
    (name "python2-pbcore")
    (version "1.2.10")
    (source (origin
              (method url-fetch)
              (uri (pypi-uri "pbcore" version))
              (sha256
               (base32
                "1kjmv891d6qbpp4shhhvkl02ff4q5xlpnls2513sm2cjcrs52f1i"))))
    (build-system python-build-system)
    (arguments `(#:python ,python-2)) ; pbcore requires Python 2.7
    (propagated-inputs
     `(("python-cython" ,python2-cython)
       ("python-numpy" ,python2-numpy)
       ("python-pysam" ,python2-pysam)
       ("python-h5py" ,python2-h5py)))
    (native-inputs
     `(("python-nose" ,python2-nose)
       ("python-sphinx" ,python2-sphinx)
       ("python-pyxb" ,python2-pyxb)))
    (home-page "http://pacificbiosciences.github.io/pbcore/")
    (synopsis "Library for reading and writing PacBio data files")
    (description
     "The pbcore package provides Python APIs for interacting with PacBio data
files and writing bioinformatics applications.")
    (license license:bsd-3)))

(define-public python2-warpedlmm
  (package
    (name "python2-warpedlmm")
    (version "0.21")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/W/WarpedLMM/WarpedLMM-"
             version ".zip"))
       (sha256
        (base32
         "1agfz6zqa8nc6cw47yh0s3y14gkpa9wqazwcj7mwwj3ffnw39p3j"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2))  ; requires Python 2.7
    (propagated-inputs
     `(("python-scipy" ,python2-scipy)
       ("python-numpy" ,python2-numpy)
       ("python-matplotlib" ,python2-matplotlib)
       ("python-fastlmm" ,python2-fastlmm)
       ("python-pandas" ,python2-pandas)
       ("python-pysnptools" ,python2-pysnptools)))
    (native-inputs
     `(("python-mock" ,python2-mock)
       ("python-nose" ,python2-nose)
       ("unzip" ,unzip)))
    (home-page "https://github.com/PMBio/warpedLMM")
    (synopsis "Implementation of warped linear mixed models")
    (description
     "WarpedLMM is a Python implementation of the warped linear mixed model,
which automatically learns an optimal warping function (or transformation) for
the phenotype as it models the data.")
    (license license:asl2.0)))

(define-public pbtranscript-tofu
  (let ((commit "8f5467fe6a4472bcfb4226c8720993c8507adfe4"))
    (package
      (name "pbtranscript-tofu")
      (version (string-append "2.2.3." (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/PacificBiosciences/cDNA_primer.git")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "1lgnpi35ihay42qx0b6yl3kkgra723i413j33kvs0kvs61h82w0f"))
                (modules '((guix build utils)))
                (snippet
                 '(begin
                    ;; remove bundled Cython sources
                    (delete-file "pbtranscript-tofu/pbtranscript/Cython-0.20.1.tar.gz")
                    #t))))
      (build-system python-build-system)
      (arguments
       `(#:python ,python-2
         #:phases
         (modify-phases %standard-phases
           (add-after 'unpack 'enter-directory
            (lambda _
              (chdir "pbtranscript-tofu/pbtranscript/")
              #t))
           ;; With setuptools version 18.0 and later this setup.py hack causes
           ;; a build error, so we disable it.
           (add-after 'enter-directory 'patch-setuppy
            (lambda _
              (substitute* "setup.py"
                (("if 'setuptools.extension' in sys.modules:")
                 "if False:"))
              #t)))))
      (inputs
       `(("python-numpy" ,python2-numpy)
         ("python-bx-python" ,python2-bx-python)
         ("python-networkx" ,python2-networkx)
         ("python-scipy" ,python2-scipy)
         ("python-pbcore" ,python2-pbcore)
         ("python-h5py" ,python2-h5py)))
      (native-inputs
       `(("python-cython" ,python2-cython)
         ("python-nose" ,python2-nose)))
      (home-page "https://github.com/PacificBiosciences/cDNA_primer")
      (synopsis "Analyze transcriptome data generated with the Iso-Seq protocol")
      (description
       "pbtranscript-tofu contains scripts to analyze transcriptome data
generated using the PacBio Iso-Seq protocol.")
      (license license:bsd-3))))

(define-public prank
  (package
    (name "prank")
    (version "150803")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://wasabiapp.org/download/prank/prank.source."
                    version ".tgz"))
              (sha256
               (base32
                "0am4z94fs3w2n5xpfls9zda61vq7qqz4q2i7b9hlsxz5q4j3kfm4"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'enter-src-dir
            (lambda _
              (chdir "src")
              #t))
         (add-after 'unpack 'remove-m64-flag
           ;; Prank will build with the correct 'bit-ness' without this flag
           ;; and this allows building on 32-bit machines.
           (lambda _ (substitute* "src/Makefile"
                                  (("-m64") ""))
             #t))
         (delete 'configure)
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (bin (string-append out "/bin"))
                    (man (string-append out "/share/man/man1"))
                    (path (string-append
                           (assoc-ref %build-inputs "mafft") "/bin:"
                           (assoc-ref %build-inputs "exonerate") "/bin:"
                           (assoc-ref %build-inputs "bppsuite") "/bin")))
               (install-file "prank" bin)
               (wrap-program (string-append bin "/prank")
                 `("PATH" ":" prefix (,path)))
               (install-file "prank.1" man))
             #t)))))
    (inputs
     `(("mafft" ,mafft)
       ("exonerate" ,exonerate)
       ("bppsuite" ,bppsuite)))
    (home-page "http://wasabiapp.org/software/prank/")
    (synopsis "Probabilistic multiple sequence alignment program")
    (description
     "PRANK is a probabilistic multiple sequence alignment program for DNA,
codon and amino-acid sequences.  It is based on a novel algorithm that treats
insertions correctly and avoids over-estimation of the number of deletion
events.  In addition, PRANK borrows ideas from maximum likelihood methods used
in phylogenetics and correctly takes into account the evolutionary distances
between sequences.  Lastly, PRANK allows for defining a potential structure
for sequences to be aligned and then, simultaneously with the alignment,
predicts the locations of structural units in the sequences.")
    (license license:gpl2+)))

(define-public proteinortho
  (package
    (name "proteinortho")
    (version "5.15")
    (source
     (origin
      (method url-fetch)
      (uri
       (string-append
        "http://www.bioinf.uni-leipzig.de/Software/proteinortho/proteinortho_v"
        version "_src.tar.gz"))
      (sha256
       (base32
        "05wacnnbx56avpcwhzlcf6b7s77swcpv3qnwz5sh1z54i51gg2ki"))))
    (build-system gnu-build-system)
    (arguments
     `(#:test-target "test"
       #:phases
       (modify-phases %standard-phases
         (replace 'configure
           ;; There is no configure script, so we modify the Makefile directly.
           (lambda* (#:key outputs #:allow-other-keys)
             (substitute* "Makefile"
               (("INSTALLDIR=.*")
                (string-append
                 "INSTALLDIR=" (assoc-ref outputs "out") "/bin\n")))
             #t))
         (add-before 'install 'make-install-directory
           ;; The install directory is not created during 'make install'.
           (lambda* (#:key outputs #:allow-other-keys)
             (mkdir-p (string-append (assoc-ref outputs "out") "/bin"))
             #t))
         (add-after 'install 'wrap-programs
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((path (getenv "PATH"))
                    (out (assoc-ref outputs "out"))
                    (binary (string-append out "/bin/proteinortho5.pl")))
               (wrap-program binary `("PATH" ":" prefix (,path))))
             #t)))))
    (inputs
     `(("perl" ,perl)
       ("python" ,python-2)
       ("blast+" ,blast+)))
    (home-page "http://www.bioinf.uni-leipzig.de/Software/proteinortho")
    (synopsis "Detect orthologous genes across species")
    (description
     "Proteinortho is a tool to detect orthologous genes across different
species.  For doing so, it compares similarities of given gene sequences and
clusters them to find significant groups.  The algorithm was designed to handle
large-scale data and can be applied to hundreds of species at once.")
    (license license:gpl2+)))

(define-public pyicoteo
  (package
    (name "pyicoteo")
    (version "2.0.7")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://bitbucket.org/regulatorygenomicsupf/"
                           "pyicoteo/get/v" version ".tar.bz2"))
       (file-name (string-append name "-" version ".tar.bz2"))
       (sha256
        (base32
         "0d6087f29xp8wxwlj111c3sylli98n0l8ry58c51ixzq0zfm50wa"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2 ; does not work with Python 3
       #:tests? #f))      ; there are no tests
    (inputs
     `(("python2-matplotlib" ,python2-matplotlib)))
    (home-page "https://bitbucket.org/regulatorygenomicsupf/pyicoteo")
    (synopsis "Analyze high-throughput genetic sequencing data")
    (description
     "Pyicoteo is a suite of tools for the analysis of high-throughput genetic
sequencing data.  It works with genomic coordinates.  There are currently six
different command-line tools:

@enumerate
@item pyicoregion: for generating exploratory regions automatically;
@item pyicoenrich: for differential enrichment between two conditions;
@item pyicoclip: for calling CLIP-Seq peaks without a control;
@item pyicos: for genomic coordinates manipulation;
@item pyicoller: for peak calling on punctuated ChIP-Seq;
@item pyicount: to count how many reads from N experiment files overlap in a
  region file;
@item pyicotrocol: to combine operations from pyicoteo.
@end enumerate\n")
    (license license:gpl3+)))

(define-public prodigal
  (package
    (name "prodigal")
    (version "2.6.3")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/hyattpd/Prodigal/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "17srxkqd3jc77xk15pfbgg1a9xahqg7337w95mrsia7mpza4l2c9"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ;no check target
       #:make-flags (list (string-append "INSTALLDIR="
                                         (assoc-ref %outputs "out")
                                         "/bin"))
       #:phases
       (modify-phases %standard-phases
         (delete 'configure))))
    (home-page "http://prodigal.ornl.gov")
    (synopsis "Protein-coding gene prediction for Archaea and Bacteria")
    (description
     "Prodigal runs smoothly on finished genomes, draft genomes, and
metagenomes, providing gene predictions in GFF3, Genbank, or Sequin table
format.  It runs quickly, in an unsupervised fashion, handles gaps, handles
partial genes, and identifies translation initiation sites.")
    (license license:gpl3+)))

(define-public roary
  (package
    (name "roary")
    (version "3.7.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "mirror://cpan/authors/id/A/AJ/AJPAGE/Bio-Roary-"
             version ".tar.gz"))
       (sha256
        (base32
         "0x2hpb3nfsc6x2nq1788w0fhqfzc7cn2dp4xwyva9m3k6xlz0m43"))))
    (build-system perl-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (delete 'build)
         (replace 'check
           (lambda _
             ;; The tests are not run by default, so we run each test file
             ;; directly.
             (setenv "PATH" (string-append (getcwd) "/bin" ":"
                                           (getenv "PATH")))
             (setenv "PERL5LIB" (string-append (getcwd) "/lib" ":"
                                               (getenv "PERL5LIB")))
             (zero? (length (filter (lambda (file)
                                      (display file)(display "\n")
                                      (not (zero? (system* "perl" file))))
                                    (find-files "t" ".*\\.t$"))))))
         (replace 'install
           ;; There is no 'install' target in the Makefile.
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (bin (string-append out "/bin"))
                    (perl (string-append out "/lib/perl5/site_perl"))
                    (roary-plots "contrib/roary_plots"))
               (mkdir-p bin)
               (mkdir-p perl)
               (copy-recursively "bin" bin)
               (copy-recursively "lib" perl)
               #t)))
         (add-after 'install 'wrap-programs
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (perl5lib (getenv "PERL5LIB"))
                    (path (getenv "PATH")))
               (for-each (lambda (prog)
                           (let ((binary (string-append out "/" prog)))
                             (wrap-program binary
                               `("PERL5LIB" ":" prefix
                                 (,(string-append perl5lib ":" out
                                                  "/lib/perl5/site_perl"))))
                             (wrap-program binary
                               `("PATH" ":" prefix
                                 (,(string-append path ":" out "/bin"))))))
                         (find-files "bin" ".*[^R]$"))
               (let ((file
                      (string-append out "/bin/roary-create_pan_genome_plots.R"))
                     (r-site-lib (getenv "R_LIBS_SITE"))
                     (coreutils-path
                      (string-append (assoc-ref inputs "coreutils") "/bin")))
                 (wrap-program file
                   `("R_LIBS_SITE" ":" prefix
                     (,(string-append r-site-lib ":" out "/site-library/"))))
                 (wrap-program file
                   `("PATH" ":" prefix
                     (,(string-append coreutils-path ":" out "/bin"))))))
             #t)))))
    (native-inputs
     `(("perl-env-path" ,perl-env-path)
       ("perl-test-files" ,perl-test-files)
       ("perl-test-most" ,perl-test-most)
       ("perl-test-output" ,perl-test-output)))
    (inputs
     `(("perl-array-utils" ,perl-array-utils)
       ("bioperl" ,bioperl-minimal)
       ("perl-exception-class" ,perl-exception-class)
       ("perl-file-find-rule" ,perl-file-find-rule)
       ("perl-file-grep" ,perl-file-grep)
       ("perl-file-slurper" ,perl-file-slurper)
       ("perl-file-which" ,perl-file-which)
       ("perl-graph" ,perl-graph)
       ("perl-graph-readwrite" ,perl-graph-readwrite)
       ("perl-log-log4perl" ,perl-log-log4perl)
       ("perl-moose" ,perl-moose)
       ("perl-perlio-utf8_strict" ,perl-perlio-utf8_strict)
       ("perl-text-csv" ,perl-text-csv)
       ("bedtools" ,bedtools)
       ("cd-hit" ,cd-hit)
       ("blast+" ,blast+)
       ("mcl" ,mcl)
       ("parallel" ,parallel)
       ("prank" ,prank)
       ("mafft" ,mafft)
       ("fasttree" ,fasttree)
       ("grep" ,grep)
       ("sed" ,sed)
       ("gawk" ,gawk)
       ("r" ,r)
       ("r-ggplot2" ,r-ggplot2)
       ("coreutils" ,coreutils)))
    (home-page "http://sanger-pathogens.github.io/Roary")
    (synopsis "High speed stand-alone pan genome pipeline")
    (description
     "Roary is a high speed stand alone pan genome pipeline, which takes
annotated assemblies in GFF3 format (produced by the Prokka program) and
calculates the pan genome.  Using a standard desktop PC, it can analyse
datasets with thousands of samples, without compromising the quality of the
results.  128 samples can be analysed in under 1 hour using 1 GB of RAM and a
single processor.  Roary is not intended for metagenomics or for comparing
extremely diverse sets of genomes.")
    (license license:gpl3)))

(define-public raxml
  (package
    (name "raxml")
    (version "8.2.9")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append
         "https://github.com/stamatak/standard-RAxML/archive/v"
         version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1pv8p2fy67y21a9y4cm7xpvxqjwz2v4201flfjshdq1p8j52rqf7"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; There are no tests.
       ;; Use 'standard' Makefile rather than SSE or AVX ones.
       #:make-flags (list "-f" "Makefile.HYBRID.gcc")
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (bin (string-append out "/bin"))
                    (executable "raxmlHPC-HYBRID"))
               (install-file executable bin)
               (symlink (string-append bin "/" executable) "raxml"))
             #t)))))
    (inputs
     `(("openmpi" ,openmpi)))
    (home-page "http://sco.h-its.org/exelixis/web/software/raxml/index.html")
    (synopsis "Randomized Axelerated Maximum Likelihood phylogenetic trees")
    (description
     "RAxML is a tool for phylogenetic analysis and post-analysis of large
phylogenies.")
    (license license:gpl2+)))

(define-public rsem
  (package
    (name "rsem")
    (version "1.2.20")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "http://deweylab.biostat.wisc.edu/rsem/src/rsem-"
                       version ".tar.gz"))
       (sha256
        (base32 "0nzdc0j0hjllhsd5f2xli95dafm3nawskigs140xzvjk67xh0r9q"))
       (patches (search-patches "rsem-makefile.patch"))
       (modules '((guix build utils)))
       (snippet
        '(begin
           ;; remove bundled copy of boost
           (delete-file-recursively "boost")
           #t))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ;no "check" target
       #:phases
       (modify-phases %standard-phases
         ;; No "configure" script.
         ;; Do not build bundled samtools library.
         (replace 'configure
                  (lambda _
                    (substitute* "Makefile"
                      (("^all : sam/libbam.a") "all : "))
                    #t))
         (replace 'install
                  (lambda* (#:key outputs #:allow-other-keys)
                    (let* ((out (string-append (assoc-ref outputs "out")))
                           (bin (string-append out "/bin/"))
                           (perl (string-append out "/lib/perl5/site_perl")))
                      (mkdir-p bin)
                      (mkdir-p perl)
                      (for-each (lambda (file)
                                  (copy-file file
                                             (string-append bin (basename file))))
                                (find-files "." "rsem-.*"))
                      (copy-file "rsem_perl_utils.pm"
                                 (string-append perl "/rsem_perl_utils.pm")))
                    #t))
         (add-after
          'install 'wrap-program
          (lambda* (#:key outputs #:allow-other-keys)
            (let ((out (assoc-ref outputs "out")))
              (for-each (lambda (prog)
                          (wrap-program (string-append out "/bin/" prog)
                            `("PERL5LIB" ":" prefix
                              (,(string-append out "/lib/perl5/site_perl")))))
                        '("rsem-plot-transcript-wiggles"
                          "rsem-calculate-expression"
                          "rsem-generate-ngvector"
                          "rsem-run-ebseq"
                          "rsem-prepare-reference")))
            #t)))))
    (inputs
     `(("boost" ,boost)
       ("ncurses" ,ncurses)
       ("r" ,r)
       ("perl" ,perl)
       ("samtools" ,samtools-0.1)
       ("zlib" ,zlib)))
    (home-page "http://deweylab.biostat.wisc.edu/rsem/")
    (synopsis "Estimate gene expression levels from RNA-Seq data")
    (description
     "RSEM is a software package for estimating gene and isoform expression
levels from RNA-Seq data.  The RSEM package provides a user-friendly
interface, supports threads for parallel computation of the EM algorithm,
single-end and paired-end read data, quality scores, variable-length reads and
RSPD estimation.  In addition, it provides posterior mean and 95% credibility
interval estimates for expression levels.  For visualization, it can generate
BAM and Wiggle files in both transcript-coordinate and genomic-coordinate.")
    (license license:gpl3+)))

(define-public rseqc
  (package
    (name "rseqc")
    (version "2.6.1")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "mirror://sourceforge/rseqc/"
                       "RSeQC-" version ".tar.gz"))
       (sha256
        (base32 "15ly0254yi032qzkdplg00q144qfdsd986gh62829rl5bkxhj330"))
       (modules '((guix build utils)))
       (snippet
        '(begin
           ;; remove bundled copy of pysam
           (delete-file-recursively "lib/pysam")
           (substitute* "setup.py"
             ;; remove dependency on outdated "distribute" module
             (("^from distribute_setup import use_setuptools") "")
             (("^use_setuptools\\(\\)") "")
             ;; do not use bundled copy of pysam
             (("^have_pysam = False") "have_pysam = True"))))))
    (build-system python-build-system)
    (arguments `(#:python ,python-2))
    (inputs
     `(("python-cython" ,python2-cython)
       ("python-pysam" ,python2-pysam)
       ("python-numpy" ,python2-numpy)
       ("zlib" ,zlib)))
    (native-inputs
     `(("python-nose" ,python2-nose)))
    (home-page "http://rseqc.sourceforge.net/")
    (synopsis "RNA-seq quality control package")
    (description
     "RSeQC provides a number of modules that can comprehensively evaluate
high throughput sequence data, especially RNA-seq data.  Some basic modules
inspect sequence quality, nucleotide composition bias, PCR bias and GC bias,
while RNA-seq specific modules evaluate sequencing saturation, mapped reads
distribution, coverage uniformity, strand specificity, etc.")
    (license license:gpl3+)))

(define-public seek
  ;; There are no release tarballs.  According to the installation
  ;; instructions at http://seek.princeton.edu/installation.jsp, the latest
  ;; stable release is identified by this changeset ID.
  (let ((changeset "2329130")
        (revision "1"))
    (package
      (name "seek")
      (version (string-append "0-" revision "." changeset))
      (source (origin
                (method hg-fetch)
                (uri (hg-reference
                      (url "https://bitbucket.org/libsleipnir/sleipnir")
                      (changeset changeset)))
                (sha256
                 (base32
                  "0qrvilwh18dpbhkf92qvxbmay0j75ra3jg2wrhz67gf538zzphsx"))))
      (build-system gnu-build-system)
      (arguments
       `(#:modules ((srfi srfi-1)
                    (guix build gnu-build-system)
                    (guix build utils))
         #:phases
         (let ((dirs '("SeekMiner"
                       "SeekEvaluator"
                       "SeekPrep"
                       "Distancer"
                       "Data2DB"
                       "PCL2Bin")))
           (modify-phases %standard-phases
             (add-before 'configure 'bootstrap
               (lambda _
                 (zero? (system* "bash" "gen_auto"))))
             (add-after 'build 'build-additional-tools
               (lambda* (#:key make-flags #:allow-other-keys)
                 (every (lambda (dir)
                          (with-directory-excursion (string-append "tools/" dir)
                            (zero? (apply system* "make" make-flags))))
                        dirs)))
             (add-after 'install 'install-additional-tools
               (lambda* (#:key make-flags #:allow-other-keys)
                 (fold (lambda (dir result)
                         (with-directory-excursion (string-append "tools/" dir)
                           (and result
                                (zero? (apply system*
                                              `("make" ,@make-flags "install"))))))
                       #t dirs)))))))
      (inputs
       `(("gsl" ,gsl)
         ("boost" ,boost)
         ("libsvm" ,libsvm)
         ("readline" ,readline)
         ("gengetopt" ,gengetopt)
         ("log4cpp" ,log4cpp)))
      (native-inputs
       `(("autoconf" ,autoconf)
         ("automake" ,automake)
         ("perl" ,perl)))
      (home-page "http://seek.princeton.edu")
      (synopsis "Gene co-expression search engine")
      (description
       "SEEK is a computational gene co-expression search engine.  SEEK provides
biologists with a way to navigate the massive human expression compendium that
now contains thousands of expression datasets.  SEEK returns a robust ranking
of co-expressed genes in the biological area of interest defined by the user's
query genes.  It also prioritizes thousands of expression datasets according
to the user's query of interest.")
      (license license:cc-by3.0))))

(define-public samtools
  (package
    (name "samtools")
    (version "1.3.1")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "mirror://sourceforge/samtools/samtools/"
                       version "/samtools-" version ".tar.bz2"))
       (sha256
        (base32
         "0znnnxc467jbf1as2dpskrjhfh8mbll760j6w6rdkwlwbqsp8gbc"))))
    (build-system gnu-build-system)
    (arguments
     `(#:modules ((ice-9 ftw)
                  (ice-9 regex)
                  (guix build gnu-build-system)
                  (guix build utils))
       #:make-flags (list (string-append "prefix=" (assoc-ref %outputs "out")))
       #:configure-flags (list "--with-ncurses")
       #:phases
       (alist-cons-after
        'unpack 'patch-tests
        (lambda _
          (substitute* "test/test.pl"
            ;; The test script calls out to /bin/bash
            (("/bin/bash") (which "bash")))
          #t)
        (alist-cons-after
         'install 'install-library
         (lambda* (#:key outputs #:allow-other-keys)
           (let ((lib (string-append (assoc-ref outputs "out") "/lib")))
             (install-file "libbam.a" lib)))
         (alist-cons-after
          'install 'install-headers
          (lambda* (#:key outputs #:allow-other-keys)
            (let ((include (string-append (assoc-ref outputs "out")
                                          "/include/samtools/")))
              (for-each (lambda (file)
                          (install-file file include))
                        (scandir "." (lambda (name) (string-match "\\.h$" name))))
              #t))
          %standard-phases)))))
    (native-inputs `(("pkg-config" ,pkg-config)))
    (inputs `(("ncurses" ,ncurses)
              ("perl" ,perl)
              ("python" ,python)
              ("zlib" ,zlib)))
    (home-page "http://samtools.sourceforge.net")
    (synopsis "Utilities to efficiently manipulate nucleotide sequence alignments")
    (description
     "Samtools implements various utilities for post-processing nucleotide
sequence alignments in the SAM, BAM, and CRAM formats, including indexing,
variant calling (in conjunction with bcftools), and a simple alignment
viewer.")
    (license license:expat)))

(define-public samtools-0.1
  ;; This is the most recent version of the 0.1 line of samtools.  The input
  ;; and output formats differ greatly from that used and produced by samtools
  ;; 1.x and is still used in many bioinformatics pipelines.
  (package (inherit samtools)
    (version "0.1.19")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "mirror://sourceforge/samtools/samtools/"
                       version "/samtools-" version ".tar.bz2"))
       (sha256
        (base32 "1m33xsfwz0s8qi45lylagfllqg7fphf4dr0780rsvw75av9wk06h"))))
    (arguments
     `(#:tests? #f ;no "check" target
       ,@(substitute-keyword-arguments (package-arguments samtools)
           ((#:make-flags flags)
            `(cons "LIBCURSES=-lncurses" ,flags))
           ((#:phases phases)
            `(modify-phases ,phases
               (replace 'install
                 (lambda* (#:key outputs #:allow-other-keys)
                   (let ((bin (string-append
                               (assoc-ref outputs "out") "/bin")))
                     (mkdir-p bin)
                     (copy-file "samtools"
                                (string-append bin "/samtools")))))
               (delete 'patch-tests)
               (delete 'configure))))))))

(define-public mosaik
  (let ((commit "5c25216d3522d6a33e53875cd76a6d65001e4e67"))
    (package
      (name "mosaik")
      (version "2.2.30")
      (source (origin
                ;; There are no release tarballs nor tags.
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/wanpinglee/MOSAIK.git")
                      (commit commit)))
                (file-name (string-append name "-" version))
                (sha256
                 (base32
                  "17gj3s07cm77r41z92awh0bim7w7q7fbn0sf5nkqmcm1vw052qgw"))))
      (build-system gnu-build-system)
      (arguments
       `(#:tests? #f ; no tests
         #:make-flags (list "CC=gcc")
         #:phases
         (modify-phases %standard-phases
           (replace 'configure
                    (lambda _ (chdir "src") #t))
           (replace 'install
                    (lambda* (#:key outputs #:allow-other-keys)
                      (let ((bin (string-append (assoc-ref outputs "out")
                                                "/bin")))
                        (mkdir-p bin)
                        (copy-recursively "../bin" bin)
                        #t))))))
      (inputs
       `(("perl" ,perl)
         ("zlib" ,zlib)))
      (supported-systems '("x86_64-linux"))
      (home-page "https://github.com/wanpinglee/MOSAIK")
      (synopsis "Map nucleotide sequence reads to reference genomes")
      (description
       "MOSAIK is a program for mapping second and third-generation sequencing
reads to a reference genome.  MOSAIK can align reads generated by all the
major sequencing technologies, including Illumina, Applied Biosystems SOLiD,
Roche 454, Ion Torrent and Pacific BioSciences SMRT.")
      ;; MOSAIK is released under the GPLv2+ with the exception of third-party
      ;; code released into the public domain:
      ;; 1. fastlz by Ariya Hidayat - http://www.fastlz.org/
      ;; 2. MD5 implementation - RSA Data Security, RFC 1321
      (license (list license:gpl2+ license:public-domain)))))

(define-public ngs-sdk
  (package
    (name "ngs-sdk")
    (version "1.2.5")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "https://github.com/ncbi/ngs/archive/"
                       version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "04y1fsmdnb5y86m3gg6f5g9wcscr6r25n7m8mdlcxy0i2q6w6cia"))))
    (build-system gnu-build-system)
    (arguments
     `(#:parallel-build? #f ; not supported
       #:tests? #f ; no "check" target
       #:phases
       (alist-replace
        'configure
        (lambda* (#:key outputs #:allow-other-keys)
          (let ((out (assoc-ref outputs "out")))
            ;; The 'configure' script doesn't recognize things like
            ;; '--enable-fast-install'.
            (zero? (system* "./configure"
                            (string-append "--build-prefix=" (getcwd) "/build")
                            (string-append "--prefix=" out)))))
        (alist-cons-after
         'unpack 'enter-dir
         (lambda _ (chdir "ngs-sdk") #t)
         %standard-phases))))
    (native-inputs `(("perl" ,perl)))
    ;; According to the test
    ;;   unless ($MARCH =~ /x86_64/i || $MARCH =~ /i?86/i)
    ;; in ngs-sdk/setup/konfigure.perl
    (supported-systems '("i686-linux" "x86_64-linux"))
    (home-page "https://github.com/ncbi/ngs")
    (synopsis "API for accessing Next Generation Sequencing data")
    (description
     "NGS is a domain-specific API for accessing reads, alignments and pileups
produced from Next Generation Sequencing.  The API itself is independent from
any particular back-end implementation, and supports use of multiple back-ends
simultaneously.")
    (license license:public-domain)))

(define-public java-ngs
  (package (inherit ngs-sdk)
    (name "java-ngs")
    (arguments
     `(,@(substitute-keyword-arguments
             `(#:modules ((guix build gnu-build-system)
                          (guix build utils)
                          (srfi srfi-1)
                          (srfi srfi-26))
                         ,@(package-arguments ngs-sdk))
           ((#:phases phases)
            `(modify-phases ,phases
               (replace 'enter-dir (lambda _ (chdir "ngs-java") #t)))))))
    (inputs
     `(("jdk" ,icedtea "jdk")
       ("ngs-sdk" ,ngs-sdk)))
    (synopsis "Java bindings for NGS SDK")))

(define-public ncbi-vdb
  (package
    (name "ncbi-vdb")
    (version "2.7.0")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "https://github.com/ncbi/ncbi-vdb/archive/"
                       version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0x1cg1x8vy0yjlkp0snc1533zcjhxqzqsaiwqk598n7vvw37n8lf"))))
    (build-system gnu-build-system)
    (arguments
     `(#:parallel-build? #f ; not supported
       #:tests? #f ; no "check" target
       #:phases
       (alist-replace
        'configure
        (lambda* (#:key inputs outputs #:allow-other-keys)
          (let ((out (assoc-ref outputs "out")))
            ;; Override include path for libmagic
            (substitute* "setup/package.prl"
              (("name => 'magic', Include => '/usr/include'")
               (string-append "name=> 'magic', Include => '"
                              (assoc-ref inputs "libmagic")
                              "/include" "'")))

            ;; Install kdf5 library (needed by sra-tools)
            (substitute* "build/Makefile.install"
              (("LIBRARIES_TO_INSTALL =")
               "LIBRARIES_TO_INSTALL = kdf5.$(VERSION_LIBX) kdf5.$(VERSION_SHLX)"))

            (substitute* "build/Makefile.env"
              (("CFLAGS	=" prefix)
               (string-append prefix "-msse2 ")))

            ;; The 'configure' script doesn't recognize things like
            ;; '--enable-fast-install'.
            (zero? (system*
                    "./configure"
                    (string-append "--build-prefix=" (getcwd) "/build")
                    (string-append "--prefix=" (assoc-ref outputs "out"))
                    (string-append "--debug")
                    (string-append "--with-xml2-prefix="
                                   (assoc-ref inputs "libxml2"))
                    (string-append "--with-ngs-sdk-prefix="
                                   (assoc-ref inputs "ngs-sdk"))
                    (string-append "--with-ngs-java-prefix="
                                   (assoc-ref inputs "java-ngs"))
                    (string-append "--with-hdf5-prefix="
                                   (assoc-ref inputs "hdf5"))))))
        (alist-cons-after
         'install 'install-interfaces
         (lambda* (#:key outputs #:allow-other-keys)
           ;; Install interface libraries.  On i686 the interface libraries
           ;; are installed to "linux/gcc/i386", so we need to use the Linux
           ;; architecture name ("i386") instead of the target system prefix
           ;; ("i686").
           (mkdir (string-append (assoc-ref outputs "out") "/ilib"))
           (copy-recursively (string-append "build/ncbi-vdb/linux/gcc/"
                                            ,(system->linux-architecture
                                              (or (%current-target-system)
                                                  (%current-system)))
                                            "/rel/ilib")
                             (string-append (assoc-ref outputs "out")
                                            "/ilib"))
           ;; Install interface headers
           (copy-recursively "interfaces"
                             (string-append (assoc-ref outputs "out")
                                            "/include")))
         %standard-phases))))
    (inputs
     `(("libxml2" ,libxml2)
       ("ngs-sdk" ,ngs-sdk)
       ("java-ngs" ,java-ngs)
       ("libmagic" ,file)
       ("hdf5" ,hdf5)))
    (native-inputs `(("perl" ,perl)))
    ;; NCBI-VDB requires SSE capability.
    (supported-systems '("i686-linux" "x86_64-linux"))
    (home-page "https://github.com/ncbi/ncbi-vdb")
    (synopsis "Database engine for genetic information")
    (description
     "The NCBI-VDB library implements a highly compressed columnar data
warehousing engine that is most often used to store genetic information.
Databases are stored in a portable image within the file system, and can be
accessed/downloaded on demand across HTTP.")
    (license license:public-domain)))

(define-public plink
  (package
    (name "plink")
    (version "1.07")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "http://pngu.mgh.harvard.edu/~purcell/plink/dist/plink-"
             version "-src.zip"))
       (sha256
        (base32 "0as8gxm4pjyc8dxmm1sl873rrd7wn5qs0l29nqfnl31x8i467xaa"))
       (patches (search-patches "plink-1.07-unclobber-i.patch"
                                "plink-endian-detection.patch"))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f ;no "check" target
       #:make-flags (list (string-append "LIB_LAPACK="
                                         (assoc-ref %build-inputs "lapack")
                                         "/lib/liblapack.so")
                          "WITH_LAPACK=1"
                          "FORCE_DYNAMIC=1"
                          ;; disable phoning home
                          "WITH_WEBCHECK=")
       #:phases
       (modify-phases %standard-phases
         ;; no "configure" script
         (delete 'configure)
         (replace 'install
                  (lambda* (#:key outputs #:allow-other-keys)
                    (let ((bin (string-append (assoc-ref outputs "out")
                                              "/bin/")))
                      (install-file "plink" bin)
                      #t))))))
    (inputs
     `(("zlib" ,zlib)
       ("lapack" ,lapack)))
    (native-inputs
     `(("unzip" ,unzip)))
    (home-page "http://pngu.mgh.harvard.edu/~purcell/plink/")
    (synopsis "Whole genome association analysis toolset")
    (description
     "PLINK is a whole genome association analysis toolset, designed to
perform a range of basic, large-scale analyses in a computationally efficient
manner.  The focus of PLINK is purely on analysis of genotype/phenotype data,
so there is no support for steps prior to this (e.g. study design and
planning, generating genotype or CNV calls from raw data).  Through
integration with gPLINK and Haploview, there is some support for the
subsequent visualization, annotation and storage of results.")
    ;; Code is released under GPLv2, except for fisher.h, which is under
    ;; LGPLv2.1+
    (license (list license:gpl2 license:lgpl2.1+))))

(define-public smithlab-cpp
  (let ((revision "1")
        (commit "728a097bec88c6f4b8528b685932049e660eff2e"))
    (package
      (name "smithlab-cpp")
      (version (string-append "0." revision "." (string-take commit 7)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/smithlabcode/smithlab_cpp.git")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "0d476lmj312xk77kr9fzrv7z1bv96yfyx0w7y62ycmnfbx32ll74"))))
      (build-system gnu-build-system)
      (arguments
       `(#:modules ((guix build gnu-build-system)
                    (guix build utils)
                    (srfi srfi-26))
         #:tests? #f ;no "check" target
         #:phases
         (modify-phases %standard-phases
           (add-after 'unpack 'use-samtools-headers
            (lambda _
              (substitute* '("SAM.cpp"
                             "SAM.hpp")
                (("sam.h") "samtools/sam.h"))
              #t))
           (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let* ((out     (assoc-ref outputs "out"))
                     (lib     (string-append out "/lib"))
                     (include (string-append out "/include/smithlab-cpp")))
                (mkdir-p lib)
                (mkdir-p include)
                (for-each (cut install-file <> lib)
                          (find-files "." "\\.o$"))
                (for-each (cut install-file <> include)
                          (find-files "." "\\.hpp$")))
              #t))
           (delete 'configure))))
      (inputs
       `(("samtools" ,samtools-0.1)
         ("zlib" ,zlib)))
      (home-page "https://github.com/smithlabcode/smithlab_cpp")
      (synopsis "C++ helper library for functions used in Smith lab projects")
      (description
       "Smithlab CPP is a C++ library that includes functions used in many of
the Smith lab bioinformatics projects, such as a wrapper around Samtools data
structures, classes for genomic regions, mapped sequencing reads, etc.")
      (license license:gpl3+))))

(define-public preseq
  (package
    (name "preseq")
    (version "2.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/smithlabcode/"
                                  "preseq/archive/v" version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32 "08r684l50pnxjpvmhzjgqq56yv9rfw90k8vx0nsrnrzk8mf9hsdq"))
              (modules '((guix build utils)))
              (snippet
               ;; Remove bundled samtools.
               '(delete-file-recursively "samtools"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ;no "check" target
       #:phases
       (modify-phases %standard-phases
         (delete 'configure))
       #:make-flags
       (list (string-append "PREFIX="
                            (assoc-ref %outputs "out"))
             (string-append "LIBBAM="
                            (assoc-ref %build-inputs "samtools")
                            "/lib/libbam.a")
             (string-append "SMITHLAB_CPP="
                            (assoc-ref %build-inputs "smithlab-cpp")
                            "/lib")
             "PROGS=preseq"
             "INCLUDEDIRS=$(SMITHLAB_CPP)/../include/smithlab-cpp $(SAMTOOLS_DIR)")))
    (inputs
     `(("gsl" ,gsl)
       ("samtools" ,samtools-0.1)
       ("smithlab-cpp" ,smithlab-cpp)
       ("zlib" ,zlib)))
    (home-page "http://smithlabresearch.org/software/preseq/")
    (synopsis "Program for analyzing library complexity")
    (description
     "The preseq package is aimed at predicting and estimating the complexity
of a genomic sequencing library, equivalent to predicting and estimating the
number of redundant reads from a given sequencing depth and how many will be
expected from additional sequencing using an initial sequencing experiment.
The estimates can then be used to examine the utility of further sequencing,
optimize the sequencing depth, or to screen multiple libraries to avoid low
complexity samples.")
    (license license:gpl3+)))

(define-public python-screed
  (package
    (name "python-screed")
    (version "0.9")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "screed" version))
       (sha256
        (base32
         "18czszp9fkx3j6jr7y5kp6dfialscgddk05mw1zkhh2zhn0jd8i0"))))
    (build-system python-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'check
           (lambda _
             (setenv "PYTHONPATH"
                     (string-append (getenv "PYTHONPATH") ":."))
             (zero? (system* "nosetests" "--attr" "!known_failing")))))))
    (native-inputs
     `(("python-nose" ,python-nose)))
    (inputs
     `(("python-bz2file" ,python-bz2file)))
    (home-page "http://github.com/dib-lab/screed/")
    (synopsis "Short read sequence database utilities")
    (description "Screed parses FASTA and FASTQ files and generates databases.
Values such as sequence name, sequence description, sequence quality and the
sequence itself can be retrieved from these databases.")
    (license license:bsd-3)))

(define-public python2-screed
  (package-with-python2 python-screed))

(define-public sra-tools
  (package
    (name "sra-tools")
    (version "2.7.0")
    (source
     (origin
       (method url-fetch)
       (uri
        (string-append "https://github.com/ncbi/sra-tools/archive/"
                       version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "13paw7bq6y47d2pl0ac5gpgcqp1xsy1g7v1fwysm3hr8lb2dck17"))))
    (build-system gnu-build-system)
    (arguments
     `(#:parallel-build? #f ; not supported
       #:tests? #f ; no "check" target
       #:make-flags
       (list (string-append "VDB_LIBDIR="
                            (assoc-ref %build-inputs "ncbi-vdb")
                            ,(if (string-prefix? "x86_64"
                                                 (or (%current-target-system)
                                                     (%current-system)))
                                 "/lib64"
                                 "/lib32")))
       #:phases
       (alist-replace
        'configure
        (lambda* (#:key inputs outputs #:allow-other-keys)
          ;; The build system expects a directory containing the sources and
          ;; raw build output of ncbi-vdb, including files that are not
          ;; installed.  Since we are building against an installed version of
          ;; ncbi-vdb, the following modifications are needed.
          (substitute* "setup/konfigure.perl"
            ;; Make the configure script look for the "ilib" directory of
            ;; "ncbi-vdb" without first checking for the existence of a
            ;; matching library in its "lib" directory.
            (("^            my \\$f = File::Spec->catdir\\(\\$libdir, \\$lib\\);")
             "my $f = File::Spec->catdir($ilibdir, $ilib);")
            ;; Look for interface libraries in ncbi-vdb's "ilib" directory.
            (("my \\$ilibdir = File::Spec->catdir\\(\\$builddir, 'ilib'\\);")
             "my $ilibdir = File::Spec->catdir($dir, 'ilib');"))

          ;; Dynamic linking
          (substitute* "tools/copycat/Makefile"
            (("smagic-static") "lmagic"))

          ;; The 'configure' script doesn't recognize things like
          ;; '--enable-fast-install'.
          (zero? (system*
                  "./configure"
                  (string-append "--build-prefix=" (getcwd) "/build")
                  (string-append "--prefix=" (assoc-ref outputs "out"))
                  (string-append "--debug")
                  (string-append "--with-fuse-prefix="
                                 (assoc-ref inputs "fuse"))
                  (string-append "--with-magic-prefix="
                                 (assoc-ref inputs "libmagic"))
                  ;; TODO: building with libxml2 fails with linker errors
                  ;; (string-append "--with-xml2-prefix="
                  ;;                (assoc-ref inputs "libxml2"))
                  (string-append "--with-ncbi-vdb-sources="
                                 (assoc-ref inputs "ncbi-vdb"))
                  (string-append "--with-ncbi-vdb-build="
                                 (assoc-ref inputs "ncbi-vdb"))
                  (string-append "--with-ngs-sdk-prefix="
                                 (assoc-ref inputs "ngs-sdk"))
                  (string-append "--with-hdf5-prefix="
                                 (assoc-ref inputs "hdf5")))))
        %standard-phases)))
    (native-inputs `(("perl" ,perl)))
    (inputs
     `(("ngs-sdk" ,ngs-sdk)
       ("ncbi-vdb" ,ncbi-vdb)
       ("libmagic" ,file)
       ("fuse" ,fuse)
       ("hdf5" ,hdf5)
       ("zlib" ,zlib)))
    (home-page "http://www.ncbi.nlm.nih.gov/Traces/sra/sra.cgi?view=software")
    (synopsis "Tools and libraries for reading and writing sequencing data")
    (description
     "The SRA Toolkit from NCBI is a collection of tools and libraries for
reading of sequencing files from the Sequence Read Archive (SRA) database and
writing files into the .sra format.")
    (license license:public-domain)))

(define-public seqan
  (package
    (name "seqan")
    (version "1.4.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://packages.seqan.de/seqan-library/"
                                  "seqan-library-" version ".tar.bz2"))
              (sha256
               (base32
                "05s3wrrwn50f81aklfm65i4a749zag1vr8z03k21xm0pdxy47yvp"))))
    ;; The documentation is 7.8MB and the includes are 3.6MB heavy, so it
    ;; makes sense to split the outputs.
    (outputs '("out" "doc"))
    (build-system trivial-build-system)
    (arguments
     `(#:modules ((guix build utils))
       #:builder
       (begin
         (use-modules (guix build utils))
         (let ((tar  (assoc-ref %build-inputs "tar"))
               (bzip (assoc-ref %build-inputs "bzip2"))
               (out  (assoc-ref %outputs "out"))
               (doc  (assoc-ref %outputs "doc")))
           (setenv "PATH" (string-append tar "/bin:" bzip "/bin"))
           (system* "tar" "xvf" (assoc-ref %build-inputs "source"))
           (chdir (string-append "seqan-library-" ,version))
           (copy-recursively "include" (string-append out "/include"))
           (copy-recursively "share"  (string-append doc "/share"))))))
    (native-inputs
     `(("source" ,source)
       ("tar" ,tar)
       ("bzip2" ,bzip2)))
    (home-page "http://www.seqan.de")
    (synopsis "Library for nucleotide sequence analysis")
    (description
     "SeqAn is a C++ library of efficient algorithms and data structures for
the analysis of sequences with the focus on biological data.  It contains
algorithms and data structures for string representation and their
manipulation, online and indexed string search, efficient I/O of
bioinformatics file formats, sequence alignment, and more.")
    (license license:bsd-3)))

(define-public seqmagick
  (package
    (name "seqmagick")
    (version "0.6.1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://pypi.python.org/packages/source/s/seqmagick/seqmagick-"
             version ".tar.gz"))
       (sha256
        (base32
         "0cgn477n74gsl4qdaakrrhi953kcsd4q3ivk2lr18x74s3g4ma1d"))))
    (build-system python-build-system)
    (arguments
     ;; python2 only, see https://github.com/fhcrc/seqmagick/issues/56
     `(#:python ,python-2
       #:phases
       (modify-phases %standard-phases
         ;; Current test in setup.py does not work as of 0.6.1,
         ;; so use nose to run tests instead for now. See
         ;; https://github.com/fhcrc/seqmagick/issues/55
         (replace 'check (lambda _ (zero? (system* "nosetests")))))))
    (inputs
     ;; biopython-1.66 is required due to
     ;; https://github.com/fhcrc/seqmagick/issues/59
     ;; When that issue is resolved the 'python2-biopython-1.66' package
     ;; should be removed.
     `(("python-biopython" ,python2-biopython-1.66)))
    (native-inputs
     `(("python-nose" ,python2-nose)))
    (home-page "http://github.com/fhcrc/seqmagick")
    (synopsis "Tools for converting and modifying sequence files")
    (description
     "Bioinformaticians often have to convert sequence files between formats
and do little manipulations on them, and it's not worth writing scripts for
that.  Seqmagick is a utility to expose the file format conversion in
BioPython in a convenient way.  Instead of having a big mess of scripts, there
is one that takes arguments.")
    (license license:gpl3)))

(define-public seqtk
  (package
    (name "seqtk")
    (version "1.2")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/lh3/seqtk/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "0ywdyzpmfiz2wp6ampbzqg4y8bj450nfgqarpamg045b8mk32lxx"))
                            (modules '((guix build utils)))
              (snippet
               '(begin
                  ;; Remove extraneous header files, as is done in the seqtk
                  ;; master branch.
                  (for-each (lambda (file) (delete-file file))
                            (list "ksort.h" "kstring.h" "kvec.h"))
                  #t))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'check
           ;; There are no tests, so we just run a sanity check.
           (lambda _ (zero? (system* "./seqtk" "seq"))))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((bin (string-append (assoc-ref outputs "out") "/bin/")))
               (install-file "seqtk" bin)))))))
    (inputs
     `(("zlib" ,zlib)))
    (home-page "https://github.com/lh3/seqtk")
    (synopsis "Toolkit for processing biological sequences in FASTA/Q format")
    (description
     "Seqtk is a fast and lightweight tool for processing sequences in the
FASTA or FASTQ format.  It parses both FASTA and FASTQ files which can be
optionally compressed by gzip.")
      (license license:expat)))

(define-public snap-aligner
  (package
    (name "snap-aligner")
    (version "1.0beta.18")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/amplab/snap/archive/v"
                    version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1vnsjwv007k1fl1q7d681kbwn6bc66cgw6h16hym6gvyy71qv2ly"))))
    (build-system gnu-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'check (lambda _ (zero? (system* "./unit_tests"))))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (bin (string-append out "/bin")))
               (install-file "snap-aligner" bin)
               (install-file "SNAPCommand" bin)
               #t))))))
    (native-inputs
     `(("zlib" ,zlib)))
    (home-page "http://snap.cs.berkeley.edu/")
    (synopsis "Short read DNA sequence aligner")
    (description
     "SNAP is a fast and accurate aligner for short DNA reads.  It is
optimized for modern read lengths of 100 bases or higher, and takes advantage
of these reads to align data quickly through a hash-based indexing scheme.")
    ;; 32-bit systems are not supported by the unpatched code.
    ;; Following the bug reports https://github.com/amplab/snap/issues/68 and
    ;; https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=812378 we see that
    ;; systems without a lot of memory cannot make good use of this program.
    (supported-systems '("x86_64-linux"))
    (license license:asl2.0)))

(define-public sortmerna
  (package
    (name "sortmerna")
    (version "2.1b")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/biocore/sortmerna/archive/"
             version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1ghaghvd82af9j5adavxh77g7hm247d1r69m3fbi6f1jdivj5ldk"))))
    (build-system gnu-build-system)
    (outputs '("out"      ;for binaries
               "db"))     ;for sequence databases
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out   (assoc-ref outputs "out"))
                    (bin   (string-append out "/bin"))
                    (db    (assoc-ref outputs "db"))
                    (share
                     (string-append db "/share/sortmerna/rRNA_databases")))
               (install-file "sortmerna" bin)
               (install-file "indexdb_rna" bin)
               (for-each (lambda (file)
                           (install-file file share))
                         (find-files "rRNA_databases" ".*fasta"))
               #t))))))
    (inputs
     `(("zlib" ,zlib)))
    (home-page "http://bioinfo.lifl.fr/RNA/sortmerna")
    (synopsis "Biological sequence analysis tool for NGS reads")
    (description
     "SortMeRNA is a biological sequence analysis tool for filtering, mapping
and operational taxonomic unit (OTU) picking of next generation
sequencing (NGS) reads.  The core algorithm is based on approximate seeds and
allows for fast and sensitive analyses of nucleotide sequences.  The main
application of SortMeRNA is filtering rRNA from metatranscriptomic data.")
    (license license:lgpl3)))

(define-public star
  (package
    (name "star")
    (version "2.5.2b")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/alexdobin/STAR/archive/"
                                  version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1na6np880r1zaamiy00hy8bid5anpy0kgf63587v2yl080krk2zq"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  (substitute* "source/Makefile"
                    (("/bin/rm") "rm"))
                  ;; Remove pre-built binaries and bundled htslib sources.
                  (delete-file-recursively "bin/MacOSX_x86_64")
                  (delete-file-recursively "bin/Linux_x86_64")
                  (delete-file-recursively "bin/Linux_x86_64_static")
                  (delete-file-recursively "source/htslib")
                  #t))))
    (build-system gnu-build-system)
    (arguments
     '(#:tests? #f ;no check target
       #:make-flags '("STAR")
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'enter-source-dir
           (lambda _ (chdir "source") #t))
         (add-after 'enter-source-dir 'do-not-use-bundled-htslib
           (lambda _
             (substitute* "Makefile"
               (("(Depend.list: \\$\\(SOURCES\\) parametersDefault\\.xxd) htslib"
                 _ prefix) prefix))
             (substitute* '("BAMfunctions.cpp"
                            "signalFromBAM.h"
                            "bam_cat.h"
                            "bam_cat.c"
                            "STAR.cpp"
                            "bamRemoveDuplicates.cpp")
               (("#include \"htslib/([^\"]+\\.h)\"" _ header)
                (string-append "#include <" header ">")))
             (substitute* "IncludeDefine.h"
               (("\"htslib/(htslib/[^\"]+.h)\"" _ header)
                (string-append "<" header ">")))
             #t))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((bin (string-append (assoc-ref outputs "out") "/bin/")))
               (install-file "STAR" bin))
             #t))
         (delete 'configure))))
    (native-inputs
     `(("vim" ,vim))) ; for xxd
    (inputs
     `(("htslib" ,htslib)
       ("zlib" ,zlib)))
    (home-page "https://github.com/alexdobin/STAR")
    (synopsis "Universal RNA-seq aligner")
    (description
     "The Spliced Transcripts Alignment to a Reference (STAR) software is
based on a previously undescribed RNA-seq alignment algorithm that uses
sequential maximum mappable seed search in uncompressed suffix arrays followed
by seed clustering and stitching procedure.  In addition to unbiased de novo
detection of canonical junctions, STAR can discover non-canonical splices and
chimeric (fusion) transcripts, and is also capable of mapping full-length RNA
sequences.")
    ;; Only 64-bit systems are supported according to the README.
    (supported-systems '("x86_64-linux" "mips64el-linux"))
    ;; STAR is licensed under GPLv3 or later; htslib is MIT-licensed.
    (license license:gpl3+)))

(define-public subread
  (package
    (name "subread")
    (version "1.5.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://sourceforge/subread/subread-"
                                  version "/subread-" version "-source.tar.gz"))
              (sha256
               (base32
                "0gn5zhbvllks0mmdg3qlmsbg91p2mpdc2wixwfqpi85yzfrh8hcy"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ;no "check" target
      ;; The CC and CCFLAGS variables are set to contain a lot of x86_64
      ;; optimizations by default, so we override these flags such that x86_64
      ;; flags are only added when the build target is an x86_64 system.
       #:make-flags
       (list (let ((system ,(or (%current-target-system)
                                (%current-system)))
                   (flags '("-ggdb" "-fomit-frame-pointer"
                            "-ffast-math" "-funroll-loops"
                            "-fmessage-length=0"
                            "-O9" "-Wall" "-DMAKE_FOR_EXON"
                            "-DMAKE_STANDALONE"
                            "-DSUBREAD_VERSION=\\\"${SUBREAD_VERSION}\\\""))
                   (flags64 '("-mmmx" "-msse" "-msse2" "-msse3")))
               (if (string-prefix? "x86_64" system)
                   (string-append "CCFLAGS=" (string-join (append flags flags64)))
                   (string-append "CCFLAGS=" (string-join flags))))
             "-f" "Makefile.Linux"
             "CC=gcc ${CCFLAGS}")
       #:phases
       (alist-cons-after
        'unpack 'enter-dir
        (lambda _ (chdir "src") #t)
        (alist-replace
         'install
         (lambda* (#:key outputs #:allow-other-keys)
           (let ((bin (string-append (assoc-ref outputs "out") "/bin/")))
             (mkdir-p bin)
             (copy-recursively "../bin" bin)))
         ;; no "configure" script
         (alist-delete 'configure %standard-phases)))))
    (inputs `(("zlib" ,zlib)))
    (home-page "http://bioinf.wehi.edu.au/subread-package/")
    (synopsis "Tool kit for processing next-gen sequencing data")
    (description
     "The subread package contains the following tools: subread aligner, a
general-purpose read aligner; subjunc aligner: detecting exon-exon junctions
and mapping RNA-seq reads; featureCounts: counting mapped reads for genomic
features; exactSNP: a SNP caller that discovers SNPs by testing signals
against local background noises.")
    (license license:gpl3+)))

(define-public stringtie
  (package
    (name "stringtie")
    (version "1.2.1")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://ccb.jhu.edu/software/stringtie/dl/"
                                  "stringtie-" version ".tar.gz"))
              (sha256
               (base32
                "1cqllsc1maq4kh92isi8yadgzbmnf042hlnalpk3y59aph1z3bfz"))
              (modules '((guix build utils)))
              (snippet
               '(begin
                  (delete-file-recursively "samtools-0.1.18")
                  #t))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ;no test suite
       #:phases
       (modify-phases %standard-phases
         ;; no configure script
         (delete 'configure)
         (add-before 'build 'use-system-samtools
           (lambda _
             (substitute* "Makefile"
               (("stringtie: \\$\\{BAM\\}/libbam\\.a")
                "stringtie: "))
             (substitute* '("gclib/GBam.h"
                            "gclib/GBam.cpp")
               (("#include \"(bam|sam|kstring).h\"" _ header)
                (string-append "#include <samtools/" header ".h>")))
             #t))
         (replace 'install
          (lambda* (#:key outputs #:allow-other-keys)
            (let ((bin (string-append (assoc-ref outputs "out") "/bin/")))
              (install-file "stringtie" bin)
              #t))))))
    (inputs
     `(("samtools" ,samtools-0.1)
       ("zlib" ,zlib)))
    (home-page "http://ccb.jhu.edu/software/stringtie/")
    (synopsis "Transcript assembly and quantification for RNA-Seq data")
    (description
     "StringTie is a fast and efficient assembler of RNA-Seq sequence
alignments into potential transcripts.  It uses a novel network flow algorithm
as well as an optional de novo assembly step to assemble and quantitate
full-length transcripts representing multiple splice variants for each gene
locus.  Its input can include not only the alignments of raw reads used by
other transcript assemblers, but also alignments of longer sequences that have
been assembled from those reads.  To identify differentially expressed genes
between experiments, StringTie's output can be processed either by the
Cuffdiff or Ballgown programs.")
    (license license:artistic2.0)))

(define-public vcftools
  (package
    (name "vcftools")
    (version "0.1.14")
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/vcftools/vcftools/releases/download/v"
                    version "/vcftools-" version ".tar.gz"))
              (sha256
               (base32
                "10l5c07z9p4i9pr4gl54b2c9h6ndhqlbq1rashg2zcgwkbfrkmvn"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; no "check" target
       #:make-flags (list
                     "CFLAGS=-O2" ; override "-m64" flag
                     (string-append "PREFIX=" (assoc-ref %outputs "out"))
                     (string-append "MANDIR=" (assoc-ref %outputs "out")
                                    "/share/man/man1"))))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (inputs
     `(("perl" ,perl)
       ("zlib" ,zlib)))
    (home-page "https://vcftools.github.io/")
    (synopsis "Tools for working with VCF files")
    (description
     "VCFtools is a program package designed for working with VCF files, such
as those generated by the 1000 Genomes Project.  The aim of VCFtools is to
provide easily accessible methods for working with complex genetic variation
data in the form of VCF files.")
    ;; The license is declared as LGPLv3 in the README and
    ;; at https://vcftools.github.io/license.html
    (license license:lgpl3)))

(define-public infernal
  (package
    (name "infernal")
    (version "1.1.2")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://eddylab.org/software/infernal/"
                                  "infernal-" version ".tar.gz"))
              (sha256
               (base32
                "0sr2hiz3qxfwqpz3whxr6n82p3x27336v3f34iqznp10hks2935c"))))
    (build-system gnu-build-system)
    (native-inputs
     `(("perl" ,perl))) ; for tests
    (home-page "http://eddylab.org/infernal/")
    (synopsis "Inference of RNA alignments")
    (description "Infernal (\"INFERence of RNA ALignment\") is a tool for
searching DNA sequence databases for RNA structure and sequence similarities.
It is an implementation of a special case of profile stochastic context-free
grammars called @dfn{covariance models} (CMs).  A CM is like a sequence
profile, but it scores a combination of sequence consensus and RNA secondary
structure consensus, so in many cases, it is more capable of identifying RNA
homologs that conserve their secondary structure more than their primary
sequence.")
    ;; Infernal 1.1.2 requires VMX or SSE capability for parallel instructions.
    (supported-systems '("i686-linux" "x86_64-linux"))
    (license license:bsd-3)))

(define-public r-vegan
  (package
    (name "r-vegan")
    (version "2.4-1")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "vegan" version))
       (sha256
        (base32
         "0i0c7rc0nzgbysd1nlxzxd2rvy75qcnw3yc7nggzqjzzj5d7yzsd"))))
    (build-system r-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'revert-test-deletion
           ;; The distributed sources do not include tests with the CRAN
           ;; package.  Here we revert the commit
           ;; `591d0e8ba1deaaf82445474ec6619c0b43db4e63' which deletes these
           ;; tests.  There are plans to not delete tests in future as
           ;; documented at https://github.com/vegandevs/vegan/issues/181.
           (lambda* (#:key inputs #:allow-other-keys)
             (zero?
              (system* "patch" "-R" "-p1" "-i"
                       (assoc-ref inputs "r-vegan-delete-tests-patch"))))))))
    (native-inputs
     `(("gfortran" ,gfortran)
       ("r-knitr" ,r-knitr)
       ("r-vegan-delete-tests-patch"
        ,(origin
           (method url-fetch)
           (uri (string-append
                 "https://github.com/vegandevs/vegan/commit/"
                 "591d0e8ba1deaaf82445474ec6619c0b43db4e63.patch"))
           (sha256
            (base32
             "0b1bi7y4jjdl3ph721vm9apm51dr2z9piwvhy4355sf2b4kyyj5a"))))))
    (propagated-inputs
     `(("r-cluster" ,r-cluster)
       ("r-lattice" ,r-lattice)
       ("r-mgcv" ,r-mgcv)
       ("r-permute" ,r-permute)))
    (home-page "https://cran.r-project.org/web/packages/vegan")
    (synopsis "Functions for community ecology")
    (description
     "The vegan package provides tools for descriptive community ecology.  It
has most basic functions of diversity analysis, community ordination and
dissimilarity analysis.  Most of its multivariate tools can be used for other
data types as well.")
    (license license:gpl2+)))

(define-public r-annotate
  (package
    (name "r-annotate")
    (version "1.52.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "annotate" version))
       (sha256
        (base32
         "1fd2csq7dcs2gwndgwdx2nwkymz8gsmlnqqzv3p0vjjsvvq5n2a8"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotationdbi" ,r-annotationdbi)
       ("r-biobase" ,r-biobase)
       ("r-biocgenerics" ,r-biocgenerics)
       ("r-dbi" ,r-dbi)
       ("r-xml" ,r-xml)
       ("r-xtable" ,r-xtable)))
    (home-page
     "http://bioconductor.org/packages/annotate")
    (synopsis "Annotation for microarrays")
    (description "This package provides R enviroments for the annotation of
microarrays.")
    (license license:artistic2.0)))

(define-public r-geneplotter
  (package
    (name "r-geneplotter")
    (version "1.52.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "geneplotter" version))
       (sha256
        (base32
         "1p6yvxi243irhjxwm97hp73abhwampj0myyf8z00ij166674pc7h"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotate" ,r-annotate)
       ("r-annotationdbi" ,r-annotationdbi)
       ("r-biobase" ,r-biobase)
       ("r-biocgenerics" ,r-biocgenerics)
       ("r-lattice" ,r-lattice)
       ("r-rcolorbrewer" ,r-rcolorbrewer)))
    (home-page "http://bioconductor.org/packages/geneplotter")
    (synopsis "Graphics functions for genomic data")
    (description
     "This package provides functions for plotting genomic data.")
    (license license:artistic2.0)))

(define-public r-genefilter
  (package
    (name "r-genefilter")
    (version "1.56.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "genefilter" version))
       (sha256
        (base32
         "1vzgciqd09csqcw9qync8blsv51ylrd86a65iadgyy6j26g01fwd"))))
    (build-system r-build-system)
    (native-inputs
     `(("gfortran" ,gfortran)))
    (propagated-inputs
     `(("r-annotate" ,r-annotate)
       ("r-annotationdbi" ,r-annotationdbi)
       ("r-biobase" ,r-biobase)
       ("r-s4vectors" ,r-s4vectors)))
    (home-page "http://bioconductor.org/packages/genefilter")
    (synopsis "Filter genes from high-throughput experiments")
    (description
     "This package provides basic functions for filtering genes from
high-throughput sequencing experiments.")
    (license license:artistic2.0)))

(define-public r-deseq2
  (package
    (name "r-deseq2")
    (version "1.14.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "DESeq2" version))
       (sha256
        (base32
         "0kq06jy4xg5ii3a9l62f17kirsfx0gsiwq6mhiy985cqzpdn893g"))))
    (properties `((upstream-name . "DESeq2")))
    (build-system r-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'link-against-armadillo
           (lambda _
             (substitute* "src/Makevars"
               (("PKG_LIBS =" prefix)
                (string-append prefix "-larmadillo"))))))))
    (propagated-inputs
     `(("r-biobase" ,r-biobase)
       ("r-biocgenerics" ,r-biocgenerics)
       ("r-biocparallel" ,r-biocparallel)
       ("r-genefilter" ,r-genefilter)
       ("r-geneplotter" ,r-geneplotter)
       ("r-genomicranges" ,r-genomicranges)
       ("r-ggplot2" ,r-ggplot2)
       ("r-hmisc" ,r-hmisc)
       ("r-iranges" ,r-iranges)
       ("r-locfit" ,r-locfit)
       ("r-rcpp" ,r-rcpp)
       ("r-rcpparmadillo" ,r-rcpparmadillo)
       ("r-s4vectors" ,r-s4vectors)
       ("r-summarizedexperiment" ,r-summarizedexperiment)))
    (home-page "http://bioconductor.org/packages/DESeq2")
    (synopsis "Differential gene expression analysis")
    (description
     "This package provides functions to estimate variance-mean dependence in
count data from high-throughput nucleotide sequencing assays and test for
differential expression based on a model using the negative binomial
distribution.")
    (license license:lgpl3+)))

(define-public r-annotationforge
  (package
    (name "r-annotationforge")
    (version "1.16.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "AnnotationForge" version))
       (sha256
        (base32
         "02msyb9p3hywrryx00zpjkjl126mrv827i1ah1092s0cplm6xxvf"))))
    (properties
     `((upstream-name . "AnnotationForge")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotationdbi" ,r-annotationdbi)
       ("r-biobase" ,r-biobase)
       ("r-biocgenerics" ,r-biocgenerics)
       ("r-dbi" ,r-dbi)
       ("r-rcurl" ,r-rcurl)
       ("r-rsqlite" ,r-rsqlite)
       ("r-s4vectors" ,r-s4vectors)
       ("r-xml" ,r-xml)))
    (home-page "http://bioconductor.org/packages/AnnotationForge")
    (synopsis "Code for building annotation database packages")
    (description
     "This package provides code for generating Annotation packages and their
databases.  Packages produced are intended to be used with AnnotationDbi.")
    (license license:artistic2.0)))

(define-public r-rbgl
  (package
    (name "r-rbgl")
    (version "1.50.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "RBGL" version))
       (sha256
        (base32
         "1q14m8w6ih56v680kf3d9wh1qbgp7af33kz3cxafdf1vvzx9km08"))))
    (properties `((upstream-name . "RBGL")))
    (build-system r-build-system)
    (propagated-inputs `(("r-graph" ,r-graph)))
    (home-page "http://www.bioconductor.org/packages/RBGL")
    (synopsis "Interface to the Boost graph library")
    (description
     "This package provides a fairly extensive and comprehensive interface to
the graph algorithms contained in the Boost library.")
    (license license:artistic2.0)))

(define-public r-gseabase
  (package
    (name "r-gseabase")
    (version "1.36.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "GSEABase" version))
       (sha256
        (base32
         "0l2x7yj7lfb0m2dmsav5ib026dikpgl4crdckrnj776yy08lgxpj"))))
    (properties `((upstream-name . "GSEABase")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotate" ,r-annotate)
       ("r-annotationdbi" ,r-annotationdbi)
       ("r-biobase" ,r-biobase)
       ("r-biocgenerics" ,r-biocgenerics)
       ("r-graph" ,r-graph)
       ("r-xml" ,r-xml)))
    (home-page "http://bioconductor.org/packages/GSEABase")
    (synopsis "Gene set enrichment data structures and methods")
    (description
     "This package provides classes and methods to support @dfn{Gene Set
Enrichment Analysis} (GSEA).")
    (license license:artistic2.0)))

(define-public r-category
  (package
    (name "r-category")
    (version "2.40.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "Category" version))
       (sha256
        (base32
         "16ncwz7b4y48k0p3fvbrbmvf7nfz63li9ysgcl8kp9kl4hg7llng"))))
    (properties `((upstream-name . "Category")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotate" ,r-annotate)
       ("r-annotationdbi" ,r-annotationdbi)
       ("r-biobase" ,r-biobase)
       ("r-biocgenerics" ,r-biocgenerics)
       ("r-genefilter" ,r-genefilter)
       ("r-graph" ,r-graph)
       ("r-gseabase" ,r-gseabase)
       ("r-matrix" ,r-matrix)
       ("r-rbgl" ,r-rbgl)
       ("r-rsqlite" ,r-rsqlite)))
    (home-page "http://bioconductor.org/packages/Category")
    (synopsis "Category analysis")
    (description
     "This package provides a collection of tools for performing category
analysis.")
    (license license:artistic2.0)))

(define-public r-gostats
  (package
    (name "r-gostats")
    (version "2.40.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "GOstats" version))
       (sha256
        (base32
         "0g2czm94zhzx92z7y2r4mjfxhwml7bhab2db6820ks8nkw1zvr9n"))))
    (properties `((upstream-name . "GOstats")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotate" ,r-annotate)
       ("r-annotationdbi" ,r-annotationdbi)
       ("r-annotationforge" ,r-annotationforge)
       ("r-biobase" ,r-biobase)
       ("r-category" ,r-category)
       ("r-go-db" ,r-go-db)
       ("r-graph" ,r-graph)
       ("r-rbgl" ,r-rbgl)))
    (home-page "http://bioconductor.org/packages/GOstats")
    (synopsis "Tools for manipulating GO and microarrays")
    (description
     "This package provides a set of tools for interacting with GO and
microarray data.  A variety of basic manipulation tools for graphs, hypothesis
testing and other simple calculations.")
    (license license:artistic2.0)))

(define-public r-shortread
  (package
    (name "r-shortread")
    (version "1.32.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "ShortRead" version))
       (sha256
        (base32
         "0mjdlg92x5qw4x2djc4dv5lxwl7ai6ix56nnf86zr07jk8vc7yls"))))
    (properties `((upstream-name . "ShortRead")))
    (build-system r-build-system)
    (inputs
     `(("zlib" ,zlib)))
    (propagated-inputs
     `(("r-biobase" ,r-biobase)
       ("r-biocgenerics" ,r-biocgenerics)
       ("r-biocparallel" ,r-biocparallel)
       ("r-biostrings" ,r-biostrings)
       ("r-genomeinfodb" ,r-genomeinfodb)
       ("r-genomicalignments" ,r-genomicalignments)
       ("r-genomicranges" ,r-genomicranges)
       ("r-hwriter" ,r-hwriter)
       ("r-iranges" ,r-iranges)
       ("r-lattice" ,r-lattice)
       ("r-latticeextra" ,r-latticeextra)
       ("r-rsamtools" ,r-rsamtools)
       ("r-s4vectors" ,r-s4vectors)
       ("r-xvector" ,r-xvector)
       ("r-zlibbioc" ,r-zlibbioc)))
    (home-page "http://bioconductor.org/packages/ShortRead")
    (synopsis "FASTQ input and manipulation tools")
    (description
     "This package implements sampling, iteration, and input of FASTQ files.
It includes functions for filtering and trimming reads, and for generating a
quality assessment report.  Data are represented as
@code{DNAStringSet}-derived objects, and easily manipulated for a diversity of
purposes.  The package also contains legacy support for early single-end,
ungapped alignment formats.")
    (license license:artistic2.0)))

(define-public r-systempiper
  (package
    (name "r-systempiper")
    (version "1.8.1")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "systemPipeR" version))
       (sha256
        (base32
         "0hyi841w8fm2yzpm6lwqi3jz5kc8ny8dy5p29dxynzaw5bpjw56d"))))
    (properties `((upstream-name . "systemPipeR")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotate" ,r-annotate)
       ("r-batchjobs" ,r-batchjobs)
       ("r-biocgenerics" ,r-biocgenerics)
       ("r-biostrings" ,r-biostrings)
       ("r-deseq2" ,r-deseq2)
       ("r-edger" ,r-edger)
       ("r-genomicfeatures" ,r-genomicfeatures)
       ("r-genomicranges" ,r-genomicranges)
       ("r-ggplot2" ,r-ggplot2)
       ("r-go-db" ,r-go-db)
       ("r-gostats" ,r-gostats)
       ("r-limma" ,r-limma)
       ("r-pheatmap" ,r-pheatmap)
       ("r-rjson" ,r-rjson)
       ("r-rsamtools" ,r-rsamtools)
       ("r-shortread" ,r-shortread)
       ("r-summarizedexperiment" ,r-summarizedexperiment)
       ("r-variantannotation" ,r-variantannotation)))
    (home-page "https://github.com/tgirke/systemPipeR")
    (synopsis "Next generation sequencing workflow and reporting environment")
    (description
     "This R package provides tools for building and running automated
end-to-end analysis workflows for a wide range of @dfn{next generation
sequence} (NGS) applications such as RNA-Seq, ChIP-Seq, VAR-Seq and Ribo-Seq.
Important features include a uniform workflow interface across different NGS
applications, automated report generation, and support for running both R and
command-line software, such as NGS aligners or peak/variant callers, on local
computers or compute clusters.  Efficient handling of complex sample sets and
experimental designs is facilitated by a consistently implemented sample
annotation infrastructure.")
    (license license:artistic2.0)))

(define-public r-grohmm
  (package
    (name "r-grohmm")
    (version "1.8.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "groHMM" version))
       (sha256
        (base32
         "0d91nyhqbi5hv3mgmr2z0g29wg2md26g0hyv5mgapmz20cd9zi4y"))))
    (properties `((upstream-name . "groHMM")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-genomeinfodb" ,r-genomeinfodb)
       ("r-genomicalignments" ,r-genomicalignments)
       ("r-genomicranges" ,r-genomicranges)
       ("r-iranges" ,r-iranges)
       ("r-rtracklayer" ,r-rtracklayer)
       ("r-s4vectors" ,r-s4vectors)))
    (home-page "https://github.com/Kraus-Lab/groHMM")
    (synopsis "GRO-seq analysis pipeline")
    (description
     "This package provides a pipeline for the analysis of GRO-seq data.")
    (license license:gpl3+)))

(define-public r-txdb-hsapiens-ucsc-hg19-knowngene
  (package
    (name "r-txdb-hsapiens-ucsc-hg19-knowngene")
    (version "3.2.2")
    (source (origin
              (method url-fetch)
              ;; We cannot use bioconductor-uri here because this tarball is
              ;; located under "data/annotation/" instead of "bioc/".
              (uri (string-append "http://bioconductor.org/packages/"
                                  "release/data/annotation/src/contrib"
                                  "/TxDb.Hsapiens.UCSC.hg19.knownGene_"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1sajhcqqwazgz2lqbik7rd935i7kpnh08zxbp2ra10j72yqy4g86"))))
    (properties
     `((upstream-name . "TxDb.Hsapiens.UCSC.hg19.knownGene")))
    (build-system r-build-system)
    ;; As this package provides little more than a very large data file it
    ;; doesn't make sense to build substitutes.
    (arguments `(#:substitutable? #f))
    (propagated-inputs
     `(("r-genomicfeatures" ,r-genomicfeatures)))
    (home-page
     "http://bioconductor.org/packages/TxDb.Hsapiens.UCSC.hg19.knownGene/")
    (synopsis "Annotation package for human genome in TxDb format")
    (description
     "This package provides an annotation database of Homo sapiens genome
data.  It is derived from the UCSC hg19 genome and based on the \"knownGene\"
track.  The database is exposed as a @code{TxDb} object.")
    (license license:artistic2.0)))

(define-public vsearch
  (package
    (name "vsearch")
    (version "2.3.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/torognes/vsearch/archive/v"
             version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "1xyraxmhyx62mxx8z7c8waygvcijwkh48ms1ar60w2cv2y2sn4al"))
       (modules '((guix build utils)))
       (snippet
        '(begin
           ;; Remove bundled cityhash and '-mtune=native'.
           (substitute* "src/Makefile.am"
             (("^AM_CXXFLAGS=-I\\$\\{srcdir\\}/cityhash \
-O3 -mtune=native -Wall -Wsign-compare")
              (string-append "AM_CXXFLAGS=-lcityhash"
                             " -O3 -Wall -Wsign-compare"))
             (("^__top_builddir__bin_vsearch_SOURCES = city.h \\\\")
              "__top_builddir__bin_vsearch_SOURCES = \\")
             (("^city.h \\\\") "\\")
             (("^citycrc.h \\\\") "\\")
             (("^libcityhash_a.*") "")
             (("noinst_LIBRARIES = libcpu_sse2.a libcpu_ssse3.a \
libcityhash.a")
              "noinst_LIBRARIES = libcpu_sse2.a libcpu_ssse3.a")
             (("__top_builddir__bin_vsearch_LDADD = libcpu_ssse3.a \
libcpu_sse2.a libcityhash.a")
              "__top_builddir__bin_vsearch_LDADD = libcpu_ssse3.a \
libcpu_sse2.a -lcityhash"))
           (substitute* "src/vsearch.h"
             (("^\\#include \"city.h\"") "#include <city.h>")
             (("^\\#include \"citycrc.h\"") "#include <citycrc.h>"))
           (delete-file "src/city.h")
           (delete-file "src/citycrc.h")
           (delete-file "src/city.cc")
           #t))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'configure 'autogen
                     (lambda _ (zero? (system* "autoreconf" "-vif")))))))
    (inputs
     `(("zlib" ,zlib)
       ("bzip2" ,bzip2)
       ("cityhash" ,cityhash)))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)))
    (synopsis "Sequence search tools for metagenomics")
    (description
     "VSEARCH supports DNA sequence searching, clustering, chimera detection,
dereplication, pairwise alignment, shuffling, subsampling, sorting and
masking.  The tool takes advantage of parallelism in the form of SIMD
vectorization as well as multiple threads to perform accurate alignments at
high speed.  VSEARCH uses an optimal global aligner (full dynamic programming
Needleman-Wunsch).")
    (home-page "https://github.com/torognes/vsearch")
    ;; vsearch uses non-portable SSE intrinsics so building fails on other
    ;; platforms.
    (supported-systems '("x86_64-linux"))
    ;; Dual licensed; also includes public domain source.
    (license (list license:gpl3 license:bsd-2))))

(define-public pardre
  (package
    (name "pardre")
    ;; The source of 1.1.5 changed in place, so we append "-1" to the version.
    (version "1.1.5-1")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "mirror://sourceforge/pardre/ParDRe-rel"
                           "1.1.5" ".tar.gz"))
       (sha256
        (base32
         "17j73nc0viq4f6qj50nrndsrif5d6b71q8fl87m54psiv0ilns2b"))))
    (build-system gnu-build-system)
    (arguments
     `(#:tests? #f ; no tests included
       #:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((bin (string-append (assoc-ref outputs "out") "/bin")))
               (install-file "ParDRe" bin)
               #t))))))
    (inputs
     `(("openmpi" ,openmpi)
       ("zlib" ,zlib)))
    (synopsis "Parallel tool to remove duplicate DNA reads")
    (description
     "ParDRe is a parallel tool to remove duplicate genetic sequence reads.
Duplicate reads can be seen as identical or nearly identical sequences with
some mismatches.  This tool lets users avoid the analysis of unnecessary
reads, reducing the time of subsequent procedures with the
dataset (e.g. assemblies, mappings, etc.).  The tool is implemented with MPI
in order to exploit the parallel capabilities of multicore clusters.  It is
faster than multithreaded counterparts (end of 2015) for the same number of
cores and, thanks to the message-passing technology, it can be executed on
clusters.")
    (home-page "https://sourceforge.net/projects/pardre/")
    (license license:gpl3+)))

(define-public ruby-bio-kseq
  (package
    (name "ruby-bio-kseq")
    (version "0.0.2")
    (source
     (origin
       (method url-fetch)
       (uri (rubygems-uri "bio-kseq" version))
       (sha256
        (base32
         "1xyaha46khb5jc6wzkbf7040jagac49jbimn0vcrzid0j8jdikrz"))))
    (build-system ruby-build-system)
    (arguments
     `(#:test-target "spec"))
    (native-inputs
     `(("bundler" ,bundler)
       ("ruby-rspec" ,ruby-rspec)
       ("ruby-rake-compiler" ,ruby-rake-compiler)))
    (inputs
     `(("zlib" ,zlib)))
    (synopsis "Ruby bindings for the kseq.h FASTA/Q parser")
    (description
     "@code{Bio::Kseq} provides ruby bindings to the @code{kseq.h} FASTA and
FASTQ parsing code.  It provides a fast iterator over sequences and their
quality scores.")
    (home-page "https://github.com/gusevfe/bio-kseq")
    (license license:expat)))

(define-public bio-locus
  (package
    (name "bio-locus")
    (version "0.0.7")
    (source
     (origin
       (method url-fetch)
       (uri (rubygems-uri "bio-locus" version))
       (sha256
        (base32
         "02vmrxyimkj9sahsp4zhfhnmbvz6dbbqz1y01vglf8cbwvkajfl0"))))
    (build-system ruby-build-system)
    (native-inputs
     `(("ruby-rspec" ,ruby-rspec)))
    (synopsis "Tool for fast querying of genome locations")
    (description
     "Bio-locus is a tabix-like tool for fast querying of genome
locations.  Many file formats in bioinformatics contain records that
start with a chromosome name and a position for a SNP, or a start-end
position for indels.  Bio-locus allows users to store this chr+pos or
chr+pos+alt information in a database.")
    (home-page "https://github.com/pjotrp/bio-locus")
    (license license:expat)))

(define-public bio-blastxmlparser
  (package
    (name "bio-blastxmlparser")
    (version "2.0.4")
    (source (origin
              (method url-fetch)
              (uri (rubygems-uri "bio-blastxmlparser" version))
              (sha256
               (base32
                "1wf4qygcmdjgcqm6flmvsagfr1gs9lf63mj32qv3z1f481zc5692"))))
    (build-system ruby-build-system)
    (propagated-inputs
     `(("ruby-bio-logger" ,ruby-bio-logger)
       ("ruby-nokogiri" ,ruby-nokogiri)))
    (inputs
     `(("ruby-rspec" ,ruby-rspec)))
    (synopsis "Fast big data BLAST XML parser and library")
    (description
     "Very fast parallel big-data BLAST XML file parser which can be used as
command line utility.  Use blastxmlparser to: Parse BLAST XML; filter output;
generate FASTA, JSON, YAML, RDF, JSON-LD, HTML, CSV, tabular output etc.")
    (home-page "http://github.com/pjotrp/blastxmlparser")
    (license license:expat)))

(define-public bioruby
  (package
    (name "bioruby")
    (version "1.5.0")
    (source
     (origin
       (method url-fetch)
       (uri (rubygems-uri "bio" version))
       (sha256
        (base32
         "01k2fyjl5fpx4zn8g6gqiqvsg2j1fgixrs9p03vzxckynxdq3wmc"))))
    (build-system ruby-build-system)
    (propagated-inputs
     `(("ruby-libxml" ,ruby-libxml)))
    (native-inputs
     `(("which" ,which)))  ; required for test phase
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'build 'patch-test-command
          (lambda _
            (substitute* '("test/functional/bio/test_command.rb")
              (("/bin/sh") (which "sh")))
            (substitute* '("test/functional/bio/test_command.rb")
              (("/bin/ls") (which "ls")))
            (substitute* '("test/functional/bio/test_command.rb")
              (("which") (which "which")))
            (substitute* '("test/functional/bio/test_command.rb",
                           "test/data/command/echoarg2.sh")
              (("/bin/echo") (which "echo")))
            #t)))))
    (synopsis "Ruby library, shell and utilities for bioinformatics")
    (description "BioRuby comes with a comprehensive set of Ruby development
tools and libraries for bioinformatics and molecular biology.  BioRuby has
components for sequence analysis, pathway analysis, protein modelling and
phylogenetic analysis; it supports many widely used data formats and provides
easy access to databases, external programs and public web services, including
BLAST, KEGG, GenBank, MEDLINE and GO.")
    (home-page "http://bioruby.org/")
    ;; Code is released under Ruby license, except for setup
    ;; (LGPLv2.1+) and scripts in samples (which have GPL2 and GPL2+)
    (license (list license:ruby license:lgpl2.1+ license:gpl2+ ))))

(define-public r-acsnminer
  (package
    (name "r-acsnminer")
    (version "0.16.8.25")
    (source (origin
              (method url-fetch)
              (uri (cran-uri "ACSNMineR" version))
              (sha256
               (base32
                "0gh604s8qall6zfjlwcg2ilxjvz08dplf9k5g47idhv43scm748l"))))
    (properties `((upstream-name . "ACSNMineR")))
    (build-system r-build-system)
    (propagated-inputs
      `(("r-ggplot2" ,r-ggplot2)
        ("r-gridextra" ,r-gridextra)))
    (home-page "http://cran.r-project.org/web/packages/ACSNMineR")
    (synopsis "Gene enrichment analysis")
    (description
     "This package provides tools to compute and represent gene set enrichment
or depletion from your data based on pre-saved maps from the @dfn{Atlas of
Cancer Signalling Networks} (ACSN) or user imported maps.  The gene set
enrichment can be run with hypergeometric test or Fisher exact test, and can
use multiple corrections.  Visualization of data can be done either by
barplots or heatmaps.")
    (license license:gpl2+)))

(define-public r-biocgenerics
  (package
    (name "r-biocgenerics")
    (version "0.20.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "BiocGenerics" version))
              (sha256
               (base32
                "06szdz7dfs1iyv5zdl4fjzad18nnf1zf3wvglc6c6yd9mrqlf7vk"))))
    (properties
     `((upstream-name . "BiocGenerics")))
    (build-system r-build-system)
    (home-page "http://bioconductor.org/packages/BiocGenerics")
    (synopsis "S4 generic functions for Bioconductor")
    (description
     "This package provides S4 generic functions needed by many Bioconductor
packages.")
    (license license:artistic2.0)))

(define-public r-biocinstaller
  (package
    (name "r-biocinstaller")
    (version "1.24.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "BiocInstaller" version))
              (sha256
               (base32
                "0y1y5wmy6lzjqx3hdg15n91d417ccjj8dbvdkhmp99bs5aijwcpn"))))
    (properties
     `((upstream-name . "BiocInstaller")))
    (build-system r-build-system)
    (home-page "http://bioconductor.org/packages/BiocInstaller")
    (synopsis "Install Bioconductor packages")
    (description "This package is used to install and update R packages from
Bioconductor, CRAN, and Github.")
    (license license:artistic2.0)))

(define-public r-biocviews
  (package
    (name "r-biocviews")
    (version "1.42.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "biocViews" version))
              (sha256
               (base32
                "07rjk10b91pkriyq297w86199r2d3sfji3ggs9mq2gyalsa8y4b6"))))
    (properties
     `((upstream-name . "biocViews")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biobase" ,r-biobase)
       ("r-graph" ,r-graph)
       ("r-rbgl" ,r-rbgl)
       ("r-rcurl" ,r-rcurl)
       ("r-xml" ,r-xml)
       ("r-knitr" ,r-knitr)
       ("r-runit" ,r-runit)))
    (home-page "http://bioconductor.org/packages/biocViews")
    (synopsis "Bioconductor package categorization helper")
    (description "The purpose of biocViews is to create HTML pages that
categorize packages in a Bioconductor package repository according to keywords,
also known as views, in a controlled vocabulary.")
    (license license:artistic2.0)))

(define-public r-biocstyle
  (package
   (name "r-biocstyle")
   (version "2.2.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "BiocStyle" version))
              (sha256
               (base32
                "0qbk23fz8cn260isd9xlh9lxfj4adar6iqzai01c4kz0p31f45za"))))
    (properties
     `((upstream-name . "BiocStyle")))
    (build-system r-build-system)
    (home-page "http://bioconductor.org/packages/BiocStyle")
    (synopsis "Bioconductor formatting styles")
    (description "This package provides standard formatting styles for
Bioconductor PDF and HTML documents.  Package vignettes illustrate use and
functionality.")
    (license license:artistic2.0)))

(define-public r-bioccheck
  (package
    (name "r-bioccheck")
    (version "1.10.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "BiocCheck" version))
              (sha256
               (base32
                "1rfy37xg1nc2cmgbclvzsi7sgmdcdjiahsx9crgx3yaw7kxgiack"))))
    (properties
     `((upstream-name . "BiocCheck")))
    (build-system r-build-system)
    (arguments
     '(#:phases
       (modify-phases %standard-phases
         ;; This package can be used by calling BiocCheck(<package>) from
         ;; within R, or by running R CMD BiocCheck <package>.  This phase
         ;; makes sure the latter works.  For this to work, the BiocCheck
         ;; script must be somewhere on the PATH (not the R bin directory).
         (add-after 'install 'install-bioccheck-subcommand
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (dest-dir (string-append out "/bin"))
                    (script-dir
                     (string-append out "/site-library/BiocCheck/script/")))
               (mkdir-p dest-dir)
               (symlink (string-append script-dir "/checkBadDeps.R")
                        (string-append dest-dir "/checkBadDeps.R"))
               (symlink (string-append script-dir "/BiocCheck")
                        (string-append dest-dir "/BiocCheck")))
             #t)))))
    (native-inputs
     `(("which" ,which)))
    (propagated-inputs
     `(("r-graph" ,r-graph)
       ("r-knitr" ,r-knitr)
       ("r-httr" ,r-httr)
       ("r-optparse" ,r-optparse)
       ("r-devtools" ,r-devtools)
       ("r-biocinstaller" ,r-biocinstaller)
       ("r-biocviews" ,r-biocviews)))
    (home-page "http://bioconductor.org/packages/BiocCheck")
    (synopsis "Executes Bioconductor-specific package checks")
    (description "This package contains tools to perform additional quality
checks on R packages that are to be submitted to the Bioconductor repository.")
    (license license:artistic2.0)))

(define-public r-getopt
  (package
    (name "r-getopt")
    (version "1.20.0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "getopt" version))
       (sha256
        (base32
         "00f57vgnzmg7cz80rjmjz1556xqcmx8nhrlbbhaq4w7gl2ibl87r"))))
    (build-system r-build-system)
    (home-page "https://github.com/trevorld/getopt")
    (synopsis "Command-line option processor for R")
    (description
     "This package is designed to be used with Rscript to write shebang
scripts that accept short and long options.  Many users will prefer to
use the packages @code{optparse} or @code{argparse} which add extra
features like automatically generated help options and usage texts,
support for default values, positional argument support, etc.")
    (license license:gpl2+)))

(define-public r-optparse
  (package
    (name "r-optparse")
    (version "1.3.2")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "optparse" version))
       (sha256
        (base32
         "1g8as89r91xxi5j5azsd6vrfrhg84mnfx2683j7pacdp8s33radw"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-getopt" ,r-getopt)))
    (home-page
     "https://github.com/trevorld/optparse")
    (synopsis "Command line option parser")
    (description
     "This package provides a command line parser inspired by Python's
@code{optparse} library to be used with Rscript to write shebang scripts
that accept short and long options.")
    (license license:gpl2+)))

(define-public r-dnacopy
  (package
    (name "r-dnacopy")
    (version "1.48.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "DNAcopy" version))
              (sha256
               (base32
                "1idyvfvy7xx8k9vk00y4k3819qmip8iqm809j3vpxabmsn7r9zyh"))))
    (properties
     `((upstream-name . "DNAcopy")))
    (build-system r-build-system)
    (inputs
     `(("gfortran" ,gfortran)))
    (home-page "https://bioconductor.org/packages/DNAcopy")
    (synopsis "Implementation of a circular binary segmentation algorithm")
    (description "This package implements the circular binary segmentation (CBS)
algorithm to segment DNA copy number data and identify genomic regions with
abnormal copy number.")
    (license license:gpl2+)))

(define-public r-s4vectors
  (package
    (name "r-s4vectors")
    (version "0.12.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "S4Vectors" version))
              (sha256
               (base32
                "0m0npc0vhmcwcxws7v2f8k4hvvrjvnlrsr94klxf4a8m4xw2xzzk"))))
    (properties
     `((upstream-name . "S4Vectors")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)))
    (home-page "http://bioconductor.org/packages/S4Vectors")
    (synopsis "S4 implementation of vectors and lists")
    (description
     "The S4Vectors package defines the @code{Vector} and @code{List} virtual
classes and a set of generic functions that extend the semantic of ordinary
vectors and lists in R.  Package developers can easily implement vector-like
or list-like objects as concrete subclasses of @code{Vector} or @code{List}.
In addition, a few low-level concrete subclasses of general interest (e.g.
@code{DataFrame}, @code{Rle}, and @code{Hits}) are implemented in the
S4Vectors package itself.")
    (license license:artistic2.0)))

(define-public r-seqinr
  (package
    (name "r-seqinr")
    (version "3.3-3")
    (source
      (origin
        (method url-fetch)
        (uri (cran-uri "seqinr" version))
        (sha256
          (base32
            "0rk4yba8km26c0rh1f4h474zsb5n6kjmqsi55bnzr6p8pymp18hj"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-ade4" ,r-ade4)
       ("r-segmented" ,r-segmented)))
    (inputs
     `(("zlib" ,zlib)))
    (home-page "http://seqinr.r-forge.r-project.org/")
    (synopsis "Biological sequences retrieval and analysis")
    (description
     "This package provides tools for exploratory data analysis and data
visualization of biological sequence (DNA and protein) data.  It also includes
utilities for sequence data management under the ACNUC system.")
    (license license:gpl2+)))

(define-public r-iranges
  (package
    (name "r-iranges")
    (version "2.8.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "IRanges" version))
              (sha256
               (base32
                "0cdl1sfd3cvf93lnz91fdk64fbg1mnd5g958dwh1il8r358hqq3f"))))
    (properties
     `((upstream-name . "IRanges")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)
       ("r-s4vectors" ,r-s4vectors)))
    (home-page "http://bioconductor.org/packages/IRanges")
    (synopsis "Infrastructure for manipulating intervals on sequences")
    (description
     "This package provides efficient low-level and highly reusable S4 classes
for storing ranges of integers, RLE vectors (Run-Length Encoding), and, more
generally, data that can be organized sequentially (formally defined as
@code{Vector} objects), as well as views on these @code{Vector} objects.
Efficient list-like classes are also provided for storing big collections of
instances of the basic classes.  All classes in the package use consistent
naming and share the same rich and consistent \"Vector API\" as much as
possible.")
    (license license:artistic2.0)))

(define-public r-genomeinfodb
  (package
    (name "r-genomeinfodb")
    (version "1.10.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "GenomeInfoDb" version))
              (sha256
               (base32
                "0nhg4bk38gzvf3mvnbqgisbbhfv1kzjld27z1z9knnlkplkiyyyv"))))
    (properties
     `((upstream-name . "GenomeInfoDb")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)
       ("r-iranges" ,r-iranges)
       ("r-s4vectors" ,r-s4vectors)))
    (home-page "http://bioconductor.org/packages/GenomeInfoDb")
    (synopsis "Utilities for manipulating chromosome identifiers")
    (description
     "This package contains data and functions that define and allow
translation between different chromosome sequence naming conventions (e.g.,
\"chr1\" versus \"1\"), including a function that attempts to place sequence
names in their natural, rather than lexicographic, order.")
    (license license:artistic2.0)))

(define-public r-edger
  (package
    (name "r-edger")
    (version "3.16.1")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "edgeR" version))
              (sha256
               (base32
                "1r6hhwkqp13m022hjajzr1lnjsbai0yjhykwn0kp1f0la990a808"))))
    (properties `((upstream-name . "edgeR")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-limma" ,r-limma)
       ("r-locfit" ,r-locfit)))
    (home-page "http://bioinf.wehi.edu.au/edgeR")
    (synopsis "EdgeR does empirical analysis of digital gene expression data")
    (description "This package can do differential expression analysis of
RNA-seq expression profiles with biological replication.  It implements a range
of statistical methodology based on the negative binomial distributions,
including empirical Bayes estimation, exact tests, generalized linear models
and quasi-likelihood tests.  It be applied to differential signal analysis of
other types of genomic data that produce counts, including ChIP-seq, SAGE and
CAGE.")
    (license license:gpl2+)))

(define-public r-variantannotation
  (package
    (name "r-variantannotation")
    (version "1.20.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "VariantAnnotation" version))
              (sha256
               (base32
                "1lwzfgahz8ipwli73kcfqb18y6adi129hap1gnycnj3980m54i8q"))))
    (properties
     `((upstream-name . "VariantAnnotation")))
    (inputs
     `(("zlib" ,zlib)))
    (propagated-inputs
     `(("r-annotationdbi" ,r-annotationdbi)
       ("r-biobase" ,r-biobase)
       ("r-biocgenerics" ,r-biocgenerics)
       ("r-biostrings" ,r-biostrings)
       ("r-bsgenome" ,r-bsgenome)
       ("r-dbi" ,r-dbi)
       ("r-genomeinfodb" ,r-genomeinfodb)
       ("r-genomicfeatures" ,r-genomicfeatures)
       ("r-genomicranges" ,r-genomicranges)
       ("r-iranges" ,r-iranges)
       ("r-summarizedexperiment" ,r-summarizedexperiment)
       ("r-rsamtools" ,r-rsamtools)
       ("r-rtracklayer" ,r-rtracklayer)
       ("r-s4vectors" ,r-s4vectors)
       ("r-xvector" ,r-xvector)
       ("r-zlibbioc" ,r-zlibbioc)))
    (build-system r-build-system)
    (home-page "https://bioconductor.org/packages/VariantAnnotation")
    (synopsis "Package for annotation of genetic variants")
    (description "This R package can annotate variants, compute amino acid
coding changes and predict coding outcomes.")
    (license license:artistic2.0)))

(define-public r-limma
  (package
    (name "r-limma")
    (version "3.30.2")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "limma" version))
              (sha256
               (base32
                "04jris7wk2lxksrrvrjsysznsdb2k04lfgrnp18ic49sazva0hfy"))))
    (build-system r-build-system)
    (home-page "http://bioinf.wehi.edu.au/limma")
    (synopsis "Package for linear models for microarray and RNA-seq data")
    (description "This package can be used for the analysis of gene expression
studies, especially the use of linear models for analysing designed experiments
and the assessment of differential expression.  The analysis methods apply to
different technologies, including microarrays, RNA-seq, and quantitative PCR.")
    (license license:gpl2+)))

(define-public r-xvector
  (package
    (name "r-xvector")
    (version "0.14.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "XVector" version))
              (sha256
               (base32
                "09lbqxpqr80g0kw77mpz0p1a8cq706j33kz8194wp71il67cdzi7"))))
    (properties
     `((upstream-name . "XVector")))
    (build-system r-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'use-system-zlib
           (lambda _
             (substitute* "DESCRIPTION"
               (("zlibbioc, ") ""))
             (substitute* "NAMESPACE"
               (("import\\(zlibbioc\\)") ""))
             #t)))))
    (inputs
     `(("zlib" ,zlib)))
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)
       ("r-iranges" ,r-iranges)
       ("r-s4vectors" ,r-s4vectors)))
    (home-page "http://bioconductor.org/packages/XVector")
    (synopsis "Representation and manpulation of external sequences")
    (description
     "This package provides memory efficient S4 classes for storing sequences
\"externally\" (behind an R external pointer, or on disk).")
    (license license:artistic2.0)))

(define-public r-genomicranges
  (package
    (name "r-genomicranges")
    (version "1.26.1")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "GenomicRanges" version))
              (sha256
               (base32
                "039nxccg9i2an8q2wni79x8dr9p1fcfcqvih9hg9w243pczg2g3c"))))
    (properties
     `((upstream-name . "GenomicRanges")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)
       ("r-genomeinfodb" ,r-genomeinfodb)
       ("r-iranges" ,r-iranges)
       ("r-s4vectors" ,r-s4vectors)
       ("r-xvector" ,r-xvector)))
    (home-page "http://bioconductor.org/packages/GenomicRanges")
    (synopsis "Representation and manipulation of genomic intervals")
    (description
     "This package provides tools to efficiently represent and manipulate
genomic annotations and alignments is playing a central role when it comes to
analyzing high-throughput sequencing data (a.k.a. NGS data).  The
GenomicRanges package defines general purpose containers for storing and
manipulating genomic intervals and variables defined along a genome.")
    (license license:artistic2.0)))

(define-public r-biobase
  (package
    (name "r-biobase")
    (version "2.34.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "Biobase" version))
              (sha256
               (base32
                "0js9j9wqls8f571ifl9ylllbb9a9hwf7b7drf2grwb1fl31ldazl"))))
    (properties
     `((upstream-name . "Biobase")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)))
    (home-page "http://bioconductor.org/packages/Biobase")
    (synopsis "Base functions for Bioconductor")
    (description
     "This package provides functions that are needed by many other packages
on Bioconductor or which replace R functions.")
    (license license:artistic2.0)))

(define-public r-annotationdbi
  (package
    (name "r-annotationdbi")
    (version "1.36.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "AnnotationDbi" version))
              (sha256
               (base32
                "0ydrqw1k1j5p6w76bwc753cx545c055x88q87wzya93858synj6r"))))
    (properties
     `((upstream-name . "AnnotationDbi")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biobase" ,r-biobase)
       ("r-biocgenerics" ,r-biocgenerics)
       ("r-dbi" ,r-dbi)
       ("r-iranges" ,r-iranges)
       ("r-rsqlite" ,r-rsqlite)
       ("r-s4vectors" ,r-s4vectors)))
    (home-page "http://bioconductor.org/packages/AnnotationDbi")
    (synopsis "Annotation database interface")
    (description
     "This package provides user interface and database connection code for
annotation data packages using SQLite data storage.")
    (license license:artistic2.0)))

(define-public r-biomart
  (package
    (name "r-biomart")
    (version "2.30.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "biomaRt" version))
              (sha256
               (base32
                "1x0flcghq71784q2l02j0g4f9jkmyb14f6i307n6c59d6ji7h7x6"))))
    (properties
     `((upstream-name . "biomaRt")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotationdbi" ,r-annotationdbi)
       ("r-rcurl" ,r-rcurl)
       ("r-xml" ,r-xml)))
    (home-page "http://bioconductor.org/packages/biomaRt")
    (synopsis "Interface to BioMart databases")
    (description
     "biomaRt provides an interface to a growing collection of databases
implementing the @url{BioMart software suite, http://www.biomart.org}.  The
package enables retrieval of large amounts of data in a uniform way without
the need to know the underlying database schemas or write complex SQL queries.
Examples of BioMart databases are Ensembl, COSMIC, Uniprot, HGNC, Gramene,
Wormbase and dbSNP mapped to Ensembl.  These major databases give biomaRt
users direct access to a diverse set of data and enable a wide range of
powerful online queries from gene annotation to database mining.")
    (license license:artistic2.0)))

(define-public r-biocparallel
  (package
    (name "r-biocparallel")
    (version "1.8.1")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "BiocParallel" version))
              (sha256
               (base32
                "123i928rwi4h4sy4fpysv6pinw5nns0sm3myxi2ghqhm34ws8gyl"))))
    (properties
     `((upstream-name . "BiocParallel")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-futile-logger" ,r-futile-logger)
       ("r-snow" ,r-snow)))
    (home-page "http://bioconductor.org/packages/BiocParallel")
    (synopsis "Bioconductor facilities for parallel evaluation")
    (description
     "This package provides modified versions and novel implementation of
functions for parallel evaluation, tailored to use with Bioconductor
objects.")
    (license (list license:gpl2+ license:gpl3+))))

(define-public r-biostrings
  (package
    (name "r-biostrings")
    (version "2.42.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "Biostrings" version))
              (sha256
               (base32
                "08z8lkz3axa94wkf144a931ry6vf6cc25avi1ywr84ln2k5czz9f"))))
    (properties
     `((upstream-name . "Biostrings")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)
       ("r-iranges" ,r-iranges)
       ("r-s4vectors" ,r-s4vectors)
       ("r-xvector" ,r-xvector)))
    (home-page "http://bioconductor.org/packages/Biostrings")
    (synopsis "String objects and algorithms for biological sequences")
    (description
     "This package provides memory efficient string containers, string
matching algorithms, and other utilities, for fast manipulation of large
biological sequences or sets of sequences.")
    (license license:artistic2.0)))

(define-public r-rsamtools
  (package
    (name "r-rsamtools")
    (version "1.26.1")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "Rsamtools" version))
              (sha256
               (base32
                "0pf4f6brf4bl5zgjrah0f38qslazrs49ayqgyh0xfqgrh63yx4ck"))))
    (properties
     `((upstream-name . "Rsamtools")))
    (build-system r-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'use-system-zlib
           (lambda _
             (substitute* "DESCRIPTION"
               (("zlibbioc, ") ""))
             (substitute* "NAMESPACE"
               (("import\\(zlibbioc\\)") ""))
             #t)))))
    (inputs
     `(("zlib" ,zlib)))
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)
       ("r-biocparallel" ,r-biocparallel)
       ("r-biostrings" ,r-biostrings)
       ("r-bitops" ,r-bitops)
       ("r-genomeinfodb" ,r-genomeinfodb)
       ("r-genomicranges" ,r-genomicranges)
       ("r-iranges" ,r-iranges)
       ("r-s4vectors" ,r-s4vectors)
       ("r-xvector" ,r-xvector)))
    (home-page "http://bioconductor.org/packages/release/bioc/html/Rsamtools.html")
    (synopsis "Interface to samtools, bcftools, and tabix")
    (description
     "This package provides an interface to the 'samtools', 'bcftools', and
'tabix' utilities for manipulating SAM (Sequence Alignment / Map), FASTA,
binary variant call (BCF) and compressed indexed tab-delimited (tabix)
files.")
    (license license:expat)))

(define-public r-summarizedexperiment
  (package
    (name "r-summarizedexperiment")
    (version "1.4.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "SummarizedExperiment" version))
              (sha256
               (base32
                "1kbj8sg2ik9f8d6g95wz0py62jldg01qy5rsdpg1cxw95nf7dzi3"))))
    (properties
     `((upstream-name . "SummarizedExperiment")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biobase" ,r-biobase)
       ("r-biocgenerics" ,r-biocgenerics)
       ("r-genomeinfodb" ,r-genomeinfodb)
       ("r-genomicranges" ,r-genomicranges)
       ("r-iranges" ,r-iranges)
       ("r-s4vectors" ,r-s4vectors)))
    (home-page "http://bioconductor.org/packages/SummarizedExperiment")
    (synopsis "Container for representing genomic ranges by sample")
    (description
     "The SummarizedExperiment container contains one or more assays, each
represented by a matrix-like object of numeric or other mode.  The rows
typically represent genomic ranges of interest and the columns represent
samples.")
    (license license:artistic2.0)))

(define-public r-genomicalignments
  (package
    (name "r-genomicalignments")
    (version "1.10.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "GenomicAlignments" version))
              (sha256
               (base32
                "11vb0a0zd36i4yhg4mfijv787v0nihn6pkjj6q7rfy19gwy61xlc"))))
    (properties
     `((upstream-name . "GenomicAlignments")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)
       ("r-biocparallel" ,r-biocparallel)
       ("r-biostrings" ,r-biostrings)
       ("r-genomeinfodb" ,r-genomeinfodb)
       ("r-genomicranges" ,r-genomicranges)
       ("r-iranges" ,r-iranges)
       ("r-rsamtools" ,r-rsamtools)
       ("r-s4vectors" ,r-s4vectors)
       ("r-summarizedexperiment" ,r-summarizedexperiment)))
    (home-page "http://bioconductor.org/packages/GenomicAlignments")
    (synopsis "Representation and manipulation of short genomic alignments")
    (description
     "This package provides efficient containers for storing and manipulating
short genomic alignments (typically obtained by aligning short reads to a
reference genome).  This includes read counting, computing the coverage,
junction detection, and working with the nucleotide content of the
alignments.")
    (license license:artistic2.0)))

(define-public r-rtracklayer
  (package
    (name "r-rtracklayer")
    (version "1.34.1")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "rtracklayer" version))
              (sha256
               (base32
                "0x59k2fd0iaqi93gy6bm58p2j2z90z1b7a6w5b4c098y98n096rc"))))
    (build-system r-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'use-system-zlib
           (lambda _
             (substitute* "DESCRIPTION"
               (("zlibbioc, ") ""))
             (substitute* "NAMESPACE"
               (("import\\(zlibbioc\\)") ""))
             #t)))))
    (inputs
     `(("zlib" ,zlib)))
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)
       ("r-biostrings" ,r-biostrings)
       ("r-genomeinfodb" ,r-genomeinfodb)
       ("r-genomicalignments" ,r-genomicalignments)
       ("r-genomicranges" ,r-genomicranges)
       ("r-iranges" ,r-iranges)
       ("r-rcurl" ,r-rcurl)
       ("r-rsamtools" ,r-rsamtools)
       ("r-s4vectors" ,r-s4vectors)
       ("r-xml" ,r-xml)
       ("r-xvector" ,r-xvector)))
    (home-page "http://bioconductor.org/packages/rtracklayer")
    (synopsis "R interface to genome browsers and their annotation tracks")
    (description
     "rtracklayer is an extensible framework for interacting with multiple
genome browsers (currently UCSC built-in) and manipulating annotation tracks
in various formats (currently GFF, BED, bedGraph, BED15, WIG, BigWig and 2bit
built-in).  The user may export/import tracks to/from the supported browsers,
as well as query and modify the browser state, such as the current viewport.")
    (license license:artistic2.0)))

(define-public r-genomicfeatures
  (package
    (name "r-genomicfeatures")
    (version "1.26.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "GenomicFeatures" version))
              (sha256
               (base32
                "0z8spi2knwzwi10c38vr7xlvi3ah9faj7m1lka880mmxkl9cai4k"))))
    (properties
     `((upstream-name . "GenomicFeatures")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotationdbi" ,r-annotationdbi)
       ("r-biobase" ,r-biobase)
       ("r-biocgenerics" ,r-biocgenerics)
       ("r-biomart" ,r-biomart)
       ("r-biostrings" ,r-biostrings)
       ("r-dbi" ,r-dbi)
       ("r-genomeinfodb" ,r-genomeinfodb)
       ("r-genomicranges" ,r-genomicranges)
       ("r-iranges" ,r-iranges)
       ("r-rcurl" ,r-rcurl)
       ("r-rsqlite" ,r-rsqlite)
       ("r-rtracklayer" ,r-rtracklayer)
       ("r-s4vectors" ,r-s4vectors)
       ("r-xvector" ,r-xvector)))
    (home-page "http://bioconductor.org/packages/GenomicFeatures")
    (synopsis "Tools for working with transcript centric annotations")
    (description
     "This package provides a set of tools and methods for making and
manipulating transcript centric annotations.  With these tools the user can
easily download the genomic locations of the transcripts, exons and cds of a
given organism, from either the UCSC Genome Browser or a BioMart
database (more sources will be supported in the future).  This information is
then stored in a local database that keeps track of the relationship between
transcripts, exons, cds and genes.  Flexible methods are provided for
extracting the desired features in a convenient format.")
    (license license:artistic2.0)))

(define-public r-go-db
  (package
    (name "r-go-db")
    (version "3.4.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "http://www.bioconductor.org/packages/"
                                  "release/data/annotation/src/contrib/GO.db_"
                                  version ".tar.gz"))
              (sha256
               (base32
                "02cj8kqi5w39jwcs8gp1dgj08sah262ppxnkz4h3qd0w191y8yyl"))))
    (properties
     `((upstream-name . "GO.db")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotationdbi" ,r-annotationdbi)))
    (home-page "http://bioconductor.org/packages/GO.db")
    (synopsis "Annotation maps describing the entire Gene Ontology")
    (description
     "The purpose of this GO.db annotation package is to provide detailed
information about the latest version of the Gene Ontologies.")
    (license license:artistic2.0)))

(define-public r-graph
  (package
    (name "r-graph")
    (version "1.52.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "graph" version))
              (sha256
               (base32
                "0g3dk5vsdp489fmyg8mifczmzgqrjlakkkr8i96dj15gghp3l135"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)))
    (home-page "http://bioconductor.org/packages/graph")
    (synopsis "Handle graph data structures in R")
    (description
     "This package implements some simple graph handling capabilities for R.")
    (license license:artistic2.0)))

(define-public r-topgo
  (package
    (name "r-topgo")
    (version "2.26.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "topGO" version))
              (sha256
               (base32
                "0j6sgvam4lk9348ag6pypcbkv93x4fk0di8ivhr23mz2s2yqzwrx"))))
    (properties
     `((upstream-name . "topGO")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotationdbi" ,r-annotationdbi)
       ("r-dbi" ,r-dbi)
       ("r-biobase" ,r-biobase)
       ("r-biocgenerics" ,r-biocgenerics)
       ("r-go-db" ,r-go-db)
       ("r-matrixstats" ,r-matrixstats)
       ("r-graph" ,r-graph)
       ("r-sparsem" ,r-sparsem)))
    (home-page "http://bioconductor.org/packages/topGO")
    (synopsis "Enrichment analysis for gene ontology")
    (description
     "The topGO package provides tools for testing @dfn{gene ontology} (GO)
terms while accounting for the topology of the GO graph.  Different test
statistics and different methods for eliminating local similarities and
dependencies between GO terms can be implemented and applied.")
    ;; Any version of the LGPL applies.
    (license license:lgpl2.1+)))

(define-public r-bsgenome
  (package
    (name "r-bsgenome")
    (version "1.42.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "BSgenome" version))
              (sha256
               (base32
                "0hxwc02h5mzhkrk60d1jmlsfjf0ai9jxdc0128kj1sg4r2k1q94y"))))
    (properties
     `((upstream-name . "BSgenome")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)
       ("r-biostrings" ,r-biostrings)
       ("r-genomeinfodb" ,r-genomeinfodb)
       ("r-genomicranges" ,r-genomicranges)
       ("r-iranges" ,r-iranges)
       ("r-rsamtools" ,r-rsamtools)
       ("r-rtracklayer" ,r-rtracklayer)
       ("r-s4vectors" ,r-s4vectors)
       ("r-xvector" ,r-xvector)))
    (home-page "http://bioconductor.org/packages/BSgenome")
    (synopsis "Infrastructure for Biostrings-based genome data packages")
    (description
     "This package provides infrastructure shared by all Biostrings-based
genome data packages and support for efficient SNP representation.")
    (license license:artistic2.0)))

(define-public r-impute
  (package
    (name "r-impute")
    (version "1.48.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "impute" version))
              (sha256
               (base32
                "1164zvnikbjd0ybdn9xwn520rlmdjd824vmhnl83zgv3v9lzp9bm"))))
    (inputs
     `(("gfortran" ,gfortran)))
    (build-system r-build-system)
    (home-page "http://bioconductor.org/packages/impute")
    (synopsis "Imputation for microarray data")
    (description
     "This package provides a function to impute missing gene expression
microarray data, using nearest neighbor averaging.")
    (license license:gpl2+)))

(define-public r-seqpattern
  (package
    (name "r-seqpattern")
    (version "1.6.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "seqPattern" version))
              (sha256
               (base32
                "0lsa5pz36xapi3yiv78k3z286a5md5sm5g21pgfyg8zmhmkxr7y8"))))
    (properties
     `((upstream-name . "seqPattern")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biostrings" ,r-biostrings)
       ("r-genomicranges" ,r-genomicranges)
       ("r-iranges" ,r-iranges)
       ("r-kernsmooth" ,r-kernsmooth)
       ("r-plotrix" ,r-plotrix)))
    (home-page "http://bioconductor.org/packages/seqPattern")
    (synopsis "Visualising oligonucleotide patterns and motif occurrences")
    (description
     "This package provides tools to visualize oligonucleotide patterns and
sequence motif occurrences across a large set of sequences centred at a common
reference point and sorted by a user defined feature.")
    (license license:gpl3+)))

(define-public r-genomation
  (package
    (name "r-genomation")
    (version "1.6.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "genomation" version))
              (sha256
               (base32
                "1m4mz7wihj8yqivwkzw68div8ybk4rjsai3ffki7xp7sh21ax03y"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biostrings" ,r-biostrings)
       ("r-bsgenome" ,r-bsgenome)
       ("r-data-table" ,r-data-table)
       ("r-genomeinfodb" ,r-genomeinfodb)
       ("r-genomicalignments" ,r-genomicalignments)
       ("r-genomicranges" ,r-genomicranges)
       ("r-ggplot2" ,r-ggplot2)
       ("r-gridbase" ,r-gridbase)
       ("r-impute" ,r-impute)
       ("r-iranges" ,r-iranges)
       ("r-matrixstats" ,r-matrixstats)
       ("r-plotrix" ,r-plotrix)
       ("r-plyr" ,r-plyr)
       ("r-rcpp" ,r-rcpp)
       ("r-readr" ,r-readr)
       ("r-reshape2" ,r-reshape2)
       ("r-rhtslib" ,r-rhtslib)
       ("r-rsamtools" ,r-rsamtools)
       ("r-rtracklayer" ,r-rtracklayer)
       ("r-runit" ,r-runit)
       ("r-s4vectors" ,r-s4vectors)
       ("r-seqpattern" ,r-seqpattern)))
    (inputs
     `(("zlib" ,zlib)))
    (home-page "http://bioinformatics.mdc-berlin.de/genomation/")
    (synopsis "Summary, annotation and visualization of genomic data")
    (description
     "This package provides a package for summary and annotation of genomic
intervals.  Users can visualize and quantify genomic intervals over
pre-defined functional regions, such as promoters, exons, introns, etc.  The
genomic intervals represent regions with a defined chromosome position, which
may be associated with a score, such as aligned reads from HT-seq experiments,
TF binding sites, methylation scores, etc.  The package can use any tabular
genomic feature data as long as it has minimal information on the locations of
genomic intervals.  In addition, it can use BAM or BigWig files as input.")
    (license license:artistic2.0)))

(define-public r-genomationdata
  (package
    (name "r-genomationdata")
    (version "1.6.0")
    (source (origin
              (method url-fetch)
              ;; We cannot use bioconductor-uri here because this tarball is
              ;; located under "data/annotation/" instead of "bioc/".
              (uri (string-append "https://bioconductor.org/packages/"
                                  "release/data/experiment/src/contrib/"
                                  "genomationData_" version ".tar.gz"))
              (sha256
               (base32
                "16dqwb7wx1igx77zdbcskx5m1hs4g4gp2hl56zzm70hcagnlkz8y"))))
    (build-system r-build-system)
    ;; As this package provides little more than large data files, it doesn't
    ;; make sense to build substitutes.
    (arguments `(#:substitutable? #f))
    (native-inputs
     `(("r-knitr" ,r-knitr)))
    (home-page "http://bioinformatics.mdc-berlin.de/genomation/")
    (synopsis "Experimental data for use with the genomation package")
    (description
     "This package contains experimental genetic data for use with the
genomation package.  Included are Chip Seq, Methylation and Cage data,
downloaded from Encode.")
    (license license:gpl3+)))

(define-public r-org-hs-eg-db
  (package
    (name "r-org-hs-eg-db")
    (version "3.4.0")
    (source (origin
              (method url-fetch)
              ;; We cannot use bioconductor-uri here because this tarball is
              ;; located under "data/annotation/" instead of "bioc/".
              (uri (string-append "http://www.bioconductor.org/packages/"
                                  "release/data/annotation/src/contrib/"
                                  "org.Hs.eg.db_" version ".tar.gz"))
              (sha256
               (base32
                "19mg64pw8zcvb9yxzzyf7caz1kvdrkfsj1hd84bzq7crrh8kc4y6"))))
    (properties
     `((upstream-name . "org.Hs.eg.db")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotationdbi" ,r-annotationdbi)))
    (home-page "http://www.bioconductor.org/packages/org.Hs.eg.db/")
    (synopsis "Genome wide annotation for Human")
    (description
     "This package provides mappings from Entrez gene identifiers to various
annotations for the human genome.")
    (license license:artistic2.0)))

(define-public r-org-ce-eg-db
  (package
    (name "r-org-ce-eg-db")
    (version "3.4.0")
    (source (origin
              (method url-fetch)
              ;; We cannot use bioconductor-uri here because this tarball is
              ;; located under "data/annotation/" instead of "bioc/".
              (uri (string-append "http://www.bioconductor.org/packages/"
                                  "release/data/annotation/src/contrib/"
                                  "org.Ce.eg.db_" version ".tar.gz"))
              (sha256
               (base32
                "12llfzrrc09kj2wzbisdspv38qzkzgpsbn8kv7qkwg746k3pq436"))))
    (properties
     `((upstream-name . "org.Ce.eg.db")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotationdbi" ,r-annotationdbi)))
    (home-page "http://www.bioconductor.org/packages/org.Ce.eg.db/")
    (synopsis "Genome wide annotation for Worm")
    (description
     "This package provides mappings from Entrez gene identifiers to various
annotations for the genome of the model worm Caenorhabditis elegans.")
    (license license:artistic2.0)))

(define-public r-org-dm-eg-db
  (package
    (name "r-org-dm-eg-db")
    (version "3.4.0")
    (source (origin
              (method url-fetch)
              ;; We cannot use bioconductor-uri here because this tarball is
              ;; located under "data/annotation/" instead of "bioc/".
              (uri (string-append "http://www.bioconductor.org/packages/"
                                  "release/data/annotation/src/contrib/"
                                  "org.Dm.eg.db_" version ".tar.gz"))
              (sha256
               (base32
                "1vzbphbrh1cf7xi5cksia9xy9a9l42js2z2qsajvjxvddiphrb7j"))))
    (properties
     `((upstream-name . "org.Dm.eg.db")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotationdbi" ,r-annotationdbi)))
    (home-page "http://www.bioconductor.org/packages/org.Dm.eg.db/")
    (synopsis "Genome wide annotation for Fly")
    (description
     "This package provides mappings from Entrez gene identifiers to various
annotations for the genome of the model fruit fly Drosophila melanogaster.")
    (license license:artistic2.0)))

(define-public r-org-mm-eg-db
  (package
    (name "r-org-mm-eg-db")
    (version "3.4.0")
    (source (origin
              (method url-fetch)
              ;; We cannot use bioconductor-uri here because this tarball is
              ;; located under "data/annotation/" instead of "bioc/".
              (uri (string-append "http://www.bioconductor.org/packages/"
                                  "release/data/annotation/src/contrib/"
                                  "org.Mm.eg.db_" version ".tar.gz"))
              (sha256
               (base32
                "1lykjqjaf01fmgg3cvfcvwd5xjq6zc5vbxnm5r4l32fzvl89q50c"))))
    (properties
     `((upstream-name . "org.Mm.eg.db")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotationdbi" ,r-annotationdbi)))
    (home-page "http://www.bioconductor.org/packages/org.Mm.eg.db/")
    (synopsis "Genome wide annotation for Mouse")
    (description
     "This package provides mappings from Entrez gene identifiers to various
annotations for the genome of the model mouse Mus musculus.")
    (license license:artistic2.0)))

(define-public r-seqlogo
  (package
    (name "r-seqlogo")
    (version "1.40.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "seqLogo" version))
       (sha256
        (base32
         "18bajdl75h3039559d81rgllqqvnq8ygsfxfx081xphxs0v6xggy"))))
    (properties `((upstream-name . "seqLogo")))
    (build-system r-build-system)
    (home-page "http://bioconductor.org/packages/seqLogo")
    (synopsis "Sequence logos for DNA sequence alignments")
    (description
     "seqLogo takes the position weight matrix of a DNA sequence motif and
plots the corresponding sequence logo as introduced by Schneider and
Stephens (1990).")
    (license license:lgpl2.0+)))

(define-public r-bsgenome-hsapiens-ucsc-hg19
  (package
    (name "r-bsgenome-hsapiens-ucsc-hg19")
    (version "1.4.0")
    (source (origin
              (method url-fetch)
              ;; We cannot use bioconductor-uri here because this tarball is
              ;; located under "data/annotation/" instead of "bioc/".
              (uri (string-append "http://www.bioconductor.org/packages/"
                                  "release/data/annotation/src/contrib/"
                                  "BSgenome.Hsapiens.UCSC.hg19_"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1y0nqpk8cw5a34sd9hmin3z4v7iqm6hf6l22cl81vlbxqbjibxc8"))))
    (properties
     `((upstream-name . "BSgenome.Hsapiens.UCSC.hg19")))
    (build-system r-build-system)
    ;; As this package provides little more than a very large data file it
    ;; doesn't make sense to build substitutes.
    (arguments `(#:substitutable? #f))
    (propagated-inputs
     `(("r-bsgenome" ,r-bsgenome)))
    (home-page
     "http://www.bioconductor.org/packages/BSgenome.Hsapiens.UCSC.hg19/")
    (synopsis "Full genome sequences for Homo sapiens")
    (description
     "This package provides full genome sequences for Homo sapiens as provided
by UCSC (hg19, February 2009) and stored in Biostrings objects.")
    (license license:artistic2.0)))

(define-public r-bsgenome-mmusculus-ucsc-mm9
  (package
    (name "r-bsgenome-mmusculus-ucsc-mm9")
    (version "1.4.0")
    (source (origin
              (method url-fetch)
              ;; We cannot use bioconductor-uri here because this tarball is
              ;; located under "data/annotation/" instead of "bioc/".
              (uri (string-append "http://www.bioconductor.org/packages/"
                                  "release/data/annotation/src/contrib/"
                                  "BSgenome.Mmusculus.UCSC.mm9_"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1birqw30g2azimxpnjfzmkphan7x131yy8b9h85lfz5fjdg7841i"))))
    (properties
     `((upstream-name . "BSgenome.Mmusculus.UCSC.mm9")))
    (build-system r-build-system)
    ;; As this package provides little more than a very large data file it
    ;; doesn't make sense to build substitutes.
    (arguments `(#:substitutable? #f))
    (propagated-inputs
     `(("r-bsgenome" ,r-bsgenome)))
    (home-page
     "http://www.bioconductor.org/packages/BSgenome.Mmusculus.UCSC.mm9/")
    (synopsis "Full genome sequences for Mouse")
    (description
     "This package provides full genome sequences for Mus musculus (Mouse) as
provided by UCSC (mm9, July 2007) and stored in Biostrings objects.")
    (license license:artistic2.0)))

(define-public r-bsgenome-mmusculus-ucsc-mm10
  (package
    (name "r-bsgenome-mmusculus-ucsc-mm10")
    (version "1.4.0")
    (source (origin
              (method url-fetch)
              ;; We cannot use bioconductor-uri here because this tarball is
              ;; located under "data/annotation/" instead of "bioc/".
              (uri (string-append "http://www.bioconductor.org/packages/"
                                  "release/data/annotation/src/contrib/"
                                  "BSgenome.Mmusculus.UCSC.mm10_"
                                  version ".tar.gz"))
              (sha256
               (base32
                "12s0nm2na9brjad4rn9l7d3db2aj8qa1xvz0y1k7gk08wayb6bkf"))))
    (properties
     `((upstream-name . "BSgenome.Mmusculus.UCSC.mm10")))
    (build-system r-build-system)
    ;; As this package provides little more than a very large data file it
    ;; doesn't make sense to build substitutes.
    (arguments `(#:substitutable? #f))
    (propagated-inputs
     `(("r-bsgenome" ,r-bsgenome)))
    (home-page
     "http://www.bioconductor.org/packages/BSgenome.Mmusculus.UCSC.mm10/")
    (synopsis "Full genome sequences for Mouse")
    (description
     "This package provides full genome sequences for Mus
musculus (Mouse) as provided by UCSC (mm10, December 2011) and stored
in Biostrings objects.")
    (license license:artistic2.0)))

(define-public r-bsgenome-celegans-ucsc-ce6
  (package
    (name "r-bsgenome-celegans-ucsc-ce6")
    (version "1.4.0")
    (source (origin
              (method url-fetch)
              ;; We cannot use bioconductor-uri here because this tarball is
              ;; located under "data/annotation/" instead of "bioc/".
              (uri (string-append "http://www.bioconductor.org/packages/"
                                  "release/data/annotation/src/contrib/"
                                  "BSgenome.Celegans.UCSC.ce6_"
                                  version ".tar.gz"))
              (sha256
               (base32
                "0mqzb353xv2c3m3vkb315dkmnxkgczp7ndnknyhpgjlybyf715v9"))))
    (properties
     `((upstream-name . "BSgenome.Celegans.UCSC.ce6")))
    (build-system r-build-system)
    ;; As this package provides little more than a very large data file it
    ;; doesn't make sense to build substitutes.
    (arguments `(#:substitutable? #f))
    (propagated-inputs
     `(("r-bsgenome" ,r-bsgenome)))
    (home-page
     "http://www.bioconductor.org/packages/BSgenome.Celegans.UCSC.ce6/")
    (synopsis "Full genome sequences for Worm")
    (description
     "This package provides full genome sequences for Caenorhabditis
elegans (Worm) as provided by UCSC (ce6, May 2008) and stored in Biostrings
objects.")
    (license license:artistic2.0)))

(define-public r-bsgenome-celegans-ucsc-ce10
  (package
    (name "r-bsgenome-celegans-ucsc-ce10")
    (version "1.4.0")
    (source (origin
              (method url-fetch)
              ;; We cannot use bioconductor-uri here because this tarball is
              ;; located under "data/annotation/" instead of "bioc/".
              (uri (string-append "http://www.bioconductor.org/packages/"
                                  "release/data/annotation/src/contrib/"
                                  "BSgenome.Celegans.UCSC.ce10_"
                                  version ".tar.gz"))
              (sha256
               (base32
                "1zaym97jk4npxk14ifvwz2rvhm4zx9xgs33r9vvx9rlynp0gydrk"))))
    (properties
     `((upstream-name . "BSgenome.Celegans.UCSC.ce10")))
    (build-system r-build-system)
    ;; As this package provides little more than a very large data file it
    ;; doesn't make sense to build substitutes.
    (arguments `(#:substitutable? #f))
    (propagated-inputs
     `(("r-bsgenome" ,r-bsgenome)))
    (home-page
     "http://www.bioconductor.org/packages/BSgenome.Celegans.UCSC.ce10/")
    (synopsis "Full genome sequences for Worm")
    (description
     "This package provides full genome sequences for Caenorhabditis
elegans (Worm) as provided by UCSC (ce10, Oct 2010) and stored in Biostrings
objects.")
    (license license:artistic2.0)))

(define-public r-bsgenome-dmelanogaster-ucsc-dm3
  (package
    (name "r-bsgenome-dmelanogaster-ucsc-dm3")
    (version "1.4.0")
    (source (origin
              (method url-fetch)
              ;; We cannot use bioconductor-uri here because this tarball is
              ;; located under "data/annotation/" instead of "bioc/".
              (uri (string-append "http://www.bioconductor.org/packages/"
                                  "release/data/annotation/src/contrib/"
                                  "BSgenome.Dmelanogaster.UCSC.dm3_"
                                  version ".tar.gz"))
              (sha256
               (base32
                "19bm3lkhhkag3gnwp419211fh0cnr0x6fa0r1lr0ycwrikxdxsv8"))))
    (properties
     `((upstream-name . "BSgenome.Dmelanogaster.UCSC.dm3")))
    (build-system r-build-system)
    ;; As this package provides little more than a very large data file it
    ;; doesn't make sense to build substitutes.
    (arguments `(#:substitutable? #f))
    (propagated-inputs
     `(("r-bsgenome" ,r-bsgenome)))
    (home-page
     "http://www.bioconductor.org/packages/BSgenome.Dmelanogaster.UCSC.dm3/")
    (synopsis "Full genome sequences for Fly")
    (description
     "This package provides full genome sequences for Drosophila
melanogaster (Fly) as provided by UCSC (dm3, April 2006) and stored in
Biostrings objects.")
    (license license:artistic2.0)))

(define-public r-motifrg
  (package
    (name "r-motifrg")
    (version "1.18.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "motifRG" version))
       (sha256
        (base32
         "1pa97aj6c5f3gx4bgriw110764dj3m9h104ddi8rv2bpy41yd98d"))))
    (properties `((upstream-name . "motifRG")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biostrings" ,r-biostrings)
       ("r-bsgenome" ,r-bsgenome)
       ("r-bsgenome.hsapiens.ucsc.hg19" ,r-bsgenome-hsapiens-ucsc-hg19)
       ("r-iranges" ,r-iranges)
       ("r-seqlogo" ,r-seqlogo)
       ("r-xvector" ,r-xvector)))
    (home-page "http://bioconductor.org/packages/motifRG")
    (synopsis "Discover motifs in high throughput sequencing data")
    (description
     "This package provides tools for discriminative motif discovery in high
throughput genetic sequencing data sets using regression methods.")
    (license license:artistic2.0)))

(define-public r-qtl
 (package
  (name "r-qtl")
  (version "1.39-5")
  (source
   (origin
    (method url-fetch)
    (uri (string-append "mirror://cran/src/contrib/qtl_"
                        version ".tar.gz"))
    (sha256
     (base32
      "1grwgvyv7x0dgay1858bg7qf4wk47gpnq7qkqpcda9cn0h970d6f"))))
  (build-system r-build-system)
  (home-page "http://rqtl.org/")
  (synopsis "R package for analyzing QTL experiments in genetics")
  (description "R/qtl is an extension library for the R statistics
system.  It is used to analyze experimental crosses for identifying
genes contributing to variation in quantitative traits (so-called
quantitative trait loci, QTLs).

Using a hidden Markov model, R/qtl allows to estimate genetic maps, to
identify genotyping errors, and to perform single-QTL and two-QTL,
two-dimensional genome scans.")
  (license license:gpl3)))

(define-public r-zlibbioc
  (package
    (name "r-zlibbioc")
    (version "1.20.0")
    (source (origin
              (method url-fetch)
              (uri (bioconductor-uri "zlibbioc" version))
              (sha256
               (base32
                "0hbk90q5hl0fycfvy5nxxa4hxgglag9lzp7i0fg849bqygg5nbyq"))))
    (properties
     `((upstream-name . "zlibbioc")))
    (build-system r-build-system)
    (home-page "https://bioconductor.org/packages/zlibbioc")
    (synopsis "Provider for zlib-1.2.5 to R packages")
    (description "This package uses the source code of zlib-1.2.5 to create
libraries for systems that do not have these available via other means.")
    (license license:artistic2.0)))

(define-public r-r4rna
  (package
    (name "r-r4rna")
    (version "0.1.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "http://www.e-rna.org/r-chie/files/R4RNA_"
                           version ".tar.gz"))
       (sha256
        (base32
         "1p0i78wh76jfgmn9jphbwwaz6yy6pipzfg08xs54cxavxg2j81p5"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-optparse" ,r-optparse)
       ("r-rcolorbrewer" ,r-rcolorbrewer)))
    (home-page "http://www.e-rna.org/r-chie/index.cgi")
    (synopsis "Analysis framework for RNA secondary structure")
    (description
     "The R4RNA package aims to be a general framework for the analysis of RNA
secondary structure and comparative analysis in R.")
    (license license:gpl3+)))

(define-public r-rhtslib
  (package
    (name "r-rhtslib")
    (version "1.6.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "Rhtslib" version))
       (sha256
        (base32
         "1vk3ng61dhi3pbia1lp3gl3mlr3i1vb2lkq83qb53i9dzz128wh9"))))
    (properties `((upstream-name . "Rhtslib")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-zlibbioc" ,r-zlibbioc)))
    (inputs
     `(("zlib" ,zlib)))
    (native-inputs
     `(("autoconf" ,autoconf)))
    (home-page "https://github.com/nhayden/Rhtslib")
    (synopsis "High-throughput sequencing library as an R package")
    (description
     "This package provides the HTSlib C library for high-throughput
nucleotide sequence analysis.  The package is primarily useful to developers
of other R packages who wish to make use of HTSlib.")
    (license license:lgpl2.0+)))

(define-public r-bamsignals
  (package
    (name "r-bamsignals")
    (version "1.6.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "bamsignals" version))
       (sha256
        (base32
         "1k42gvk5mgq4la1fp0in3an2zfdz69h6522jsqhmk0f6i75kg4mb"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)
       ("r-genomicranges" ,r-genomicranges)
       ("r-iranges" ,r-iranges)
       ("r-rcpp" ,r-rcpp)
       ("r-rhtslib" ,r-rhtslib)
       ("r-zlibbioc" ,r-zlibbioc)))
    (inputs
     `(("zlib" ,zlib)))
    (home-page "http://bioconductor.org/packages/bamsignals")
    (synopsis "Extract read count signals from bam files")
    (description
     "This package allows to efficiently obtain count vectors from indexed bam
files.  It counts the number of nucleotide sequence reads in given genomic
ranges and it computes reads profiles and coverage profiles.  It also handles
paired-end data.")
    (license license:gpl2+)))

(define-public r-rcas
  (package
    (name "r-rcas")
    (version "1.0.0")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://github.com/BIMSBbioinfo/RCAS/archive/v"
                                  version ".tar.gz"))
              (file-name (string-append name "-" version ".tar.gz"))
              (sha256
               (base32
                "1h7di822ihgkhmmmlfbfz3c2dkjyjxl307i6mx8w0cwjqbna1kp6"))))
    (build-system r-build-system)
    (native-inputs
     `(("r-knitr" ,r-knitr)
       ("r-testthat" ,r-testthat)
       ;; During vignette building knitr checks that "pandoc-citeproc"
       ;; is in the PATH.
       ("ghc-pandoc-citeproc" ,ghc-pandoc-citeproc)))
    (propagated-inputs
     `(("r-data-table" ,r-data-table)
       ("r-biomart" ,r-biomart)
       ("r-org-hs-eg-db" ,r-org-hs-eg-db)
       ("r-org-ce-eg-db" ,r-org-ce-eg-db)
       ("r-org-dm-eg-db" ,r-org-dm-eg-db)
       ("r-org-mm-eg-db" ,r-org-mm-eg-db)
       ("r-bsgenome-hsapiens-ucsc-hg19" ,r-bsgenome-hsapiens-ucsc-hg19)
       ("r-bsgenome-mmusculus-ucsc-mm9" ,r-bsgenome-mmusculus-ucsc-mm9)
       ("r-bsgenome-celegans-ucsc-ce10" ,r-bsgenome-celegans-ucsc-ce10)
       ("r-bsgenome-dmelanogaster-ucsc-dm3" ,r-bsgenome-dmelanogaster-ucsc-dm3)
       ("r-topgo" ,r-topgo)
       ("r-dt" ,r-dt)
       ("r-plotly" ,r-plotly)
       ("r-motifrg" ,r-motifrg)
       ("r-genomation" ,r-genomation)
       ("r-genomicfeatures" ,r-genomicfeatures)
       ("r-rtracklayer" ,r-rtracklayer)
       ("r-rmarkdown" ,r-rmarkdown)))
    (synopsis "RNA-centric annotation system")
    (description
     "RCAS aims to be a standalone RNA-centric annotation system that provides
intuitive reports and publication-ready graphics.  This package provides the R
library implementing most of the pipeline's features.")
    (home-page "https://github.com/BIMSBbioinfo/RCAS")
    (license license:expat)))

(define-public rcas-web
  (package
    (name "rcas-web")
    (version "0.0.3")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/BIMSBbioinfo/rcas-web/"
                           "releases/download/v" version
                           "/rcas-web-" version ".tar.gz"))
       (sha256
        (base32
         "0d3my0g8i7js59n184zzzjdki7hgmhpi4rhfvk7i6jsw01ba04qq"))))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-after 'install 'wrap-executable
           (lambda* (#:key inputs outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (json   (assoc-ref inputs "guile-json"))
                    (redis  (assoc-ref inputs "guile-redis"))
                    (path   (string-append
                             json  "/share/guile/site/2.2:"
                             redis "/share/guile/site/2.2")))
               (wrap-program (string-append out "/bin/rcas-web")
                 `("GUILE_LOAD_PATH" ":" = (,path))
                 `("GUILE_LOAD_COMPILED_PATH" ":" = (,path))
                 `("R_LIBS_SITE" ":" = (,(getenv "R_LIBS_SITE")))))
             #t)))))
    (inputs
     `(("r" ,r)
       ("r-rcas" ,r-rcas)
       ("guile-next" ,guile-next)
       ("guile-json" ,guile2.2-json)
       ("guile-redis" ,guile2.2-redis)))
    (native-inputs
     `(("pkg-config" ,pkg-config)))
    (home-page "https://github.com/BIMSBbioinfo/rcas-web")
    (synopsis "Web interface for RNA-centric annotation system (RCAS)")
    (description "This package provides a simple web interface for the
@dfn{RNA-centric annotation system} (RCAS).")
    (license license:agpl3+)))

(define-public r-mutationalpatterns
  (package
    (name "r-mutationalpatterns")
    (version "1.0.0")
    (source
     (origin
       (method url-fetch)
       (uri (bioconductor-uri "MutationalPatterns" version))
       (sha256
        (base32
         "1a3c2bm0xx0q4gf98jiw74msmdf2fr8rbsdysd5ww9kqlzmsbr17"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)
       ("r-biostrings" ,r-biostrings)
       ("r-genomicranges" ,r-genomicranges)
       ("r-genomeinfodb" ,r-genomeinfodb)
       ("r-ggplot2" ,r-ggplot2)
       ("r-gridextra" ,r-gridextra)
       ("r-iranges" ,r-iranges)
       ("r-nmf" ,r-nmf)
       ("r-plyr" ,r-plyr)
       ("r-pracma" ,r-pracma)
       ("r-reshape2" ,r-reshape2)
       ("r-summarizedexperiment" ,r-summarizedexperiment)
       ("r-variantannotation" ,r-variantannotation)))
    (home-page "http://bioconductor.org/packages/MutationalPatterns/")
    (synopsis "Extract and visualize mutational patterns in genomic data")
    (description "This package provides an extensive toolset for the
characterization and visualization of a wide range of mutational patterns
in SNV base substitution data.")
    (license license:expat)))

(define-public r-wgcna
  (package
    (name "r-wgcna")
    (version "1.51")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "WGCNA" version))
       (sha256
        (base32
         "0hzvnhw76vwg8bl8x368f0c5szpwb8323bmrb3bir93i5bmfjsxx"))))
    (properties `((upstream-name . "WGCNA")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-annotationdbi" ,r-annotationdbi)
       ("r-doparallel" ,r-doparallel)
       ("r-dynamictreecut" ,r-dynamictreecut)
       ("r-fastcluster" ,r-fastcluster)
       ("r-foreach" ,r-foreach)
       ("r-go-db" ,r-go-db)
       ("r-hmisc" ,r-hmisc)
       ("r-impute" ,r-impute)
       ("r-matrixstats" ,r-matrixstats)
       ("r-preprocesscore" ,r-preprocesscore)))
    (home-page
     "http://www.genetics.ucla.edu/labs/horvath/CoexpressionNetwork/Rpackages/WGCNA/")
    (synopsis "Weighted correlation network analysis")
    (description
     "This package provides functions necessary to perform Weighted
Correlation Network Analysis on high-dimensional data.  It includes functions
for rudimentary data cleaning, construction and summarization of correlation
networks, module identification and functions for relating both variables and
modules to sample traits.  It also includes a number of utility functions for
data manipulation and visualization.")
    (license license:gpl2+)))

(define-public r-chipkernels
  (let ((commit "c9cfcacb626b1221094fb3490ea7bac0fd625372")
        (revision "1"))
    (package
      (name "r-chipkernels")
      (version (string-append "1.1-" revision "." (string-take commit 9)))
      (source
       (origin
         (method git-fetch)
         (uri (git-reference
               (url "https://github.com/ManuSetty/ChIPKernels.git")
               (commit commit)))
         (file-name (string-append name "-" version))
         (sha256
          (base32
           "14bj5qhjm1hsm9ay561nfbqi9wxsa7y487df2idsaaf6z10nw4v0"))))
      (build-system r-build-system)
      (propagated-inputs
       `(("r-iranges" ,r-iranges)
         ("r-xvector" ,r-xvector)
         ("r-biostrings" ,r-biostrings)
         ("r-bsgenome" ,r-bsgenome)
         ("r-gtools" ,r-gtools)
         ("r-genomicranges" ,r-genomicranges)
         ("r-sfsmisc" ,r-sfsmisc)
         ("r-kernlab" ,r-kernlab)
         ("r-s4vectors" ,r-s4vectors)
         ("r-biocgenerics" ,r-biocgenerics)))
      (home-page "https://github.com/ManuSetty/ChIPKernels")
      (synopsis "Build string kernels for DNA Sequence analysis")
      (description "ChIPKernels is an R package for building different string
kernels used for DNA Sequence analysis.  A dictionary of the desired kernel
must be built and this dictionary can be used for determining kernels for DNA
Sequences.")
      (license license:gpl2+))))

(define-public r-seqgl
  (package
    (name "r-seqgl")
    (version "1.1.4")
    (source
     (origin
       (method url-fetch)
       (uri (string-append "https://github.com/ManuSetty/SeqGL/"
                           "archive/" version ".tar.gz"))
       (file-name (string-append name "-" version ".tar.gz"))
       (sha256
        (base32
         "0pnk1p3sci5yipyc8xnb6jbmydpl80fld927xgnbcv104hy8h8yh"))))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biostrings" ,r-biostrings)
       ("r-chipkernels" ,r-chipkernels)
       ("r-genomicranges" ,r-genomicranges)
       ("r-spams" ,r-spams)
       ("r-wgcna" ,r-wgcna)
       ("r-fastcluster" ,r-fastcluster)))
    (home-page "https://github.com/ManuSetty/SeqGL")
    (synopsis "Group lasso for Dnase/ChIP-seq data")
    (description "SeqGL is a group lasso based algorithm to extract
transcription factor sequence signals from ChIP, DNase and ATAC-seq profiles.
This package presents a method which uses group lasso to discriminate between
bound and non bound genomic regions to accurately identify transcription
factors bound at the specific regions.")
    (license license:gpl2+)))

(define-public r-gkmsvm
  (package
    (name "r-gkmsvm")
    (version "0.71.0")
    (source
     (origin
       (method url-fetch)
       (uri (cran-uri "gkmSVM" version))
       (sha256
        (base32
         "1zpxgxmf2nd5j5wn00ps6kfxr8wxh7d1swr1rr4spq7sj5z5z0k0"))))
    (properties `((upstream-name . "gkmSVM")))
    (build-system r-build-system)
    (propagated-inputs
     `(("r-biocgenerics" ,r-biocgenerics)
       ("r-biostrings" ,r-biostrings)
       ("r-genomeinfodb" ,r-genomeinfodb)
       ("r-genomicranges" ,r-genomicranges)
       ("r-iranges" ,r-iranges)
       ("r-kernlab" ,r-kernlab)
       ("r-rcpp" ,r-rcpp)
       ("r-rocr" ,r-rocr)
       ("r-rtracklayer" ,r-rtracklayer)
       ("r-s4vectors" ,r-s4vectors)
       ("r-seqinr" ,r-seqinr)))
    (home-page "http://cran.r-project.org/web/packages/gkmSVM")
    (synopsis "Gapped-kmer support vector machine")
    (description
     "This R package provides tools for training gapped-kmer SVM classifiers
for DNA and protein sequences.  This package supports several sequence
kernels, including: gkmSVM, kmer-SVM, mismatch kernel and wildcard kernel.")
    (license license:gpl2+)))

(define-public emboss
  (package
    (name "emboss")
    (version "6.5.7")
    (source (origin
              (method url-fetch)
              (uri (string-append "ftp://emboss.open-bio.org/pub/EMBOSS/old/"
                                  (version-major+minor version) ".0/"
                                  "EMBOSS-" version ".tar.gz"))
              (sha256
               (base32
                "0vsmz96gc411yj2iyzdrsmg4l2n1nhgmp7vrgzlxx3xixv9xbf0q"))))
    (build-system gnu-build-system)
    (arguments
     `(#:configure-flags
       (list (string-append "--with-hpdf="
                            (assoc-ref %build-inputs "libharu")))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'fix-checks
           (lambda _
             ;; The PNGDRIVER tests check for the presence of libgd, libpng
             ;; and zlib, but assume that they are all found at the same
             ;; prefix.
             (substitute* "configure.in"
               (("CHECK_PNGDRIVER")
                "LIBS=\"$LIBS -lgd -lpng -lz -lm\"
AC_DEFINE([PLD_png], [1], [Define to 1 if PNG support is available])
AM_CONDITIONAL(AMPNG, true)"))
             #t))
         (add-after 'unpack 'disable-update-check
           (lambda _
             ;; At build time there is no connection to the Internet, so
             ;; looking for updates will not work.
             (substitute* "Makefile.am"
               (("\\$\\(bindir\\)/embossupdate") ""))
             #t))
         (add-before 'configure 'autogen
           (lambda _ (zero? (system* "autoreconf" "-vif")))))))
    (inputs
     `(("perl" ,perl)
       ("libpng" ,libpng)
       ("gd" ,gd)
       ("libx11" ,libx11)
       ("libharu" ,libharu)
       ("zlib" ,zlib)))
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("libtool" ,libtool)
       ("pkg-config" ,pkg-config)))
    (home-page "http://emboss.sourceforge.net")
    (synopsis "Molecular biology analysis suite")
    (description "EMBOSS is the \"European Molecular Biology Open Software
Suite\".  EMBOSS is an analysis package specially developed for the needs of
the molecular biology (e.g. EMBnet) user community.  The software
automatically copes with data in a variety of formats and even allows
transparent retrieval of sequence data from the web.  It also provides a
number of libraries for the development of software in the field of molecular
biology.  EMBOSS also integrates a range of currently available packages and
tools for sequence analysis into a seamless whole.")
    (license license:gpl2+)))

(define-public bits
  (let ((revision "1")
        (commit "3cc4567896d9d6442923da944beb704750a08d2d"))
    (package
      (name "bits")
      ;; The version is 2.13.0 even though no release archives have been
      ;; published as yet.
      (version (string-append "2.13.0-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/arq5x/bits.git")
                      (commit commit)))
                (file-name (string-append name "-" version "-checkout"))
                (sha256
                 (base32
                  "17n2kffk4kmhivd8c98g2vr6y1s23vbg4sxlxs689wni66797hbs"))))
      (build-system gnu-build-system)
      (arguments
       `(#:tests? #f ;no tests included
         #:phases
         (modify-phases %standard-phases
           (delete 'configure)
           (add-after 'unpack 'remove-cuda
             (lambda _
               (substitute* "Makefile"
                 ((".*_cuda") "")
                 (("(bits_test_intersections) \\\\" _ match) match))
               #t))
           (replace 'install
             (lambda* (#:key outputs #:allow-other-keys)
               (copy-recursively
                "bin" (string-append (assoc-ref outputs "out") "/bin"))
               #t)))))
      (inputs
       `(("gsl" ,gsl)
         ("zlib" ,zlib)))
      (home-page "https://github.com/arq5x/bits")
      (synopsis "Implementation of binary interval search algorithm")
      (description "This package provides an implementation of the
BITS (Binary Interval Search) algorithm, an approach to interval set
intersection.  It is especially suited for the comparison of diverse genomic
datasets and the exploration of large datasets of genome
intervals (e.g. genes, sequence alignments).")
      (license license:gpl2))))

(define-public piranha
  ;; There is no release tarball for the latest version.  The latest commit is
  ;; older than one year at the time of this writing.
  (let ((revision "1")
        (commit   "0466d364b71117d01e4471b74c514436cc281233"))
    (package
      (name "piranha")
      (version (string-append "1.2.1-" revision "." (string-take commit 9)))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/smithlabcode/piranha.git")
                      (commit commit)))
                (sha256
                 (base32
                  "117dc0zf20c61jam69sk4abl57ah6yi6i7qra7d7y5zrbgk12q5n"))))
      (build-system gnu-build-system)
      (arguments
       `(#:test-target "test"
         #:phases
         (modify-phases %standard-phases
           (add-after 'unpack 'copy-smithlab-cpp
             (lambda* (#:key inputs #:allow-other-keys)
               (for-each (lambda (file)
                           (install-file file "./src/smithlab_cpp/"))
                         (find-files (assoc-ref inputs "smithlab-cpp")))
               #t))
           (add-after 'install 'install-to-store
             (lambda* (#:key outputs #:allow-other-keys)
               (let* ((out (assoc-ref outputs "out"))
                      (bin (string-append out "/bin")))
                 (for-each (lambda (file)
                             (install-file file bin))
                           (find-files "bin" ".*")))
               #t)))
         #:configure-flags
         (list (string-append "--with-bam_tools_headers="
                              (assoc-ref %build-inputs "bamtools") "/include/bamtools")
               (string-append "--with-bam_tools_library="
                              (assoc-ref %build-inputs "bamtools") "/lib/bamtools"))))
      (inputs
       `(("bamtools" ,bamtools)
         ("samtools" ,samtools-0.1)
         ("gsl" ,gsl)
         ("smithlab-cpp"
          ,(let ((commit "3723e2db438c51501d0423429ff396c3035ba46a"))
             (origin
               (method git-fetch)
               (uri (git-reference
                     (url "https://github.com/smithlabcode/smithlab_cpp.git")
                     (commit commit)))
               (file-name (string-append "smithlab_cpp-" commit "-checkout"))
               (sha256
                (base32
                 "0l4gvbwslw5ngziskja41c00x1r06l3yidv7y0xw9djibhykzy0g")))))))
      (native-inputs
       `(("python" ,python-2)))
      (home-page "https://github.com/smithlabcode/piranha")
      (synopsis "Peak-caller for CLIP-seq and RIP-seq data")
      (description
       "Piranha is a peak-caller for genomic data produced by CLIP-seq and
RIP-seq experiments.  It takes input in BED or BAM format and identifies
regions of statistically significant read enrichment.  Additional covariates
may optionally be provided to further inform the peak-calling process.")
      (license license:gpl3+))))

(define-public pepr
  (package
    (name "pepr")
    (version "1.0.9")
    (source (origin
              (method url-fetch)
              (uri (string-append "https://pypi.python.org/packages/source/P"
                                  "/PePr/PePr-" version ".tar.gz"))
              (sha256
               (base32
                "0qxjfdpl1b1y53nccws2d85f6k74zwmx8y8sd9rszcqhfayx6gdx"))))
    (build-system python-build-system)
    (arguments
     `(#:python ,python-2 ; python2 only
       #:tests? #f)) ; no tests included
    (propagated-inputs
     `(("python2-numpy" ,python2-numpy)
       ("python2-scipy" ,python2-scipy)
       ("python2-pysam" ,python2-pysam)))
    (home-page "https://github.com/shawnzhangyx/PePr")
    (synopsis "Peak-calling and prioritization pipeline for ChIP-Seq data")
    (description
     "PePr is a ChIP-Seq peak calling or differential binding analysis tool
that is primarily designed for data with biological replicates.  It uses a
negative binomial distribution to model the read counts among the samples in
the same group, and look for consistent differences between ChIP and control
group or two ChIP groups run under different conditions.")
    (license license:gpl3+)))

(define-public filevercmp
  (let ((commit "1a9b779b93d0b244040274794d402106907b71b7"))
    (package
      (name "filevercmp")
      (version (string-append "0-1." (string-take commit 7)))
      (source (origin
        (method url-fetch)
        (uri (string-append "https://github.com/ekg/filevercmp/archive/"
                            commit ".tar.gz"))
        (file-name (string-append name "-" version ".tar.gz"))
        (sha256
         (base32 "0yp5jswf5j2pqc6517x277s4s6h1ss99v57kxw9gy0jkfl3yh450"))))
      (build-system gnu-build-system)
      (arguments
       `(#:tests? #f ; There are no tests to run.
         #:phases
         (modify-phases %standard-phases
           (delete 'configure) ; There is no configure phase.
           (replace 'install
             (lambda* (#:key outputs #:allow-other-keys)
               (let ((bin (string-append (assoc-ref outputs "out") "/bin")))
                 (install-file "filevercmp" bin)))))))
      (home-page "https://github.com/ekg/filevercmp")
      (synopsis "This program compares version strings")
      (description "This program compares version strings.  It intends to be a
replacement for strverscmp.")
      (license license:gpl3+))))

(define-public multiqc
  (package
    (name "multiqc")
    (version "0.6")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "multiqc" version))
       (sha256
        (base32
         "0avw11h63ldpxy5pizc3wl1wa01ha7q10wb240nggsjz3jaqvyiy"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-jinja2" ,python-jinja2)
       ("python-simplejson" ,python-simplejson)
       ("python-pyyaml" ,python-pyyaml)
       ("python-click" ,python-click)
       ("python-matplotlib" ,python-matplotlib)
       ("python-numpy" ,python-numpy)))
    (home-page "http://multiqc.info")
    (synopsis "Aggregate bioinformatics analysis reports")
    (description
     "MultiQC is a tool to aggregate bioinformatics results across many
samples into a single report.  It contains modules for a large number of
common bioinformatics tools.")
    (license license:gpl3)))
