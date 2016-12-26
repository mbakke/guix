;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2015, 2016 Ludovic Courtès <ludo@gnu.org>
;;; Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
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

(define-module (guix graph)
  #:use-module (guix store)
  #:use-module (guix monads)
  #:use-module (guix records)
  #:use-module (guix sets)
  #:use-module (rnrs io ports)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match)
  #:use-module (ice-9 vlist)
  #:export (node-type
            node-type?
            node-type-identifier
            node-type-label
            node-type-edges
            node-type-convert
            node-type-name
            node-type-description

            node-edges
            node-back-edges
            traverse/depth-first
            node-transitive-edges
            node-reachable-count

            %graph-backends
            %d3js-backend
            %graphviz-backend
            graph-backend?
            graph-backend
            graph-backend-name
            graph-backend-description

            export-graph))

;;; Commentary:
;;;
;;; This module provides an abstract way to represent graphs and to manipulate
;;; them.  It comes with several such representations for packages,
;;; derivations, and store items.  It also provides a generic interface for
;;; exporting graphs in an external format, including a Graphviz
;;; implementation thereof.
;;;
;;; Code:


;;;
;;; Node types.
;;;

(define-record-type* <node-type> node-type make-node-type
  node-type?
  (identifier  node-type-identifier)              ;node -> M identifier
  (label       node-type-label)                   ;node -> string
  (edges       node-type-edges)                   ;node -> M list of nodes
  (convert     node-type-convert                  ;any -> M list of nodes
               (default (lift1 list %store-monad)))
  (name        node-type-name)                    ;string
  (description node-type-description))            ;string

(define (%node-edges type nodes cons-edge)
  (with-monad %store-monad
    (match type
      (($ <node-type> identifier label node-edges)
       (define (add-edge node edges)
         (>>= (node-edges node)
              (lambda (nodes)
                (return (fold (cut cons-edge node <> <>)
                              edges nodes)))))

       (mlet %store-monad ((edges (foldm %store-monad
                                         add-edge vlist-null nodes)))
         (return (lambda (node)
                   (reverse (vhash-foldq* cons '() node edges)))))))))

(define (node-edges type nodes)
  "Return, as a monadic value, a one-argument procedure that, given a node of TYPE,
returns its edges.  NODES is taken to be the sinks of the global graph."
  (%node-edges type nodes
               (lambda (source target edges)
                 (vhash-consq source target edges))))

(define (node-back-edges type nodes)
  "Return, as a monadic value, a one-argument procedure that, given a node of TYPE,
returns its back edges.  NODES is taken to be the sinks of the global graph."
  (%node-edges type nodes
               (lambda (source target edges)
                 (vhash-consq target source edges))))

(define (traverse/depth-first proc seed nodes node-edges)
  "Do a depth-first traversal of NODES along NODE-EDGES, calling PROC with
each node and the current result, and visiting each reachable node exactly
once.  NODES must be a list of nodes, and NODE-EDGES must be a one-argument
procedure as returned by 'node-edges' or 'node-back-edges'."
  (let loop ((nodes   (append-map node-edges nodes))
             (result  seed)
             (visited (setq)))
    (match nodes
      (()
       result)
      ((head . tail)
       (if (set-contains? visited head)
           (loop tail result visited)
           (let ((edges (node-edges head)))
             (loop (append edges tail)
                   (proc head result)
                   (set-insert head visited))))))))

(define (node-transitive-edges nodes node-edges)
  "Return the list of nodes directly or indirectly connected to NODES
according to the NODE-EDGES procedure.  NODE-EDGES must be a one-argument
procedure that, given a node, returns its list of direct dependents; it is
typically returned by 'node-edges' or 'node-back-edges'."
  (traverse/depth-first cons '() nodes node-edges))

(define (node-reachable-count nodes node-edges)
  "Return the number of nodes reachable from NODES along NODE-EDGES."
  (traverse/depth-first (lambda (_ count)
                          (+ 1 count))
                        0
                        nodes node-edges))


;;;
;;; Graphviz export.
;;;

(define-record-type <graph-backend>
  (graph-backend name description prologue epilogue node edge)
  graph-backend?
  (name         graph-backend-name)
  (description  graph-backend-description)
  (prologue     graph-backend-prologue)
  (epilogue     graph-backend-epilogue)
  (node         graph-backend-node)
  (edge         graph-backend-edge))

(define %colors
  ;; See colortbl.h in Graphviz.
  #("red" "magenta" "blue" "cyan3" "darkseagreen"
    "peachpuff4" "darkviolet" "dimgrey" "darkgoldenrod"))

(define (pop-color hint)
  "Return a Graphviz color based on HINT, an arbitrary object."
  (let ((index (hash hint (vector-length %colors))))
    (vector-ref %colors index)))

(define (emit-prologue name port)
  (format port "digraph \"Guix ~a\" {\n"
          name))
(define (emit-epilogue port)
  (display "\n}\n" port))
(define (emit-node id label port)
  (format port "  \"~a\" [label = \"~a\", shape = box, fontname = Helvetica];~%"
          id label))
(define (emit-edge id1 id2 port)
  (format port "  \"~a\" -> \"~a\" [color = ~a];~%"
          id1 id2 (pop-color id1)))

(define %graphviz-backend
  (graph-backend "graphviz"
                 "Generate graph in DOT format for use with Graphviz."
                 emit-prologue emit-epilogue
                 emit-node emit-edge))


;;;
;;; d3js export.
;;;

(define (emit-d3js-prologue name port)
  (format port "\
<!DOCTYPE html>
<html>
  <head>
    <meta charset=\"utf-8\">
    <style>
text {
  font: 10px sans-serif;
  pointer-events: none;
}
    </style>
    <script type=\"text/javascript\" src=\"~a\"></script>
  </head>
  <body>
    <script type=\"text/javascript\">
var nodes = {},
    nodeArray = [],
    links = [];
" (search-path %load-path "d3.v3.js")))

(define (emit-d3js-epilogue port)
  (format port "</script><script type=\"text/javascript\" src=\"~a\"></script></body></html>"
          (search-path %load-path "graph.js")))

(define (emit-d3js-node id label port)
  (format port "\
nodes[\"~a\"] = {\"id\": \"~a\", \"label\": \"~a\", \"index\": nodeArray.length};
nodeArray.push(nodes[\"~a\"]);~%"
          id id label id))

(define (emit-d3js-edge id1 id2 port)
  (format port "links.push({\"source\": \"~a\", \"target\": \"~a\"});~%"
          id1 id2))

(define %d3js-backend
  (graph-backend "d3js"
                 "Generate chord diagrams with d3js."
                 emit-d3js-prologue emit-d3js-epilogue
                 emit-d3js-node emit-d3js-edge))


;;;
;;; Shared.
;;;

(define %graph-backends
  (list %graphviz-backend
        %d3js-backend))

(define* (export-graph sinks port
                       #:key
                       reverse-edges? node-type
                       (backend %graphviz-backend))
  "Write to PORT the representation of the DAG with the given SINKS, using the
given BACKEND.  Use NODE-TYPE to traverse the DAG.  When REVERSE-EDGES? is
true, draw reverse arrows."
  (match backend
    (($ <graph-backend> _ _ emit-prologue emit-epilogue emit-node emit-edge)
     (emit-prologue (node-type-name node-type) port)

     (match node-type
       (($ <node-type> node-identifier node-label node-edges)
        (let loop ((nodes   sinks)
                   (visited (set)))
          (match nodes
            (()
             (with-monad %store-monad
               (emit-epilogue port)
               (store-return #t)))
            ((head . tail)
             (mlet %store-monad ((id (node-identifier head)))
               (if (set-contains? visited id)
                   (loop tail visited)
                   (mlet* %store-monad ((dependencies (node-edges head))
                                        (ids          (mapm %store-monad
                                                            node-identifier
                                                            dependencies)))
                     (emit-node id (node-label head) port)
                     (for-each (lambda (dependency dependency-id)
                                 (if reverse-edges?
                                     (emit-edge dependency-id id port)
                                     (emit-edge id dependency-id port)))
                               dependencies ids)
                     (loop (append dependencies tail)
                           (set-insert id visited)))))))))))))

;;; graph.scm ends here
