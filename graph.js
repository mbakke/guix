// GNU Guix --- Functional package management for GNU
// Copyright © 2016 Ricardo Wurmus <rekado@elephly.net>
//
// This file is part of GNU Guix.
//
// GNU Guix is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or (at
// your option) any later version.
//
// GNU Guix is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with GNU Guix.  If not, see <http://www.gnu.org/licenses/>.

var outerRadius = Math.max(nodeArray.length * 15, 500) / 2,
    innerRadius = outerRadius - Math.min(nodeArray.length * 5, 200),
    width = outerRadius * 2,
    height = outerRadius * 2,
    colors = d3.scale.category20c(),
    matrix = [];

function neighborsOf (node) {
    return links.filter(function (e) {
        return e.source === node;
    }).map(function (e) {
       return e.target;
    });
}

function zoomed () {
    zoomer.attr("transform",
                "translate(" + d3.event.translate + ")" +
                "scale(" + d3.event.scale + ")");
}

function fade (opacity, root) {
    return function (g, i) {
        root.selectAll("g path.chord")
            .filter(function (d) {
                return d.source.index != i && d.target.index != i;
            })
            .transition()
            .style("opacity", opacity);
    };
}

// Now that we have all nodes in an object we can replace each reference
// with the actual node object.
links.forEach(function (link) {
  link.target = nodes[link.target];
  link.source = nodes[link.source];
});

// Construct a square matrix for package dependencies
nodeArray.forEach(function (d, index, arr) {
    var source = index,
        row = matrix[source];
    if (!row) {
        row = matrix[source] = [];
        for (var i = -1; ++i < arr.length;) row[i] = 0;
    }
    neighborsOf(d).forEach(function (d) { row[d.index]++; });
});

// chord layout
var chord = d3.layout.chord()
    .padding(0.01)
    .sortSubgroups(d3.descending)
    .sortChords(d3.descending)
    .matrix(matrix);

var arc = d3.svg.arc()
    .innerRadius(innerRadius)
    .outerRadius(innerRadius + 20);

var zoom = d3.behavior.zoom()
    .scaleExtent([0.1, 10])
    .on("zoom", zoomed);

var svg = d3.select("body").append("svg")
    .attr("width", "100%")
    .attr("height", "100%")
    .attr('viewBox', '0 0 ' + Math.min(width, height) + ' ' + Math.min(width, height))
    .attr('preserveAspectRatio', 'xMinYMin')
    .call(zoom);

var zoomer = svg.append("g");

var container = zoomer.append("g")
    .attr("transform", "translate(" + outerRadius + "," + outerRadius + ")");

// Group for arcs and labels
var g = container.selectAll(".group")
    .data(chord.groups)
    .enter().append("g")
    .attr("class", "group")
    .on("mouseout", fade(1, container))
    .on("mouseover", fade(0.1, container));

// Draw one segment per package
g.append("path")
    .style("fill",   function (d) { return colors(d.index); })
    .style("stroke", function (d) { return colors(d.index); })
    .attr("d", arc);

// Add circular labels
g.append("text")
    .each(function (d) { d.angle = (d.startAngle + d.endAngle) / 2; })
    .attr("dy", ".35em")
    .attr("transform", function (d) {
      return "rotate(" + (d.angle * 180 / Math.PI - 90) + ")"
          + "translate(" + (innerRadius + 26) + ")"
          + (d.angle > Math.PI ? "rotate(180)" : "");
    })
    .style("text-anchor", function (d) { return d.angle > Math.PI ? "end" : null; })
    .text(function (d) { return nodeArray[d.index].label; });

// Draw chords from source to target; color by source.
container.selectAll(".chord")
    .data(chord.chords)
    .enter().append("path")
    .attr("class", "chord")
    .style("stroke", function (d) { return d3.rgb(colors(d.source.index)).darker(); })
    .style("fill", function (d) { return colors(d.source.index); })
    .attr("d", d3.svg.chord().radius(innerRadius));
