#!/bin/sh
# usage: sh build.sh chart_name   (compiles twice for legend-to-name refs, then exports PDF/PNG/SVG to ..)
cd "$(dirname "$0")"
n="$1"
for pass in 1 2; do
  timeout 90 pdflatex -interaction=nonstopmode -halt-on-error "$n.tex" > "$n.buildlog" 2>&1 || {
    grep -n -A4 "^!" "$n.log" | head -20; exit 1; }
done
grep -n -i -E "overfull|undefined|warning" "$n.log" | grep -v -i "font shape" | head -10
cp "$n.pdf" ../"$n.pdf"
pdftoppm -r 300 -png -singlefile ../"$n.pdf" ../"$n"
pdftocairo -svg ../"$n.pdf" ../"$n.svg"
pdfinfo ../"$n.pdf" | grep "Page size"
