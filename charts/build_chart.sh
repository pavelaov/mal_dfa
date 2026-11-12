#!/bin/sh
# usage: build_chart.sh <name>   (compile charts/src/<name>.tex, export pdf/png/svg to charts/)
set -e
cd "$(dirname "$0")"
n="$1"
pdflatex -interaction=nonstopmode -halt-on-error "$n.tex" > "$n.buildlog" 2>&1 || { grep -n "^!" -A6 "$n.log" | head -40; exit 1; }
grep -i "overfull\|warning" "$n.log" | grep -v "pgfplots.*compat\|Font shape" | head -10 || true
cp "$n.pdf" "../$n.pdf"
pdftoppm -r 300 -png -singlefile "../$n.pdf" "../$n"
pdftocairo -svg "../$n.pdf" "../$n.svg"
pdfinfo "../$n.pdf" | grep "Page size" | awk '{printf "size: %.3f x %.3f in\n", $3/72, $5/72}'
