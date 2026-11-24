#!/bin/sh
# Stands in for the staged openac_bench until its CLI is final: `present --stage D --input J --expected-roots R`.
# statement_ok compares the input's presented roots (<J>.roots.json) with the expected roots file.
while [ $# -gt 0 ]; do
  case "$1" in
    --input) input="$2"; shift 2 ;;
    --expected-roots) expected="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if cmp -s "$input.roots.json" "$expected"; then ok=true; else ok=false; fi
echo "{\"ok\": true, \"statement_ok\": $ok, \"present_total_ms\": 3.0, \"show_prove_ms\": 1.0, \"verify_total_ms\": 1.0, \"statement_check_ms\": 0.1, \"roots\": {}}"
