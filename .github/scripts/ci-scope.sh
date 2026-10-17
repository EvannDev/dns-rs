#!/usr/bin/env bash
# Reads changed file paths, one per line, and prints "code=false" when they
# are all documentation, so CI can skip the build checks; "code=true"
# otherwise, and when there is no file to judge.
#
# Documentation: docs/, the site config, Markdown at the root, the agents'
# definitions. Markdown elsewhere may be packaged or tested (the chart's
# README), and dns-rs.example.toml is parsed by a test: both are code.
set -u
files=0
while IFS= read -r path; do
  [ -n "$path" ] || continue
  files=$((files + 1))
  case $path in
    docs/* | book.toml | .claude/agents/*.md) ;;
    */*) echo "code=true"; exit 0 ;;
    *.md) ;;
    *) echo "code=true"; exit 0 ;;
  esac
done
[ "$files" -gt 0 ] && echo "code=false" || echo "code=true"
