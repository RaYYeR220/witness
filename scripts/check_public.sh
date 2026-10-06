#!/usr/bin/env bash
# Pre-push hygiene: no internal planning files tracked, no tool attribution in tracked content.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
status=0
bad_files=$(git ls-files | grep -E '(^|/)(BRIEF|PLAN|DESIGN|POSITIONING)\.md$|(^|/)\.superpowers/|(^|/)\.claude/|(^|/)\.remember/|(^|/)secrets/' || true)
if [ -n "$bad_files" ]; then echo "tracked files that must stay private:"; echo "$bad_files"; status=1; fi
pattern='cl''aude|anthro''pic|open''ai|\bg''pt\b|cop''ilot|generated w''ith|co-auth''ored-by|voice''over|super''powers'
hits=$(git grep -n -i -E "$pattern" -- . ':!scripts/check_public.sh' || true)
if [ -n "$hits" ]; then echo "forbidden strings found:"; echo "$hits"; status=1; fi
[ $status -eq 0 ] && echo "check_public: clean"
exit $status
