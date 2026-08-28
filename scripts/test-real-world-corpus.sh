#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest=${BYTETRAWL_CORPUS_MANIFEST:-"$project_root/tests/real-world-corpus/manifest.json"}
corpus_root=${BYTETRAWL_CORPUS_DIR:-"$project_root/target/real-world-corpus/artifacts"}
report_dir=${BYTETRAWL_CORPUS_REPORT_DIR:-"$project_root/target/real-world-corpus/reports"}
cli="$project_root/target/debug/bytetrawl-cli"

command -v jq >/dev/null 2>&1 || {
    echo "required tool not found: jq" >&2
    exit 1
}

"$project_root/scripts/fetch-real-world-corpus.sh"
cargo build --locked -p bytetrawl-cli
mkdir -p "$report_dir"

jq -c '.artifacts[]' "$manifest" | while IFS= read -r artifact; do
    artifact_id=$(printf '%s' "$artifact" | jq -r '.id')
    file_name=$(printf '%s' "$artifact" | jq -r '.file')
    report="$report_dir/$artifact_id.json"

    echo "Inspecting $artifact_id"
    set +e
    "$cli" inspect "$corpus_root/$file_name" --depth standard --output "$report"
    status=$?
    set -e
    if [ "$status" -ne 0 ] && [ "$status" -ne 5 ]; then
        echo "$artifact_id: inspect exited with status $status" >&2
        exit "$status"
    fi
    test -s "$report"
    jq -e '.schema_version != null and .artifact != null and .run != null' "$report" >/dev/null

    printf '%s' "$artifact" | jq -r '.assertions[]' | while IFS= read -r assertion; do
        if ! jq -e "$assertion" "$report" >/dev/null; then
            echo "$artifact_id: assertion failed: $assertion" >&2
            exit 1
        fi
    done
    echo "Passed $artifact_id"
done
