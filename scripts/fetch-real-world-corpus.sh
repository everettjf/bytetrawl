#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest=${BYTETRAWL_CORPUS_MANIFEST:-"$project_root/tests/real-world-corpus/manifest.json"}
corpus_dir=${BYTETRAWL_CORPUS_DIR:-"$project_root/target/real-world-corpus/artifacts"}

for tool in curl jq shasum; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "required tool not found: $tool" >&2
        exit 1
    }
done

mkdir -p "$corpus_dir"

jq -c '.artifacts[]' "$manifest" | while IFS= read -r artifact; do
    artifact_id=$(printf '%s' "$artifact" | jq -r '.id')
    file_name=$(printf '%s' "$artifact" | jq -r '.file')
    url=$(printf '%s' "$artifact" | jq -r '.url')
    expected_bytes=$(printf '%s' "$artifact" | jq -r '.bytes')
    expected_sha256=$(printf '%s' "$artifact" | jq -r '.sha256')
    destination="$corpus_dir/$file_name"

    valid=false
    if [ -f "$destination" ]; then
        actual_bytes=$(wc -c < "$destination" | tr -d ' ')
        actual_sha256=$(shasum -a 256 "$destination" | awk '{print $1}')
        if [ "$actual_bytes" = "$expected_bytes" ] && [ "$actual_sha256" = "$expected_sha256" ]; then
            valid=true
        fi
    fi

    if [ "$valid" = false ]; then
        temporary="$destination.part"
        rm -f "$temporary"
        echo "Downloading $artifact_id"
        curl --fail --location --retry 3 --retry-all-errors --output "$temporary" "$url"
        actual_bytes=$(wc -c < "$temporary" | tr -d ' ')
        actual_sha256=$(shasum -a 256 "$temporary" | awk '{print $1}')
        if [ "$actual_bytes" != "$expected_bytes" ]; then
            echo "$artifact_id: expected $expected_bytes bytes, received $actual_bytes" >&2
            rm -f "$temporary"
            exit 1
        fi
        if [ "$actual_sha256" != "$expected_sha256" ]; then
            echo "$artifact_id: SHA-256 mismatch" >&2
            rm -f "$temporary"
            exit 1
        fi
        mv "$temporary" "$destination"
    fi

    echo "Verified $artifact_id ($expected_sha256)"
done
