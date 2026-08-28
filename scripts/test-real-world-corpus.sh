#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest=${BYTETRAWL_CORPUS_MANIFEST:-"$project_root/tests/real-world-corpus/manifest.json"}
corpus_root=${BYTETRAWL_CORPUS_DIR:-"$project_root/target/real-world-corpus/artifacts"}
report_dir=${BYTETRAWL_CORPUS_REPORT_DIR:-"$project_root/target/real-world-corpus/reports"}
prepared_root=${BYTETRAWL_CORPUS_PREPARED_DIR:-"$project_root/target/real-world-corpus/prepared"}
cli="$project_root/target/debug/bytetrawl-cli"

command -v jq >/dev/null 2>&1 || {
    echo "required tool not found: jq" >&2
    exit 1
}

"$project_root/scripts/fetch-real-world-corpus.sh"
cargo build --locked -p bytetrawl-cli
mkdir -p "$report_dir" "$prepared_root"

jq -c '.artifacts[]' "$manifest" | while IFS= read -r artifact; do
    artifact_id=$(printf '%s' "$artifact" | jq -r '.id')
    file_name=$(printf '%s' "$artifact" | jq -r '.file')
    depth=$(printf '%s' "$artifact" | jq -r '.depth // "standard"')
    prepare_kind=$(printf '%s' "$artifact" | jq -r '.prepare.kind // "none"')
    prepare_path=$(printf '%s' "$artifact" | jq -r '.prepare.path // empty')
    mutation_kind=$(printf '%s' "$artifact" | jq -r '.mutation.kind // "none"')
    mutation_path=$(printf '%s' "$artifact" | jq -r '.mutation.path // empty')
    host_check=$(printf '%s' "$artifact" | jq -r '.host_check // "none"')
    report="$report_dir/$artifact_id.json"
    input="$corpus_root/$file_name"

    case "$artifact_id" in
        *[!A-Za-z0-9._-]*)
            echo "unsafe artifact id: $artifact_id" >&2
            exit 1
            ;;
    esac

    if [ "$prepare_kind" != "none" ]; then
        prepared_dir="$prepared_root/$artifact_id"
        rm -rf "$prepared_dir"
        mkdir -p "$prepared_dir"
        case "$prepare_kind" in
            zip)
                command -v zipinfo >/dev/null 2>&1 || {
                    echo "required tool not found: zipinfo" >&2
                    exit 1
                }
                if zipinfo -1 "$input" | awk '
                    /^\// { bad = 1 }
                    /(^|\/)\.\.(\/|$)/ { bad = 1 }
                    index($0, "\\") { bad = 1 }
                    END { exit bad }
                '; then :; else
                    echo "$artifact_id: unsafe ZIP member path" >&2
                    exit 1
                fi
                ditto -x -k "$input" "$prepared_dir"
                ;;
            tar_gz)
                if tar -tzf "$input" | awk '
                    /^\// { bad = 1 }
                    /(^|\/)\.\.(\/|$)/ { bad = 1 }
                    END { exit bad }
                '; then :; else
                    echo "$artifact_id: unsafe tar member path" >&2
                    exit 1
                fi
                tar -xzf "$input" -C "$prepared_dir"
                ;;
            *)
                echo "$artifact_id: unsupported preparation kind: $prepare_kind" >&2
                exit 1
                ;;
        esac
        input="$prepared_dir/$prepare_path"
        if [ ! -e "$input" ]; then
            echo "$artifact_id: prepared input does not exist: $prepare_path" >&2
            exit 1
        fi
    fi

    case "$mutation_kind" in
        none) ;;
        append_nul)
            case "$mutation_path" in
                ""|/*|*\\*|../*|*/../*|*/..)
                    echo "$artifact_id: unsafe mutation path: $mutation_path" >&2
                    exit 1
                    ;;
            esac
            mutation_target="$prepared_dir/$mutation_path"
            if [ ! -f "$mutation_target" ]; then
                echo "$artifact_id: mutation target is not a file: $mutation_path" >&2
                exit 1
            fi
            printf '\000' >> "$mutation_target"
            ;;
        *)
            echo "$artifact_id: unsupported mutation kind: $mutation_kind" >&2
            exit 1
            ;;
    esac

    case "$host_check" in
        none) ;;
        macos_app_valid_notarized)
            codesign --verify --deep --strict --verbose=2 "$input"
            xcrun stapler validate "$input"
            spctl --assess --type execute --verbose=4 "$input"
            ;;
        macos_app_invalid_signature)
            set +e
            codesign --verify --deep --strict --verbose=2 "$input"
            signature_status=$?
            set -e
            if [ "$signature_status" -eq 0 ]; then
                echo "$artifact_id: mutated app unexpectedly retained a valid signature" >&2
                exit 1
            fi
            ;;
        pkgutil_signed_notarized)
            set +e
            signature_output=$(pkgutil --check-signature "$input" 2>&1)
            signature_status=$?
            set -e
            if [ "$signature_status" -ne 0 ]; then
                printf '%s\n' "$signature_output" >&2
                exit "$signature_status"
            fi
            printf '%s\n' "$signature_output" | grep -q "signed by a developer certificate issued by Apple for distribution"
            printf '%s\n' "$signature_output" | grep -q "Notarization: trusted by the Apple notary service"
            ;;
        *)
            echo "$artifact_id: unsupported host check: $host_check" >&2
            exit 1
            ;;
    esac

    echo "Inspecting $artifact_id"
    set +e
    "$cli" inspect "$input" --depth "$depth" --output "$report"
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
