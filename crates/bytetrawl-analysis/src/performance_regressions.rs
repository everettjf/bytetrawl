use super::*;
use std::io::Write;

fn zip_fixture(directory: &Path, bytes: &[u8], method: zip::CompressionMethod) -> ArtifactNode {
    let path = directory.join("fixture.zip");
    let mut archive = zip::ZipWriter::new(File::create(&path).unwrap());
    archive
        .start_file(
            "member.bin",
            zip::write::SimpleFileOptions::default().compression_method(method),
        )
        .unwrap();
    archive.write_all(bytes).unwrap();
    archive.finish().unwrap();
    let root = open_artifact(&path, &CancellationToken::default()).unwrap();
    root.files()
        .find(|node| node.name == "member.bin")
        .unwrap()
        .clone()
}

#[test]
fn utf16_runs_are_emitted_once_and_long_previews_are_bounded() {
    for encoding in [StringEncoding::Utf16Le, StringEncoding::Utf16Be] {
        let text = format!("{}\0tail string", "a".repeat(100_000));
        let bytes: Vec<_> = text
            .encode_utf16()
            .flat_map(|unit| match encoding {
                StringEncoding::Utf16Le => unit.to_le_bytes(),
                _ => unit.to_be_bytes(),
            })
            .collect();
        let strings = extract_strings(&bytes, 4, 100_000);
        let runs: Vec<_> = strings
            .iter()
            .filter(|string| string.encoding == encoding)
            .collect();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].offset, 0);
        assert_eq!(runs[0].value.len(), 16 * 1024);
        assert_eq!(runs[1].offset, 200_002);
        assert_eq!(runs[1].value, "tail string");
    }
}

#[test]
fn streaming_zip_hash_matches_file_and_can_cancel_between_chunks() {
    let temp = tempfile::tempdir().unwrap();
    let mut state = 42u32;
    let bytes: Vec<_> = (0..3 * 1024 * 1024 + 17)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let node = zip_fixture(temp.path(), &bytes, zip::CompressionMethod::Deflated);
    let plain = temp.path().join("plain.bin");
    std::fs::write(&plain, &bytes).unwrap();
    let options = HashOptions {
        sha256: true,
        sha1: true,
        md5: true,
    };
    let actual = hash_node(&node, options, &CancellationToken::default()).unwrap();
    let expected = hash_file(&plain, options, &CancellationToken::default()).unwrap();
    assert_eq!(actual.sha256, expected.sha256);
    assert_eq!(actual.sha1, expected.sha1);
    assert_eq!(actual.md5, expected.md5);
    assert_eq!(actual.entropy, expected.entropy);
    let cancel = CancellationToken::default();
    let mut visited = 0;
    let result = ArtifactReader::open(&node)
        .unwrap()
        .visit_chunks(&cancel, |chunk| {
            visited += chunk.len();
            cancel.cancel();
        });
    assert!(matches!(result, Err(ByteTrawlError::Cancelled)));
    assert!(visited > 0 && visited <= 1024 * 1024);
}

#[test]
fn streaming_zip_rejects_corruption_and_checks_empty_members() {
    let temp = tempfile::tempdir().unwrap();
    let node = zip_fixture(temp.path(), b"integrity", zip::CompressionMethod::Stored);
    let path = temp.path().join("fixture.zip");
    let mut archive = zip::ZipArchive::new(File::open(&path).unwrap()).unwrap();
    let offset = archive.by_index(0).unwrap().data_start();
    drop(archive);
    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(b"X").unwrap();
    assert!(
        ArtifactReader::open(&node)
            .unwrap()
            .visit_chunks(&CancellationToken::default(), |_| {})
            .is_err()
    );
    let mut empty = zip_fixture(temp.path(), b"", zip::CompressionMethod::Deflated);
    ArtifactReader::open(&empty)
        .unwrap()
        .visit_chunks(&CancellationToken::default(), |_| {
            panic!("empty member produced data")
        })
        .unwrap();
    if let Some(ArtifactSource::ArchiveMember { crc32, .. }) = &mut empty.source {
        *crc32 = 1;
    }
    assert!(
        ArtifactReader::open(&empty)
            .unwrap()
            .visit_chunks(&CancellationToken::default(), |_| {})
            .is_err()
    );
}

#[test]
fn container_stream_stops_at_member_boundary_and_rejects_truncation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("container");
    std::fs::write(&path, b"HEADbodyTAIL").unwrap();
    let mut node = ArtifactNode::new("member", path.clone(), ArtifactKind::Resource);
    node.source = Some(ArtifactSource::ContainerFile {
        container: path.clone(),
        member_path: "member".into(),
        offset: 4,
        size: 4,
    });
    let reader = ArtifactReader::open(&node).unwrap();
    let mut bytes = Vec::new();
    reader
        .visit_chunks(&CancellationToken::default(), |chunk| {
            bytes.extend_from_slice(chunk)
        })
        .unwrap();
    assert_eq!(bytes, b"body");
    std::fs::write(path, b"HEADbo").unwrap();
    assert!(
        reader
            .visit_chunks(&CancellationToken::default(), |_| {})
            .is_err()
    );
}

#[test]
fn archive_cache_hits_and_invalidates_for_source_and_container_changes() {
    let temp = tempfile::tempdir().unwrap();
    let mut node = zip_fixture(temp.path(), b"cache me", zip::CompressionMethod::Stored);
    let cache = AnalysisCache::default();
    let summary = hash_node(
        &node,
        HashOptions {
            sha256: true,
            sha1: false,
            md5: false,
        },
        &CancellationToken::default(),
    )
    .unwrap();
    let cached = cache.insert_node(&node, summary).unwrap();
    assert!(Arc::ptr_eq(&cached, &cache.get_node(&node).unwrap()));
    let original = node.clone();
    if let Some(ArtifactSource::ArchiveMember { crc32, .. }) = &mut node.source {
        *crc32 ^= 1;
    }
    assert!(cache.get_node(&node).is_none());
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(temp.path().join("fixture.zip"))
        .unwrap();
    file.write_all(&[0]).unwrap();
    assert!(cache.get_node(&original).is_none());
}

#[test]
fn indexed_directory_insertion_preserves_nested_and_wide_trees() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("nested")).unwrap();
    for index in 0..500 {
        std::fs::write(
            temp.path().join(format!("nested/{index:04}.txt")),
            b"fixture",
        )
        .unwrap();
    }
    std::fs::write(temp.path().join("0000.txt"), b"root").unwrap();
    let root = open_artifact(temp.path(), &CancellationToken::default()).unwrap();
    let paths: HashSet<_> = root.files().map(|node| node.path.clone()).collect();
    assert_eq!(paths.len(), 501);
    assert!(paths.contains(&temp.path().join("0000.txt")));
    assert!(paths.contains(&temp.path().join("nested/0499.txt")));
}
