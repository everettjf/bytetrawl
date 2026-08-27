//! Safe, host-independent executable format detection and parsing.

use bytetrawl_core::*;
use goblin::Object;
use std::path::Path;

pub const MAX_PARSE_BYTES: u64 = 512 * 1024 * 1024;

pub struct AnalysisInput<'a> {
    pub path: &'a Path,
    pub bytes: &'a [u8],
}

pub trait BinaryAnalyzer: Send + Sync {
    fn detect(&self, input: &AnalysisInput<'_>) -> bool;
    fn analyze(&self, input: &AnalysisInput<'_>) -> Result<BinaryAnalysis>;
}

pub struct PeAnalyzer;
pub struct MachOAnalyzer;
pub struct ElfAnalyzer;
pub struct UnifiedBinaryAnalyzer;

fn has_pe_header(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"MZ") || bytes.len() < 0x40 {
        return false;
    }
    let offset = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    offset
        .checked_add(4)
        .and_then(|end| bytes.get(offset..end))
        .is_some_and(|signature| signature == b"PE\0\0")
}

impl BinaryAnalyzer for PeAnalyzer {
    fn detect(&self, input: &AnalysisInput<'_>) -> bool {
        has_pe_header(input.bytes)
    }

    fn analyze(&self, input: &AnalysisInput<'_>) -> Result<BinaryAnalysis> {
        match Object::parse(input.bytes).map_err(|e| ByteTrawlError::Malformed(e.to_string()))? {
            Object::PE(pe) => analyze_pe(&pe),
            _ => Err(ByteTrawlError::Malformed("not a PE binary".into())),
        }
    }
}

impl BinaryAnalyzer for MachOAnalyzer {
    fn detect(&self, input: &AnalysisInput<'_>) -> bool {
        matches!(
            detect_format(input.bytes),
            FileFormat::MachO | FileFormat::FatMachO
        )
    }

    fn analyze(&self, input: &AnalysisInput<'_>) -> Result<BinaryAnalysis> {
        match Object::parse(input.bytes).map_err(|e| ByteTrawlError::Malformed(e.to_string()))? {
            Object::Mach(mach) => analyze_mach(mach),
            _ => Err(ByteTrawlError::Malformed("not a Mach-O binary".into())),
        }
    }
}

impl BinaryAnalyzer for ElfAnalyzer {
    fn detect(&self, input: &AnalysisInput<'_>) -> bool {
        detect_format(input.bytes) == FileFormat::Elf
    }

    fn analyze(&self, input: &AnalysisInput<'_>) -> Result<BinaryAnalysis> {
        match Object::parse(input.bytes).map_err(|e| ByteTrawlError::Malformed(e.to_string()))? {
            Object::Elf(elf) => analyze_elf(&elf, input.bytes),
            _ => Err(ByteTrawlError::Malformed("not an ELF binary".into())),
        }
    }
}

impl BinaryAnalyzer for UnifiedBinaryAnalyzer {
    fn detect(&self, input: &AnalysisInput<'_>) -> bool {
        matches!(
            detect_format(input.bytes),
            FileFormat::Pe | FileFormat::MachO | FileFormat::FatMachO | FileFormat::Elf
        )
    }
    fn analyze(&self, input: &AnalysisInput<'_>) -> Result<BinaryAnalysis> {
        let analyzers: [&dyn BinaryAnalyzer; 3] = [&PeAnalyzer, &MachOAnalyzer, &ElfAnalyzer];
        analyzers
            .into_iter()
            .find(|analyzer| analyzer.detect(input))
            .ok_or_else(|| ByteTrawlError::Malformed("not an executable binary".into()))?
            .analyze(input)
    }
}

pub fn detect_format(bytes: &[u8]) -> FileFormat {
    if has_pe_header(bytes) {
        return FileFormat::Pe;
    }
    if bytes.starts_with(b"\x7fELF") {
        return FileFormat::Elf;
    }
    if bytes.len() >= 4 {
        let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
        ) {
            return FileFormat::MachO;
        }
        if matches!(
            magic,
            [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xca, 0xfe, 0xba, 0xbf]
                | [0xbf, 0xba, 0xfe, 0xca]
        ) {
            return FileFormat::FatMachO;
        }
    }
    if bytes.starts_with(b"!<arch>\n")
        || bytes.starts_with(b"xar!")
        || bytes.starts_with(b"7z\xbc\xaf\x27\x1c")
        || bytes.starts_with(b"Rar!\x1a\x07")
        || bytes.starts_with(b"\x1f\x8b")
        || bytes.get(257..262).is_some_and(|magic| magic == b"ustar")
    {
        return FileFormat::Archive;
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        return FileFormat::Zip;
    }
    if bytes.starts_with(b"SQLite format 3\0") {
        return FileFormat::Sqlite;
    }
    if bytes.starts_with(b"bplist00") {
        return FileFormat::Plist;
    }
    if imagesize::image_type(bytes).is_ok() {
        return FileFormat::Image;
    }
    if bytes
        .get(0x8001..0x8006)
        .is_some_and(|identifier| identifier == b"CD001")
    {
        return FileFormat::DiskImage;
    }
    let prefix = bytes.get(..bytes.len().min(4096)).unwrap_or(bytes);
    if let Ok(text) = std::str::from_utf8(prefix) {
        let trimmed = text.trim_start_matches('\u{feff}').trim_start();
        let json_array = trimmed.starts_with('[')
            && trimmed
                .trim_start_matches('[')
                .trim_start()
                .as_bytes()
                .first()
                .is_some_and(|byte| {
                    matches!(
                        byte,
                        b']' | b'{' | b'"' | b'-' | b'0'..=b'9' | b't' | b'f' | b'n'
                    )
                });
        if trimmed.starts_with('{') || json_array {
            return FileFormat::Json;
        }
        if trimmed.starts_with("<?xml") || trimmed.starts_with("<plist") {
            return if trimmed.contains("<plist") {
                FileFormat::Plist
            } else {
                FileFormat::Xml
            };
        }
        if text
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        {
            return FileFormat::Text;
        }
    }
    FileFormat::UnknownBinary
}

pub fn analyze_binary(bytes: &[u8]) -> Result<BinaryAnalysis> {
    if bytes.len() as u64 > MAX_PARSE_BYTES {
        return Err(ByteTrawlError::Limit(format!(
            "binary parser limit is {MAX_PARSE_BYTES} bytes"
        )));
    }
    UnifiedBinaryAnalyzer.analyze(&AnalysisInput {
        path: Path::new("<memory>"),
        bytes,
    })
}

fn analyze_pe(pe: &goblin::pe::PE<'_>) -> Result<BinaryAnalysis> {
    let mut a = BinaryAnalysis {
        format: Some(FileFormat::Pe),
        platform: Some(BinaryPlatform::Windows),
        architecture: pe_architecture(pe.header.coff_header.machine).into(),
        bits: Some(if pe.is_64 { 64 } else { 32 }),
        entry_point: Some(pe.entry as u64),
        image_base: Some(pe.image_base),
        ..Default::default()
    };
    let dos = &pe.header.dos_header;
    for (name, value) in [
        ("DOS signature", format!("0x{:04x}", dos.signature)),
        ("DOS PE pointer", format!("0x{:x}", dos.pe_pointer)),
        ("DOS pages in file", dos.pages_in_file.to_string()),
        ("DOS bytes on last page", dos.bytes_on_last_page.to_string()),
        ("DOS relocations", dos.relocations.to_string()),
        (
            "DOS header paragraphs",
            dos.size_of_header_in_paragraphs.to_string(),
        ),
    ] {
        a.headers.insert(name.into(), value);
    }
    a.headers.insert(
        "PE signature".into(),
        format!("0x{:08x}", pe.header.signature),
    );
    a.headers.insert(
        "COFF machine".into(),
        format!("0x{:04x}", pe.header.coff_header.machine),
    );
    a.headers.insert(
        "COFF section count".into(),
        pe.header.coff_header.number_of_sections.to_string(),
    );
    a.headers.insert(
        "Compile timestamp".into(),
        format!("{}", pe.header.coff_header.time_date_stamp),
    );
    a.headers.insert(
        "Characteristics".into(),
        format!("0x{:04x}", pe.header.coff_header.characteristics),
    );
    a.headers.insert(
        "COFF symbol table offset".into(),
        format!("0x{:x}", pe.header.coff_header.pointer_to_symbol_table),
    );
    a.headers.insert(
        "COFF symbol count".into(),
        pe.header.coff_header.number_of_symbol_table.to_string(),
    );
    a.headers.insert(
        "Optional header size".into(),
        pe.header.coff_header.size_of_optional_header.to_string(),
    );
    a.headers.insert(
        "Binary kind".into(),
        if pe.is_lib {
            "Dynamic library"
        } else {
            "Executable"
        }
        .into(),
    );
    if let Some(optional) = &pe.header.optional_header {
        let standard = &optional.standard_fields;
        let windows = &optional.windows_fields;
        a.headers.insert(
            "Linker version".into(),
            format!(
                "{}.{}",
                standard.major_linker_version, standard.minor_linker_version
            ),
        );
        for (name, value) in [
            ("Optional magic", format!("0x{:04x}", standard.magic)),
            ("Code size", standard.size_of_code.to_string()),
            (
                "Initialized data size",
                standard.size_of_initialized_data.to_string(),
            ),
            (
                "Uninitialized data size",
                standard.size_of_uninitialized_data.to_string(),
            ),
            (
                "Entry point RVA",
                format!("0x{:x}", standard.address_of_entry_point),
            ),
            ("Code base RVA", format!("0x{:x}", standard.base_of_code)),
            ("Data base RVA", format!("0x{:x}", standard.base_of_data)),
            ("Image base", format!("0x{:x}", windows.image_base)),
            (
                "Operating system version",
                format!(
                    "{}.{}",
                    windows.major_operating_system_version, windows.minor_operating_system_version
                ),
            ),
            (
                "Image version",
                format!(
                    "{}.{}",
                    windows.major_image_version, windows.minor_image_version
                ),
            ),
            (
                "Subsystem version",
                format!(
                    "{}.{}",
                    windows.major_subsystem_version, windows.minor_subsystem_version
                ),
            ),
            ("Header size", windows.size_of_headers.to_string()),
            ("Checksum", format!("0x{:08x}", windows.check_sum)),
            ("Stack reserve", windows.size_of_stack_reserve.to_string()),
            ("Stack commit", windows.size_of_stack_commit.to_string()),
            ("Heap reserve", windows.size_of_heap_reserve.to_string()),
            ("Heap commit", windows.size_of_heap_commit.to_string()),
            ("Loader flags", format!("0x{:x}", windows.loader_flags)),
            (
                "Data directory count",
                windows.number_of_rva_and_sizes.to_string(),
            ),
        ] {
            a.headers.insert(name.into(), value);
        }
        a.headers
            .insert("Subsystem".into(), format!("0x{:04x}", windows.subsystem));
        a.headers.insert(
            "DLL characteristics".into(),
            format!("0x{:04x}", windows.dll_characteristics),
        );
        a.metadata.insert(
            "ASLR".into(),
            enabled_label(windows.dll_characteristics & 0x0040 != 0),
        );
        a.metadata.insert(
            "DEP / NX compatible".into(),
            enabled_label(windows.dll_characteristics & 0x0100 != 0),
        );
        a.metadata.insert(
            "Control Flow Guard".into(),
            enabled_label(windows.dll_characteristics & 0x4000 != 0),
        );
        a.headers
            .insert("Image size".into(), windows.size_of_image.to_string());
        a.headers.insert(
            "Section alignment".into(),
            windows.section_alignment.to_string(),
        );
        a.headers
            .insert("File alignment".into(), windows.file_alignment.to_string());
    }
    a.headers.insert(
        "Debug directory".into(),
        pe.debug_data.is_some().to_string(),
    );
    if let Some(debug) = &pe.debug_data {
        a.headers
            .insert("Debug entries".into(), debug.entries().count().to_string());
        for (index, entry) in debug
            .entries()
            .filter_map(std::result::Result::ok)
            .enumerate()
            .take(4096)
        {
            a.headers.insert(
                format!("Debug Entry {index}"),
                format!(
                    "type {} · version {}.{} · timestamp {} · RVA 0x{:x} · file 0x{:x} · {} bytes",
                    entry.data_type,
                    entry.major_version,
                    entry.minor_version,
                    entry.time_date_stamp,
                    entry.address_of_raw_data,
                    entry.pointer_to_raw_data,
                    entry.size_of_data
                ),
            );
        }
    }
    a.headers
        .insert("TLS directory".into(), pe.tls_data.is_some().to_string());
    a.headers.insert(
        "Relocations".into(),
        pe.relocation_data.is_some().to_string(),
    );
    if let Some(relocations) = &pe.relocation_data {
        'blocks: for block in relocations.blocks() {
            let block = block.map_err(|error| ByteTrawlError::Malformed(error.to_string()))?;
            for word in block.words() {
                let word = word.map_err(|error| ByteTrawlError::Malformed(error.to_string()))?;
                if a.relocations.len() >= 1_000_000 {
                    a.headers
                        .insert("Relocation listing".into(), "Truncated at 1,000,000".into());
                    break 'blocks;
                }
                a.relocations.push(RelocationInfo {
                    offset: block.rva as u64 + word.offset() as u64,
                    relocation_type: format!("PE base type {}", word.reloc_type()),
                    symbol: None,
                    addend: None,
                    source: format!("Block RVA 0x{:x}", block.rva),
                });
            }
        }
        a.headers
            .insert("Relocation entries".into(), a.relocations.len().to_string());
    }
    a.headers.insert(
        "Load config".into(),
        pe.load_config_data.is_some().to_string(),
    );
    a.headers
        .insert("Resources".into(), pe.resource_data.is_some().to_string());
    a.headers
        .insert("CLR metadata".into(), pe.clr_data.is_some().to_string());
    a.headers.insert(
        "Attribute certificates".into(),
        pe.certificates.len().to_string(),
    );
    if !pe.certificates.is_empty() {
        a.signature = Some(inspect_pe_authenticode(pe));
    } else {
        a.signature = Some(SignatureInfo {
            status: SignatureStatus::Unsigned,
            signer: None,
            identifier: None,
            team_id: None,
            timestamp: None,
            platform: indexmap::IndexMap::new(),
        });
    }
    if let Some(tls) = &pe.tls_data {
        a.headers
            .insert("TLS callbacks".into(), tls.callbacks.len().to_string());
        for (index, callback) in tls.callbacks.iter().enumerate().take(64) {
            a.metadata
                .insert(format!("TLS callback {index}"), format!("0x{callback:x}"));
        }
    }
    if let Some(load_config) = &pe.load_config_data {
        let directory = &load_config.directory;
        for (key, value) in [
            ("Security Cookie", directory.security_cookie),
            ("SEH Handler Count", directory.se_handler_count),
            ("Guard CF Function Count", directory.guard_cf_function_count),
            (
                "Guard Address-taken IAT Count",
                directory.guard_address_taken_iat_entry_count,
            ),
            (
                "Guard Long-jump Target Count",
                directory.guard_long_jump_target_count,
            ),
            (
                "Guard EH Continuation Count",
                directory.guard_eh_continuation_count,
            ),
        ] {
            if let Some(value) = value {
                a.metadata.insert(key.into(), format!("0x{value:x}"));
            }
        }
        if let Some(flags) = directory.guard_flags {
            a.metadata
                .insert("Load Config Guard Flags".into(), format!("0x{flags:08x}"));
        }
        if let (Some(major), Some(minor)) = (directory.major_version, directory.minor_version) {
            a.metadata
                .insert("Load Config Version".into(), format!("{major}.{minor}"));
        }
    }
    if let Some(resources) = &pe.resource_data {
        let directory = &resources.image_resource_directory;
        for (name, value) in [
            ("Resource entries", directory.count().to_string()),
            (
                "Resource named entries",
                directory.number_of_named_entries.to_string(),
            ),
            (
                "Resource ID entries",
                directory.number_of_id_entries.to_string(),
            ),
            ("Resource timestamp", directory.time_date_stamp.to_string()),
            (
                "Resource version",
                format!("{}.{}", directory.major_version, directory.minor_version),
            ),
        ] {
            a.headers.insert(name.into(), value);
        }
        if let Some(version) = resources.version_info {
            let strings = version.string_info;
            for (key, value) in [
                ("Company Name", strings.company_name()),
                ("Product Name", strings.product_name()),
                ("File Version", strings.file_version()),
                ("Product Version", strings.product_version()),
                ("Original Filename", strings.original_filename()),
            ] {
                if let Some(value) = value {
                    a.metadata.insert(key.into(), value);
                }
            }
            if let Some(fixed) = version.fixed_info {
                let file = fixed.file_version();
                let product = fixed.product_version();
                a.metadata
                    .entry("Fixed File Version".into())
                    .or_insert_with(|| {
                        format!(
                            "{}.{}.{}.{}",
                            file.major, file.minor, file.build, file.revision
                        )
                    });
                a.metadata
                    .entry("Fixed Product Version".into())
                    .or_insert_with(|| {
                        format!(
                            "{}.{}.{}.{}",
                            product.major, product.minor, product.build, product.revision
                        )
                    });
            }
        }
        if let Some(manifest) = resources.manifest_data {
            let text = String::from_utf8_lossy(manifest.data);
            a.metadata
                .insert("Manifest".into(), truncate_text(&text, 64 * 1024));
            if let Some(level) = xml_attribute(&text, "requestedExecutionLevel", "level") {
                a.metadata.insert("Requested Execution Level".into(), level);
            }
        }
    }
    if let Some(pdb) = pe
        .debug_data
        .as_ref()
        .and_then(|debug| debug.codeview_pdb70_debug_info)
    {
        let filename = pdb
            .filename
            .split(|byte| *byte == 0)
            .next()
            .unwrap_or_default();
        a.metadata.insert(
            "PDB path".into(),
            String::from_utf8_lossy(filename).into_owned(),
        );
        a.metadata.insert("PDB age".into(), pdb.age.to_string());
        a.metadata.insert(
            "Compiler hint".into(),
            "Microsoft/LLVM CodeView (PDB)".into(),
        );
    } else if let Some(pdb) = pe
        .debug_data
        .as_ref()
        .and_then(|debug| debug.codeview_pdb20_debug_info)
    {
        let filename = pdb
            .filename
            .split(|byte| *byte == 0)
            .next()
            .unwrap_or_default();
        a.metadata.insert(
            "PDB path".into(),
            String::from_utf8_lossy(filename).into_owned(),
        );
        a.metadata.insert("PDB age".into(), pdb.age.to_string());
        a.metadata
            .insert("PDB signature".into(), format!("0x{:08x}", pdb.signature));
        a.metadata.insert(
            "Compiler hint".into(),
            "Microsoft CodeView (NB10 PDB)".into(),
        );
    }
    for section in &pe.sections {
        a.sections.push(SectionInfo {
            name: section.name().unwrap_or("<invalid>").to_string(),
            address: section.virtual_address as u64,
            offset: section.pointer_to_raw_data as u64,
            size: section.size_of_raw_data as u64,
            flags: format!(
                "{}{}{} · 0x{:08x}",
                if section.characteristics & 0x4000_0000 != 0 {
                    "R"
                } else {
                    "-"
                },
                if section.characteristics & 0x8000_0000 != 0 {
                    "W"
                } else {
                    "-"
                },
                if section.characteristics & 0x2000_0000 != 0 {
                    "X"
                } else {
                    "-"
                },
                section.characteristics
            ),
            entropy: None,
        });
    }
    for import in &pe.imports {
        a.imports.push(SymbolInfo {
            name: import.name.to_string(),
            address: Some(import.rva as u64),
            library: Some(import.dll.to_string()),
        });
    }
    for export in &pe.exports {
        a.exports.push(SymbolInfo {
            name: export.name.unwrap_or("<ordinal>").to_string(),
            address: Some(export.rva as u64),
            library: None,
        });
    }
    a.dependencies
        .extend(pe.libraries.iter().map(|name| Dependency {
            name: (*name).to_string(),
            path: None,
            status: DependencyStatus::Unknown,
        }));
    Ok(a)
}

fn inspect_pe_authenticode(pe: &goblin::pe::PE<'_>) -> SignatureInfo {
    use authenticode::AuthenticodeSignature;
    use sha1::Sha1;
    use sha2::{Digest, Sha256, Sha384, Sha512};

    let mut platform = indexmap::IndexMap::new();
    platform.insert(
        "Embedded certificate records".into(),
        pe.certificates.len().to_string(),
    );
    let mut signer = None;
    let mut timestamp = None;
    let mut digest_match = None;
    let mut parsed = 0usize;
    for (record_index, record) in pe.certificates.iter().enumerate() {
        match AuthenticodeSignature::from_bytes(record.certificate) {
            Ok(signature) => {
                parsed += 1;
                let oid = signature.digest_algorithm().oid.to_string();
                let embedded_digest = signature.digest();
                let calculated = match oid.as_str() {
                    "1.3.14.3.2.26" => {
                        let mut hasher = Sha1::new();
                        for range in pe.authenticode_ranges() {
                            hasher.update(range);
                        }
                        Some(hasher.finalize().to_vec())
                    }
                    "2.16.840.1.101.3.4.2.1" => {
                        let mut hasher = Sha256::new();
                        for range in pe.authenticode_ranges() {
                            hasher.update(range);
                        }
                        Some(hasher.finalize().to_vec())
                    }
                    "2.16.840.1.101.3.4.2.2" => {
                        let mut hasher = Sha384::new();
                        for range in pe.authenticode_ranges() {
                            hasher.update(range);
                        }
                        Some(hasher.finalize().to_vec())
                    }
                    "2.16.840.1.101.3.4.2.3" => {
                        let mut hasher = Sha512::new();
                        for range in pe.authenticode_ranges() {
                            hasher.update(range);
                        }
                        Some(hasher.finalize().to_vec())
                    }
                    _ => None,
                };
                platform.insert(format!("Signature {record_index} Digest Algorithm"), oid);
                platform.insert(
                    format!("Signature {record_index} Embedded Digest"),
                    hex::encode(embedded_digest),
                );
                if let Some(calculated) = calculated {
                    let matches = calculated.as_slice() == embedded_digest;
                    digest_match = Some(digest_match.unwrap_or(true) && matches);
                    platform.insert(
                        format!("Signature {record_index} File Digest"),
                        hex::encode(calculated),
                    );
                    platform.insert(
                        format!("Signature {record_index} Digest Match"),
                        if matches { "Yes" } else { "No" }.into(),
                    );
                }
                let signer_info = signature.signer_info();
                platform.insert(
                    format!("Signature {record_index} Algorithm"),
                    signer_info.signature_algorithm.oid.to_string(),
                );
                if signer_info
                    .unsigned_attrs
                    .as_ref()
                    .is_some_and(|attributes| {
                        attributes.iter().any(|attribute| {
                            matches!(
                                attribute.oid.to_string().as_str(),
                                "1.2.840.113549.1.9.6" | "1.3.6.1.4.1.311.3.3.1"
                            )
                        })
                    })
                {
                    timestamp = Some("Embedded timestamp token present".into());
                }
                let certificates = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    signature
                        .certificates()
                        .map(|certificate| {
                            (
                                certificate.tbs_certificate.subject.to_string(),
                                certificate.tbs_certificate.issuer.to_string(),
                                format!("{:?}", certificate.tbs_certificate.validity),
                            )
                        })
                        .collect::<Vec<_>>()
                }));
                if let Ok(certificates) = certificates {
                    for (certificate_index, (subject, issuer, validity)) in
                        certificates.into_iter().enumerate()
                    {
                        signer.get_or_insert_with(|| subject.clone());
                        platform
                            .insert(format!("Certificate {certificate_index} Subject"), subject);
                        platform.insert(format!("Certificate {certificate_index} Issuer"), issuer);
                        platform.insert(
                            format!("Certificate {certificate_index} Validity"),
                            validity,
                        );
                    }
                } else {
                    platform.insert(
                        format!("Signature {record_index} Certificate Chain"),
                        "Contained unsupported certificate choices".into(),
                    );
                }
            }
            Err(error) => {
                platform.insert(
                    format!("Signature {record_index} Parse Error"),
                    error.to_string(),
                );
            }
        }
    }
    platform.insert("Parsed Authenticode Signatures".into(), parsed.to_string());
    platform.insert(
        "Trust Verification".into(),
        "Embedded chain shown; OS publisher trust and revocation are not verified on this host"
            .into(),
    );
    SignatureInfo {
        status: if digest_match == Some(false) {
            SignatureStatus::Invalid
        } else {
            SignatureStatus::Unknown
        },
        signer,
        identifier: None,
        team_id: None,
        timestamp,
        platform,
    }
}

fn pe_architecture(machine: u16) -> &'static str {
    match machine {
        0x014c => "x86",
        0x8664 => "x86_64",
        0x01c0 | 0x01c4 => "ARM",
        0xaa64 => "ARM64",
        0x0200 => "IA-64",
        _ => "Unknown",
    }
}

fn analyze_elf(elf: &goblin::elf::Elf<'_>, bytes: &[u8]) -> Result<BinaryAnalysis> {
    use goblin::elf::{note::NT_GNU_BUILD_ID, program_header};

    let mut a = BinaryAnalysis {
        format: Some(FileFormat::Elf),
        platform: Some(BinaryPlatform::Linux),
        architecture: elf_architecture(elf.header.e_machine).into(),
        bits: Some(if elf.is_64 { 64 } else { 32 }),
        endianness: Some(if elf.little_endian { "Little" } else { "Big" }.into()),
        entry_point: Some(elf.entry),
        interpreter: elf.interpreter.map(str::to_owned),
        ..Default::default()
    };
    a.headers
        .insert("ELF type".into(), format!("0x{:04x}", elf.header.e_type));
    a.headers.insert(
        "Binary kind".into(),
        match elf.header.e_type {
            goblin::elf::header::ET_EXEC => "Executable",
            goblin::elf::header::ET_DYN if elf.soname.is_some() && elf.interpreter.is_none() => {
                "Dynamic library"
            }
            goblin::elf::header::ET_DYN => "Executable (position independent)",
            goblin::elf::header::ET_REL => "Relocatable object",
            goblin::elf::header::ET_CORE => "Core dump",
            _ => "Unknown",
        }
        .into(),
    );
    a.headers
        .insert("Machine".into(), format!("0x{:04x}", elf.header.e_machine));
    a.headers.insert(
        "Program headers".into(),
        elf.program_headers.len().to_string(),
    );
    a.headers.insert(
        "Section headers".into(),
        elf.section_headers.len().to_string(),
    );
    a.headers.insert(
        "Dynamic entries".into(),
        elf.dynamic
            .as_ref()
            .map(|d| d.dyns.len())
            .unwrap_or_default()
            .to_string(),
    );
    a.headers.insert(
        "Relocations".into(),
        (elf.dynrelas.len()
            + elf.dynrels.len()
            + elf.pltrelocs.len()
            + elf
                .shdr_relocs
                .iter()
                .map(|(_, relocations)| relocations.len())
                .sum::<usize>())
        .to_string(),
    );
    if let Some(dynamic) = &elf.dynamic {
        for (index, entry) in dynamic.dyns.iter().enumerate().take(100_000) {
            a.headers.insert(
                format!("Dynamic Entry {index}"),
                format!(
                    "{} (0x{:x}) · value 0x{:x}",
                    goblin::elf::dynamic::tag_to_str(entry.d_tag),
                    entry.d_tag,
                    entry.d_val
                ),
            );
        }
    }
    for (source, relocations) in [
        ("Dynamic RELA", &elf.dynrelas),
        ("Dynamic REL", &elf.dynrels),
        ("PLT", &elf.pltrelocs),
    ] {
        for relocation in relocations.iter() {
            if a.relocations.len() >= 1_000_000 {
                break;
            }
            let symbol = elf
                .dynsyms
                .get(relocation.r_sym)
                .and_then(|symbol| elf.dynstrtab.get_at(symbol.st_name))
                .filter(|name| !name.is_empty())
                .map(str::to_owned);
            a.relocations.push(RelocationInfo {
                offset: relocation.r_offset,
                relocation_type: format!("ELF type {}", relocation.r_type),
                symbol,
                addend: relocation.r_addend,
                source: source.into(),
            });
        }
    }
    for (section_index, relocations) in &elf.shdr_relocs {
        for relocation in relocations.iter() {
            if a.relocations.len() >= 1_000_000 {
                break;
            }
            let symbol = elf
                .syms
                .get(relocation.r_sym)
                .and_then(|symbol| elf.strtab.get_at(symbol.st_name))
                .filter(|name| !name.is_empty())
                .map(str::to_owned);
            a.relocations.push(RelocationInfo {
                offset: relocation.r_offset,
                relocation_type: format!("ELF type {}", relocation.r_type),
                symbol,
                addend: relocation.r_addend,
                source: format!("Section {section_index}"),
            });
        }
    }
    if a.relocations.len() >= 1_000_000 {
        a.headers
            .insert("Relocation listing".into(), "Truncated at 1,000,000".into());
    }
    if let Some(soname) = elf.soname {
        a.metadata.insert("SONAME".into(), soname.into());
    }
    for (index, ph) in elf.program_headers.iter().enumerate() {
        a.headers.insert(
            format!("Program Header {index}"),
            format!(
                "{} · {}{}{} · off 0x{:x} · vaddr 0x{:x} · filesz 0x{:x} · memsz 0x{:x} · align 0x{:x}",
                program_header::pt_to_str(ph.p_type),
                if ph.p_flags & program_header::PF_R != 0 { "R" } else { "-" },
                if ph.p_flags & program_header::PF_W != 0 { "W" } else { "-" },
                if ph.p_flags & program_header::PF_X != 0 { "X" } else { "-" },
                ph.p_offset,
                ph.p_vaddr,
                ph.p_filesz,
                ph.p_memsz,
                ph.p_align
            ),
        );
        if ph.p_type == program_header::PT_GNU_STACK {
            a.metadata.insert(
                "GNU Stack".into(),
                if ph.p_flags & program_header::PF_X != 0 {
                    "Executable"
                } else {
                    "Non-executable"
                }
                .into(),
            );
        }
        if ph.p_type == program_header::PT_GNU_RELRO {
            a.metadata.insert("GNU RELRO".into(), "Present".into());
        }
    }
    if let Some(notes) = elf.iter_note_headers(bytes) {
        for note in notes.flatten() {
            if note.name == "GNU" && note.n_type == NT_GNU_BUILD_ID {
                a.metadata.insert("Build ID".into(), hex_bytes(note.desc));
            }
        }
    }
    for sh in &elf.section_headers {
        a.sections.push(SectionInfo {
            name: elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or("<unnamed>")
                .into(),
            address: sh.sh_addr,
            offset: sh.sh_offset,
            size: sh.sh_size,
            flags: format!(
                "R{}{} · flags 0x{:x} · type 0x{:x} · link {} · align 0x{:x}",
                if sh.sh_flags & 0x1 != 0 { "W" } else { "-" },
                if sh.sh_flags & 0x4 != 0 { "X" } else { "-" },
                sh.sh_flags,
                sh.sh_type,
                sh.sh_link,
                sh.sh_addralign
            ),
            entropy: None,
        });
    }
    for lib in &elf.libraries {
        a.dependencies.push(Dependency {
            name: (*lib).into(),
            path: None,
            status: DependencyStatus::Unknown,
        });
    }
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name).filter(|s| !s.is_empty()) {
            let item = SymbolInfo {
                name: name.into(),
                address: Some(sym.st_value),
                library: None,
            };
            if sym.st_shndx == 0 {
                a.imports.push(item);
            } else {
                a.exports.push(item);
            }
        }
    }
    for sym in elf.syms.iter() {
        if let Some(name) = elf
            .strtab
            .get_at(sym.st_name)
            .filter(|name| !name.is_empty())
        {
            a.symbols.push(SymbolInfo {
                name: name.into(),
                address: Some(sym.st_value),
                library: None,
            });
        }
    }
    if let Some(rpath) = elf.rpaths.first() {
        a.metadata.insert("RPATH".into(), (*rpath).into());
    }
    if let Some(runpath) = elf.runpaths.first() {
        a.metadata.insert("RUNPATH".into(), (*runpath).into());
    }
    Ok(a)
}

fn elf_architecture(machine: u16) -> &'static str {
    match machine {
        3 => "x86",
        8 => "MIPS",
        20 => "PowerPC",
        21 => "PowerPC64",
        40 => "ARM",
        62 => "x86_64",
        183 => "AArch64",
        243 => "RISC-V",
        _ => "Unknown",
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn truncate_text(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.into();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n… truncated …", &text[..end])
}

fn xml_attribute(text: &str, element: &str, attribute: &str) -> Option<String> {
    use quick_xml::{Reader, events::Event};

    let mut reader = Reader::from_str(text);
    let matches_name = |qualified: &[u8], expected: &str| {
        qualified
            .rsplit(|byte| *byte == b':')
            .next()
            .is_some_and(|local| local == expected.as_bytes())
    };
    loop {
        match reader.read_event() {
            Ok(Event::Start(tag) | Event::Empty(tag))
                if matches_name(tag.name().as_ref(), element) =>
            {
                for candidate in tag.attributes().with_checks(true) {
                    let candidate = candidate.ok()?;
                    if matches_name(candidate.key.as_ref(), attribute) {
                        return candidate
                            .decode_and_unescape_value(reader.decoder())
                            .ok()
                            .map(|value| value.into_owned());
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => return None,
            Ok(_) => {}
        }
    }
}

fn analyze_mach(mach: goblin::mach::Mach<'_>) -> Result<BinaryAnalysis> {
    use goblin::mach::Mach;
    match mach {
        Mach::Binary(macho) => analyze_macho_binary(&macho),
        Mach::Fat(fat) => {
            use goblin::mach::SingleArch;

            let mut a = BinaryAnalysis {
                format: Some(FileFormat::FatMachO),
                platform: Some(BinaryPlatform::MacOs),
                architecture: "Universal".into(),
                ..Default::default()
            };
            for (index, arch) in fat.iter_arches().enumerate() {
                let arch = arch.map_err(|e| ByteTrawlError::Malformed(e.to_string()))?;
                let info = SliceInfo {
                    architecture: format!(
                        "{} (subtype {})",
                        macho_architecture(arch.cputype()),
                        arch.cpusubtype()
                    ),
                    offset: arch.offset as u64,
                    size: arch.size as u64,
                };
                a.slices.push(info.clone());
                if let SingleArch::MachO(macho) = fat
                    .get(index)
                    .map_err(|error| ByteTrawlError::Malformed(error.to_string()))?
                {
                    let mut slice = analyze_macho_binary(&macho)?;
                    for section in &mut slice.sections {
                        section.offset = section.offset.saturating_add(info.offset);
                    }
                    slice
                        .metadata
                        .insert("Universal Slice".into(), info.architecture.clone());
                    slice.metadata.insert(
                        "Slice File Range".into(),
                        format!(
                            "0x{:x}..0x{:x}",
                            info.offset,
                            info.offset.saturating_add(info.size)
                        ),
                    );
                    a.slice_analyses.push(slice);
                }
            }
            Ok(a)
        }
    }
}

fn analyze_macho_binary(m: &goblin::mach::MachO<'_>) -> Result<BinaryAnalysis> {
    use goblin::mach::header;

    use goblin::mach::load_command::{CommandVariant, cmd_to_str};

    let mut a = BinaryAnalysis {
        format: Some(FileFormat::MachO),
        platform: Some(BinaryPlatform::MacOs),
        architecture: format!(
            "{} (subtype {})",
            macho_architecture(m.header.cputype()),
            m.header.cpusubtype()
        ),
        bits: Some(if m.is_64 { 64 } else { 32 }),
        entry_point: Some(m.entry),
        ..Default::default()
    };
    a.headers
        .insert("File type".into(), format!("0x{:x}", m.header.filetype));
    a.headers.insert(
        "Binary kind".into(),
        match m.header.filetype {
            header::MH_EXECUTE => "Executable",
            header::MH_DYLIB | header::MH_DYLIB_STUB => "Dynamic library",
            header::MH_BUNDLE => "Plugin bundle",
            header::MH_OBJECT => "Relocatable object",
            header::MH_CORE => "Core dump",
            _ => "Other Mach-O",
        }
        .into(),
    );
    a.headers
        .insert("Load commands".into(), m.header.ncmds.to_string());
    a.headers
        .insert("Flags".into(), format!("0x{:x}", m.header.flags));
    a.headers.insert(
        "Endianness".into(),
        if m.little_endian { "Little" } else { "Big" }.into(),
    );
    a.headers.insert(
        "Entry command".into(),
        if m.old_style_entry {
            "LC_UNIXTHREAD"
        } else {
            "LC_MAIN"
        }
        .into(),
    );
    if let Some(name) = m.name {
        a.metadata.insert("Install name".into(), name.into());
    }
    if !m.rpaths.is_empty() {
        a.metadata.insert("RPATH".into(), m.rpaths.join("; "));
    }
    let mut has_code_signature = false;
    for (index, command) in m.load_commands.iter().enumerate().take(100_000) {
        a.headers.insert(
            format!("Load Command {index}"),
            format!(
                "{} · offset 0x{:x} · {} bytes",
                cmd_to_str(command.command.cmd()),
                command.offset,
                command.command.cmdsize()
            ),
        );
        match command.command {
            CommandVariant::Uuid(uuid) => {
                let bytes = uuid.uuid;
                a.metadata.insert(
                    "UUID".into(),
                    format!(
                        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
                        bytes[13], bytes[14], bytes[15]
                    ),
                );
            }
            CommandVariant::Main(main) => {
                a.headers.insert(
                    "LC_MAIN file offset".into(),
                    format!("0x{:x}", main.entryoff),
                );
                a.headers
                    .insert("Initial stack size".into(), main.stacksize.to_string());
            }
            CommandVariant::CodeSignature(signature) => {
                has_code_signature = true;
                a.headers.insert(
                    "Code signature blob".into(),
                    format!(
                        "offset 0x{:x}, {} bytes",
                        signature.dataoff, signature.datasize
                    ),
                );
            }
            CommandVariant::BuildVersion(version) => {
                a.metadata
                    .insert("Build platform".into(), version.platform.to_string());
                a.metadata
                    .insert("Minimum OS".into(), macho_version(version.minos));
                a.metadata.insert("SDK".into(), macho_version(version.sdk));
                a.metadata
                    .insert("Build tools".into(), version.ntools.to_string());
            }
            CommandVariant::VersionMinMacosx(version)
            | CommandVariant::VersionMinIphoneos(version)
            | CommandVariant::VersionMinTvos(version)
            | CommandVariant::VersionMinWatchos(version) => {
                a.metadata
                    .entry("Minimum OS".into())
                    .or_insert_with(|| macho_version(version.version));
                a.metadata
                    .entry("SDK".into())
                    .or_insert_with(|| macho_version(version.sdk));
            }
            _ => {}
        }
    }
    a.signature = Some(SignatureInfo {
        status: if has_code_signature {
            SignatureStatus::Unknown
        } else {
            SignatureStatus::Unsigned
        },
        signer: None,
        identifier: None,
        team_id: None,
        timestamp: None,
        platform: indexmap::IndexMap::from([(
            "Static Code Signature Blob".into(),
            if has_code_signature {
                "Present; select Signature for host verification"
            } else {
                "Not present"
            }
            .into(),
        )]),
    });
    for segment in &m.segments {
        let segname = segment.name().unwrap_or("<invalid>");
        a.segments.push(SegmentInfo {
            name: segname.into(),
            address: segment.vmaddr,
            virtual_size: segment.vmsize,
            file_offset: segment.fileoff,
            file_size: segment.filesize,
            protections: format!(
                "init {}{}{} · max {}{}{}",
                if segment.initprot & 0x1 != 0 {
                    "R"
                } else {
                    "-"
                },
                if segment.initprot & 0x2 != 0 {
                    "W"
                } else {
                    "-"
                },
                if segment.initprot & 0x4 != 0 {
                    "X"
                } else {
                    "-"
                },
                if segment.maxprot & 0x1 != 0 { "R" } else { "-" },
                if segment.maxprot & 0x2 != 0 { "W" } else { "-" },
                if segment.maxprot & 0x4 != 0 { "X" } else { "-" },
            ),
            section_count: segment.nsects as usize,
        });
        for (section, _data) in segment
            .sections()
            .map_err(|e| ByteTrawlError::Malformed(e.to_string()))?
        {
            a.sections.push(SectionInfo {
                name: format!("{segname},{}", section.name().unwrap_or("<invalid>")),
                address: section.addr,
                offset: section.offset as u64,
                size: section.size,
                flags: format!(
                    "{}{}{} · section 0x{:x}",
                    if segment.initprot & 0x1 != 0 {
                        "R"
                    } else {
                        "-"
                    },
                    if segment.initprot & 0x2 != 0 {
                        "W"
                    } else {
                        "-"
                    },
                    if segment.initprot & 0x4 != 0 {
                        "X"
                    } else {
                        "-"
                    },
                    section.flags
                ),
                entropy: None,
            });
        }
    }
    for lib in &m.libs {
        a.dependencies.push(Dependency {
            name: (*lib).into(),
            path: None,
            status: DependencyStatus::Unknown,
        });
    }
    for export in m
        .exports()
        .map_err(|e| ByteTrawlError::Malformed(e.to_string()))?
    {
        a.exports.push(SymbolInfo {
            name: export.name,
            address: Some(export.offset),
            library: None,
        });
    }
    for import in m
        .imports()
        .map_err(|e| ByteTrawlError::Malformed(e.to_string()))?
    {
        a.imports.push(SymbolInfo {
            name: import.name.into(),
            address: Some(import.offset),
            library: Some(import.dylib.into()),
        });
    }
    for symbol in m.symbols() {
        if let Ok((name, nlist)) = symbol
            && !name.is_empty()
        {
            a.symbols.push(SymbolInfo {
                name: name.into(),
                address: Some(nlist.n_value),
                library: None,
            });
        }
    }
    Ok(a)
}

fn macho_version(value: u32) -> String {
    format!("{}.{}.{}", value >> 16, (value >> 8) & 0xff, value & 0xff)
}

fn macho_architecture(cpu: u32) -> &'static str {
    match cpu {
        7 => "x86",
        0x0100_0007 => "x86_64",
        12 => "ARM",
        0x0100_000c => "arm64",
        18 => "PowerPC",
        0x0100_0012 => "PowerPC64",
        _ => "Unknown",
    }
}

fn enabled_label(enabled: bool) -> String {
    if enabled { "Enabled" } else { "Disabled" }.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    #[test]
    fn detects_magic_without_extension() {
        assert_eq!(detect_format(b"\x7fELFrest"), FileFormat::Elf);
        assert_ne!(detect_format(b"MZnot-really-complete"), FileFormat::Pe);
        let mut pe = vec![0u8; 0x84];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert_eq!(detect_format(&pe), FileFormat::Pe);
        assert_eq!(detect_format(b"bplist00rest"), FileFormat::Plist);
        assert_eq!(
            detect_format(b"[workspace]\nmembers = []"),
            FileFormat::Text
        );
        assert_eq!(detect_format(b"[[bin]]\nname = \"tool\""), FileFormat::Text);
        assert_eq!(detect_format(br#"[{"name":"fixture"}]"#), FileFormat::Json);
        assert_eq!(detect_format(b"xar!rest"), FileFormat::Archive);
        assert_eq!(
            detect_format(b"7z\xbc\xaf\x27\x1crest"),
            FileFormat::Archive
        );
        let mut iso = vec![0u8; 0x8006];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(detect_format(&iso), FileFormat::DiskImage);
    }

    #[test]
    fn concrete_analyzers_only_claim_their_own_format() {
        let elf = AnalysisInput {
            path: Path::new("fixture"),
            bytes: b"\x7fELFrest",
        };
        assert!(ElfAnalyzer.detect(&elf));
        assert!(!PeAnalyzer.detect(&elf));
        assert!(!MachOAnalyzer.detect(&elf));

        let dos_only = AnalysisInput {
            path: Path::new("fixture"),
            bytes: b"MZnot-a-pe-image",
        };
        assert!(!PeAnalyzer.detect(&dos_only));
    }
    #[test]
    fn truncated_untrusted_inputs_fail_without_panicking() {
        for prefix in [
            b"MZ".as_slice(),
            b"\x7fELF".as_slice(),
            b"\xcf\xfa\xed\xfe".as_slice(),
        ] {
            for length in 0..256 {
                let mut bytes = vec![0u8; length];
                let copy = prefix.len().min(bytes.len());
                bytes[..copy].copy_from_slice(&prefix[..copy]);
                let outcome = std::panic::catch_unwind(|| analyze_binary(&bytes));
                assert!(
                    outcome.is_ok(),
                    "parser panicked for {}-byte input",
                    bytes.len()
                );
            }
        }
    }
    #[test]
    fn adversarial_header_offsets_never_panic() {
        let magics: [&[u8]; 5] = [
            b"MZ",
            b"\x7fELF",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
            b"\xfe\xed\xfa\xcf",
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for case in 0..2_000usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let length = 8 + (state as usize % 4_089);
            let mut bytes = vec![0u8; length];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let magic = magics[case % magics.len()];
            bytes[..magic.len()].copy_from_slice(magic);
            if magic == b"MZ" && bytes.len() >= 0x40 {
                bytes[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
            }
            let outcome = std::panic::catch_unwind(|| analyze_binary(&bytes));
            assert!(
                outcome.is_ok(),
                "parser panicked for adversarial case {case}"
            );
        }
    }
    #[test]
    fn reads_requested_execution_level() {
        let manifest =
            r#"<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>"#;
        assert_eq!(
            xml_attribute(manifest, "requestedExecutionLevel", "level").as_deref(),
            Some("requireAdministrator")
        );
    }
    #[test]
    fn analyzes_cross_platform_zig_fixtures_when_available() {
        if Command::new("zig").arg("version").output().is_err() {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "bytetrawl-cross-format-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::create_dir_all(&root).expect("create cross-format fixture directory");
        let source = root.join("fixture.c");
        std::fs::write(
            &source,
            b"#ifdef _WIN32\n__declspec(dllexport) int exported_value(void){return 42;}\n#endif\nint main(void){return 0;}\n",
        )
        .expect("write cross-format fixture source");
        let cache = root.join("zig-cache");
        let compile = |target: &str, output: &Path, extra: &[&str]| {
            let mut command = Command::new("zig");
            command
                .arg("cc")
                .arg("-target")
                .arg(target)
                .args(extra)
                .arg(&source)
                .arg("-o")
                .arg(output)
                .env("ZIG_GLOBAL_CACHE_DIR", &cache)
                .env("ZIG_LOCAL_CACHE_DIR", root.join("zig-local-cache"))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            command.status().expect("run Zig cross compiler").success()
        };

        let executable = root.join("fixture.exe");
        let library = root.join("fixture.dll");
        let elf = root.join("fixture-elf");
        if !compile("x86_64-windows-gnu", &executable, &[]) {
            let _ = std::fs::remove_dir_all(root);
            return;
        }
        assert!(compile("x86_64-windows-gnu", &library, &["-shared"]));
        assert!(compile("x86_64-linux-musl", &elf, &[]));

        let pe = analyze_binary(&std::fs::read(&executable).expect("read PE fixture"))
            .expect("analyze PE fixture");
        assert_eq!(pe.platform, Some(BinaryPlatform::Windows));
        assert_eq!(pe.architecture, "x86_64");
        assert_eq!(
            pe.headers.get("Binary kind").map(String::as_str),
            Some("Executable")
        );
        assert!(pe.headers.contains_key("DOS PE pointer"));
        assert!(!pe.sections.is_empty());

        let dll = analyze_binary(&std::fs::read(&library).expect("read DLL fixture"))
            .expect("analyze DLL fixture");
        assert_eq!(
            dll.headers.get("Binary kind").map(String::as_str),
            Some("Dynamic library")
        );
        assert!(dll.exports.iter().any(|item| item.name == "exported_value"));

        let elf = analyze_binary(&std::fs::read(&elf).expect("read ELF fixture"))
            .expect("analyze ELF fixture");
        assert_eq!(elf.platform, Some(BinaryPlatform::Linux));
        assert_eq!(elf.architecture, "x86_64");
        assert!(elf.headers.contains_key("ELF type"));
        assert!(!elf.sections.is_empty());

        let _ = std::fs::remove_dir_all(root);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn parses_the_real_host_test_binary() {
        let executable = std::env::current_exe().expect("locate test executable");
        let bytes = std::fs::read(executable).expect("read test executable");
        let analysis = analyze_binary(&bytes).expect("analyze Mach-O test executable");
        assert!(matches!(
            analysis.format,
            Some(FileFormat::MachO | FileFormat::FatMachO)
        ));
        assert_eq!(analysis.platform, Some(BinaryPlatform::MacOs));
        assert!(!analysis.architecture.is_empty());
        let selected = analysis.slice_analyses.first().unwrap_or(&analysis);
        assert!(!selected.segments.is_empty());
        assert!(
            selected
                .headers
                .keys()
                .any(|key| key.starts_with("Load Command "))
        );
    }
}
