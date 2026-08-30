//! Portable Markdown and PDF rendering for desktop analysis exports.

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReportDocument {
    pub title: String,
    pub subtitle: String,
    pub sections: Vec<ReportSection>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReportSection {
    pub title: String,
    pub blocks: Vec<ReportBlock>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportBlock {
    Paragraph(String),
    KeyValues(Vec<(String, String)>),
    Bullets(Vec<String>),
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    Code(String),
}

pub fn render_markdown(document: &ReportDocument) -> String {
    let mut output = format!("# {}\n\n{}\n", document.title, document.subtitle);
    for section in &document.sections {
        output.push_str(&format!("\n## {}\n\n", section.title));
        for block in &section.blocks {
            match block {
                ReportBlock::Paragraph(text) => {
                    output.push_str(text);
                    output.push_str("\n\n");
                }
                ReportBlock::KeyValues(values) => {
                    for (key, value) in values {
                        output.push_str(&format!(
                            "- **{}:** {}\n",
                            markdown_inline(key),
                            markdown_inline(value)
                        ));
                    }
                    output.push('\n');
                }
                ReportBlock::Bullets(items) => {
                    for item in items {
                        output.push_str(&format!("- {}\n", markdown_inline(item)));
                    }
                    output.push('\n');
                }
                ReportBlock::Table { headers, rows } => {
                    output.push('|');
                    for header in headers {
                        output.push_str(&format!(" {} |", markdown_cell(header)));
                    }
                    output.push('\n');
                    output.push('|');
                    for _ in headers {
                        output.push_str("---|");
                    }
                    output.push('\n');
                    for row in rows {
                        output.push('|');
                        for index in 0..headers.len() {
                            output.push_str(&format!(
                                " {} |",
                                markdown_cell(row.get(index).map(String::as_str).unwrap_or(""))
                            ));
                        }
                        output.push('\n');
                    }
                    output.push('\n');
                }
                ReportBlock::Code(code) => {
                    output.push_str("```text\n");
                    output.push_str(code.trim_end());
                    output.push_str("\n```\n\n");
                }
            }
        }
    }
    output.push_str("\n---\n\n*Powered by [ByteTrawl](https://xnu.app/bytetrawl/)*\n");
    output
}

fn markdown_inline(value: &str) -> String {
    value.replace('\n', " ").replace('\r', "")
}

fn markdown_cell(value: &str) -> String {
    markdown_inline(value).replace('|', "\\|")
}

#[derive(Clone, Copy)]
enum PdfStyle {
    Title,
    Subtitle,
    Heading,
    Body,
    Code,
    Spacer,
}

struct PdfLine {
    text: String,
    style: PdfStyle,
}

/// Render a dependency-free, searchable PDF using the standard Helvetica fonts.
/// The report body is English; non-ASCII path characters use a readable fallback.
pub fn render_pdf(document: &ReportDocument) -> Vec<u8> {
    let mut lines = Vec::new();
    push_wrapped(&mut lines, &document.title, PdfStyle::Title, 54);
    push_wrapped(&mut lines, &document.subtitle, PdfStyle::Subtitle, 84);
    lines.push(PdfLine {
        text: String::new(),
        style: PdfStyle::Spacer,
    });
    for section in &document.sections {
        push_wrapped(&mut lines, &section.title, PdfStyle::Heading, 66);
        for block in &section.blocks {
            match block {
                ReportBlock::Paragraph(text) => push_wrapped(&mut lines, text, PdfStyle::Body, 94),
                ReportBlock::KeyValues(values) => {
                    for (key, value) in values {
                        push_wrapped(&mut lines, &format!("{key}: {value}"), PdfStyle::Body, 94);
                    }
                }
                ReportBlock::Bullets(items) => {
                    for item in items {
                        push_wrapped(&mut lines, &format!("- {item}"), PdfStyle::Body, 92);
                    }
                }
                ReportBlock::Table { headers, rows } => {
                    push_wrapped(&mut lines, &headers.join("  |  "), PdfStyle::Code, 104);
                    lines.push(PdfLine {
                        text: "-".repeat(104),
                        style: PdfStyle::Code,
                    });
                    for row in rows {
                        push_wrapped(&mut lines, &row.join("  |  "), PdfStyle::Code, 104);
                    }
                }
                ReportBlock::Code(code) => {
                    for line in code.lines() {
                        push_wrapped(&mut lines, line, PdfStyle::Code, 104);
                    }
                }
            }
            lines.push(PdfLine {
                text: String::new(),
                style: PdfStyle::Spacer,
            });
        }
    }

    const PAGE_HEIGHT: f32 = 842.0;
    const TOP: f32 = 780.0;
    const BOTTOM: f32 = 54.0;
    let mut pages: Vec<Vec<PdfLine>> = vec![Vec::new()];
    let mut y = TOP;
    for line in lines {
        let height = line_height(line.style);
        if y - height < BOTTOM && !pages.last().is_some_and(Vec::is_empty) {
            pages.push(Vec::new());
            y = TOP;
        }
        y -= height;
        pages.last_mut().expect("PDF page exists").push(line);
    }

    let page_count = pages.len();
    let page_object_start = 6usize;
    let mut objects = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        Vec::new(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>".to_vec(),
        format!(
            "<< /Title ({}) /Author (ByteTrawl) /Creator (ByteTrawl) >>",
            pdf_escape(&ascii_pdf(&document.title))
        )
        .into_bytes(),
    ];
    let kids = (0..page_count)
        .map(|index| format!("{} 0 R", page_object_start + index * 2))
        .collect::<Vec<_>>()
        .join(" ");
    objects[1] = format!("<< /Type /Pages /Kids [{kids}] /Count {page_count} >>").into_bytes();

    for (index, page_lines) in pages.iter().enumerate() {
        let page_id = page_object_start + index * 2;
        let content_id = page_id + 1;
        objects.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 {PAGE_HEIGHT}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_id} 0 R >>"
            )
            .into_bytes(),
        );
        let stream = pdf_page_stream(page_lines, index + 1, page_count);
        let mut content = format!("<< /Length {} >>\nstream\n", stream.len()).into_bytes();
        content.extend_from_slice(stream.as_bytes());
        content.extend_from_slice(b"\nendstream");
        objects.push(content);
    }

    let mut pdf = b"%PDF-1.4\n%ByteTrawl\n".to_vec();
    let mut offsets = vec![0usize];
    for (index, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        pdf.extend_from_slice(object);
        pdf.extend_from_slice(b"\nendobj\n");
    }
    let xref = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.into_iter().skip(1) {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /Info 5 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    pdf
}

fn push_wrapped(lines: &mut Vec<PdfLine>, text: &str, style: PdfStyle, width: usize) {
    for paragraph in text.lines() {
        let words = paragraph.split_whitespace().collect::<Vec<_>>();
        if words.is_empty() {
            lines.push(PdfLine {
                text: String::new(),
                style,
            });
            continue;
        }
        let mut current = String::new();
        for word in words {
            let characters = word.chars().collect::<Vec<_>>();
            for chunk in characters.chunks(width.max(1)) {
                let piece = chunk.iter().collect::<String>();
                if current.is_empty() {
                    current.push_str(&piece);
                } else if current.chars().count() + 1 + piece.chars().count() <= width {
                    current.push(' ');
                    current.push_str(&piece);
                } else {
                    lines.push(PdfLine {
                        text: current,
                        style,
                    });
                    current = piece;
                }
                if chunk.len() == width {
                    lines.push(PdfLine {
                        text: std::mem::take(&mut current),
                        style,
                    });
                }
            }
        }
        if !current.is_empty() {
            lines.push(PdfLine {
                text: current,
                style,
            });
        }
    }
}

fn line_height(style: PdfStyle) -> f32 {
    match style {
        PdfStyle::Title => 31.0,
        PdfStyle::Subtitle => 18.0,
        PdfStyle::Heading => 25.0,
        PdfStyle::Body => 14.0,
        PdfStyle::Code => 12.0,
        PdfStyle::Spacer => 8.0,
    }
}

fn pdf_page_stream(lines: &[PdfLine], page: usize, pages: usize) -> String {
    let mut stream = String::from("q 0.05 0.045 0.035 rg 0 0 595 842 re f Q\n");
    stream.push_str("q 0.61 0.84 0.41 rg 0 812 595 30 re f Q\n");
    let mut y = 780.0;
    for line in lines {
        let (font, size, color) = match line.style {
            PdfStyle::Title => ("F2", 22.0, "0.61 0.84 0.41"),
            PdfStyle::Subtitle => ("F1", 10.5, "0.77 0.75 0.69"),
            PdfStyle::Heading => ("F2", 15.0, "0.85 0.62 0.32"),
            PdfStyle::Body => ("F1", 9.5, "0.88 0.87 0.83"),
            PdfStyle::Code => ("F1", 7.5, "0.72 0.74 0.70"),
            PdfStyle::Spacer => ("F1", 1.0, "0.88 0.87 0.83"),
        };
        y -= line_height(line.style);
        if !line.text.is_empty() {
            stream.push_str(&format!(
                "BT /{font} {size} Tf {color} rg 42 {y:.1} Td ({}) Tj ET\n",
                pdf_escape(&ascii_pdf(&line.text))
            ));
        }
    }
    let footer = format!("Powered by ByteTrawl  |  Page {page} of {pages}");
    stream.push_str(&format!(
        "BT /F1 8 Tf 0.61 0.84 0.41 rg 42 25 Td ({}) Tj ET\n",
        pdf_escape(&footer)
    ));
    stream
}

fn ascii_pdf(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii() && !character.is_control() {
                character
            } else {
                '?'
            }
        })
        .collect()
}

fn pdf_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_document() -> ReportDocument {
        ReportDocument {
            title: "ByteTrawl Analysis Report".into(),
            subtitle: "Static inspection of Sample.app".into(),
            sections: vec![ReportSection {
                title: "Artifact Summary".into(),
                blocks: vec![
                    ReportBlock::KeyValues(vec![("Path".into(), "/Sample.app".into())]),
                    ReportBlock::Table {
                        headers: vec!["Kind".into(), "Size".into()],
                        rows: vec![vec!["Executable".into(), "42 B".into()]],
                    },
                ],
            }],
        }
    }

    #[test]
    fn markdown_contains_branding_and_tables() {
        let markdown = render_markdown(&sample_document());
        assert!(markdown.starts_with("# ByteTrawl Analysis Report"));
        assert!(markdown.contains("| Kind | Size |"));
        assert!(markdown.contains("Powered by [ByteTrawl]"));
    }

    #[test]
    fn pdf_has_valid_structure_and_branding() {
        let pdf = render_pdf(&sample_document());
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.contains("Powered by ByteTrawl"));
        assert!(text.contains("/Type /Catalog"));
        assert!(text.contains("xref"));
    }
}
