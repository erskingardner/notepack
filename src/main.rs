use notepack::{Error, NoteBuf, NoteParser, ParsedField, StringType, pack_note_to_string, MAX_ALLOCATION_SIZE};
use std::io;

fn main() -> Result<(), Error> {
    let output_hex = std::env::args().any(|arg| arg == "--hex");

    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).expect("line");
    let trimmed = buffer.trim();

    if let Ok(packed) = NoteParser::decode(buffer.trim()) {
        if output_hex {
            println!(
                "{}",
                hex_simd::encode_to_string(&packed, hex_simd::AsciiCase::Lower)
            );
            return Ok(());
        }

        let parser = NoteParser::new(&packed);
        let mut note = NoteBuf::default();
        for field in parser {
            process_field(&mut note, field?)?;
        }
        println!("{}", serde_json::to_string(&note)?);
    } else {
        let note: NoteBuf = serde_json::from_str(trimmed).expect("decode ok");
        let packed = pack_note_to_string(&note).expect("packed ok");
        println!("{packed}");
    }

    Ok(())
}

fn process_field(note: &mut NoteBuf, field: ParsedField<'_>) -> Result<(), Error> {
    match field {
        ParsedField::Version(_v) => {}
        ParsedField::Id(id) => {
            note.id = hex_simd::encode_to_string(id, hex_simd::AsciiCase::Lower);
        }
        ParsedField::Pubkey(pk) => {
            note.pubkey = hex_simd::encode_to_string(pk, hex_simd::AsciiCase::Lower);
        }
        ParsedField::Sig(sig) => {
            note.sig = hex_simd::encode_to_string(sig, hex_simd::AsciiCase::Lower);
        }
        ParsedField::CreatedAt(ts) => {
            note.created_at = ts;
        }
        ParsedField::Kind(kind) => {
            note.kind = kind;
        }
        ParsedField::Content(content) => {
            note.content = content.to_string();
        }
        ParsedField::NumTags(n) => {
            // Cap allocation to prevent OOM from malicious payloads
            let capped = (n as usize).min(MAX_ALLOCATION_SIZE as usize);
            note.tags = Vec::with_capacity(capped);
        }
        ParsedField::NumTagElems(n) => {
            // Cap allocation to prevent OOM from malicious payloads
            let capped = (n as usize).min(MAX_ALLOCATION_SIZE as usize);
            note.tags.push(Vec::with_capacity(capped));
        }
        ParsedField::Tag(tag) => {
            let ind = note.tags.len() - 1;
            let current = &mut note.tags[ind];
            match tag {
                StringType::Bytes(bs) => {
                    current.push(hex_simd::encode_to_string(bs, hex_simd::AsciiCase::Lower));
                }
                StringType::Str(s) => {
                    current.push(s.to_string());
                }
            }
        }
    }
    Ok(())
}

/*
fn print_field(field: ParsedField<'_>) {
    match field {
        ParsedField::Version(v) => eprintln!("version: {}", v),
        ParsedField::Id(id) => eprintln!("id: {}", hex_simd::encode_to_string(id, hex_simd::AsciiCase::Lower)),
        ParsedField::Pubkey(pk) => eprintln!("pk: {}", hex_simd::encode_to_string(pk, hex_simd::AsciiCase::Lower)),
        ParsedField::Sig(sig) => eprintln!("sig: {}", hex_simd::encode_to_string(sig, hex_simd::AsciiCase::Lower)),
        ParsedField::CreatedAt(ts) => eprintln!("created_at: {}", ts),
        ParsedField::Kind(kind) => eprintln!("kind: {}", kind),
        ParsedField::Content(content) => eprintln!("content: '{}'", content),
        ParsedField::NumTags(_n) => {}
        ParsedField::NumTagElems(_n) => {
            eprintln!()
        }
        ParsedField::Tag(tag) => match tag {
            StringType::Bytes(bs) => eprint!(" b:{}", hex_simd::encode_to_string(bs, hex_simd::AsciiCase::Lower)),
            StringType::Str(s) => eprint!(" s:{}", s),
        },
    }
}
*/
