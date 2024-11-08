use asbs::{binary, Conceal, Reveal};
use std::{fs::File, io};

#[test]
fn it_conceals_and_reveals() -> io::Result<()> {
    let pattern = |i| Some(((1u8 << (i % 3)) - 1) << 1);

    let cover = File::open("tests/resources/cover")?;
    let cover_len = cover.metadata()?.len();

    let payload = b"a very very secret message";
    let payload_len = payload.len();

    let mut package = Vec::new();

    assert_eq!(
        cover_len,
        binary::Carrier::new(pattern, &mut package).conceal(payload.as_slice(), cover)? as u64,
        "package length must equal cover length",
    );

    let mut revealed_payload = Vec::with_capacity(payload_len);

    binary::Package::with_len(payload_len, pattern, package.as_slice())
        .reveal(&mut revealed_payload)?;

    assert_eq!(
        *payload, *revealed_payload,
        "revealed payload must equal expected payload"
    );

    Ok(())
}
