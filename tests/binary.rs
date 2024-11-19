use asbs::{binary, Conceal, Reveal};
use std::{fs::File, io};

#[test]
fn it_conceals_and_reveals_with_known_length() -> io::Result<()> {
    let pattern = |i| Some(((1u8 << (i % 3)) - 1) << 1);

    let cover = File::open("tests/resources/cover")?;
    let cover_len = cover.metadata()?.len() as usize;

    let payload = b"a very very secret message";
    let payload_len = payload.len();

    let mut package = Vec::with_capacity(cover_len);

    assert_eq!(
        cover_len,
        binary::Carrier::new(pattern, &mut package).conceal(payload.as_slice(), cover)?,
    );

    let mut revealed_payload = Vec::with_capacity(payload_len);

    binary::Package::with_len(payload_len, pattern, package.as_slice())
        .reveal(&mut revealed_payload)?;

    assert_eq!(*payload, *revealed_payload);

    Ok(())
}

#[test]
fn it_conceals_and_reveals_with_embedded_length() -> io::Result<()> {
    let pattern = |i| Some(1u8 << (i % 3));

    let cover = File::open("tests/resources/cover")?;
    let cover_len = cover.metadata()?.len() as usize;

    let payload = b"a very very secret message";

    let mut package = Vec::with_capacity(cover_len);

    assert_eq!(
        cover_len,
        binary::Carrier::with_embedded_len(payload.len(), pattern, &mut package)
            .conceal(payload.as_slice(), cover)?,
    );

    let mut revealed_payload = Vec::new();

    binary::Package::with_embedded_len(pattern, package.as_slice())
        .reveal(&mut revealed_payload)?;

    assert_eq!(*payload, *revealed_payload);

    Ok(())
}

#[test]
fn it_handles_zero_length_payload() -> io::Result<()> {
    let pattern = |_| Some(1);

    let mut package = Vec::new();

    binary::Carrier::with_embedded_len(0, pattern, &mut package)
        .conceal([].as_slice(), File::open("tests/resources/cover")?)?;

    let mut revealed_payload = Vec::new();

    binary::Package::with_embedded_len(pattern, package.as_slice())
        .reveal(&mut revealed_payload)?;

    assert!(revealed_payload.is_empty());

    Ok(())
}

#[test]
fn it_handles_partial_conceal() -> io::Result<()> {
    let pattern = |_| Some(1);

    let mut package = Vec::with_capacity(0);

    assert_eq!(
        io::ErrorKind::WriteZero,
        binary::Carrier::new(pattern, &mut package)
        .conceal(b"this message won't be written".as_slice(), [].as_slice())
            .unwrap_err()
            .kind()
    );

    Ok(())
}

#[test]
fn it_handles_partial_reveal() -> io::Result<()> {
    let pattern = |_| Some(1);

    let mut package = Vec::new();

    binary::Carrier::new(pattern, &mut package).conceal(
        b"this message won't fit".as_slice(),
        File::open("tests/resources/cover")?,
    )?;

    assert_eq!(
        io::ErrorKind::WriteZero,
        binary::Package::with_embedded_len(pattern, package.as_slice())
            .reveal([].as_mut_slice())
            .unwrap_err()
            .kind()
    );

    Ok(())
}
