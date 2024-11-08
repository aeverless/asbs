use crate::{binary::bits, Conceal};
use std::io::{self, BufReader, BufWriter, Read, Write};

/// A binary carrier that can conceal a steganographic message.
///
/// It writes to the carrier writer in the [`conceal`][crate::Conceal::conceal] method until
/// either occurs:
///
/// 1. The writer no longer accepts any writes, which may be possible if the writer
///    is unable to contain the concealed message in its entirety, or
/// 2. The payload is empty, in which case the remainder of the cover is copied into
///    the writer, or
/// 3. The cover is empty, in which case the message remains partially written; it may
///    be possible if the cover is unable to contain the message in its concealed form.
///    In this case it is recommended to either use a bigger cover or pick a different
///    bit pattern.
///
/// # Examples
///
/// Concealing a secret message in the supplied cover:
///
/// ```no_run
/// use asbs::{binary, Conceal};
/// use std::fs::File;
///
/// let pattern = |i| Some(1u8 << (i % 3));
///
/// let cover = File::open("cover")?;
/// let payload = b"a very secret message";
///
/// let mut package = Vec::new();
///
/// let mut carrier = binary::Carrier::new(pattern, &mut package);
/// carrier.conceal(payload.as_slice(), cover)?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct Carrier<P, W>
where
    P: FnMut(usize) -> Option<u8>,
    W: Write,
{
    pattern: P,
    writer: BufWriter<W>,
}

impl<P, W> Carrier<P, W>
where
    P: FnMut(usize) -> Option<u8>,
    W: Write,
{
    /// Creates a new [`Carrier<P, W>`] with the supplied pattern and writer.
    ///
    /// This imposes no limits upon the number of bytes written.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use asbs::binary;
    /// use std::fs::File;
    ///
    /// let pattern = |i| Some(if i % 2 == 0 { 1u8 << ((i % 2) + 1) } else { 0b_0001_0010 });
    /// let package = File::create_new("package")?;
    ///
    /// let mut carrier = binary::Carrier::new(pattern, package);
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn new(pattern: P, writer: W) -> Self {
        Self {
            pattern,
            writer: BufWriter::new(writer),
        }
    }
}

impl<M, W> Conceal for &mut Carrier<M, W>
where
    M: FnMut(usize) -> Option<u8>,
    W: Write,
{
    fn conceal<P: Read, C: Read>(self, payload: P, cover: C) -> io::Result<usize> {
        let mut payload_bytes = BufReader::new(payload).bytes();

        let mut payload_byte = match payload_bytes.next() {
            Some(byte) => byte?,
            None => return Ok(0),
        };

        let mut cover = BufReader::new(cover);

        let mut bytes_written = 0usize;
        let mut bit_count = 0usize;

        for (index, cover_byte) in cover.by_ref().bytes().enumerate() {
            let Some(mask) = (self.pattern)(index) else {
                break;
            };

            let mut package_byte = cover_byte? & !mask;
            for pow in bits::Ones::from(mask) {
                package_byte |= (payload_byte & 1) << pow;
                payload_byte >>= 1;
                bit_count += 1;

                if bit_count < 8 {
                    continue;
                }

                payload_byte = match payload_bytes.next() {
                    Some(byte) => byte?,
                    None => break,
                };

                bit_count = 0;
            }

            bytes_written += self.writer.write(&[package_byte])?;

            if bit_count == 8 {
                break;
            }
        }

        bytes_written += io::copy(&mut cover, &mut self.writer)? as usize;
        self.writer.flush()?;

        Ok(bytes_written)
    }
}
