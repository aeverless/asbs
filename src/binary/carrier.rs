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
///    bit pattern, or
/// 4. The specified length of the payload is reached.
///
/// # Examples
///
/// Concealing a secret message in the supplied cover:
///
/// ```no_run
/// use asbs::{binary, Conceal};
/// use std::fs::File;
///
/// let mut carrier = binary::Carrier::new(
///     |i| Some(1u8 << (i % 3)),
///     File::create("package")?,
/// );
///
/// carrier.conceal(
///     b"a very secret message".as_slice(),
///     File::open("cover")?,
/// )?;
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// Concealing a secret message in the supplied cover with its length embedded:
///
/// ```no_run
/// use asbs::{binary, Conceal};
/// use std::fs::File;
///
/// let payload = b"a very secret message";
///
/// let mut carrier = binary::Carrier::with_embedded_len(
///     payload.len(),
///     |i| Some(1u8 << (i % 3)),
///     File::create("package")?,
/// );
///
/// carrier.conceal(
///     payload.as_slice(),
///     File::open("cover")?,
/// )?;
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
    len: Option<u64>,
}

impl<P, W> Carrier<P, W>
where
    P: FnMut(usize) -> Option<u8>,
    W: Write,
{
    /// Creates a new [`Carrier<P, W>`] with the supplied length, pattern, and writer.
    ///
    /// This embeds a length into the payload and stops writing when the length is reached.
    /// The length is encoded as a 64-bit integer in big-endian byte order.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use asbs::binary;
    /// use std::fs::File;
    ///
    /// let mut carrier = binary::Carrier::with_embedded_len(
    ///     2048,
    ///     |_| Some(0b11),
    ///     File::create("package")?,
    /// );
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn with_embedded_len(len: usize, pattern: P, writer: W) -> Self {
        Self {
            pattern,
            writer: BufWriter::new(writer),
            len: Some(len as u64),
        }
    }

    /// Creates a new [`Carrier<P, W>`] with the supplied pattern and writer.
    ///
    /// This imposes no limits upon the number of bytes written and does not embed
    /// message length into the payload. See [`Carrier::with_embedded_len`] for such
    /// functionality.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use asbs::binary;
    /// use std::fs::File;
    ///
    /// let mut carrier = binary::Carrier::new(
    ///     |_| Some(0b101),
    ///     File::create("package")?,
    /// );
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn new(pattern: P, writer: W) -> Self {
        Self {
            pattern,
            writer: BufWriter::new(writer),
            len: None,
        }
    }
}

impl<M, W> Conceal for &mut Carrier<M, W>
where
    M: FnMut(usize) -> Option<u8>,
    W: Write,
{
    type Err = io::Error;

    fn conceal<P: Read, C: Read>(self, payload: P, cover: C) -> io::Result<usize> {
        let len_bytes = self
            .len
            .map(|len| len.to_be_bytes().to_vec())
            .unwrap_or_default();

        let mut cover = BufReader::new(cover);

        let mut payload_bytes = len_bytes.chain(BufReader::new(payload)).bytes();
        let mut payload_byte = match payload_bytes.next() {
            Some(byte) if self.len.is_none_or(|len| len > 0) => byte?,
            _ => return Ok(io::copy(&mut cover, &mut self.writer)? as usize),
        };

        let mut payload_bytes_written = 0u64;

        let mut bytes_written = 0;
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

                payload_bytes_written += 1;

                payload_byte = match payload_bytes.next() {
                    Some(byte) => byte?,
                    None => break,
                };

                if self.len.is_some_and(|len| {
                    payload_bytes_written > 8 && payload_bytes_written - 8 >= len
                }) {
                    break;
                }

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
