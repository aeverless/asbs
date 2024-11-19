use crate::{binary::bits, Conceal};
use std::io::{self, BufReader, BufWriter, Read, Write};

/// A binary carrier that can conceal a steganographic message.
///
/// It writes to the carrier writer in the [`conceal`][crate::Conceal::conceal] method until
/// either occurs:
///
/// 1. The specified length of the payload is reached, or
/// 2. The payload is empty, in which case the remainder of the cover is copied into
///    the writer, or
/// 3. The cover is empty or the writer no longer accepts any writes, in which case the
///    message may remain partially written; it may be possible if the message is too
///    large or the bit pattern is too sparse. In this case an error of kind
///    [`std::io::ErrorKind::WriteZero`] is returned.
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
            Some(byte) => byte?,
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

                if self.len.is_some_and(|len| {
                    payload_bytes_written > 8 && payload_bytes_written - 8 >= len
                }) {
                    break;
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

        if bit_count > 0 && payload_bytes.next().is_some() {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }

        bytes_written += io::copy(&mut cover, &mut self.writer)? as usize;

        self.writer.flush()?;

        Ok(bytes_written)
    }
}
