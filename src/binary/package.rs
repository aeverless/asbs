use crate::{binary::bits, Reveal};
use std::{
    io::{self, BufReader, BufWriter, Read, Write},
    ops::ControlFlow,
};

#[derive(Debug, PartialEq)]
enum PayloadLength {
    Bound(u64),
    Unbound,
    Embedded,
}

/// A binary package that contains a steganographic message.
///
/// It writes to the package writer in the [`reveal`][crate::Reveal::reveal] method until
/// either occurs:
///
/// 1. The underlying reader is empty, or
/// 2. The package no longer accepts writes, or
/// 3. The required length of bytes was written.
///
/// # Examples
///
/// Revealing a secret message of known length hidden within the package:
///
/// ```no_run
/// use asbs::{binary, Reveal};
/// use std::fs::File;
///
/// let mut package = binary::Package::with_len(
///     64,
///     |_| Some(0b_0010_00011),
///     File::open("package")?,
/// );
///
/// package.reveal(File::open("message")?)?;
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// Revealing a secret message hidden within the package with embedded length:
///
/// ```no_run
/// use asbs::{binary, Reveal};
/// use std::fs::File;
///
/// let mut package = binary::Package::with_embedded_len(
///     |_| Some(0b1010),
///     File::open("package")?,
/// );
///
/// package.reveal(File::open("message")?)?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct Package<P, R>
where
    P: FnMut(usize) -> Option<u8>,
    R: Read,
{
    pattern: P,
    reader: BufReader<R>,
    len: PayloadLength,
}

impl<P, R> Package<P, R>
where
    P: FnMut(usize) -> Option<u8>,
    R: Read,
{
    /// Creates a new [`Package<P, R>`] with the supplied message length, pattern, and reader.
    ///
    /// This function is useful when you know the expected message length.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use asbs::binary;
    /// use std::fs::File;
    ///
    /// let mut package = binary::Package::with_len(
    ///     32,
    ///     |i| Some(1u8 << (i % 3)),
    ///     File::open("package")?,
    /// );
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn with_len(len: usize, pattern: P, reader: R) -> Self {
        Self {
            pattern,
            reader: BufReader::new(reader),
            len: PayloadLength::Bound(len as u64),
        }
    }

    /// Creates a new [`Package<P, R>`] with the supplied pattern and reader.
    ///
    /// This function is useful if the encoded payload contains the message length as a
    /// 64-bit integer in big-endian byte order.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use asbs::binary;
    /// use std::fs::File;
    ///
    /// let mut package = binary::Package::with_embedded_len(
    ///     |i| Some(1u8 << (i % 4)),
    ///     File::open("package")?,
    /// );
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn with_embedded_len(pattern: P, reader: R) -> Self {
        Self {
            pattern,
            reader: BufReader::new(reader),
            len: PayloadLength::Embedded,
        }
    }

    /// Creates a new [`Package<P, R>`] with the supplied pattern and reader.
    ///
    /// This does not impose any limits upon the number of bytes that will be
    /// read from the package.
    ///
    /// If message length is known beforehand, use [`Package::with_len`].
    ///
    /// If message length is embedded, use [`Package::with_embedded_len`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use asbs::binary;
    /// use std::fs::File;
    ///
    /// let mut package = binary::Package::new(
    ///     |_| Some(0b1101),
    ///     File::open("package")?,
    /// );
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn new(pattern: P, reader: R) -> Self {
        Self {
            pattern,
            reader: BufReader::new(reader),
            len: PayloadLength::Unbound,
        }
    }
}

impl<M, R> Reveal for &mut Package<M, R>
where
    M: FnMut(usize) -> Option<u8>,
    R: Read,
{
    type Err = io::Error;

    fn reveal<W: Write>(self, output: W) -> io::Result<usize> {
        let mut output = BufWriter::new(output);

        let mut len_bytes = (self.len == PayloadLength::Embedded).then(|| Vec::with_capacity(8));

        let mut bytes_written = 0usize;
        let mut write_byte = |byte| -> Result<ControlFlow<()>, io::Error> {
            if let Some(bytes) = len_bytes.as_mut() {
                bytes.push(byte);

                if bytes.len() == 8 {
                    self.len = PayloadLength::Bound(u64::from_be_bytes(
                        *bytes.first_chunk::<8>().unwrap(),
                    ));

                    len_bytes = None;
                }

                return Ok(ControlFlow::Continue(()));
            }

            bytes_written += output.write(&[byte])?;

            Ok(match self.len {
                PayloadLength::Embedded => unreachable!("`PayloadLength::Embedded` is replaced with `PayloadLength::Known(n)` before reaching this"),
                PayloadLength::Unbound => ControlFlow::Continue(()),
                PayloadLength::Bound(len) => {
                    if (bytes_written as u64) < len {
                        ControlFlow::Continue(())
                    } else {
                        ControlFlow::Break(())
                    }
                }
            })
        };

        let mut payload_byte = 0;
        let mut bit_count = 0usize;
        for (index, package_byte) in self.reader.by_ref().bytes().enumerate() {
            let Some(mask) = (self.pattern)(index) else {
                break;
            };

            let package_byte = package_byte?;
            for pow in bits::Ones::from(mask) {
                payload_byte |= ((package_byte >> pow) & 1) << bit_count;
                bit_count += 1;

                if bit_count < 8 {
                    continue;
                }

                if write_byte(payload_byte)?.is_break() {
                    return Ok(bytes_written);
                }

                bit_count = 0;
                payload_byte = 0;
            }
        }

        if bit_count > 0 {
            write_byte(payload_byte)?;
        }

        Ok(bytes_written)
    }
}
