pub(super) struct Ones {
    byte: u8,
    offset: usize,
}

impl From<u8> for Ones {
    fn from(value: u8) -> Self {
        Self {
            byte: value,
            offset: 0,
        }
    }
}

impl Iterator for Ones {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == 8 {
            return None;
        }

        while self.byte & (1 << self.offset) == 0 {
            self.offset += 1;

            if self.offset == 8 {
                return None;
            }
        }

        let next_offset = self.offset + 1;
        Some(std::mem::replace(&mut self.offset, next_offset))
    }
}
