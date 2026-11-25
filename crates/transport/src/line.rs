use std::{io, mem};

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// One line of input, without its newline.
pub(crate) enum Line {
    Complete(Vec<u8>),
    /// A line longer than the limit. Its bytes were dropped as they arrived.
    TooLong,
}

/// Reads newline-terminated lines of at most `max` bytes.
pub(crate) struct LineReader<R> {
    input: R,
    max: usize,
    line: Vec<u8>,
    too_long: bool,
}

impl<R: AsyncBufRead + Unpin> LineReader<R> {
    pub(crate) const fn new(input: R, max: usize) -> Self {
        Self {
            input,
            max,
            line: Vec::new(),
            too_long: false,
        }
    }

    /// The next line, or `None` once the input has ended. A last line with
    /// no newline still counts.
    ///
    /// Cancel safe: the only await is `fill_buf`, which consumes nothing, and
    /// a partly read line is kept in `self` for the next call.
    pub(crate) async fn next_line(&mut self) -> io::Result<Option<Line>> {
        loop {
            let available = self.input.fill_buf().await?;
            let ended = available.is_empty();
            let (chunk, ends_line) = available
                .iter()
                .position(|&byte| byte == b'\n')
                .map_or((available, false), |newline| {
                    (available.split_at(newline).0, true)
                });
            let consumed = chunk.len() + usize::from(ends_line);
            if self.line.len() + chunk.len() > self.max {
                self.too_long = true;
                self.line = Vec::new();
            } else if !self.too_long {
                self.line.extend_from_slice(chunk);
            }
            self.input.consume(consumed);

            if ends_line || (ended && (self.too_long || !self.line.is_empty())) {
                return Ok(Some(self.take_line()));
            }
            if ended {
                return Ok(None);
            }
        }
    }

    /// The line read so far, leaving the reader ready for the next.
    fn take_line(&mut self) -> Line {
        let line = mem::take(&mut self.line);
        if mem::take(&mut self.too_long) {
            Line::TooLong
        } else {
            Line::Complete(line)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use tokio::io::BufReader;

    use super::{Line, LineReader};

    /// Each line of `input`, `None` for one over `max`, read through a
    /// three-byte buffer so lines span several reads.
    ///
    /// Every line but the last ends in a newline and the last has a byte, so
    /// there are never more lines than bytes. A reader that gives more is
    /// looping, and the read fails at once instead of hanging the test.
    async fn lines(input: &[u8], max: usize) -> io::Result<Vec<Option<Vec<u8>>>> {
        let mut reader = LineReader::new(BufReader::with_capacity(3, input), max);
        let mut out = Vec::new();
        while let Some(line) = reader.next_line().await? {
            if out.len() == input.len() {
                return Err(io::Error::other("more lines than the input has bytes"));
            }
            out.push(match line {
                Line::Complete(bytes) => Some(bytes),
                Line::TooLong => None,
            });
        }
        Ok(out)
    }

    #[tokio::test]
    async fn splits_on_newlines_and_keeps_a_last_line_without_one() -> io::Result<()> {
        assert_eq!(
            lines(b"a\n\nbcdef\ng", 10).await?,
            [
                Some(b"a".to_vec()),
                Some(vec![]),
                Some(b"bcdef".to_vec()),
                Some(b"g".to_vec())
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_line_over_the_limit_is_too_long_and_the_next_one_is_read() -> io::Result<()> {
        assert_eq!(
            lines(b"abcd\nabcdefgh\nab", 4).await?,
            [Some(b"abcd".to_vec()), None, Some(b"ab".to_vec())]
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_last_line_over_the_limit_is_too_long() -> io::Result<()> {
        assert_eq!(lines(b"abcde", 4).await?, [None]);
        Ok(())
    }
}
