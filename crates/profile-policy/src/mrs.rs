//! Validate compact Mihomo MRS v1 without materializing domains or expanding IP ranges.
//! The decoded/window budget is unchanged from the original MRS reader (16 MiB).
use std::{
    collections::VecDeque,
    io::{Cursor, Read},
};
const LIMIT: usize = 16 * 1024 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Limit,
}
#[derive(Debug, Clone, Copy)]
pub struct Metadata {
    pub behavior: &'static str,
    pub rule_count: usize,
    pub decoded_bytes: usize,
    pub entries: usize,
}
fn take<'a>(data: &mut &'a [u8], n: usize) -> Result<&'a [u8], Error> {
    let (a, b) = data.split_at_checked(n).ok_or(Error::Invalid)?;
    *data = b;
    Ok(a)
}
fn number(data: &mut &[u8]) -> Result<usize, Error> {
    let n = u64::from_be_bytes(take(data, 8)?.try_into().map_err(|_| Error::Invalid)?);
    if n > LIMIT as u64 {
        return Err(Error::Limit);
    }
    Ok(n as usize)
}
fn words<'a>(data: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let n = number(data)?;
    take(data, n.checked_mul(8).ok_or(Error::Limit)?)
}
fn bit(words: &[u8], index: usize) -> Result<bool, Error> {
    let at = index / 64 * 8;
    let word = u64::from_be_bytes(
        words
            .get(at..at + 8)
            .ok_or(Error::Invalid)?
            .try_into()
            .map_err(|_| Error::Invalid)?,
    );
    Ok(word & (1 << (index % 64)) != 0)
}
fn padding(words: &[u8], bits: usize) -> Result<(), Error> {
    if words.len() != bits.div_ceil(64) * 8 {
        return Err(Error::Invalid);
    }
    for i in bits..words.len() * 8 {
        if bit(words, i)? {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
fn window(mut data: &[u8]) -> Result<(), Error> {
    if take(&mut data, 4)? != [0x28, 0xb5, 0x2f, 0xfd] {
        return Err(Error::Invalid);
    }
    let descriptor = take(&mut data, 1)?[0];
    if descriptor & 0x18 != 0 {
        return Err(Error::Invalid);
    }
    let single = descriptor & 0x20 != 0;
    if !single {
        let w = take(&mut data, 1)?[0];
        let base = 1u64.checked_shl(10 + (w >> 3) as u32).ok_or(Error::Limit)?;
        if base.saturating_add(base / 8 * u64::from(w & 7)) > LIMIT as u64 {
            return Err(Error::Limit);
        }
    }
    if take(&mut data, [0, 1, 2, 4][(descriptor & 3) as usize])?
        .iter()
        .any(|b| *b != 0)
    {
        return Err(Error::Invalid);
    }
    let n = match descriptor >> 6 {
        0 => usize::from(single),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if n != 0 {
        let mut b = [0; 8];
        b[..n].copy_from_slice(take(&mut data, n)?);
        if u64::from_le_bytes(b).saturating_add(if n == 2 { 256 } else { 0 }) > LIMIT as u64 {
            return Err(Error::Limit);
        }
    }
    Ok(())
}
pub fn inspect(compressed: &[u8]) -> Result<Metadata, Error> {
    if compressed.len() > 8 * 1024 * 1024 {
        return Err(Error::Limit);
    }
    window(compressed)?;
    let mut cursor = Cursor::new(compressed);
    let mut decoded = Vec::new();
    ruzstd::decoding::StreamingDecoder::new(&mut cursor)
        .map_err(|_| Error::Invalid)?
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut decoded)
        .map_err(|_| Error::Invalid)?;
    if decoded.len() > LIMIT {
        return Err(Error::Limit);
    }
    if cursor.position() != compressed.len() as u64 {
        return Err(Error::Invalid);
    }
    inspect_decoded(&decoded)
}
fn inspect_decoded(mut data: &[u8]) -> Result<Metadata, Error> {
    let size = data.len();
    if take(&mut data, 4)? != b"MRS\x01" {
        return Err(Error::Invalid);
    }
    let behavior = match take(&mut data, 1)?[0] {
        0 => "domain",
        1 => "ipcidr",
        _ => return Err(Error::Invalid),
    };
    // Count is metadata only, never an allocation size. Actual work is bounded by wire layout.
    let rule_count = number(&mut data)?;
    let extra = number(&mut data)?;
    take(&mut data, extra)?;
    if take(&mut data, 1)? != [1] {
        return Err(Error::Invalid);
    }
    let entries = if behavior == "domain" {
        let leaves = words(&mut data)?;
        let bitmap = words(&mut data)?;
        let n = number(&mut data)?;
        let labels = take(&mut data, n)?;
        padding(leaves, n + 1)?;
        padding(bitmap, n * 2 + 1)?;
        let mut depths = VecDeque::from([0u8]);
        let (mut node, mut edge, mut terminals) = (0, 0, 0);
        while let Some(depth) = depths.pop_front() {
            if node > n {
                return Err(Error::Invalid);
            }
            let mut previous = None;
            while !bit(bitmap, edge + node)? {
                let label = *labels.get(edge).ok_or(Error::Invalid)?;
                if !(label.is_ascii_alphanumeric() || b"._-*+".contains(&label))
                    || previous.is_some_and(|p| p >= label)
                    || depth >= 253
                {
                    return Err(Error::Invalid);
                }
                previous = Some(label);
                depths.push_back(depth + 1);
                edge += 1;
            }
            if bit(leaves, node)? {
                if depth == 0 {
                    return Err(Error::Invalid);
                }
                terminals += 1;
            }
            node += 1;
        }
        if edge != n || node != n + 1 {
            return Err(Error::Invalid);
        }
        terminals
    } else {
        let n = number(&mut data)?;
        if n > data.len() / 32 {
            return Err(Error::Invalid);
        }
        let mut previous = None;
        for _ in 0..n {
            let from = u128::from_be_bytes(
                take(&mut data, 16)?
                    .try_into()
                    .map_err(|_| Error::Invalid)?,
            );
            let to = u128::from_be_bytes(
                take(&mut data, 16)?
                    .try_into()
                    .map_err(|_| Error::Invalid)?,
            );
            if from > to || previous.is_some_and(|p| p >= from) {
                return Err(Error::Invalid);
            }
            previous = Some(to);
        }
        n
    };
    if !data.is_empty() || (rule_count > 0 && entries == 0) {
        return Err(Error::Invalid);
    }
    Ok(Metadata {
        behavior,
        rule_count,
        decoded_bytes: size,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn excessive_frame_and_window_are_rejected_before_allocation() {
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0xa0];
        frame.extend_from_slice(&((LIMIT + 1) as u32).to_le_bytes());
        assert_eq!(inspect(&frame).unwrap_err(), Error::Limit);
        assert_eq!(
            inspect(&[0x28, 0xb5, 0x2f, 0xfd, 0, 0x71]).unwrap_err(),
            Error::Limit
        );
    }
}
