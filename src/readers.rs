//! Plain PC/SC access, for asking cards who they are without disturbing them.
//!
//! The card libraries find a card by opening every one, and both close what they open with a
//! reset (the pcsc crate's `Drop`): another program's verified pin or half-done import on
//! that card is gone. Asking here happens inside one transaction per card, which no other
//! program can interleave with, and every card is left as it was found.

use std::ffi::{CStr, CString};

use anyhow::{Result, anyhow};

/// A PC/SC context, or the error that names the way out when the resource manager is not
/// there to give one
pub(crate) fn context() -> Result<pcsc::Context> {
    pcsc::Context::establish(pcsc::Scope::User).map_err(|err| match err {
        pcsc::Error::NoService | pcsc::Error::ServiceStopped => anyhow!(
            "pcscd is not running: start it (`systemctl start pcscd.socket` where systemd \
             runs), or see the chapter on cards on a Linux system"
        ),
        err => err.into(),
    })
}

/// The PC/SC context and the names of every reader it sees
pub(crate) fn list() -> Result<(pcsc::Context, Vec<CString>)> {
    let context = context()?;
    let mut names = vec![0; context.list_readers_len()?];
    let readers = context
        .list_readers(&mut names)?
        .map(CStr::to_owned)
        .collect();
    Ok((context, readers))
}

/// Ask the card in one reader something, inside a transaction, and leave it as it was
///
/// The error is the connection's, so a caller can tell an empty reader from one another
/// program holds exclusively; `None` is the card's own refusal to answer.
pub(crate) fn ask<T>(
    context: &pcsc::Context,
    reader: &CStr,
    question: impl FnOnce(&pcsc::Transaction<'_>) -> Option<T>,
) -> Result<Option<T>, pcsc::Error> {
    let mut card = context.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)?;
    let answer = card
        .transaction()
        .ok()
        .and_then(|transaction| question(&transaction));
    let _ = card.disconnect(pcsc::Disposition::LeaveCard);
    Ok(answer)
}

/// Send one APDU and return its data on 9000, collecting a long answer through GET RESPONSE
pub(crate) fn transmit(transaction: &pcsc::Transaction<'_>, apdu: &[u8]) -> Option<Vec<u8>> {
    let mut buffer = [0; pcsc::MAX_BUFFER_SIZE];
    let mut data = Vec::new();
    let mut reply = transaction.transmit(apdu, &mut buffer).ok()?.to_vec();
    loop {
        let (body, status) = reply.split_at(reply.len().checked_sub(2)?);
        data.extend_from_slice(body);
        match *status {
            [0x90, 0x00] => return Some(data),
            [0x61, remaining] => {
                let get_response = [0x00, 0xC0, 0x00, 0x00, remaining];
                reply = transaction
                    .transmit(&get_response, &mut buffer)
                    .ok()?
                    .to_vec();
            }
            _ => return None,
        }
    }
}

/// A SELECT by application identifier, with Le, as an APDU
pub(crate) fn select(aid: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
    apdu.extend_from_slice(aid);
    apdu.push(0x00);
    apdu
}

/// One BER-TLV object, split off the front of `data`: its tag, whether it is constructed, its
/// value and what follows it
///
/// Tags of one or two bytes and lengths in the short or 81/82 form, as the cards here use;
/// `None` for anything else or for an object cut short.
pub(crate) fn split_tlv(data: &[u8]) -> Option<(u16, bool, &[u8], &[u8])> {
    let first = *data.first()?;
    let (tag, header) = match first {
        first if first & 0x1F == 0x1F => (u16::from_be_bytes([first, *data.get(1)?]), 2),
        first => (u16::from(first), 1),
    };
    let (len, len_size) = match *data.get(header)? {
        0x81 => (usize::from(*data.get(header + 1)?), 2),
        0x82 => {
            (usize::from(u16::from_be_bytes([*data.get(header + 1)?, *data.get(header + 2)?])), 3)
        }
        short if short < 0x80 => (usize::from(short), 1),
        _ => return None,
    };
    let start = header + len_size;
    let value = data.get(start..start + len)?;
    Some((tag, first & 0x20 != 0, value, &data[start + len..]))
}

/// The value of the first `tag` in a run of BER-TLV objects, descending into constructed ones
pub(crate) fn find_tlv(mut data: &[u8], tag: u16) -> Option<&[u8]> {
    while !data.is_empty() {
        let (found, constructed, value, rest) = split_tlv(data)?;
        if found == tag {
            return Some(value);
        }
        if constructed && let Some(inner) = find_tlv(value, tag) {
            return Some(inner);
        }
        data = rest;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_nested_and_long_tags() {
        // 6E { 4F 02 AABB, 73 { C5 03 010203 } }, then 5F50 with a long-form length
        let mut data = vec![
            0x6E, 0x0B, 0x4F, 0x02, 0xAA, 0xBB, 0x73, 0x05, 0xC5, 0x03, 1, 2, 3,
        ];
        data.extend_from_slice(&[0x5F, 0x50, 0x81, 0x01, 0x42]);
        assert_eq!(find_tlv(&data, 0x4F), Some(&[0xAA, 0xBB][..]));
        assert_eq!(find_tlv(&data, 0xC5), Some(&[1, 2, 3][..]));
        assert_eq!(find_tlv(&data, 0x5F50), Some(&[0x42][..]));
        assert_eq!(find_tlv(&data, 0xC6), None);
        // Truncated input is no answer, not a panic
        assert_eq!(find_tlv(&data[..5], 0x4F), None);
    }
}
