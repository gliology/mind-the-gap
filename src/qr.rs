//! Render byte blobs as terminal QR codes, the transfer path off an air-gapped machine.

use anyhow::Result;
use qrcode::QrCode;
use qrcode::render::unicode;

/// Print the data as a unicode QR code, inverted so it scans on dark terminals
pub fn print_qr(data: &[u8]) -> Result<()> {
    let code = QrCode::new(data)
        .map_err(|e| anyhow::anyhow!("Data too large for QR code ({} bytes): {}", data.len(), e))?;
    let image = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light) // inverted for dark terminals
        .light_color(unicode::Dense1x2::Dark)
        .build();
    println!("{}", image);
    Ok(())
}
