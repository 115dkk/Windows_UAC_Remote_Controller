// SPDX-License-Identifier: GPL-2.0-or-later
//! Decode exactly one QR from actual native-screen pixels supplied over the
//! private stdin pipe. PNG, decoded pixels and invitation text never leave RAM.

use std::io::Cursor;

use base64::{Engine, engine::general_purpose::STANDARD};
use image::{ImageFormat, ImageReader, Limits};
use zeroize::Zeroizing;

use crate::Result;

const MAX_PNG_BYTES: usize = 8 * 1024 * 1024;
const MAX_BASE64_BYTES: usize = MAX_PNG_BYTES.div_ceil(3) * 4;
const MAX_DIMENSION: u32 = 4096;

pub(super) fn decode(encoded: Zeroizing<String>) -> Result<Zeroizing<String>> {
    if encoded.len() > MAX_BASE64_BYTES {
        return Err("png_too_large");
    }
    let png = Zeroizing::new(
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| "invalid_png_base64")?,
    );
    drop(encoded);
    if png.len() > MAX_PNG_BYTES || !png.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err("invalid_png");
    }
    // Read dimensions before pixel allocation, then apply decoder allocation
    // limits too. Only PNG is enabled; no format inference or URL/file access.
    let mut dimension_reader =
        ImageReader::with_format(Cursor::new(png.as_slice()), ImageFormat::Png);
    dimension_reader.limits(limits());
    let (width, height) = dimension_reader
        .into_dimensions()
        .map_err(|_| "png_dimensions_rejected")?;
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
        return Err("png_dimensions_rejected");
    }
    let mut reader = ImageReader::with_format(Cursor::new(png.as_slice()), ImageFormat::Png);
    reader.limits(limits());
    let grayscale = reader
        .decode()
        .map_err(|_| "png_decode_rejected")?
        .into_luma8();
    let pixels = Zeroizing::new(grayscale.into_raw());
    drop(png);
    let width = usize::try_from(width).map_err(|_| "png_dimensions_rejected")?;
    let height = usize::try_from(height).map_err(|_| "png_dimensions_rejected")?;
    let mut prepared =
        rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| pixels[y * width + x]);
    let grids = prepared.detect_grids();
    if grids.len() != 1 {
        return Err("expected_exactly_one_qr");
    }
    let (_, decoded) = grids[0].decode().map_err(|_| "qr_decode_rejected")?;
    let decoded = Zeroizing::new(decoded);
    if decoded.len() > 16 * 1024 {
        return Err("qr_too_large");
    }
    // Validate the protocol here as well, before passing the retained text to
    // the exact same original-invitation/pin checking enrollment path.
    service_protocol::PairingInvitation::from_qr_text(&decoded)
        .map_err(|_| "qr_protocol_rejected")?;
    Ok(decoded)
}

fn limits() -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(128 * 1024 * 1024);
    limits
}
