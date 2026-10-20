//! KLV (SMPTE 336) parsing and MISB ST 0601 UAS Datalink Local Set decoding.

pub const UL_PREFIX: [u8; 4] = [0x06, 0x0e, 0x2b, 0x34];
pub const ST0601_KEY: [u8; 16] = [
    0x06, 0x0e, 0x2b, 0x34, 0x02, 0x0b, 0x01, 0x01, 0x0e, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00,
];

/// One top-level KLV packet (16-byte universal key + BER length + value).
pub struct KlvPacket {
    pub key: [u8; 16],
    /// The whole packet: key, length and value.
    pub raw: Vec<u8>,
    /// Offset of the value within `raw`.
    pub value_off: usize,
}

impl KlvPacket {
    pub fn value(&self) -> &[u8] {
        &self.raw[self.value_off..]
    }
}

/// BER short/long form length. Returns (length, bytes consumed).
pub fn ber_length(b: &[u8]) -> Option<(usize, usize)> {
    let first = *b.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 8 || b.len() < 1 + n {
        return None;
    }
    let len = b[1..1 + n]
        .iter()
        .fold(0usize, |acc, &x| (acc << 8) | x as usize);
    Some((len, 1 + n))
}

/// BER-OID encoded tag. Returns (tag, bytes consumed).
pub fn ber_oid(b: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for (i, &x) in b.iter().enumerate().take(9) {
        v = (v << 7) | (x & 0x7f) as u64;
        if x & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

/// Split a PES payload into KLV packets. Handles both raw KLV (async, stream_type
/// 0x06) and synchronous metadata access-unit cells (stream_type 0x15, ST 1402),
/// which prefix each cell with a 5-byte header.
pub fn split_packets(payload: &[u8]) -> Vec<KlvPacket> {
    if payload.starts_with(&UL_PREFIX) {
        return split_raw(payload);
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i + 5 <= payload.len() {
        let cell_len = ((payload[i + 3] as usize) << 8) | payload[i + 4] as usize;
        let start = i + 5;
        let end = (start + cell_len).min(payload.len());
        if !payload[start..end].starts_with(&UL_PREFIX) {
            break;
        }
        out.extend(split_raw(&payload[start..end]));
        i = end;
    }
    if out.is_empty() {
        // Last resort: scan for a key anywhere in the payload.
        if let Some(pos) = payload.windows(4).position(|w| w == UL_PREFIX) {
            return split_raw(&payload[pos..]);
        }
    }
    out
}

fn split_raw(mut b: &[u8]) -> Vec<KlvPacket> {
    let mut out = Vec::new();
    while b.len() >= 17 && b.starts_with(&UL_PREFIX) {
        let Some((len, n)) = ber_length(&b[16..]) else {
            break;
        };
        let value_off = 16 + n;
        let total = (value_off + len).min(b.len());
        out.push(KlvPacket {
            key: b[..16].try_into().unwrap(),
            raw: b[..total].to_vec(),
            value_off,
        });
        b = &b[total..];
    }
    out
}

/// Tag/value items of a local set.
pub fn local_set(mut b: &[u8]) -> Vec<(u64, &[u8])> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let Some((tag, tn)) = ber_oid(b) else { break };
        let Some((len, ln)) = ber_length(&b[tn..]) else {
            break;
        };
        let start = tn + ln;
        if start + len > b.len() {
            out.push((tag, &b[start.min(b.len())..]));
            break;
        }
        out.push((tag, &b[start..start + len]));
        b = &b[start + len..];
    }
    out
}

pub fn is_st0601(key: &[u8; 16]) -> bool {
    // Byte 7 (version) varies between encoders; compare everything else.
    key.iter()
        .zip(ST0601_KEY.iter())
        .enumerate()
        .all(|(i, (a, b))| i == 7 || a == b)
}

/// ST 0601 checksum: running 16-bit sum over the packet up to and including the
/// checksum tag and length bytes. Returns (expected, computed).
pub fn st0601_checksum(raw: &[u8]) -> Option<(u16, u16)> {
    if raw.len() < 4 || raw[raw.len() - 4] != 0x01 || raw[raw.len() - 3] != 0x02 {
        return None;
    }
    let expected = u16::from_be_bytes([raw[raw.len() - 2], raw[raw.len() - 1]]);
    let mut sum: u16 = 0;
    for (i, &x) in raw[..raw.len() - 2].iter().enumerate() {
        sum = sum.wrapping_add((x as u16) << (8 * ((i + 1) % 2)));
    }
    Some((expected, sum))
}

pub struct Field {
    pub tag: u64,
    pub name: &'static str,
    pub value: String,
}

/// Decode an ST 0601 local set into human-readable fields.
pub fn decode_st0601(value: &[u8]) -> Vec<Field> {
    local_set(value)
        .into_iter()
        .map(|(tag, v)| {
            let (name, value) = decode_tag(tag, v);
            Field { tag, name, value }
        })
        .collect()
}

// ---- value helpers ---------------------------------------------------------

fn uint(v: &[u8]) -> Option<u64> {
    if v.is_empty() || v.len() > 8 {
        return None;
    }
    Some(v.iter().fold(0u64, |a, &x| (a << 8) | x as u64))
}

fn int(v: &[u8]) -> Option<i64> {
    let u = uint(v)?;
    let bits = v.len() * 8;
    Some(if bits == 64 {
        u as i64
    } else {
        ((u << (64 - bits)) as i64) >> (64 - bits)
    })
}

/// Unsigned integer mapped linearly onto [min, max].
fn umap(v: &[u8], min: f64, max: f64) -> Option<f64> {
    let u = uint(v)?;
    let full = ((1u128 << (v.len() * 8)) - 1) as f64;
    Some(min + u as f64 * (max - min) / full)
}

/// Signed integer mapped symmetrically onto [-range, range]; the most negative
/// value is reserved as the "out of range" indicator.
fn smap(v: &[u8], range: f64) -> Result<f64, &'static str> {
    let i = int(v).ok_or("bad length")?;
    let bits = v.len() * 8;
    let min = if bits == 64 {
        i64::MIN
    } else {
        -(1i64 << (bits - 1))
    };
    if i == min {
        return Err("out of range");
    }
    let half = ((1u128 << (bits - 1)) - 1) as f64;
    Ok(i as f64 * range / half)
}

/// MISB ST 1201 IMAPB floating point mapping.
fn imapb(v: &[u8], a: f64, b: f64) -> Option<f64> {
    let y = uint(v)? as f64;
    let l = v.len() as i32;
    let b_pow = (b - a).log2().ceil() as i32;
    let d_pow = 8 * l - 1;
    let s_f = 2f64.powi(d_pow - b_pow);
    let s_r = 2f64.powi(b_pow - d_pow);
    let z = if a < 0.0 && b > 0.0 {
        s_f * a - (s_f * a).floor()
    } else {
        0.0
    };
    Some(s_r * (y - z) + a)
}

fn us_time(v: &[u8]) -> String {
    match uint(v) {
        Some(us) => match chrono::DateTime::from_timestamp_micros(us as i64) {
            Some(t) => t.format("%Y-%m-%d %H:%M:%S%.6f UTC").to_string(),
            None => format!("{us} µs"),
        },
        None => hex(v),
    }
}

pub fn hex(v: &[u8]) -> String {
    v.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn text(v: &[u8]) -> String {
    format!("\"{}\"", String::from_utf8_lossy(v).trim_end_matches('\0'))
}

fn f(o: Option<f64>, prec: usize, unit: &str) -> String {
    match o {
        Some(x) => format!("{x:.prec$}{unit}"),
        None => "?".into(),
    }
}

fn s(r: Result<f64, &'static str>, prec: usize, unit: &str) -> String {
    match r {
        Ok(x) => format!("{x:.prec$}{unit}"),
        Err(e) => format!("N/A ({e})"),
    }
}

fn u(v: &[u8], unit: &str) -> String {
    match uint(v) {
        Some(x) => format!("{x}{unit}"),
        None => hex(v),
    }
}

fn nested(v: &[u8]) -> String {
    let items = local_set(v);
    format!("[{} items] {}", items.len(), hex(&v[..v.len().min(24)]))
        + if v.len() > 24 { " …" } else { "" }
}

const DEG: &str = "°";
const ALT: (f64, f64) = (-900.0, 19000.0);

fn alt(v: &[u8]) -> String {
    f(umap(v, ALT.0, ALT.1), 1, " m")
}

fn decode_tag(tag: u64, v: &[u8]) -> (&'static str, String) {
    match tag {
        1 => ("Checksum", format!("0x{}", hex(v).replace(' ', ""))),
        2 => ("Precision Time Stamp", us_time(v)),
        3 => ("Mission ID", text(v)),
        4 => ("Platform Tail Number", text(v)),
        5 => ("Platform Heading", f(umap(v, 0.0, 360.0), 4, DEG)),
        6 => ("Platform Pitch", s(smap(v, 20.0), 4, DEG)),
        7 => ("Platform Roll", s(smap(v, 50.0), 4, DEG)),
        8 => ("Platform True Airspeed", u(v, " m/s")),
        9 => ("Platform Indicated Airspeed", u(v, " m/s")),
        10 => ("Platform Designation", text(v)),
        11 => ("Image Source Sensor", text(v)),
        12 => ("Image Coordinate System", text(v)),
        13 => ("Sensor Latitude", s(smap(v, 90.0), 7, DEG)),
        14 => ("Sensor Longitude", s(smap(v, 180.0), 7, DEG)),
        15 => ("Sensor True Altitude", alt(v)),
        16 => ("Sensor Horizontal FOV", f(umap(v, 0.0, 180.0), 4, DEG)),
        17 => ("Sensor Vertical FOV", f(umap(v, 0.0, 180.0), 4, DEG)),
        18 => ("Sensor Rel. Azimuth", f(umap(v, 0.0, 360.0), 4, DEG)),
        19 => ("Sensor Rel. Elevation", s(smap(v, 180.0), 4, DEG)),
        20 => ("Sensor Rel. Roll", f(umap(v, 0.0, 360.0), 4, DEG)),
        21 => ("Slant Range", f(umap(v, 0.0, 5_000_000.0), 1, " m")),
        22 => ("Target Width", f(umap(v, 0.0, 10_000.0), 1, " m")),
        23 => ("Frame Center Latitude", s(smap(v, 90.0), 7, DEG)),
        24 => ("Frame Center Longitude", s(smap(v, 180.0), 7, DEG)),
        25 => ("Frame Center Elevation", alt(v)),
        26 => ("Offset Corner Lat Pt 1", s(smap(v, 0.075), 7, DEG)),
        27 => ("Offset Corner Lon Pt 1", s(smap(v, 0.075), 7, DEG)),
        28 => ("Offset Corner Lat Pt 2", s(smap(v, 0.075), 7, DEG)),
        29 => ("Offset Corner Lon Pt 2", s(smap(v, 0.075), 7, DEG)),
        30 => ("Offset Corner Lat Pt 3", s(smap(v, 0.075), 7, DEG)),
        31 => ("Offset Corner Lon Pt 3", s(smap(v, 0.075), 7, DEG)),
        32 => ("Offset Corner Lat Pt 4", s(smap(v, 0.075), 7, DEG)),
        33 => ("Offset Corner Lon Pt 4", s(smap(v, 0.075), 7, DEG)),
        34 => ("Icing Detected", u(v, "")),
        35 => ("Wind Direction", f(umap(v, 0.0, 360.0), 2, DEG)),
        36 => ("Wind Speed", f(umap(v, 0.0, 100.0), 1, " m/s")),
        37 => ("Static Pressure", f(umap(v, 0.0, 5000.0), 1, " mbar")),
        38 => ("Density Altitude", alt(v)),
        39 => (
            "Outside Air Temperature",
            int(v).map_or(hex(v), |x| format!("{x} °C")),
        ),
        40 => ("Target Location Latitude", s(smap(v, 90.0), 7, DEG)),
        41 => ("Target Location Longitude", s(smap(v, 180.0), 7, DEG)),
        42 => ("Target Location Elevation", alt(v)),
        43 => (
            "Target Track Gate Width",
            uint(v).map_or(hex(v), |x| format!("{} px", x * 2)),
        ),
        44 => (
            "Target Track Gate Height",
            uint(v).map_or(hex(v), |x| format!("{} px", x * 2)),
        ),
        45 => (
            "Target Error Estimate CE90",
            f(umap(v, 0.0, 4095.0), 1, " m"),
        ),
        46 => (
            "Target Error Estimate LE90",
            f(umap(v, 0.0, 4095.0), 1, " m"),
        ),
        47 => (
            "Generic Flag Data",
            uint(v).map_or(hex(v), |x| format!("0b{x:08b}")),
        ),
        48 => ("Security Local Set", nested(v)),
        49 => ("Differential Pressure", f(umap(v, 0.0, 5000.0), 1, " mbar")),
        50 => ("Platform Angle of Attack", s(smap(v, 20.0), 4, DEG)),
        51 => ("Platform Vertical Speed", s(smap(v, 180.0), 2, " m/s")),
        52 => ("Platform Sideslip Angle", s(smap(v, 20.0), 4, DEG)),
        53 => (
            "Airfield Barometric Pressure",
            f(umap(v, 0.0, 5000.0), 1, " mbar"),
        ),
        54 => ("Airfield Elevation", alt(v)),
        55 => ("Relative Humidity", f(umap(v, 0.0, 100.0), 1, " %")),
        56 => ("Platform Ground Speed", u(v, " m/s")),
        57 => ("Ground Range", f(umap(v, 0.0, 5_000_000.0), 1, " m")),
        58 => (
            "Platform Fuel Remaining",
            f(umap(v, 0.0, 10_000.0), 1, " kg"),
        ),
        59 => ("Platform Call Sign", text(v)),
        60 => ("Weapon Load", hex(v)),
        61 => ("Weapon Fired", hex(v)),
        62 => ("Laser PRF Code", u(v, "")),
        63 => (
            "Sensor Field of View Name",
            match uint(v) {
                Some(0) => "Ultranarrow".into(),
                Some(1) => "Narrow".into(),
                Some(2) => "Medium".into(),
                Some(3) => "Wide".into(),
                Some(4) => "Ultrawide".into(),
                Some(5) => "Narrow Medium".into(),
                Some(6) => "2x Ultranarrow".into(),
                Some(7) => "4x Ultranarrow".into(),
                Some(8) => "Continuous Zoom".into(),
                _ => hex(v),
            },
        ),
        64 => ("Platform Magnetic Heading", f(umap(v, 0.0, 360.0), 4, DEG)),
        65 => ("UAS Datalink LS Version", u(v, "")),
        67 => ("Alt. Platform Latitude", s(smap(v, 90.0), 7, DEG)),
        68 => ("Alt. Platform Longitude", s(smap(v, 180.0), 7, DEG)),
        69 => ("Alt. Platform Altitude", alt(v)),
        70 => ("Alt. Platform Name", text(v)),
        71 => ("Alt. Platform Heading", f(umap(v, 0.0, 360.0), 4, DEG)),
        72 => ("Event Start Time", us_time(v)),
        73 => ("RVT Local Set", nested(v)),
        74 => ("VMTI Local Set", nested(v)),
        75 => ("Sensor Ellipsoid Height", alt(v)),
        76 => ("Alt. Platform Ellipsoid Height", alt(v)),
        77 => (
            "Operational Mode",
            match uint(v) {
                Some(0) => "Other".into(),
                Some(1) => "Operational".into(),
                Some(2) => "Training".into(),
                Some(3) => "Exercise".into(),
                Some(4) => "Maintenance".into(),
                Some(5) => "Test".into(),
                _ => hex(v),
            },
        ),
        78 => ("Frame Center HAE", alt(v)),
        79 => ("Sensor North Velocity", s(smap(v, 327.0), 2, " m/s")),
        80 => ("Sensor East Velocity", s(smap(v, 327.0), 2, " m/s")),
        81 => ("Image Horizon Pixel Pack", hex(v)),
        82 => ("Corner Latitude Pt 1", s(smap(v, 90.0), 7, DEG)),
        83 => ("Corner Longitude Pt 1", s(smap(v, 180.0), 7, DEG)),
        84 => ("Corner Latitude Pt 2", s(smap(v, 90.0), 7, DEG)),
        85 => ("Corner Longitude Pt 2", s(smap(v, 180.0), 7, DEG)),
        86 => ("Corner Latitude Pt 3", s(smap(v, 90.0), 7, DEG)),
        87 => ("Corner Longitude Pt 3", s(smap(v, 180.0), 7, DEG)),
        88 => ("Corner Latitude Pt 4", s(smap(v, 90.0), 7, DEG)),
        89 => ("Corner Longitude Pt 4", s(smap(v, 180.0), 7, DEG)),
        90 => ("Platform Pitch (full)", s(smap(v, 90.0), 4, DEG)),
        91 => ("Platform Roll (full)", s(smap(v, 90.0), 4, DEG)),
        92 => ("Platform Angle of Attack (full)", s(smap(v, 90.0), 4, DEG)),
        93 => ("Platform Sideslip (full)", s(smap(v, 180.0), 4, DEG)),
        94 => ("MIIS Core Identifier", hex(v)),
        95 => ("SAR Motion Imagery LS", nested(v)),
        96 => (
            "Target Width Extended",
            f(imapb(v, 0.0, 1_500_000.0), 2, " m"),
        ),
        97 => ("Range Image LS", nested(v)),
        98 => ("Geo-Registration LS", nested(v)),
        99 => ("Composite Imaging LS", nested(v)),
        100 => ("Segment LS", nested(v)),
        101 => ("Amend LS", nested(v)),
        102 => ("SDCC-FLP", hex(v)),
        103 => (
            "Density Altitude Extended",
            f(imapb(v, -900.0, 40_000.0), 2, " m"),
        ),
        104 => (
            "Sensor Ellipsoid Height Ext.",
            f(imapb(v, -900.0, 40_000.0), 2, " m"),
        ),
        105 => (
            "Alt. Platform Ellipsoid Height Ext.",
            f(imapb(v, -900.0, 40_000.0), 2, " m"),
        ),
        106 => ("Stream Designator", text(v)),
        107 => ("Operational Base", text(v)),
        108 => ("Broadcast Source", text(v)),
        109 => (
            "Range To Recovery Location",
            f(imapb(v, 0.0, 21_000.0), 3, " km"),
        ),
        110 => ("Time Airborne", u(v, " s")),
        111 => ("Propulsion Unit Speed", u(v, " RPM")),
        112 => ("Platform Course Angle", f(imapb(v, 0.0, 360.0), 4, DEG)),
        113 => ("Altitude AGL", f(imapb(v, -900.0, 40_000.0), 2, " m")),
        114 => ("Radar Altimeter", f(imapb(v, -900.0, 40_000.0), 2, " m")),
        115 => ("Control Command", hex(v)),
        116 => ("Control Command Verification", hex(v)),
        117 => (
            "Sensor Azimuth Rate",
            f(imapb(v, -1000.0, 1000.0), 4, "°/s"),
        ),
        118 => (
            "Sensor Elevation Rate",
            f(imapb(v, -1000.0, 1000.0), 4, "°/s"),
        ),
        119 => ("Sensor Roll Rate", f(imapb(v, -1000.0, 1000.0), 4, "°/s")),
        120 => ("On-board MI Storage Full", f(imapb(v, 0.0, 100.0), 2, " %")),
        121 => ("Active Wavelength List", hex(v)),
        122 => ("Country Codes", hex(v)),
        123 => ("Number of NAVSATs in View", u(v, "")),
        124 => (
            "Positioning Method Source",
            uint(v).map_or(hex(v), |x| format!("0b{x:08b}")),
        ),
        125 => ("Platform Status", u(v, "")),
        126 => ("Sensor Control Mode", u(v, "")),
        127 => ("Sensor Frame Rate Pack", hex(v)),
        128 => ("Wavelengths List", hex(v)),
        129 => ("Target ID", text(v)),
        130 => ("Airbase Locations", hex(v)),
        131 => ("Take-off Time", us_time(v)),
        132 => (
            "Transmission Frequency",
            f(imapb(v, 1.0, 99_999.0), 3, " MHz"),
        ),
        133 => ("On-board MI Storage Capacity", u(v, " GB")),
        134 => ("Zoom Percentage", f(imapb(v, 0.0, 100.0), 2, " %")),
        135 => ("Communications Method", text(v)),
        136 => ("Leap Seconds", int(v).map_or(hex(v), |x| format!("{x} s"))),
        137 => (
            "Correction Offset",
            int(v).map_or(hex(v), |x| format!("{x} µs")),
        ),
        138 => ("Payload List", hex(v)),
        139 => ("Active Payloads", hex(v)),
        140 => ("Weapons Stores", hex(v)),
        141 => ("Waypoint List", hex(v)),
        142 => ("View Domain", hex(v)),
        _ => ("(unknown tag)", hex(v)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_mapping() {
        assert!((smap(&[0x7f, 0xff], 20.0).unwrap() - 20.0).abs() < 1e-9);
        assert!(smap(&[0x80, 0x00], 20.0).is_err());
        // ST 0601 example: Sensor Latitude 0x5595B66D -> 60.1768229669783°
        let lat = smap(&[0x55, 0x95, 0xb6, 0x6d], 90.0).unwrap();
        assert!((lat - 60.176822966978335).abs() < 1e-9);
    }

    #[test]
    fn unsigned_mapping() {
        // ST 0601 example: Platform Heading 0x71C2 -> 159.9744°
        let h = umap(&[0x71, 0xc2], 0.0, 360.0).unwrap();
        assert!((h - 159.97436484321355).abs() < 1e-9);
        // ST 0601 example: Sensor True Altitude 0xC221 -> 14190.72 m
        let a = umap(&[0xc2, 0x21], -900.0, 19000.0).unwrap();
        assert!((a - 14190.719462882427).abs() < 1e-6);
    }

    #[test]
    fn imapb_mapping() {
        assert_eq!(imapb(&[0x00, 0x00, 0x00], 0.0, 100.0).unwrap(), 0.0);
        // -900..40000 in 2 bytes: bPow = 16, dPow = 15, so the step is 2 m.
        let v = imapb(&[0x40, 0x00], -900.0, 40_000.0).unwrap();
        assert!((v - (-900.0 + 0x4000 as f64 * 2f64.powi(16 - 15))).abs() < 1e-9);
    }

    #[test]
    fn checksum_and_parse() {
        let mut body = vec![0x02, 0x08, 0x00, 0x04, 0x60, 0x50, 0x58, 0x4e, 0x01, 0x80];
        body.extend([0x05, 0x02, 0x71, 0xc2]);
        body.extend([0x01, 0x02]);
        let mut raw = ST0601_KEY.to_vec();
        raw.push((body.len() + 2) as u8);
        raw.extend(&body);
        let mut sum: u16 = 0;
        for (i, &x) in raw.iter().enumerate() {
            sum = sum.wrapping_add((x as u16) << (8 * ((i + 1) % 2)));
        }
        raw.extend(sum.to_be_bytes());
        let pkts = split_packets(&raw);
        assert_eq!(pkts.len(), 1);
        let (exp, got) = st0601_checksum(&pkts[0].raw).unwrap();
        assert_eq!(exp, got);
        let fields = decode_st0601(pkts[0].value());
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].value, "2009-01-12 22:08:22.000000 UTC");
    }
}
