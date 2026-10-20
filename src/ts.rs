//! Minimal MPEG-TS demuxer: tracks PAT/PMT, finds KLV elementary streams and
//! reassembles their PES packets.

use std::collections::HashMap;

pub const TS_PACKET_SIZE: usize = 188;

/// A complete PES payload from a KLV elementary stream.
pub struct KlvPes {
    pub pid: u16,
    pub stream_type: u8,
    pub pts: Option<u64>,
    pub payload: Vec<u8>,
}

#[derive(Default)]
pub struct DemuxStats {
    pub ts_packets: u64,
    pub sync_errors: u64,
    pub cc_errors: u64,
}

struct PesAssembler {
    stream_type: u8,
    buf: Vec<u8>,
    active: bool,
    last_cc: Option<u8>,
}

pub struct Demuxer {
    /// PMT PIDs announced by the PAT.
    pmt_pids: Vec<u16>,
    /// KLV PIDs -> assembler.
    klv: HashMap<u16, PesAssembler>,
    /// PID forced from the command line; disables PMT-based detection.
    forced_pid: Option<u16>,
    /// Section reassembly for PSI PIDs.
    psi: HashMap<u16, Vec<u8>>,
    pub stats: DemuxStats,
    /// Leftover bytes when input isn't aligned to 188-byte packets.
    carry: Vec<u8>,
}

impl Demuxer {
    pub fn new(forced_pid: Option<u16>) -> Self {
        let mut d = Demuxer {
            pmt_pids: Vec::new(),
            klv: HashMap::new(),
            forced_pid,
            psi: HashMap::new(),
            stats: DemuxStats::default(),
            carry: Vec::new(),
        };
        if let Some(pid) = forced_pid {
            d.add_klv_pid(pid, 0);
        }
        d
    }

    pub fn klv_pids(&self) -> Vec<(u16, u8)> {
        let mut v: Vec<_> = self.klv.iter().map(|(p, a)| (*p, a.stream_type)).collect();
        v.sort();
        v
    }

    fn add_klv_pid(&mut self, pid: u16, stream_type: u8) {
        self.klv.entry(pid).or_insert(PesAssembler {
            stream_type,
            buf: Vec::new(),
            active: false,
            last_cc: None,
        });
    }

    /// Feed arbitrary bytes (a UDP datagram or a file chunk).
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<KlvPes>) {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(data);
        let mut i = 0;
        while i + TS_PACKET_SIZE <= buf.len() {
            if buf[i] != 0x47 {
                self.stats.sync_errors += 1;
                // Resync: find next 0x47 that is followed by another 0x47 one packet later
                // (or that is the last candidate in the buffer).
                let mut j = i + 1;
                while j < buf.len() {
                    if buf[j] == 0x47
                        && (j + TS_PACKET_SIZE >= buf.len() || buf[j + TS_PACKET_SIZE] == 0x47)
                    {
                        break;
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
            let pkt: [u8; TS_PACKET_SIZE] = buf[i..i + TS_PACKET_SIZE].try_into().unwrap();
            self.packet(&pkt, out);
            i += TS_PACKET_SIZE;
        }
        self.carry = buf[i..].to_vec();
    }

    /// Flush any partially-assembled PES packets (end of input).
    pub fn flush(&mut self, out: &mut Vec<KlvPes>) {
        let pids: Vec<u16> = self.klv.keys().copied().collect();
        for pid in pids {
            self.finish_pes(pid, out);
        }
    }

    fn packet(&mut self, p: &[u8; TS_PACKET_SIZE], out: &mut Vec<KlvPes>) {
        self.stats.ts_packets += 1;
        if p[1] & 0x80 != 0 {
            return; // transport_error_indicator
        }
        let pusi = p[1] & 0x40 != 0;
        let pid = (((p[1] & 0x1f) as u16) << 8) | p[2] as u16;
        let afc = (p[3] >> 4) & 0x3;
        let cc = p[3] & 0x0f;

        let mut off = 4;
        if afc & 0x2 != 0 {
            off += 1 + p[4] as usize;
        }
        if afc & 0x1 == 0 || off >= TS_PACKET_SIZE {
            return; // no payload
        }
        let payload = &p[off..];

        if self.forced_pid.is_none() && (pid == 0 || self.pmt_pids.contains(&pid)) {
            self.psi_packet(pid, pusi, payload);
        } else if self.klv.contains_key(&pid) {
            let discontinuity = afc & 0x2 != 0 && p[4] > 0 && p[5] & 0x80 != 0;
            let a = self.klv.get_mut(&pid).unwrap();
            if let Some(last) = a.last_cc
                && !discontinuity
                && cc != (last + 1) & 0x0f
                && cc != last
            {
                self.stats.cc_errors += 1;
                // Drop the partial PES; it is corrupt.
                a.active = false;
                a.buf.clear();
            }
            a.last_cc = Some(cc);
            if pusi {
                self.finish_pes(pid, out);
                let a = self.klv.get_mut(&pid).unwrap();
                a.buf.clear();
                a.active = true;
            }
            let a = self.klv.get_mut(&pid).unwrap();
            if a.active {
                a.buf.extend_from_slice(payload);
                // If PES_packet_length is known and satisfied, emit immediately
                // instead of waiting for the next PUSI.
                if a.buf.len() >= 6 {
                    let len = ((a.buf[4] as usize) << 8) | a.buf[5] as usize;
                    if len != 0 && a.buf.len() >= 6 + len {
                        self.finish_pes(pid, out);
                    }
                }
            }
        }
    }

    fn finish_pes(&mut self, pid: u16, out: &mut Vec<KlvPes>) {
        let a = self.klv.get_mut(&pid).unwrap();
        if !a.active {
            return;
        }
        a.active = false;
        let buf = std::mem::take(&mut a.buf);
        if let Some((pts, payload)) = parse_pes(&buf) {
            out.push(KlvPes {
                pid,
                stream_type: a.stream_type,
                pts,
                payload: payload.to_vec(),
            });
        }
    }

    fn psi_packet(&mut self, pid: u16, pusi: bool, payload: &[u8]) {
        let mut buf = self.psi.remove(&pid).unwrap_or_default();
        if pusi {
            let ptr = payload[0] as usize;
            if 1 + ptr > payload.len() {
                return;
            }
            if !buf.is_empty() {
                // Finish the previous section with the bytes before the pointer.
                buf.extend_from_slice(&payload[1..1 + ptr]);
                self.try_sections(pid, &buf);
            }
            buf = payload[1 + ptr..].to_vec();
        } else if buf.is_empty() {
            return; // joined mid-section
        } else {
            buf.extend_from_slice(payload);
        }
        if !self.try_sections(pid, &buf) {
            self.psi.insert(pid, buf);
        }
    }

    /// Parse all complete sections in `data`. Returns false if the data ends with
    /// an incomplete section (more packets needed).
    fn try_sections(&mut self, pid: u16, data: &[u8]) -> bool {
        let mut i = 0;
        while i < data.len() {
            if data[i] == 0xff {
                return true; // stuffing
            }
            if i + 3 > data.len() {
                return false;
            }
            let slen = (((data[i + 1] & 0x0f) as usize) << 8) | data[i + 2] as usize;
            if i + 3 + slen > data.len() {
                return false;
            }
            let sec = &data[i..i + 3 + slen];
            match sec[0] {
                0x00 if pid == 0 => self.parse_pat(sec),
                0x02 => self.parse_pmt(sec),
                _ => {}
            }
            i += 3 + slen;
        }
        true
    }

    fn parse_pat(&mut self, s: &[u8]) {
        if s.len() < 12 {
            return;
        }
        let end = s.len() - 4; // CRC
        let mut i = 8;
        while i + 4 <= end {
            let program = ((s[i] as u16) << 8) | s[i + 1] as u16;
            let pid = (((s[i + 2] & 0x1f) as u16) << 8) | s[i + 3] as u16;
            if program != 0 && !self.pmt_pids.contains(&pid) {
                self.pmt_pids.push(pid);
            }
            i += 4;
        }
    }

    fn parse_pmt(&mut self, s: &[u8]) {
        if s.len() < 16 {
            return;
        }
        let end = s.len() - 4;
        let prog_info_len = (((s[10] & 0x0f) as usize) << 8) | s[11] as usize;
        let mut i = 12 + prog_info_len;
        while i + 5 <= end {
            let stream_type = s[i];
            let pid = (((s[i + 1] & 0x1f) as u16) << 8) | s[i + 2] as u16;
            let es_len = (((s[i + 3] & 0x0f) as usize) << 8) | s[i + 4] as usize;
            let desc_end = (i + 5 + es_len).min(end);
            let desc = &s[i + 5..desc_end];
            let has_klva = desc.windows(4).any(|w| w == b"KLVA");
            // 0x15 = metadata carried in PES (synchronous KLV, ST 1402),
            // 0x06 + 'KLVA' registration = asynchronous KLV.
            if stream_type == 0x15 || has_klva {
                self.add_klv_pid(pid, stream_type);
            }
            i = desc_end;
        }
    }
}

/// Returns (PTS, payload) of a PES packet.
fn parse_pes(b: &[u8]) -> Option<(Option<u64>, &[u8])> {
    if b.len() < 9 || b[0] != 0 || b[1] != 0 || b[2] != 1 {
        return None;
    }
    let stream_id = b[3];
    let len = ((b[4] as usize) << 8) | b[5] as usize;
    let end = if len == 0 {
        b.len()
    } else {
        (6 + len).min(b.len())
    };
    // Streams without the optional PES header.
    if matches!(
        stream_id,
        0xbc | 0xbe | 0xbf | 0xf0 | 0xf1 | 0xf2 | 0xf8 | 0xff
    ) {
        return Some((None, &b[6..end]));
    }
    let hdr_len = b[8] as usize;
    let start = 9 + hdr_len;
    if start > end {
        return None;
    }
    let pts = if b[7] & 0x80 != 0 && b.len() >= 14 {
        Some(
            (((b[9] as u64 >> 1) & 0x07) << 30)
                | ((b[10] as u64) << 22)
                | (((b[11] as u64) >> 1) << 15)
                | ((b[12] as u64) << 7)
                | ((b[13] as u64) >> 1),
        )
    } else {
        None
    };
    Some((pts, &b[start..end]))
}
