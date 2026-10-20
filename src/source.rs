//! Input readers. Each runs on its own thread, demuxes TS and sends KLV PES
//! payloads to the UI over a channel.

use std::fs::File;
use std::io::{self, Read};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use crate::ts::{Demuxer, KlvPes};

#[derive(Clone, Debug)]
pub enum Input {
    Udp {
        group: Ipv4Addr,
        port: u16,
        iface: Ipv4Addr,
    },
    File(String),
}

impl Input {
    pub fn parse(s: &str, iface: Ipv4Addr) -> Result<Input, String> {
        let addr = s
            .strip_prefix("udp://")
            .map(|r| r.trim_start_matches('@'))
            .or_else(|| s.parse::<SocketAddrV4>().ok().map(|_| s));
        match addr {
            Some(a) => {
                let sa: SocketAddrV4 = a.parse().map_err(|e| format!("bad address '{a}': {e}"))?;
                Ok(Input::Udp {
                    group: *sa.ip(),
                    port: sa.port(),
                    iface,
                })
            }
            None => Ok(Input::File(s.to_string())),
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, Input::Udp { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Input::Udp { group, port, iface } if iface.is_unspecified() => {
                format!("udp://{group}:{port}")
            }
            Input::Udp { group, port, iface } => format!("udp://{group}:{port} via {iface}"),
            Input::File(p) => format!("file {p}"),
        }
    }
}

/// Clock that can be frozen. Live sources never freeze it (the network keeps
/// going); file sources do, so pausing doesn't register as a KLV gap.
pub struct Clock {
    start: Instant,
    inner: Mutex<ClockState>,
}

struct ClockState {
    paused_at: Option<Instant>,
    paused_total: Duration,
}

impl Clock {
    pub fn new() -> Self {
        Clock {
            start: Instant::now(),
            inner: Mutex::new(ClockState {
                paused_at: None,
                paused_total: Duration::ZERO,
            }),
        }
    }

    pub fn now(&self) -> Duration {
        let s = self.inner.lock().unwrap();
        let t = s.paused_at.unwrap_or_else(Instant::now);
        t.duration_since(self.start) - s.paused_total
    }

    pub fn set_paused(&self, paused: bool) {
        let mut s = self.inner.lock().unwrap();
        match (paused, s.paused_at) {
            (true, None) => s.paused_at = Some(Instant::now()),
            (false, Some(t)) => {
                s.paused_total += t.elapsed();
                s.paused_at = None;
            }
            _ => {}
        }
    }
}

pub enum Event {
    Klv { at: Duration, pes: KlvPes },
    Info(String),
    Error(String),
    Eof,
}

#[derive(Default, Clone)]
pub struct SourceStats {
    pub bytes: u64,
    pub ts_packets: u64,
    pub sync_errors: u64,
    pub cc_errors: u64,
    pub klv_pids: Vec<(u16, u8)>,
}

pub struct Shared {
    pub clock: Clock,
    pub paused: AtomicBool,
    pub quit: AtomicBool,
    pub stats: Mutex<SourceStats>,
}

pub struct Options {
    pub forced_pid: Option<u16>,
    /// For files: don't pace playback by PTS.
    pub fast: bool,
    /// For files: start over at the end.
    pub r#loop: bool,
}

pub fn spawn(input: Input, opts: Options, shared: Arc<Shared>, tx: Sender<Event>) {
    thread::spawn(move || {
        let res = match &input {
            Input::Udp { group, port, iface } => {
                run_udp(*group, *port, *iface, &opts, &shared, &tx)
            }
            Input::File(path) => run_file(path, &opts, &shared, &tx),
        };
        match res {
            Ok(()) => {
                let _ = tx.send(Event::Eof);
            }
            Err(e) => {
                let _ = tx.send(Event::Error(e.to_string()));
            }
        }
    });
}

fn update_stats(shared: &Shared, demux: &Demuxer, bytes: u64) {
    let mut s = shared.stats.lock().unwrap();
    s.bytes += bytes;
    s.ts_packets = demux.stats.ts_packets;
    s.sync_errors = demux.stats.sync_errors;
    s.cc_errors = demux.stats.cc_errors;
    if s.klv_pids.len() != demux.klv_pids().len() {
        s.klv_pids = demux.klv_pids();
    }
}

fn run_udp(
    group: Ipv4Addr,
    port: u16,
    iface: Ipv4Addr,
    opts: &Options,
    shared: &Shared,
    tx: &Sender<Event>,
) -> io::Result<()> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    let _ = sock.set_recv_buffer_size(8 * 1024 * 1024);
    // Windows can't bind to a multicast address; binding to ANY works everywhere.
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    if group.is_multicast() {
        sock.join_multicast_v4(&group, &iface)
            .map_err(|e| io::Error::new(e.kind(), format!("joining {group} on {iface}: {e}")))?;
        let _ = tx.send(Event::Info(format!(
            "joined {group}:{port} on interface {iface}"
        )));
    } else {
        let _ = tx.send(Event::Info(format!("listening on UDP port {port}")));
    }
    sock.set_read_timeout(Some(Duration::from_millis(200)))?;

    let mut demux = Demuxer::new(opts.forced_pid);
    let mut buf = [MaybeUninit::<u8>::uninit(); 65536];
    let mut out = Vec::new();
    while !shared.quit.load(Ordering::Relaxed) {
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        // SAFETY: recv initialised the first n bytes.
        let data: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        let at = shared.clock.now();
        demux.feed(strip_rtp(data), &mut out);
        update_stats(shared, &demux, n as u64);
        for pes in out.drain(..) {
            if tx.send(Event::Klv { at, pes }).is_err() {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Accept RTP-wrapped TS too: if the datagram isn't TS but there's a sync byte
/// after a 12-byte RTP header, skip the header.
fn strip_rtp(d: &[u8]) -> &[u8] {
    if d.first() != Some(&0x47) && d.len() > 12 && d[0] >> 6 == 2 {
        let cc = (d[0] & 0x0f) as usize;
        let hdr = 12 + 4 * cc;
        if d.get(hdr) == Some(&0x47) {
            return &d[hdr..];
        }
    }
    d
}

fn run_file(path: &str, opts: &Options, shared: &Shared, tx: &Sender<Event>) -> io::Result<()> {
    loop {
        let mut f = File::open(path)?;
        let mut demux = Demuxer::new(opts.forced_pid);
        let mut buf = vec![0u8; 188 * 64];
        let mut out = Vec::new();
        // Pacing: map the first KLV PTS to the clock, then wait for each later one.
        let mut base: Option<(u64, Duration)> = None;
        loop {
            if shared.quit.load(Ordering::Relaxed) {
                return Ok(());
            }
            while shared.paused.load(Ordering::Relaxed) {
                if shared.quit.load(Ordering::Relaxed) {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(50));
            }
            let n = f.read(&mut buf)?;
            if n == 0 {
                demux.flush(&mut out);
            } else {
                demux.feed(&buf[..n], &mut out);
            }
            update_stats(shared, &demux, n as u64);
            for pes in out.drain(..) {
                if !opts.fast
                    && let Some(pts) = pes.pts
                {
                    pace(&mut base, pts, shared);
                }
                let at = shared.clock.now();
                if tx.send(Event::Klv { at, pes }).is_err() {
                    return Ok(());
                }
            }
            if n == 0 {
                break;
            }
        }
        if !opts.r#loop {
            return Ok(());
        }
        let _ = tx.send(Event::Info("end of file, looping".into()));
    }
}

fn pace(base: &mut Option<(u64, Duration)>, pts: u64, shared: &Shared) {
    let now = shared.clock.now();
    let Some((pts0, t0)) = *base else {
        *base = Some((pts, now));
        return;
    };
    // PTS is 33-bit at 90 kHz; handle wrap.
    let delta = pts.wrapping_sub(pts0) & ((1 << 33) - 1);
    let target = t0 + Duration::from_micros(delta * 100 / 9);
    if target < now || target - now > Duration::from_secs(10) {
        // Discontinuity or we've fallen behind: re-anchor.
        if target + Duration::from_secs(10) < now || target > now + Duration::from_secs(10) {
            *base = Some((pts, now));
        }
        return;
    }
    // Sleep in small steps so pause/quit stay responsive.
    while shared.clock.now() < target {
        if shared.quit.load(Ordering::Relaxed) {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
}
