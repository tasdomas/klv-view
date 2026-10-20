//! Terminal UI: live status, KLV gap tracking and the decoded frame view.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Duration;

use chrono::{DateTime, Local};
use crossterm::event::{self, Event as TermEvent, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor};
use crossterm::terminal::{self, Clear, ClearType};
use crossterm::{cursor, queue};

use crate::klv::{self, Field};
use crate::source::{Event, Input, Shared};
use crate::ts::KlvPes;

struct DecodedPacket {
    key: [u8; 16],
    raw: Vec<u8>,
    is_0601: bool,
    checksum: Option<(u16, u16)>,
    fields: Vec<Field>,
}

struct Frame {
    number: u64,
    wall: DateTime<Local>,
    pid: u16,
    stream_type: u8,
    pts: Option<u64>,
    payload_len: usize,
    packets: Vec<DecodedPacket>,
}

struct Gap {
    /// Wall-clock time of the last frame before the gap.
    started: DateTime<Local>,
    len: Duration,
}

pub struct App {
    input: Input,
    shared: Arc<Shared>,
    gap_threshold: Duration,

    paused: bool,
    show_hex: bool,
    scroll: usize,

    frames: u64,
    checksum_errors: u64,
    empty_payloads: u64,
    first_frame_at: Option<Duration>,
    last_at: Option<Duration>,
    last_wall: Option<DateTime<Local>>,
    arrivals: VecDeque<Duration>,
    intervals: VecDeque<Duration>,
    gaps: Vec<Gap>,
    longest_gap: Duration,

    live: Option<Frame>,
    shown: Option<Frame>,
    message: Option<(Color, String)>,
    eof: bool,
}

const RATE_WINDOW: Duration = Duration::from_secs(5);
const INTERVAL_HISTORY: usize = 300;
const GAP_LINES: usize = 5;

impl App {
    pub fn new(input: Input, shared: Arc<Shared>, gap_threshold: Duration) -> Self {
        App {
            input,
            shared,
            gap_threshold,
            paused: false,
            show_hex: false,
            scroll: 0,
            frames: 0,
            checksum_errors: 0,
            empty_payloads: 0,
            first_frame_at: None,
            last_at: None,
            last_wall: None,
            arrivals: VecDeque::new(),
            intervals: VecDeque::new(),
            gaps: Vec::new(),
            longest_gap: Duration::ZERO,
            live: None,
            shown: None,
            message: None,
            eof: false,
        }
    }

    pub fn run(&mut self, rx: Receiver<Event>) -> io::Result<()> {
        let mut out = io::stdout();
        loop {
            loop {
                match rx.try_recv() {
                    Ok(ev) => self.on_event(ev),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.eof = true;
                        break;
                    }
                }
            }
            self.draw(&mut out)?;
            if event::poll(Duration::from_millis(66))? {
                while event::poll(Duration::ZERO)? {
                    if let TermEvent::Key(k) = event::read()? {
                        if k.kind == KeyEventKind::Release {
                            continue;
                        }
                        let ctrl_c = k.code == KeyCode::Char('c')
                            && k.modifiers.contains(KeyModifiers::CONTROL);
                        match k.code {
                            _ if ctrl_c => return Ok(()),
                            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                            KeyCode::Char(' ') => self.toggle_pause(),
                            KeyCode::Char('h') | KeyCode::Char('x') => {
                                self.show_hex = !self.show_hex;
                                self.scroll = 0;
                            }
                            KeyCode::Char('c') => self.clear_stats(),
                            KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
                            KeyCode::Down => self.scroll += 1,
                            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
                            KeyCode::PageDown => self.scroll += 10,
                            KeyCode::Home => self.scroll = 0,
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    fn toggle_pause(&mut self) {
        self.paused = !self.paused;
        self.shared.paused.store(self.paused, Ordering::Relaxed);
        if !self.input.is_live() {
            // Files actually stop reading; freeze the clock so it isn't a gap.
            self.shared.clock.set_paused(self.paused);
        }
        if !self.paused {
            self.shown = self.live.take();
        }
    }

    fn clear_stats(&mut self) {
        self.gaps.clear();
        self.longest_gap = Duration::ZERO;
        self.intervals.clear();
        self.checksum_errors = 0;
        self.empty_payloads = 0;
        self.message = None;
    }

    fn on_event(&mut self, ev: Event) {
        match ev {
            Event::Klv { at, pes } => self.on_klv(at, pes),
            Event::Info(s) => self.message = Some((Color::DarkGrey, s)),
            Event::Error(s) => self.message = Some((Color::Red, format!("input error: {s}"))),
            Event::Eof => {
                self.eof = true;
                self.message = Some((Color::Yellow, "end of input".into()));
            }
        }
    }

    fn on_klv(&mut self, at: Duration, pes: KlvPes) {
        let packets: Vec<DecodedPacket> = klv::split_packets(&pes.payload)
            .into_iter()
            .map(|p| {
                let is_0601 = klv::is_st0601(&p.key);
                let (checksum, fields) = if is_0601 {
                    (klv::st0601_checksum(&p.raw), klv::decode_st0601(p.value()))
                } else {
                    (None, Vec::new())
                };
                DecodedPacket {
                    key: p.key,
                    raw: p.raw,
                    is_0601,
                    checksum,
                    fields,
                }
            })
            .collect();
        if packets.is_empty() {
            // PES on a KLV PID that didn't contain a recognisable KLV packet.
            self.empty_payloads += 1;
            return;
        }
        if packets
            .iter()
            .any(|p| matches!(p.checksum, Some((e, g)) if e != g))
        {
            self.checksum_errors += 1;
        }

        if let Some(last) = self.last_at {
            let dt = at.saturating_sub(last);
            self.intervals.push_back(dt);
            if self.intervals.len() > INTERVAL_HISTORY {
                self.intervals.pop_front();
            }
            if dt >= self.gap_threshold {
                let started = self.last_wall.unwrap_or_else(Local::now);
                self.gaps.push(Gap { started, len: dt });
                self.longest_gap = self.longest_gap.max(dt);
            }
        } else {
            self.first_frame_at = Some(at);
        }
        self.last_at = Some(at);
        self.last_wall = Some(Local::now());
        self.arrivals.push_back(at);
        while self
            .arrivals
            .front()
            .is_some_and(|t| at.saturating_sub(*t) > RATE_WINDOW)
        {
            self.arrivals.pop_front();
        }

        self.frames += 1;
        let frame = Frame {
            number: self.frames,
            wall: Local::now(),
            pid: pes.pid,
            stream_type: pes.stream_type,
            pts: pes.pts,
            payload_len: pes.payload.len(),
            packets,
        };
        if self.paused {
            self.live = Some(frame);
        } else {
            self.shown = Some(frame);
        }
    }

    fn rate(&self) -> f64 {
        if self.arrivals.len() < 2 {
            return 0.0;
        }
        let span = *self.arrivals.back().unwrap() - *self.arrivals.front().unwrap();
        if span.is_zero() {
            0.0
        } else {
            (self.arrivals.len() - 1) as f64 / span.as_secs_f64()
        }
    }

    // ---- drawing -----------------------------------------------------------

    fn draw(&mut self, out: &mut impl Write) -> io::Result<()> {
        let (w, h) = terminal::size()?;
        let (w, h) = (w as usize, h as usize);
        let mut lines: Vec<Line> = Vec::new();
        let now = self.shared.clock.now();
        let stats = self.shared.stats.lock().unwrap().clone();

        // Title
        let mut l = Line::new();
        l.push(Some(Color::Cyan), "KLV View  ");
        l.push(None, &self.input.describe());
        l.push(None, "  ");
        if self.paused {
            l.bold(Color::Yellow, " ⏸ PAUSED ");
        } else if self.eof {
            l.bold(Color::DarkGrey, " ■ STOPPED ");
        } else {
            l.bold(Color::Green, " ● LIVE ");
        }
        lines.push(l);
        lines.push(Line::dim(
            "space pause/resume · h hex/decoded · ↑↓ PgUp PgDn scroll · c clear stats · q quit",
        ));
        lines.push(Line::new());

        // Time since last KLV frame — the main health indicator.
        let mut l = Line::new();
        match self.last_at {
            Some(last) => {
                let since = now.saturating_sub(last);
                let color = if since >= self.gap_threshold {
                    Color::Red
                } else if since >= self.gap_threshold / 2 {
                    Color::Yellow
                } else {
                    Color::Green
                };
                l.push(None, "Since last KLV frame: ");
                l.bold(color, &format!("{:>9}", fmt_dur(since)));
                if since >= self.gap_threshold {
                    l.bold(Color::Red, "   ⚠ KLV MISSING");
                }
            }
            None => {
                l.push(None, "Since last KLV frame: ");
                l.bold(
                    Color::Red,
                    &format!("no KLV received yet ({})", fmt_dur(now)),
                );
            }
        }
        if self.paused && self.input.is_live() {
            l.push(Some(Color::DarkGrey), "   (still receiving while paused)");
        }
        lines.push(l);

        let mut l = Line::new();
        l.push(
            None,
            &format!("Frames: {}   Rate: {:.2}/s", self.frames, self.rate()),
        );
        if !self.intervals.is_empty() {
            let min = self.intervals.iter().min().unwrap();
            let max = self.intervals.iter().max().unwrap();
            let avg = self.intervals.iter().sum::<Duration>() / self.intervals.len() as u32;
            l.push(
                None,
                &format!(
                    "   Interval min/avg/max: {} / {} / {}",
                    fmt_dur(*min),
                    fmt_dur(avg),
                    fmt_dur(*max)
                ),
            );
        }
        lines.push(l);

        let mut l = Line::new();
        l.push(
            None,
            &format!(
                "TS packets: {}   Data: {:.1} MB   ",
                stats.ts_packets,
                stats.bytes as f64 / 1e6
            ),
        );
        let pids = if stats.klv_pids.is_empty() {
            "none found yet (waiting for PAT/PMT)".to_string()
        } else {
            stats
                .klv_pids
                .iter()
                .map(|(p, t)| format!("0x{p:04X} (type 0x{t:02X})"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        l.push(None, &format!("KLV PID: {pids}"));
        lines.push(l);

        let mut l = Line::new();
        let err = |n: u64| if n > 0 { Some(Color::Red) } else { None };
        l.push(
            err(stats.cc_errors),
            &format!("KLV CC errors: {}   ", stats.cc_errors),
        );
        l.push(
            err(stats.sync_errors),
            &format!("TS sync errors: {}   ", stats.sync_errors),
        );
        l.push(
            err(self.checksum_errors),
            &format!("Checksum errors: {}   ", self.checksum_errors),
        );
        if self.empty_payloads > 0 {
            l.push(
                Some(Color::Yellow),
                &format!("Non-KLV payloads: {}", self.empty_payloads),
            );
        }
        lines.push(l);

        // Gap history
        let mut l = Line::new();
        l.push(
            None,
            &format!("KLV gaps ≥ {}: ", fmt_dur(self.gap_threshold)),
        );
        l.bold(
            if self.gaps.is_empty() {
                Color::Green
            } else {
                Color::Red
            },
            &self.gaps.len().to_string(),
        );
        if !self.gaps.is_empty() {
            l.push(None, &format!("   longest: {}", fmt_dur(self.longest_gap)));
        }
        lines.push(l);
        if let Some(last) = self.last_at {
            let since = now.saturating_sub(last);
            if since >= self.gap_threshold {
                let started = self.last_wall.unwrap_or_else(Local::now);
                let mut l = Line::new();
                l.push(
                    Some(Color::Red),
                    &format!(
                        "  {}  ongoing  {}",
                        started.format("%H:%M:%S%.3f"),
                        fmt_dur(since)
                    ),
                );
                lines.push(l);
            }
        }
        for g in self.gaps.iter().rev().take(GAP_LINES) {
            let mut l = Line::new();
            l.push(
                Some(Color::Yellow),
                &format!(
                    "  {}  missing  {}",
                    g.started.format("%H:%M:%S%.3f"),
                    fmt_dur(g.len)
                ),
            );
            lines.push(l);
        }
        if let Some((c, m)) = &self.message {
            let mut l = Line::new();
            l.push(Some(*c), m);
            lines.push(l);
        }
        lines.push(Line::dim(&"─".repeat(w)));

        // Frame view (scrollable)
        let body = match &self.shown {
            None => vec![Line::dim("waiting for KLV data…")],
            Some(f) => self.frame_lines(f),
        };
        let avail = h.saturating_sub(lines.len());
        let max_scroll = body.len().saturating_sub(avail);
        self.scroll = self.scroll.min(max_scroll);
        lines.extend(body.into_iter().skip(self.scroll).take(avail));

        queue!(out, cursor::MoveTo(0, 0))?;
        for (y, line) in lines.iter().take(h).enumerate() {
            queue!(out, cursor::MoveTo(0, y as u16))?;
            line.render(out, w)?;
            queue!(out, Clear(ClearType::UntilNewLine))?;
        }
        queue!(out, Clear(ClearType::FromCursorDown))?;
        out.flush()
    }

    fn frame_lines(&self, f: &Frame) -> Vec<Line> {
        let mut v = Vec::new();
        let mut l = Line::new();
        l.bold(Color::Cyan, &format!("Frame #{}", f.number));
        l.push(
            None,
            &format!(
                "   received {}   PID 0x{:04X}   PTS {}   {} bytes",
                f.wall.format("%H:%M:%S%.3f"),
                f.pid,
                f.pts
                    .map_or("-".into(), |p| format!("{:.3}s", p as f64 / 90000.0)),
                f.payload_len
            ),
        );
        if f.stream_type == 0x15 {
            l.push(Some(Color::DarkGrey), "  (sync metadata)");
        }
        v.push(l);

        for (i, p) in f.packets.iter().enumerate() {
            let mut l = Line::new();
            if f.packets.len() > 1 {
                l.push(Some(Color::Cyan), &format!("[{}] ", i + 1));
            }
            l.push(None, &format!("Key {}", klv::hex(&p.key)));
            if p.is_0601 {
                l.push(Some(Color::Green), "  MISB ST 0601");
            }
            match p.checksum {
                Some((e, g)) if e == g => l.push(Some(Color::Green), "  checksum OK"),
                Some((e, g)) => l.bold(
                    Color::Red,
                    &format!("  checksum BAD (got 0x{e:04X}, computed 0x{g:04X})"),
                ),
                None if p.is_0601 => l.push(Some(Color::Yellow), "  no checksum"),
                None => {}
            }
            v.push(l);

            if self.show_hex || !p.is_0601 {
                for chunk in p.raw.chunks(16) {
                    let off = chunk.as_ptr() as usize - p.raw.as_ptr() as usize;
                    let ascii: String = chunk
                        .iter()
                        .map(|&b| {
                            if (0x20..0x7f).contains(&b) {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    let mut l = Line::new();
                    l.push(Some(Color::DarkGrey), &format!("  {off:04X}  "));
                    l.push(None, &format!("{:<47}  ", klv::hex(chunk)));
                    l.push(Some(Color::DarkGrey), &ascii);
                    v.push(l);
                }
            } else {
                let name_w = p
                    .fields
                    .iter()
                    .map(|f| f.name.chars().count())
                    .max()
                    .unwrap_or(0);
                for fld in &p.fields {
                    let mut l = Line::new();
                    l.push(Some(Color::DarkGrey), &format!("  {:>3}  ", fld.tag));
                    l.push(Some(Color::Cyan), &format!("{:<name_w$}  ", fld.name));
                    l.push(None, &fld.value);
                    v.push(l);
                }
            }
        }
        v
    }
}

fn fmt_dur(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s < 60.0 {
        format!("{s:.3} s")
    } else if s < 3600.0 {
        format!("{}m {:06.3}s", (s / 60.0) as u64, s % 60.0)
    } else {
        format!(
            "{}h {:02}m {:02}s",
            (s / 3600.0) as u64,
            ((s % 3600.0) / 60.0) as u64,
            (s % 60.0) as u64
        )
    }
}

/// A line of styled text.
struct Line {
    spans: Vec<(Option<Color>, bool, String)>,
}

impl Line {
    fn new() -> Self {
        Line { spans: Vec::new() }
    }

    fn dim(s: &str) -> Self {
        let mut l = Line::new();
        l.push(Some(Color::DarkGrey), s);
        l
    }

    fn push(&mut self, color: Option<Color>, s: &str) {
        self.spans.push((color, false, s.to_string()));
    }

    fn bold(&mut self, color: Color, s: &str) {
        self.spans.push((Some(color), true, s.to_string()));
    }

    fn render(&self, out: &mut impl Write, width: usize) -> io::Result<()> {
        let mut left = width;
        for (color, bold, text) in &self.spans {
            if left == 0 {
                break;
            }
            let t: String = text.chars().take(left).collect();
            left -= t.chars().count();
            if let Some(c) = color {
                queue!(out, SetForegroundColor(*c))?;
            }
            if *bold {
                queue!(out, SetAttribute(Attribute::Bold))?;
            }
            queue!(out, Print(t))?;
            if *bold {
                queue!(out, SetAttribute(Attribute::Reset))?;
            }
            if color.is_some() {
                queue!(out, ResetColor)?;
            }
        }
        Ok(())
    }
}
