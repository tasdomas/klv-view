mod klv;
mod source;
mod ts;
mod ui;

use std::io;
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossterm::{cursor, execute, terminal};

use source::{Clock, Input, Options, Shared, SourceStats};

const DEFAULT_INPUT: &str = "udp://227.1.1.1:15001";

const USAGE: &str = "\
klv-view - live viewer for KLV (MISB ST 0601) metadata in MPEG-TS

USAGE:
    klv-view [OPTIONS] [INPUT]

INPUT:
    udp://GROUP:PORT     multicast/unicast MPEG-TS over UDP (default: udp://227.1.1.1:15001)
    GROUP:PORT           same as above
    PATH                 a .ts file (played back in real time using KLV PTS)

OPTIONS:
    -i, --iface IP       local interface IP to join the multicast group on
                         (default: let the OS choose)
    -p, --pid PID        force the KLV PID (decimal or 0x hex) instead of reading the PMT
    -g, --gap SECONDS    report KLV gaps at least this long (default: 1.0)
    -s, --stale SECONDS  all-tags view: show tags not updated for this long in red
                         (default: 1.0)
        --fast           files: don't pace playback, read as fast as possible
        --loop           files: restart at the end
    -h, --help           show this help

KEYS:
    space   pause/resume (live: freezes the display, gap tracking continues)
    a       toggle all-tags-seen view / latest frame
    h       toggle hex dump / decoded view
    ↑ ↓ PgUp PgDn Home   scroll the frame view
    c       clear gap history and counters
    q, Esc  quit
";

struct Args {
    input: String,
    iface: Ipv4Addr,
    pid: Option<u16>,
    gap: Duration,
    stale: Duration,
    fast: bool,
    r#loop: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        input: DEFAULT_INPUT.into(),
        iface: Ipv4Addr::UNSPECIFIED,
        pid: None,
        gap: Duration::from_secs(1),
        stale: Duration::from_secs(1),
        fast: false,
        r#loop: false,
    };
    let mut it = std::env::args().skip(1);
    let mut got_input = false;
    while let Some(arg) = it.next() {
        let mut val = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "-h" | "--help" | "/?" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "-i" | "--iface" => {
                a.iface = val(&arg)?.parse().map_err(|e| format!("--iface: {e}"))?;
            }
            "-p" | "--pid" => {
                let v = val(&arg)?;
                let pid = match v.strip_prefix("0x").or(v.strip_prefix("0X")) {
                    Some(h) => u16::from_str_radix(h, 16),
                    None => v.parse(),
                }
                .map_err(|e| format!("--pid: {e}"))?;
                a.pid = Some(pid);
            }
            "-g" | "--gap" => {
                let s: f64 = val(&arg)?.parse().map_err(|e| format!("--gap: {e}"))?;
                if s.is_nan() || s <= 0.0 {
                    return Err("--gap must be > 0".into());
                }
                a.gap = Duration::from_secs_f64(s);
            }
            "-s" | "--stale" => {
                let s: f64 = val(&arg)?.parse().map_err(|e| format!("--stale: {e}"))?;
                if s.is_nan() || s <= 0.0 {
                    return Err("--stale must be > 0".into());
                }
                a.stale = Duration::from_secs_f64(s);
            }
            "--fast" => a.fast = true,
            "--loop" => a.r#loop = true,
            s if s.starts_with('-') && s.len() > 1 => return Err(format!("unknown option {s}")),
            s => {
                if got_input {
                    return Err(format!("unexpected argument {s}"));
                }
                a.input = s.to_string();
                got_input = true;
            }
        }
    }
    Ok(a)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let input = match Input::parse(&args.input, args.iface) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    if let Input::File(p) = &input
        && let Err(e) = std::fs::metadata(p)
    {
        eprintln!("error: cannot open {p}: {e}");
        return ExitCode::from(2);
    }

    let shared = Arc::new(Shared {
        clock: Clock::new(),
        paused: AtomicBool::new(false),
        quit: AtomicBool::new(false),
        stats: Mutex::new(SourceStats::default()),
    });
    let (tx, rx) = mpsc::channel();
    source::spawn(
        input.clone(),
        Options {
            forced_pid: args.pid,
            fast: args.fast,
            r#loop: args.r#loop,
        },
        shared.clone(),
        tx,
    );

    // Restore the terminal even if we panic.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        hook(info);
    }));

    let res = setup_terminal()
        .and_then(|()| ui::App::new(input, shared.clone(), args.gap, args.stale).run(rx));
    shared.quit.store(true, Ordering::Relaxed);
    restore_terminal();
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn setup_terminal() -> io::Result<()> {
    terminal::enable_raw_mode()?;
    execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide)
}

fn restore_terminal() {
    let _ = execute!(io::stdout(), cursor::Show, terminal::LeaveAlternateScreen);
    let _ = terminal::disable_raw_mode();
}
