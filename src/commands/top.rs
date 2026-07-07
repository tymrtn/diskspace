//! `diskspace top` — live TUI dashboard over the P1 measurement logs.
//!
//! The interactive sibling of `diskspace trend`: a free-space chart, the
//! burn-rate / days-to-full readout, and the top-growers table, refreshed in
//! place. Read-only and advisory like `trend` — nothing here can trigger a
//! deletion, and the data comes entirely from `df_series.jsonl` /
//! `series.jsonl` (no filesystem walk, so a refresh is ~150 ms).
//!
//! Agents never need this: it requires a TTY and bails with a pointer to
//! `diskspace --json trend`, which carries the same data.

use anyhow::Result;
use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table};
use ratatui::Terminal;

use crate::core::metrics::{self, BurnTrend, Grower};
use crate::output::format_bytes;

/// How often the dashboard re-reads the logs. The watch agent appends one df
/// sample per 5 minutes, so anything faster than ~30 s is wasted reads.
const REFRESH_SECS: u64 = 30;

/// One coherent snapshot of everything the dashboard draws.
struct Snapshot {
    trend: BurnTrend,
    growers: Vec<Grower>,
    /// Free-bytes history inside the window, oldest-first (sparkline data).
    free_series: Vec<u64>,
    free_now: u64,
    total: u64,
}

fn load_snapshot(window_days: f64, top: usize) -> Result<Snapshot> {
    let trend = metrics::burn_trend(window_days)?;
    let growers = metrics::top_growers(window_days, top)?;
    let cutoff =
        chrono::Utc::now() - chrono::Duration::milliseconds((window_days * 86_400_000.0) as i64);
    let df: Vec<_> = metrics::read_df_series()?
        .into_iter()
        .filter(|s| s.ts >= cutoff)
        .collect();
    let (free_now, total) = df
        .last()
        .map(|s| (s.free_bytes, s.total_bytes))
        .unwrap_or((0, 0));
    Ok(Snapshot {
        trend,
        growers,
        free_series: df.iter().map(|s| s.free_bytes).collect(),
        free_now,
        total,
    })
}

pub fn run(window_days: f64, top: usize) -> Result<()> {
    use std::io::IsTerminal;
    if !io::stdout().is_terminal() {
        anyhow::bail!(
            "`diskspace top` is interactive and needs a TTY — use `diskspace --json trend` \
             for the same data as JSON"
        );
    }

    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let result = event_loop(window_days, top);
    // Always restore the terminal, even when the loop errored.
    let _ = disable_raw_mode();
    let _ = io::stdout().execute(LeaveAlternateScreen);
    result
}

fn event_loop(window_days: f64, top: usize) -> Result<()> {
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut snapshot = load_snapshot(window_days, top)?;
    let mut last_refresh = Instant::now();

    loop {
        terminal.draw(|f| draw(f.area(), f, &snapshot, window_days))?;

        // Poll for input in short slices so a refresh can fire between keys.
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        KeyCode::Char('r') => {
                            snapshot = load_snapshot(window_days, top)?;
                            last_refresh = Instant::now();
                        }
                        _ => {}
                    }
                }
            }
        }
        if last_refresh.elapsed() >= Duration::from_secs(REFRESH_SECS) {
            snapshot = load_snapshot(window_days, top)?;
            last_refresh = Instant::now();
        }
    }
}

fn draw(area: Rect, f: &mut ratatui::Frame, snap: &Snapshot, window_days: f64) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header / status line
            Constraint::Length(8), // free-space sparkline
            Constraint::Min(5),    // growers table
            Constraint::Length(1), // key hints
        ])
        .split(area);

    // --- header ------------------------------------------------------------
    let pct = if snap.total > 0 {
        snap.free_now as f64 / snap.total as f64 * 100.0
    } else {
        100.0
    };
    let trend_span = match (snap.trend.burn_rate_bytes_per_day, snap.trend.days_to_full) {
        (Some(rate), Some(days)) if rate > 0.0 => Span::styled(
            format!(
                "filling at {}/day · full in ~{} day(s)",
                format_bytes(rate as u64),
                days
            ),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        (Some(rate), _) if rate < 0.0 => Span::styled(
            format!("reclaiming {}/day", format_bytes((-rate) as u64)),
            Style::default().fg(Color::Green),
        ),
        (Some(_), _) => Span::styled("flat", Style::default().fg(Color::DarkGray)),
        (None, _) => Span::styled(
            format!("not enough samples yet ({})", snap.trend.samples),
            Style::default().fg(Color::DarkGray),
        ),
    };
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {} free ({:.1}%)  ", format_bytes(snap.free_now), pct),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        trend_span,
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" diskspace top · last {:.0} day(s) ", window_days)),
    );
    f.render_widget(header, rows[0]);

    // --- free-space sparkline ------------------------------------------------
    let lo = snap.free_series.iter().min().copied().unwrap_or(0);
    let hi = snap.free_series.iter().max().copied().unwrap_or(0);
    // Downsample to the widget's inner width so the whole window fits.
    let inner_w = rows[1].width.saturating_sub(2) as usize;
    let data: Vec<u64> = if snap.free_series.len() <= inner_w || inner_w == 0 {
        snap.free_series.clone()
    } else {
        (0..inner_w)
            .map(|i| {
                let lo_i = i * snap.free_series.len() / inner_w;
                let hi_i = (((i + 1) * snap.free_series.len()) / inner_w).max(lo_i + 1);
                let slice = &snap.free_series[lo_i..hi_i];
                slice.iter().sum::<u64>() / slice.len() as u64
            })
            .collect()
    };
    let spark = Sparkline::default()
        .block(Block::default().borders(Borders::ALL).title(format!(
            " free space · low {} · high {} ",
            format_bytes(lo),
            format_bytes(hi)
        )))
        .data(&data)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(spark, rows[1]);

    // --- growers table -------------------------------------------------------
    let max_delta = snap
        .growers
        .iter()
        .map(|g| g.delta_bytes)
        .max()
        .unwrap_or(0);
    let table_rows: Vec<Row> = snap
        .growers
        .iter()
        .map(|g| {
            let bar_w = 14usize;
            let filled = if max_delta > 0 {
                ((g.delta_bytes as f64 / max_delta as f64) * bar_w as f64).round() as usize
            } else {
                0
            };
            let bar = format!(
                "{}{}",
                "█".repeat(filled.min(bar_w)),
                "░".repeat(bar_w.saturating_sub(filled))
            );
            Row::new(vec![
                Cell::from(format!("+{}", format_bytes(g.delta_bytes)))
                    .style(Style::default().add_modifier(Modifier::BOLD)),
                Cell::from(bar).style(Style::default().fg(Color::Yellow)),
                Cell::from(format!("{}/day", format_bytes(g.per_day_bytes as u64)))
                    .style(Style::default().fg(Color::DarkGray)),
                Cell::from(g.path.display().to_string()),
            ])
        })
        .collect();
    let table = Table::new(
        table_rows,
        [
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Min(20),
        ],
    )
    .header(
        Row::new(vec!["growth", "", "rate", "path"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" top growers — what is driving the fill "),
    );
    f.render_widget(table, rows[2]);

    // --- key hints -----------------------------------------------------------
    let hints = Paragraph::new(Line::from(Span::styled(
        " q quit · r refresh · auto-refresh 30s · advisory only — nothing here deletes ",
        Style::default().fg(Color::DarkGray),
    )));
    f.render_widget(hints, rows[3]);
}
