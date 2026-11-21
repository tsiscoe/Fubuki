//! 3-pane `ratatui` v0.30 layout renderer with CWE-150 ANSI/OSC escape sanitization.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use super::{ActivePane, FubukiTuiApp};
use crate::volume::BLOCK_SIZE;

/// Strip C0/C1 control characters and ANSI/OSC escape sequences (`\x1b`) before rendering
/// untrusted paths, labels, or diagnostic strings into the terminal (`CWE-150`).
pub fn sanitize_for_tui(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || (!c.is_control() && c != '\u{001b}'))
        .collect()
}

/// Render the 3-pane `fubuki` console (`Stream & Stride`, `Cryptographic Gate`, `Indistinguishability Telemetry`).
pub fn render(frame: &mut Frame, app: &FubukiTuiApp) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " FUBUKI v0.2.0 ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" // "),
        Span::styled(
            "CIPHERLESS WINNOWING & ELLIGATOR2 COERCION VOLUMES",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, vertical[0]);

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(vertical[1]);

    // Pane 1: Stream & Stride Inspector
    // Privacy invariant: ONLY render the unlocked slot's logical span; never highlight slack or B_decoy.
    let p1_border = pane_border_style(app.active_pane == ActivePane::StreamStride);
    let slot_text = if let Some(slot) = &app.unlocked_slot {
        format!(
            "Unlocked Span: Blocks [{}..{})\nStride Blocks: {}\nPayload Size: {} bytes\nCreated UTC Epoch: {}",
            slot.anchor_block,
            slot.anchor_block + u64::from(slot.block_count),
            slot.block_count,
            slot.payload_len,
            slot.created_unix_secs
        )
    } else {
        "Active Slot: Locked\n(Supply passphrase or Hundi handshake in Gate)".to_string()
    };

    let pane1_body = format!(
        "Target: {}\nSize: {} bytes\nBlock Alignment: {} B\nGeometry: {}\nStream Tuples: {}\nThroughput: {:.1} pkt/s\n\n{}",
        sanitize_for_tui(&app.target_label),
        app.total_bytes,
        BLOCK_SIZE,
        sanitize_for_tui(&app.alignment_summary()),
        app.stream_tuple_count
            .map_or_else(|| "n/a".to_string(), |t| t.to_string()),
        app.packet_throughput_pps,
        slot_text,
    );
    let pane1 = Paragraph::new(pane1_body).wrap(Wrap { trim: false }).block(
        Block::default()
            .title(" [01] STREAM & STRIDE INSPECTOR ")
            .borders(Borders::ALL)
            .border_style(p1_border),
    );
    frame.render_widget(pane1, panes[0]);

    // Pane 2: Cryptographic Gate & Pipeline Control
    let p2_border = pane_border_style(app.active_pane == ActivePane::CryptoGate);
    let masked_pw: String = "*".repeat(app.passphrase_buf.chars().count());
    let ratio_bar_filled = usize::from(app.chaff_ratio).min(31) / 2;
    let ratio_bar = format!(
        "[{}{}]",
        "#".repeat(ratio_bar_filled),
        "-".repeat(15usize.saturating_sub(ratio_bar_filled))
    );
    let challenge_line = app
        .challenge_token()
        .unwrap_or_else(|| "n/a (no volume loaded)".to_string());
    let pane2_body = format!(
        "Modality: [{}]\nCredential Gate (Zeroizing):\n> [{}]\n\nHundi Challenge (S_0[0..32]):\n  {}\n\nChaff Ratio (rho): {}:1  {}\nKDF: {}\n\nGate Status:\n  {}",
        app.active_modality().label(),
        masked_pw,
        sanitize_for_tui(&challenge_line),
        app.chaff_ratio,
        ratio_bar,
        sanitize_for_tui(&app.kdf_profile.label()),
        sanitize_for_tui(&app.status_message),
    );
    let pane2 = Paragraph::new(pane2_body).wrap(Wrap { trim: false }).block(
        Block::default()
            .title(" [02] CRYPTOGRAPHIC GATE & PIPELINE ")
            .borders(Borders::ALL)
            .border_style(p2_border),
    );
    frame.render_widget(pane2, panes[1]);

    // Pane 3: Statistical Indistinguishability Telemetry
    let p3_border = pane_border_style(app.active_pane == ActivePane::EntropyTelemetry);
    let pane3_body = if let Some(rep) = &app.audit_report {
        let sig_summary = if rep.detected_magic_signatures.is_empty() {
            "none (DATA / uniform noise)".to_string()
        } else {
            sanitize_for_tui(&rep.detected_magic_signatures.join(", "))
        };
        let verdict = if rep.is_indistinguishable_noise {
            "PASS [UNIFORM NOISE]"
        } else {
            "WARN [NON-UNIFORM / SIGNATURE]"
        };
        format!(
            "Verdict: {verdict}\nShannon Entropy H(X): {:.5} bits/byte\nPearson Chi-Sq: {:.2}\nChi-Sq p-value: {:.5}\nSerial Correlation: {:.6}\nBit 254 / 255: {} / {}\nMagic Signatures: {}",
            rep.shannon_entropy_bits_per_byte,
            rep.chi_square_stat,
            rep.chi_square_p_value,
            rep.serial_correlation,
            rep.msb_bit254_freq
                .map_or_else(|| "n/a".into(), |v| format!("{v:.0}")),
            rep.msb_bit255_freq
                .map_or_else(|| "n/a".into(), |v| format!("{v:.0}")),
            sig_summary,
        )
    } else {
        "Verdict: IDLE\nLoad a winnowed .bin stream or coercion volume .dat to compute H(X), Pearson chi-square p-value, serial correlation, and magic-byte scan."
            .to_string()
    };
    let pane3 = Paragraph::new(pane3_body).wrap(Wrap { trim: false }).block(
        Block::default()
            .title(" [03] INDISTINGUISHABILITY TELEMETRY ")
            .borders(Borders::ALL)
            .border_style(p3_border),
    );
    frame.render_widget(pane3, panes[2]);

    let footer = Paragraph::new(
        "Keys: [Tab/Shift-Tab] Pane  |  [+/-] Ratio  |  [F2/Ctrl-P] KDF  |  [Enter] Unlock  |  [Esc] Quit",
    )
    .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, vertical[2]);
}

fn pane_border_style(active: bool) -> Style {
    if active {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}
