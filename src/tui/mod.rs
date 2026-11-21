//! Ratatui v0.30+ 3-pane interactive console (`fubuki tui`).

pub mod panes;

use std::io;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use zeroize::{Zeroize, Zeroizing};

use crate::audit::{EntropyAuditReport, audit_bytes};
use crate::kdf::{AuthModality, KdfProfile};
use crate::pubkey::{detect_auth_modality, format_challenge_token, parse_credential_input};
use crate::volume::{
    BLOCK_SIZE, PREAMBLE_SIZE, unlock_volume_with_modality_bytes, validate_container_len,
};
use crate::winnow::{STREAM_SEED_LEN, TUPLE_WIRE_LEN};

/// Active pane focus inside the 3-pane `fubuki tui` console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePane {
    StreamStride,
    CryptoGate,
    EntropyTelemetry,
}

/// Safe metadata summary for a single unlocked volume slot.
///
/// Intentionally carries **only** the unlocked slot's logical span and never exposes decoy
/// ceilings, unallocated slack boundaries, or hints about any other slot.
#[derive(Debug, Clone, Zeroize)]
pub struct UnlockedSlotSummary {
    pub anchor_block: u64,
    pub block_count: u32,
    pub payload_len: usize,
    pub created_unix_secs: u64,
}

/// Interactive TEA application model for `fubuki tui`.
pub struct FubukiTuiApp {
    pub target_label: String,
    pub target_bytes: Option<Vec<u8>>,
    pub total_bytes: usize,
    pub total_blocks: Option<u64>,
    pub stream_tuple_count: Option<usize>,
    pub packet_throughput_pps: f64,
    pub chaff_ratio: u8,
    pub kdf_profile: KdfProfile,
    pub passphrase_buf: Zeroizing<String>,
    pub unlocked_slot: Option<UnlockedSlotSummary>,
    pub status_message: String,
    pub audit_report: Option<EntropyAuditReport>,
    pub active_pane: ActivePane,
}

impl Drop for FubukiTuiApp {
    fn drop(&mut self) {
        self.passphrase_buf.zeroize();
        if let Some(ref mut slot) = self.unlocked_slot {
            slot.zeroize();
        }
    }
}

impl FubukiTuiApp {
    /// Construct a TUI state snapshot from an optional target file or in-memory container/stream.
    pub fn from_bytes(target_label: impl Into<String>, bytes: Option<Vec<u8>>) -> Self {
        let label = target_label.into();
        let (total_bytes, total_blocks, stream_tuple_count, audit_report) = match &bytes {
            Some(buf) => {
                let blocks = validate_container_len(buf.len()).ok();
                let tuples = if buf.len() >= STREAM_SEED_LEN + TUPLE_WIRE_LEN
                    && (buf.len() - STREAM_SEED_LEN).is_multiple_of(TUPLE_WIRE_LEN)
                {
                    Some((buf.len() - STREAM_SEED_LEN) / TUPLE_WIRE_LEN)
                } else {
                    None
                };
                let report = Some(audit_bytes(buf));
                (buf.len(), blocks, tuples, report)
            }
            None => (0, None, None, None),
        };

        Self {
            target_label: label,
            target_bytes: bytes,
            total_bytes,
            total_blocks,
            stream_tuple_count,
            packet_throughput_pps: 0.0,
            chaff_ratio: 7,
            kdf_profile: KdfProfile::production(),
            passphrase_buf: Zeroizing::new(String::new()),
            unlocked_slot: None,
            status_message: "Ready. Enter passphrase or fubuki-hs-v1:<hex> and press Enter."
                .to_string(),
            audit_report,
            active_pane: ActivePane::StreamStride,
        }
    }

    /// Load a target container or winnowed stream file from disk.
    pub fn from_path(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) => {
                let data = std::fs::read(p)?;
                Ok(Self::from_bytes(p.display().to_string(), Some(data)))
            }
            None => Ok(Self::from_bytes("<no target loaded>", None)),
        }
    }

    /// Extract the container's `Elligator2` Hundi Challenge token (`fubuki-chal-v1:...`) if valid.
    pub fn challenge_token(&self) -> Option<String> {
        let data = self.target_bytes.as_ref()?;
        if self.total_blocks.is_some() && data.len() >= 32 {
            let mut repr = [0u8; 32];
            repr.copy_from_slice(&data[0..32]);
            Some(format_challenge_token(&repr))
        } else {
            None
        }
    }

    /// Detect the authentication modality corresponding to the current credential buffer.
    pub fn active_modality(&self) -> AuthModality {
        detect_auth_modality(&self.passphrase_buf)
    }

    pub fn next_pane(&mut self) {
        self.active_pane = match self.active_pane {
            ActivePane::StreamStride => ActivePane::CryptoGate,
            ActivePane::CryptoGate => ActivePane::EntropyTelemetry,
            ActivePane::EntropyTelemetry => ActivePane::StreamStride,
        };
    }

    pub fn prev_pane(&mut self) {
        self.active_pane = match self.active_pane {
            ActivePane::StreamStride => ActivePane::EntropyTelemetry,
            ActivePane::CryptoGate => ActivePane::StreamStride,
            ActivePane::EntropyTelemetry => ActivePane::CryptoGate,
        };
    }

    pub fn adjust_ratio(&mut self, delta: i8) {
        let next = (i16::from(self.chaff_ratio) + i16::from(delta)).clamp(1, 31) as u8;
        self.chaff_ratio = next;
    }

    pub fn toggle_kdf_profile(&mut self) {
        self.kdf_profile = if self.kdf_profile == KdfProfile::production() {
            KdfProfile::fast()
        } else {
            KdfProfile::production()
        };
    }

    /// Attempt branchless Mode B slot unlock against loaded target bytes using Passphrase,
    /// Pubkey Handshake (`fubuki-hs-v1:...`), or Hybrid (`pass+fubuki-hs-v1:...`).
    pub fn attempt_unlock(&mut self) {
        let Some(ref data) = self.target_bytes else {
            self.status_message = "No volume loaded. Pass `--target <path>`.".to_string();
            return;
        };
        if self.passphrase_buf.is_empty() {
            self.status_message = "Credential buffer is empty.".to_string();
            return;
        }

        let parsed = parse_credential_input(&self.passphrase_buf);
        self.passphrase_buf.zeroize();

        let Ok(cred) = parsed else {
            self.unlocked_slot = None;
            self.status_message = "Malformed handshake credential format.".to_string();
            return;
        };

        match unlock_volume_with_modality_bytes(
            data,
            cred.passphrase.as_deref().map(Vec::as_slice),
            cred.handshake.as_deref(),
            self.kdf_profile,
        ) {
            Ok(slot) => {
                self.unlocked_slot = Some(UnlockedSlotSummary {
                    anchor_block: slot.anchor_block,
                    block_count: slot.block_count,
                    payload_len: slot.payload.len(),
                    created_unix_secs: slot.created_unix_secs,
                });
                self.status_message = format!(
                    "Unlocked slot span [{}..{}) ({} B payload).",
                    slot.anchor_block,
                    slot.anchor_block + u64::from(slot.block_count),
                    slot.payload.len()
                );
            }
            Err(_) => {
                self.unlocked_slot = None;
                self.status_message = "Volume authentication failed.".to_string();
            }
        }
    }

    /// Return alignment check string for Pane 1.
    pub fn alignment_summary(&self) -> String {
        if let Some(b) = self.total_blocks {
            format!(
                "Aligned ({PREAMBLE_SIZE}B + {b} * {BLOCK_SIZE}B = {}B)",
                self.total_bytes
            )
        } else if let Some(tuples) = self.stream_tuple_count {
            format!(
                "Winnow Stream ({STREAM_SEED_LEN}B seed + {tuples} * {TUPLE_WIRE_LEN}B = {}B)",
                self.total_bytes
            )
        } else if self.total_bytes == 0 {
            "Idle (no file attached)".to_string()
        } else {
            format!("Raw Buffer ({} bytes)", self.total_bytes)
        }
    }
}

fn install_terminal_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        prev(info);
    }));
}

/// Launch the interactive 3-pane `ratatui` v0.30 console with panic-safe terminal restoration.
pub fn run_interactive_tui(mut app: FubukiTuiApp) -> Result<()> {
    install_terminal_panic_hook();
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = (|| -> Result<()> {
        loop {
            terminal.draw(|frame| panes::render(frame, &app))?;
            if event::poll(Duration::from_millis(100))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                if key.code == KeyCode::Esc
                    || (key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL))
                {
                    break;
                }

                match key.code {
                    KeyCode::Tab => app.next_pane(),
                    KeyCode::BackTab => app.prev_pane(),
                    KeyCode::Char('q') if app.active_pane != ActivePane::CryptoGate => break,
                    KeyCode::Char('+') | KeyCode::Right
                        if app.active_pane != ActivePane::CryptoGate =>
                    {
                        app.adjust_ratio(1)
                    }
                    KeyCode::Char('-') | KeyCode::Left
                        if app.active_pane != ActivePane::CryptoGate =>
                    {
                        app.adjust_ratio(-1)
                    }
                    KeyCode::F(2) => app.toggle_kdf_profile(),
                    KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.toggle_kdf_profile()
                    }
                    KeyCode::Backspace if app.active_pane == ActivePane::CryptoGate => {
                        app.passphrase_buf.pop();
                    }
                    KeyCode::Enter if app.active_pane == ActivePane::CryptoGate => {
                        app.attempt_unlock();
                    }
                    KeyCode::Char(c) if app.active_pane == ActivePane::CryptoGate => {
                        app.passphrase_buf.push(c);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}
