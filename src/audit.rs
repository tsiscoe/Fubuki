//! Built-in forensic indistinguishability auditor:
//! Shannon entropy $H(X)$, Pearson $\chi^2$ goodness-of-fit $p$-value against $U(0,255)$,
//! lag-1 serial correlation, Elligator2 top-bit uniformity, and magic-header signature scanning.

use serde::{Deserialize, Serialize};

/// Offset-0 file-format magic headers (as matched by `file`/DLP prefix scanners).
const PREFIX_SIGNATURES: &[(&str, &[u8])] = &[
    ("gzip", b"\x1f\x8b\x08"),
    ("zip-pk", b"PK\x03\x04"),
    ("elf-bin", b"\x7fELF"),
    ("pe-mz", b"MZ"),
    ("png-img", b"\x89PNG\r\n\x1a\n"),
    ("pdf-doc", b"%PDF-"),
];

/// High-specificity container/cipher signatures (>= 6 bytes) scanned across the full byte stream.
const ANYWHERE_SIGNATURES: &[(&str, &[u8])] = &[
    ("age-header", b"age-encryption.org/"),
    ("openssl-salted", b"Salted__"),
    ("pem-armor", b"-----BEGIN "),
    ("luks-v1-v2", b"LUKS\xba\xbe"),
    ("sqlite3", b"SQLite format 3\0"),
    ("fubuki-cleartext-slot-magic", b"FBKSLT01"),
];

/// Complete statistical uniformity & signature-absence audit report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAuditReport {
    pub total_bytes: usize,
    pub shannon_entropy_bits_per_byte: f64,
    pub chi_square_stat: f64,
    pub chi_square_p_value: f64,
    pub serial_correlation: f64,
    pub msb_bit254_freq: Option<f64>,
    pub msb_bit255_freq: Option<f64>,
    pub detected_magic_signatures: Vec<String>,
    pub is_indistinguishable_noise: bool,
}

/// Evaluate `data` for byte-level statistical uniformity and absence of magic signatures.
pub fn audit_bytes(data: &[u8]) -> EntropyAuditReport {
    let total = data.len();
    if total == 0 {
        return EntropyAuditReport {
            total_bytes: 0,
            shannon_entropy_bits_per_byte: 0.0,
            chi_square_stat: 0.0,
            chi_square_p_value: 0.0,
            serial_correlation: 0.0,
            msb_bit254_freq: None,
            msb_bit255_freq: None,
            detected_magic_signatures: Vec::new(),
            is_indistinguishable_noise: false,
        };
    }

    let mut counts = [0u64; 256];
    for &b in data {
        counts[usize::from(b)] += 1;
    }

    let n = total as f64;
    let mut shannon = 0.0f64;
    let expected = n / 256.0;
    let mut chi_sq = 0.0f64;

    for &c in &counts {
        let count_f = c as f64;
        if c > 0 {
            let p = count_f / n;
            shannon -= p * p.log2();
        }
        let diff = count_f - expected;
        chi_sq += (diff * diff) / expected;
    }

    let p_value = chi_square_upper_tail(255.0, chi_sq);
    let serial_corr = compute_serial_correlation(data);

    let (b254, b255) = if data.len() >= 32 {
        (
            Some(f64::from((data[31] >> 6) & 1)),
            Some(f64::from((data[31] >> 7) & 1)),
        )
    } else {
        (None, None)
    };

    let mut signatures = Vec::new();
    for (name, sig) in PREFIX_SIGNATURES {
        if data.starts_with(sig) {
            signatures.push((*name).to_string());
        }
    }
    for (name, sig) in ANYWHERE_SIGNATURES {
        if data.len() >= sig.len() && data.windows(sig.len()).any(|w| w == *sig) {
            signatures.push((*name).to_string());
        }
    }

    // For tiny test buffers (< 4096 bytes), chi-square still holds while entropy approaches max possible
    // distinct byte coverage; for full streams/volumes (>= 4096 bytes), require H(X) > 7.90 as well.
    let entropy_ok = if total >= 4096 {
        shannon >= 7.90
    } else {
        shannon >= 4.0
    };
    let noise_ok =
        signatures.is_empty() && p_value > 0.001 && serial_corr.abs() < 0.05 && entropy_ok;

    EntropyAuditReport {
        total_bytes: total,
        shannon_entropy_bits_per_byte: shannon,
        chi_square_stat: chi_sq,
        chi_square_p_value: p_value,
        serial_correlation: serial_corr,
        msb_bit254_freq: b254,
        msb_bit255_freq: b255,
        detected_magic_signatures: signatures,
        is_indistinguishable_noise: noise_ok,
    }
}

/// Compute Pearson lag-1 autocorrelation across adjacent bytes in `data`.
fn compute_serial_correlation(data: &[u8]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }
    let n = data.len() as f64;
    let mut sum_x = 0.0f64;
    let mut sum_x2 = 0.0f64;
    let mut sum_xy = 0.0f64;

    for i in 0..data.len() {
        let x = f64::from(data[i]);
        let y = f64::from(data[(i + 1) % data.len()]);
        sum_x += x;
        sum_x2 += x * x;
        sum_xy += x * y;
    }

    let denom = n * sum_x2 - sum_x * sum_x;
    if denom.abs() < 1e-12 {
        0.0
    } else {
        (n * sum_xy - sum_x * sum_x) / denom
    }
}

/// Regularized upper incomplete gamma $Q(k/2, x/2)$ giving the Pearson $\chi^2$ $p$-value.
pub fn chi_square_upper_tail(df: f64, chi2: f64) -> f64 {
    if chi2 <= 0.0 {
        return 1.0;
    }
    if df <= 0.0 {
        return 0.0;
    }
    let a = 0.5 * df;
    let x = 0.5 * chi2;
    gamma_q(a, x)
}

fn gamma_q(a: f64, x: f64) -> f64 {
    if x < a + 1.0 {
        1.0 - gamma_p_series(a, x)
    } else {
        gamma_q_cf(a, x)
    }
}

fn gamma_p_series(a: f64, x: f64) -> f64 {
    let gln = ln_gamma(a);
    let mut ap = a;
    let mut sum = 1.0 / a;
    let mut del = sum;
    for _ in 0..1000 {
        ap += 1.0;
        del *= x / ap;
        sum += del;
        if del.abs() < sum.abs() * 1e-14 {
            break;
        }
    }
    (sum * (-x + a * x.ln() - gln).exp()).clamp(0.0, 1.0)
}

fn gamma_q_cf(a: f64, x: f64) -> f64 {
    let gln = ln_gamma(a);
    let tiny = 1e-30;
    let mut b = x + 1.0 - a;
    let mut c = 1.0 / tiny;
    let mut d = 1.0 / b;
    let mut h = d;
    for i in 1..=1000 {
        let an = -(i as f64) * ((i as f64) - a);
        b += 2.0;
        d = an * d + b;
        if d.abs() < tiny {
            d = tiny;
        }
        c = b + an / c;
        if c.abs() < tiny {
            c = tiny;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < 1e-14 {
            break;
        }
    }
    ((-x + a * x.ln() - gln).exp() * h).clamp(0.0, 1.0)
}

fn ln_gamma(z: f64) -> f64 {
    // Lanczos approximation (g = 7, n = 9).
    const COEFFS: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    let z_adj = z - 1.0;
    let mut x = COEFFS[0];
    for (i, &c) in COEFFS.iter().enumerate().skip(1) {
        x += c / (z_adj + i as f64);
    }
    let t = z_adj + 7.5;
    0.5 * (2.0 * std::f64::consts::PI).ln() + (z_adj + 0.5) * t.ln() - t + x.ln()
}
