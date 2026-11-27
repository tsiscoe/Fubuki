//! Two-branch uniform Curve25519 `Elligator2` map over $\mathbb{F}_{2^{255}-19}$
//! ($v^2 = u^3 + 486662 u^2 + u$, $Z = 2$ non-square, `#![forbid(unsafe_code)]`).
//!
//! Sampling randomly between preimages $r_1 = \sqrt{-2u(u+A)}/(2u)$ and
//! $r_2 = \sqrt{-2u(u+A)}/(2(u+A))$ in $[0, (p-1)/2]$ and randomizing top padding bits
//! $b_{254}, b_{255}$ yields uniform 32-byte representatives indistinguishable from $\{0,1\}^{256}$.

use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::edwards::EdwardsPoint;
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use super::fe25519::{Fe25519, P_MINUS_1_DIV_2, ct_gt_le};

/// Curve25519 Montgomery parameter `A = 486662`.
const CURVE_A: u64 = 486662;

/// Forward `Elligator2` map decoding a uniform 32-byte representative into a Curve25519
/// Montgomery `u`-coordinate.
pub fn elligator2_decode(repr: &[u8; 32]) -> [u8; 32] {
    let mut r_bytes = *repr;
    r_bytes[31] &= 0x3f;
    let r = Fe25519::from_bytes(&r_bytes);

    let a = Fe25519::from_u64(CURVE_A);
    let denom = Fe25519::ONE + (Fe25519::TWO * r.square());
    let d = (-a) * denom.inv();

    let gx = d * (d.square() + (a * d) + Fe25519::ONE);
    let eps = gx.pow_le_bytes(&P_MINUS_1_DIV_2);
    let is_non_square = eps.ct_eq(Fe25519::MINUS_ONE);

    let d_prime = -d - a;
    let u = Fe25519::ct_select(is_non_square, d_prime, d);
    u.to_bytes()
}

/// Evaluate the Legendre branch sign `eps(g(d))` (`+1` or `-1`) for statistical audits.
pub fn elligator2_branch_sign(repr: &[u8; 32]) -> i8 {
    let mut r_bytes = *repr;
    r_bytes[31] &= 0x3f;
    let r = Fe25519::from_bytes(&r_bytes);

    let a = Fe25519::from_u64(CURVE_A);
    let denom = Fe25519::ONE + (Fe25519::TWO * r.square());
    let d = (-a) * denom.inv();
    let gx = d * (d.square() + (a * d) + Fe25519::ONE);
    let eps = gx.pow_le_bytes(&P_MINUS_1_DIV_2);
    if eps.ct_eq(Fe25519::MINUS_ONE) == 1 {
        -1
    } else {
        1
    }
}

/// Verify in constant time whether `repr` decodes to any of the 8 torsion-coset translates
/// `EdwardsPoint::mul_base_clamped(sk.to_bytes()) + T_j` (`j in 0..8`).
pub fn elligator2_matches_secret(repr: &[u8; 32], sk: &StaticSecret) -> bool {
    let decoded_u = elligator2_decode(repr);
    let mut seed = sk.to_bytes();
    let base = EdwardsPoint::mul_base_clamped(seed);
    seed.zeroize();

    let mut matched = 0u8;
    for torsion in &EIGHT_TORSION {
        let candidate_u = (base + torsion).to_montgomery().to_bytes();
        matched |= decoded_u.ct_eq(&candidate_u).unwrap_u8();
    }
    matched == 1
}

/// Sample an ephemeral X25519 keypair whose public key admits a uniform two-branch `Elligator2`
/// representative `repr: [u8; 32]` with randomized bits `254..=255` and uniform 8-torsion coset
/// translation (`[8k]B + T_j`, `T_j in E[8]`), eliminating `[8]E` subgroup distinguishers while
/// preserving exact X25519 shared secrets under clamped scalar multiplication (`[8 * sk_r]T_j = O`).
pub fn elligator2_generate_ephemeral<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (StaticSecret, [u8; 32]) {
    let a = Fe25519::from_u64(CURVE_A);
    let neg_two = -Fe25519::TWO;

    loop {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut rand_bytes = [0u8; 2];
        rng.fill_bytes(&mut rand_bytes);

        let coset_idx = usize::from(rand_bytes[1] & 0b111);
        let ed_point = EdwardsPoint::mul_base_clamped(seed) + EIGHT_TORSION[coset_idx];
        let u_bytes = ed_point.to_montgomery().to_bytes();

        let sk = StaticSecret::from(seed);
        seed.zeroize();

        let u = Fe25519::from_bytes(&u_bytes);
        let u_plus_a = u + a;

        if u.is_zero() || u_plus_a.is_zero() {
            continue;
        }

        let w = neg_two * u * u_plus_a;
        let Some(root_w) = w.sqrt() else {
            continue;
        };

        let branch_bit = rand_bytes[0] & 1;
        let top2 = (rand_bytes[0] >> 1) & 0b11;

        let r1 = root_w * (Fe25519::TWO * u).inv();
        let r2 = root_w * (Fe25519::TWO * u_plus_a).inv();
        let r_raw = Fe25519::ct_select(branch_bit, r2, r1);

        let r_bytes = r_raw.to_bytes();
        let needs_neg = ct_gt_le(&r_bytes, &P_MINUS_1_DIV_2);
        let r_canon = Fe25519::ct_select(needs_neg, -r_raw, r_raw);

        let mut repr = r_canon.to_bytes();
        repr[31] |= top2 << 6;

        if elligator2_decode(&repr) == u_bytes {
            return (sk, repr);
        }
    }
}
