//! Semantic validators for high-value PII patterns.
//!
//! Each validator runs *after* a regex match so a low-quality pattern (e.g. a
//! short 11-digit sequence) does not blow up into a false positive.

/// Luhn checksum used by credit-card and IMEI numbers.
///
/// Returns `true` if the digit sequence passes the Luhn modulus-10 check.
/// Non-digit characters are ignored.
#[must_use]
pub fn luhn_check(input: &str) -> bool {
    let digits: Vec<u32> = input.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 12 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        let v = if alt {
            let doubled = d * 2;
            if doubled > 9 {
                doubled - 9
            } else {
                doubled
            }
        } else {
            d
        };
        sum += v;
        alt = !alt;
    }
    sum % 10 == 0
}

/// Polish PESEL checksum + date sanity check.
///
/// The PESEL number is 11 digits long. Digits 1-2 encode the year (last two
/// digits), 3-4 the month (with a +20/+40/+60/+80 offset for centuries other
/// than 19xx), 5-6 the day, 7-10 the serial, and digit 11 is a weighted
/// checksum (weights 1,3,7,9,1,3,7,9,1,3).
#[must_use]
pub fn pesel_check(input: &str) -> bool {
    let digits: Vec<u32> = input.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 11 {
        return false;
    }

    // Decode month / century offset.
    let month = digits[2] * 10 + digits[3];
    let valid_month = matches!(
        month,
        1..=12       // 1900–1999
            | 21..=32 // 2000–2099
            | 41..=52 // 2100–2199
            | 61..=72 // 2200–2299
            | 81..=92, // 1800–1899
    );
    if !valid_month {
        return false;
    }

    // Day sanity check (1-31).
    let day = digits[4] * 10 + digits[5];
    if !(1..=31).contains(&day) {
        return false;
    }

    // Weighted checksum.
    const WEIGHTS: [u32; 10] = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let weighted: u32 = digits
        .iter()
        .take(10)
        .zip(WEIGHTS)
        .map(|(d, w)| d * w)
        .sum();
    let check = (10 - (weighted % 10)) % 10;
    check == digits[10]
}

/// IBAN mod-97 check, generic across all 34-character ISO-13616 IBAN formats.
///
/// Steps:
/// 1. Move the first four characters to the end.
/// 2. Replace each letter with its position in the alphabet + 9 (A=10, …, Z=35).
/// 3. Interpret the resulting digit string as a big integer mod 97.
/// 4. Valid IBANs return 1.
#[must_use]
pub fn iban_check(input: &str) -> bool {
    // Strip whitespace, validate length and alphabet.
    let normalized: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if normalized.len() < 15 || normalized.len() > 34 {
        return false;
    }
    if !normalized.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }

    // Move the first four characters to the end.
    let (head, tail) = normalized.split_at(4);
    let rearranged = format!("{tail}{head}");

    // Letter → number expansion.
    let mut expanded = String::with_capacity(rearranged.len() * 2);
    for c in rearranged.chars() {
        if let Some(d) = c.to_digit(10) {
            expanded.push_str(&d.to_string());
        } else if c.is_ascii_alphabetic() {
            let n = c.to_ascii_uppercase() as u32 - b'A' as u32 + 10;
            expanded.push_str(&n.to_string());
        } else {
            return false;
        }
    }

    // mod-97 by streaming chunks (avoids big-int dependency).
    let mut remainder: u64 = 0;
    for c in expanded.chars() {
        let d = c.to_digit(10).unwrap_or(0) as u64;
        remainder = (remainder * 10 + d) % 97;
    }
    remainder == 1
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn luhn_accepts_known_cards() {
        // Visa, MasterCard, Amex test numbers (publicly published).
        assert!(luhn_check("4111111111111111"));
        assert!(luhn_check("5555555555554444"));
        assert!(luhn_check("378282246310005"));
    }

    #[test]
    fn luhn_rejects_random_digits() {
        assert!(!luhn_check("4111111111111112"));
        assert!(!luhn_check("0000000000000001"));
    }

    #[test]
    fn pesel_accepts_known_valid() {
        // Known good PESEL test numbers.
        assert!(pesel_check("44051401359"));
        assert!(pesel_check("02070803628"));
    }

    #[test]
    fn pesel_rejects_random_digits() {
        assert!(!pesel_check("12345678901"));
        assert!(!pesel_check("00000000000"));
        // Wrong checksum.
        assert!(!pesel_check("44051401358"));
        // Invalid month (e.g. 13).
        assert!(!pesel_check("44131401359"));
    }

    #[test]
    fn iban_accepts_known_valid() {
        // Polish IBAN (test).
        assert!(iban_check("PL61109010140000071219812874"));
        // German IBAN (test).
        assert!(iban_check("DE89370400440532013000"));
    }

    #[test]
    fn iban_rejects_invalid_check_digits() {
        assert!(!iban_check("PL61109010140000071219812875"));
        assert!(!iban_check("PL00000000000000000000000000"));
    }

    #[test]
    fn iban_handles_whitespace() {
        assert!(iban_check("PL61 1090 1014 0000 0712 1981 2874"));
    }
}
