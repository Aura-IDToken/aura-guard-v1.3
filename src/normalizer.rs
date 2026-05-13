//! Shadow normalization pipeline (SHADOW_SPEC v1.0).
//!
//! The normalization order is **strict** and any deviation invalidates the
//! shadow hash. Steps:
//!
//! 1. UTF-8 validation (implicit — `&str` is always valid UTF-8).
//! 2. NFKC composition (`unicode-normalization`).
//! 3. Hidden-character stripping (zero-width spaces, BOM, soft hyphen, …).
//! 4. Confusable folding (e.g. Cyrillic `а` → ASCII `a`, fullwidth digits).
//! 5. Lowercase (ASCII fold).
//!
//! The original (untouched) text is always preserved for the evidence hash —
//! normalization only feeds the regex engine.

use unicode_normalization::UnicodeNormalization;

/// Frozen list of zero-width / formatting characters stripped before evaluation.
///
/// Includes ZWSP, ZWNJ, ZWJ, BOM, soft hyphen, left-to-right / right-to-left marks,
/// word joiners, and language tag characters that can be abused to evade simple regex.
pub const HIDDEN_CHARS: &[char] = &[
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{200E}', // LEFT-TO-RIGHT MARK
    '\u{200F}', // RIGHT-TO-LEFT MARK
    '\u{2028}', // LINE SEPARATOR
    '\u{2029}', // PARAGRAPH SEPARATOR
    '\u{202A}', // LEFT-TO-RIGHT EMBEDDING
    '\u{202B}', // RIGHT-TO-LEFT EMBEDDING
    '\u{202C}', // POP DIRECTIONAL FORMATTING
    '\u{202D}', // LEFT-TO-RIGHT OVERRIDE
    '\u{202E}', // RIGHT-TO-LEFT OVERRIDE
    '\u{2060}', // WORD JOINER
    '\u{2066}', // LEFT-TO-RIGHT ISOLATE
    '\u{2067}', // RIGHT-TO-LEFT ISOLATE
    '\u{2068}', // FIRST STRONG ISOLATE
    '\u{2069}', // POP DIRECTIONAL ISOLATE
    '\u{FEFF}', // BYTE ORDER MARK
    '\u{00AD}', // SOFT HYPHEN
    '\u{180E}', // MONGOLIAN VOWEL SEPARATOR
];

/// Run the full SHADOW_SPEC v1.0 normalization pipeline.
///
/// The returned string is intended **only** for regex matching. The original
/// `input` should be retained verbatim for the SHA-256 evidence hash.
#[must_use]
pub fn shadow_normalize(input: &str) -> String {
    // Step 2: NFKC composition.
    let nfkc: String = input.nfkc().collect();

    // Step 3: hidden-character stripping.
    let stripped: String = nfkc.chars().filter(|c| !HIDDEN_CHARS.contains(c)).collect();

    // Step 4: confusable folding (Cyrillic, Greek, fullwidth, …).
    let folded = fold_confusables(&stripped);

    // Step 5: ASCII lowercase.
    folded.to_lowercase()
}

/// Map common visual look-alikes to their ASCII equivalents.
///
/// Covers the highest-value attack vectors (Cyrillic/Greek look-alikes,
/// fullwidth Latin and digits, mathematical alphanumeric symbols). This is
/// *not* a full Unicode confusables table — it is deliberately scoped to
/// "regex-evasion via homoglyph" patterns. Run-time cost is one pass over the
/// string.
#[must_use]
pub fn fold_confusables(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            // Cyrillic look-alikes (lowercase + uppercase)
            'а' | 'А' => 'a',
            'е' | 'Е' | 'ё' | 'Ё' => 'e',
            'о' | 'О' => 'o',
            'р' | 'Р' => 'p',
            'с' | 'С' => 'c',
            'у' | 'У' => 'y',
            'х' | 'Х' => 'x',
            'і' | 'І' => 'i',
            'ј' | 'Ј' => 'j',
            'ѕ' | 'Ѕ' => 's',
            'к' | 'К' => 'k',
            'в' | 'В' => 'b',
            'н' | 'Н' => 'h',
            'м' | 'М' => 'm',
            'т' | 'Т' => 't',

            // Greek look-alikes
            'Α' => 'A',
            'α' => 'a',
            'Β' => 'B',
            'Ε' => 'E',
            'ε' => 'e',
            'Ζ' => 'Z',
            'Η' => 'H',
            'Ι' => 'I',
            'ι' => 'i',
            'Κ' => 'K',
            'κ' => 'k',
            'Μ' => 'M',
            'Ν' => 'N',
            'Ο' => 'O',
            'ο' => 'o',
            'Ρ' => 'P',
            'ρ' => 'p',
            'Τ' => 'T',
            'τ' => 't',
            'Υ' => 'Y',
            'Χ' => 'X',
            'χ' => 'x',

            // Fullwidth digits 0-9
            '０' => '0',
            '１' => '1',
            '２' => '2',
            '３' => '3',
            '４' => '4',
            '５' => '5',
            '６' => '6',
            '７' => '7',
            '８' => '8',
            '９' => '9',

            // Fullwidth Latin uppercase
            'Ａ' => 'A',
            'Ｂ' => 'B',
            'Ｃ' => 'C',
            'Ｄ' => 'D',
            'Ｅ' => 'E',
            'Ｆ' => 'F',
            'Ｇ' => 'G',
            'Ｈ' => 'H',
            'Ｉ' => 'I',
            'Ｊ' => 'J',
            'Ｋ' => 'K',
            'Ｌ' => 'L',
            'Ｍ' => 'M',
            'Ｎ' => 'N',
            'Ｏ' => 'O',
            'Ｐ' => 'P',
            'Ｑ' => 'Q',
            'Ｒ' => 'R',
            'Ｓ' => 'S',
            'Ｔ' => 'T',
            'Ｕ' => 'U',
            'Ｖ' => 'V',
            'Ｗ' => 'W',
            'Ｘ' => 'X',
            'Ｙ' => 'Y',
            'Ｚ' => 'Z',

            // Fullwidth Latin lowercase
            'ａ' => 'a',
            'ｂ' => 'b',
            'ｃ' => 'c',
            'ｄ' => 'd',
            'ｅ' => 'e',
            'ｆ' => 'f',
            'ｇ' => 'g',
            'ｈ' => 'h',
            'ｉ' => 'i',
            'ｊ' => 'j',
            'ｋ' => 'k',
            'ｌ' => 'l',
            'ｍ' => 'm',
            'ｎ' => 'n',
            'ｏ' => 'o',
            'ｐ' => 'p',
            'ｑ' => 'q',
            'ｒ' => 'r',
            'ｓ' => 's',
            'ｔ' => 't',
            'ｕ' => 'u',
            'ｖ' => 'v',
            'ｗ' => 'w',
            'ｘ' => 'x',
            'ｙ' => 'y',
            'ｚ' => 'z',

            other => other,
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn lowercase_preserves_digits() {
        assert_eq!(shadow_normalize("Hello 123"), "hello 123");
    }

    #[test]
    fn strips_zero_width_space() {
        let input = "PL\u{200B}61\u{200B}1090101400000712198\u{200B}12874";
        let normalized = shadow_normalize(input);
        assert!(!normalized.contains('\u{200B}'));
        assert_eq!(normalized, "pl61109010140000071219812874");
    }

    #[test]
    fn cyrillic_homoglyph_folds_to_ascii() {
        // "AABCDE12XXX" with Cyrillic 'А' substituted for first character
        let mixed = "АABCDE12XXX";
        let normalized = shadow_normalize(mixed);
        assert_eq!(normalized, "aabcde12xxx");
    }

    #[test]
    fn fullwidth_digits_fold() {
        assert_eq!(shadow_normalize("PL６１"), "pl61");
    }

    #[test]
    fn polish_diacritics_are_preserved() {
        // Polish diacritics are NOT confusables — they must remain.
        let normalized = shadow_normalize("Niższa pensja Żółć");
        assert_eq!(normalized, "niższa pensja żółć");
    }

    #[test]
    fn nfkc_combines_decomposed_form() {
        // 'é' as two code points U+0065 U+0301 → composed U+00E9.
        let decomposed = "cafe\u{0301}";
        let normalized = shadow_normalize(decomposed);
        assert_eq!(normalized, "café");
    }
}
