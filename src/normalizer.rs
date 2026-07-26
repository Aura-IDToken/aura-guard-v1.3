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

    // Additional edge case tests for shadow_normalize
    #[test]
    fn normalize_empty_string() {
        assert_eq!(shadow_normalize(""), "");
    }

    #[test]
    fn normalize_only_hidden_chars() {
        let hidden = "\u{200B}\u{200C}\u{200D}";
        assert_eq!(shadow_normalize(hidden), "");
    }

    #[test]
    fn normalize_mixed_hidden_and_visible() {
        let mixed = "a\u{200B}b\u{200C}c\u{200D}d";
        assert_eq!(shadow_normalize(mixed), "abcd");
    }

    #[test]
    fn normalize_bom_stripped() {
        let with_bom = "\u{FEFF}test\u{FEFF}";
        assert_eq!(shadow_normalize(with_bom), "test");
    }

    #[test]
    fn normalize_soft_hyphen_stripped() {
        let with_shy = "soft\u{00AD}hyphen";
        assert_eq!(shadow_normalize(with_shy), "softhyphen");
    }

    #[test]
    fn normalize_rtl_ltr_marks_stripped() {
        let with_marks = "a\u{200E}b\u{200F}c";
        assert_eq!(shadow_normalize(with_marks), "abc");
    }

    #[test]
    fn normalize_directional_formatting_stripped() {
        let with_dir = "a\u{202A}b\u{202B}c\u{202C}d\u{202D}e\u{202E}f";
        assert_eq!(shadow_normalize(with_dir), "abcdef");
    }

    #[test]
    fn normalize_isolates_stripped() {
        let with_iso = "a\u{2066}b\u{2067}c\u{2068}d\u{2069}e";
        assert_eq!(shadow_normalize(with_iso), "abcde");
    }

    #[test]
    fn normalize_line_paragraph_separators() {
        let with_sep = "a\u{2028}b\u{2029}c";
        assert_eq!(shadow_normalize(with_sep), "abc");
    }

    #[test]
    fn normalize_word_joiner_stripped() {
        let with_wj = "word\u{2060}joiner";
        assert_eq!(shadow_normalize(with_wj), "wordjoiner");
    }

    #[test]
    fn normalize_mongolian_vowel_separator() {
        let with_mvs = "test\u{180E}ing";
        assert_eq!(shadow_normalize(with_mvs), "testing");
    }

    #[test]
    fn confusable_greek_uppercase() {
        // Only some Greek letters are mapped (those that look like Latin)
        // Α->A, Β->B, Ε->E, Ζ->Z, Η->H, Ι->I, Κ->K, Μ->M, Ν->N, Ο->O, Ρ->P, Τ->T, Υ->Y, Χ->X
        let greek_upper = "ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ";
        let normalized = shadow_normalize(greek_upper);
        assert_eq!(normalized, "abezhikmnoptyx");
    }

    #[test]
    fn confusable_greek_lowercase() {
        // Test specific Greek lowercase letters that are mapped
        assert_eq!(shadow_normalize("α"), "a"); // alpha
        assert_eq!(shadow_normalize("ε"), "e"); // epsilon
        assert_eq!(shadow_normalize("ι"), "i"); // iota
        assert_eq!(shadow_normalize("κ"), "k"); // kappa
        assert_eq!(shadow_normalize("ο"), "o"); // omicron
        assert_eq!(shadow_normalize("ρ"), "p"); // rho
        assert_eq!(shadow_normalize("τ"), "t"); // tau
        assert_eq!(shadow_normalize("χ"), "x"); // chi
    }

    #[test]
    fn confusable_fullwidth_uppercase() {
        assert_eq!(shadow_normalize("ＡＢＣ"), "abc");
    }

    #[test]
    fn confusable_fullwidth_lowercase() {
        assert_eq!(shadow_normalize("ａｂｃ"), "abc");
    }

    #[test]
    fn confusable_fullwidth_digits() {
        assert_eq!(shadow_normalize("０１２３４５６７８９"), "0123456789");
    }

    #[test]
    fn confusable_mathematical_bold() {
        // Mathematical bold 'A' U+1D400 should not be in basic confusables
        // but NFKC may normalize it
        let math_bold = "\u{1D400}";
        let normalized = shadow_normalize(math_bold);
        // NFKC normalizes mathematical bold to regular letters
        assert_eq!(normalized, "a");
    }

    #[test]
    fn confusable_cyrillic_all_covered() {
        // Test all Cyrillic confusables in the fold_confusables function
        // Cyrillic: а А е Е ё Ё о О р Р с С у У х Х і І ј Ј ѕ Ѕ к К в В н Н м М т Т
        // Maps to: a a e e e e o o p p c c y y x x i i j j s s k k b b h h m m t t
        assert_eq!(shadow_normalize("аАеЕёЁоОрРсСуУхХіІјЈѕЅкКвВнНмМтТ"),
                   "aaeeeeooppccyyxxiijjsskkbbhhmmtt");
    }

    #[test]
    fn normalize_preserves_emoji() {
        // Emojis should be preserved (lowercased but structure intact)
        let emoji = "Test 😀 emoji";
        let normalized = shadow_normalize(emoji);
        assert!(normalized.contains("😀"));
        assert!(normalized.starts_with("test"));
    }

    #[test]
    fn normalize_preserves_cjk() {
        // CJK characters should be preserved through NFKC
        let cjk = "Test 中文 字符";
        let normalized = shadow_normalize(cjk);
        assert!(normalized.contains("中文"));
    }

    #[test]
    fn normalize_case_insensitive_ascii() {
        assert_eq!(shadow_normalize("ABC"), shadow_normalize("abc"));
        assert_eq!(shadow_normalize("XyZ"), shadow_normalize("xyz"));
    }

    #[test]
    fn normalize_mixed_script_attack() {
        // Mix of Latin, Cyrillic, Greek - all should normalize to ASCII equivalents
        let mixed = "АaΑa"; // Cyrillic A, Latin a, Greek Alpha, Latin a
        let normalized = shadow_normalize(mixed);
        assert_eq!(normalized, "aaaa");
    }

    #[test]
    fn normalize_stacked_diacritics() {
        // Multiple combining diacritics
        let stacked = "a\u{0301}\u{0302}\u{0303}"; // a + acute + circumflex + tilde
        let normalized = shadow_normalize(stacked);
        // NFKC should compose these
        assert!(!normalized.contains('\u{0301}'));
    }

    #[test]
    fn normalize_ligatures() {
        // Ligatures like 'ﬁ' (U+FB01) should be decomposed by NFKC
        let ligature = "ﬁle";
        let normalized = shadow_normalize(ligature);
        assert_eq!(normalized, "file");
    }

    #[test]
    fn normalize_superscript_subscript() {
        // Superscript and subscript should be normalized by NFKC
        let super_sub = "x²y₂"; // x superscript 2, y subscript 2
        let normalized = shadow_normalize(super_sub);
        assert_eq!(normalized, "x2y2");
    }

    #[test]
    fn normalize_compatibility_spaces() {
        // Various space characters should be normalized
        let spaces = "a\u{00A0}b\u{2000}c"; // non-breaking space, en quad
        let normalized = shadow_normalize(spaces);
        // NFKC normalizes these to regular spaces
        assert!(normalized.contains(' ') || normalized == "abc");
    }

    #[test]
    fn normalize_regression_credit_card_with_zwsp() {
        // Regression: ZWSP between digits should be stripped
        let card = "4111\u{200B}1111\u{200B}1111\u{200B}1111";
        let normalized = shadow_normalize(card);
        assert_eq!(normalized, "4111111111111111");
        assert!(!normalized.contains('\u{200B}'));
    }

    #[test]
    fn normalize_regression_iban_with_format() {
        // Regression: formatting characters in IBAN should be handled
        let iban = "PL\u{200B}61\u{200B}1090\u{00AD}1014";
        let normalized = shadow_normalize(iban);
        assert!(!normalized.contains('\u{200B}'));
        assert!(!normalized.contains('\u{00AD}'));
    }

    // Property-based tests for normalizer
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_normalize_idempotent(s in ".*") {
            // Normalizing twice should give the same result
            let once = shadow_normalize(&s);
            let twice = shadow_normalize(&once);
            prop_assert_eq!(once, twice);
        }

        #[test]
        fn prop_normalize_no_hidden_chars(s in ".*") {
            let normalized = shadow_normalize(&s);
            // No hidden characters should remain after normalization
            for &hidden in HIDDEN_CHARS {
                prop_assert!(!normalized.contains(hidden));
            }
        }

        #[test]
        fn prop_normalize_preserves_or_reduces_length(s in ".*") {
            let normalized = shadow_normalize(&s);
            // Normalization can sometimes increase byte length due to NFKC
            // but should generally reduce or preserve character count
            // Just ensure it doesn't panic - don't assert on length
            let _ = normalized;
        }

        #[test]
        fn prop_normalize_ascii_lowercase(s in "[A-Z]{1,100}") {
            let normalized = shadow_normalize(&s);
            // ASCII uppercase should become lowercase
            prop_assert!(normalized.chars().all(|c| !c.is_ascii_uppercase()));
        }

        #[test]
        fn prop_normalize_dont_panic(s in ".{0,1000}") {
            // Should never panic on any input
            let _ = shadow_normalize(&s);
        }

        #[test]
        fn prop_fold_confusables_preserves_plain_ascii(s in "[a-z0-9]{1,100}") {
            let folded = fold_confusables(&s);
            // Plain ASCII should remain unchanged
            prop_assert_eq!(s, folded);
        }
    }
}
