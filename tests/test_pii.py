from vismriti.pii import IndianPIIDetector, gstin_valid, mask, normalise, normalise_digits, verhoeff_check_digit, verhoeff_valid


def aadhaar(base11: str) -> str:
    return base11 + verhoeff_check_digit(base11)


def test_verhoeff_roundtrip():
    for base in ["23456789012", "98765432109", "50000000001"]:
        assert verhoeff_valid(aadhaar(base))


def test_verhoeff_catches_single_digit_error():
    good = aadhaar("23456789012")
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    assert not verhoeff_valid(bad)


def test_aadhaar_requires_checksum():
    good = aadhaar("23456789012")
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    kinds = lambda t: [f.kind for f in IndianPIIDetector().detect(t)]
    assert kinds(f"id {good[:4]} {good[4:8]} {good[8:]}") == ["AADHAAR"]
    assert "AADHAAR" not in kinds(f"order number {bad}")


def test_aadhaar_never_starts_with_0_or_1():
    n = aadhaar("13456789012")
    assert not IndianPIIDetector().detect(n)


def test_indian_identifiers_detected():
    text = ("PAN ABCPR1234K, GSTIN 27ABCPR1234K1ZN, IFSC HDFC0001234, "
            "upi asha.rao@okhdfcbank, mail asha@example.in, call +91 98765 43210")
    kinds = [f.kind for f in IndianPIIDetector().detect(text)]
    assert kinds == ["PAN", "GSTIN", "IFSC", "UPI", "EMAIL", "PHONE_IN"]


def test_upi_is_not_confused_with_email():
    kinds = [f.kind for f in IndianPIIDetector().detect("ravi.k@ybl and ravi.k@gmail.com")]
    assert kinds == ["UPI", "EMAIL"]


def test_identifier_at_end_of_sentence_is_masked():
    masked, _ = mask("Her UPI id is asha.rao@okhdfcbank. PAN ABCPR1234K.")
    assert masked == "Her UPI id is [UPI]. PAN [PAN]."


def test_devanagari_and_odia_digits():
    good = aadhaar("23456789012")
    deva = good.translate({ord(str(i)): chr(0x0966 + i) for i in range(10)})
    odia = "९८७६५४३२१०".translate({0x0966 + i: chr(0x0B66 + i) for i in range(10)})
    assert normalise_digits(deva) == good
    assert [f.kind for f in IndianPIIDetector().detect(f"आधार {deva}")] == ["AADHAAR"]
    assert [f.kind for f in IndianPIIDetector().detect(f"ଫୋନ {odia}")] == ["PHONE_IN"]


def test_mask_replaces_and_keeps_text():
    masked, findings = mask("PAN ABCPR1234K, call 9876543210 today")
    assert masked == "PAN [PAN], call [PHONE_IN] today"
    assert len(findings) == 2


def test_invisible_characters_do_not_hide_identifiers():
    good = aadhaar("23456789012")
    zw = "\u200b".join([good[:4], good[4:8], good[8:]])
    text = f"Aadhaar {zw} and PAN ABCPR\u200b1234K."
    found = IndianPIIDetector().detect(text)
    assert [f.kind for f in found] == ["AADHAAR", "PAN"]
    assert found[0].value == zw  # reported exactly as written, invisible characters included
    masked, _ = mask(text)
    assert masked == "Aadhaar [AADHAAR] and PAN [PAN]."


def test_look_alike_letters_do_not_hide_identifiers():
    sneaky_pan = "АBСPR1234K"  # Cyrillic A and C
    sneaky_upi = "аsha.rao@okhdfcbank"  # Cyrillic a
    found = IndianPIIDetector().detect(f"PAN {sneaky_pan}, UPI {sneaky_upi}")
    assert [(f.kind, f.value) for f in found] == [("PAN", sneaky_pan), ("UPI", sneaky_upi)]


def test_aadhaar_split_across_lines():
    good = aadhaar("23456789012")
    text = f"Aadhaar {good[:4]} {good[4:8]}\n{good[8:]} received"
    found = IndianPIIDetector().detect(text)
    assert [f.kind for f in found] == ["AADHAAR"] and "\n" in found[0].value


def test_normalise_keeps_positions_of_the_original():
    text = "a\u200bА१"
    clean, index = normalise(text)
    assert clean == "aA1" and index == [0, 2, 3]


def test_plain_text_and_ordinary_numbers_unchanged():
    assert IndianPIIDetector().detect("Invoice 1234 5678 9012 for order 42") == []  # fails the checksum
    assert IndianPIIDetector().detect("Привет, это обычный текст") == []


def test_gstin_needs_a_correct_check_character():
    assert gstin_valid("27AAPFU0939F1ZV")  # widely published sample GSTIN
    assert not gstin_valid("27AAPFU0939F1ZW")
    assert [f.kind for f in IndianPIIDetector().detect("GSTIN 27AAPFU0939F1ZV")] == ["GSTIN"]
    assert [f.kind for f in IndianPIIDetector().detect("GSTIN 27AAPFU0939F1ZW")] != ["GSTIN"]
