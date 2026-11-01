from vismriti.pii import IndianPIIDetector, mask, normalise_digits, verhoeff_check_digit, verhoeff_valid


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
    text = ("PAN ABCPR1234K, GSTIN 27ABCPR1234K1Z5, IFSC HDFC0001234, "
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
