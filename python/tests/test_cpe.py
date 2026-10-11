import pytest

from gnomehome.cpe import Cpe, CpeMatch, compare_versions, match_service, parse_cpe22, parse_cpe23


def test_nmap_cpe22_to_23():
    cpe = parse_cpe22("cpe:/a:thekelleys:dnsmasq:2.85")
    assert cpe.to_23() == "cpe:2.3:a:thekelleys:dnsmasq:2.85:*:*:*:*:*:*:*"
    assert cpe.has_version


def test_special_characters_are_escaped_and_round_trip():
    cpe = parse_cpe22("cpe:/a:example:web_server%2bplus:1.0")
    name = cpe.to_23()
    assert name == "cpe:2.3:a:example:web_server\\+plus:1.0:*:*:*:*:*:*:*"
    assert parse_cpe23(name).product == "web_server+plus"


@pytest.mark.parametrize("bad", ["", "cpe:/x:a:b", "cpe:/a::b", "cpe:2.3:a:b", "nope"])
def test_bad_cpe22_is_rejected(bad):
    assert parse_cpe22(bad) is None


def test_versionless_cpe_has_no_version():
    assert not parse_cpe22("cpe:/a:openbsd:openssh").has_version


@pytest.mark.parametrize(
    ("a", "b", "want"),
    [("2.9", "2.10", -1), ("1.0rc1", "1.0", -1), ("4.8", "4.8.0", 0), ("1.1.1", "1.1.1k", -1),
     ("8.9p1", "9.0", -1), ("2.90", "2.89", 1), ("1.0beta2", "1.0rc1", -1)],
)  # fmt: skip
def test_compare_versions(a, b, want):
    assert compare_versions(a, b) == want


DNSMASQ_285 = Cpe("a", "thekelleys", "dnsmasq", "2.85")
ANY_DNSMASQ = "cpe:2.3:a:thekelleys:dnsmasq:*:*:*:*:*:*:*:*"


@pytest.mark.parametrize(
    ("rule", "want"),
    [
        (CpeMatch(ANY_DNSMASQ, True, end_excluding="2.87"), "cpe_version_range"),
        (CpeMatch(ANY_DNSMASQ, True, end_excluding="2.85"), None),
        (CpeMatch(ANY_DNSMASQ, True, end_including="2.85"), "cpe_version_range"),
        (CpeMatch(ANY_DNSMASQ, True, start_including="2.86"), None),
        (
            CpeMatch(ANY_DNSMASQ, True, start_excluding="2.84", end_excluding="2.90"),
            "cpe_version_range",
        ),
        (CpeMatch("cpe:2.3:a:thekelleys:dnsmasq:2.85:*:*:*:*:*:*:*", True), "cpe_exact"),
        (CpeMatch("cpe:2.3:a:thekelleys:dnsmasq:2.86:*:*:*:*:*:*:*", True), None),
        (CpeMatch(ANY_DNSMASQ, False, end_excluding="3.0"), None),  # not vulnerable
        (CpeMatch(ANY_DNSMASQ, True), None),  # every version, no range: too vague
        (CpeMatch("cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*", True, end_excluding="9.99"), None),
        (CpeMatch("cpe:2.3:o:thekelleys:dnsmasq:*:*:*:*:*:*:*:*", True, end_excluding="3"), None),
    ],
)
def test_match_service(rule, want):
    assert match_service(DNSMASQ_285, rule) == want
