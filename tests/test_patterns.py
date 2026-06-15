"""Tests for OSINT regex patterns: match/no-match examples for every pattern.

Every pattern gets:
  - Should-match examples (correct format)
  - Should-NOT-match examples (close but wrong: bad prefix, wrong length, forbidden chars)
  - Where important, embedded-in-text tests (verifying \\b works in prose)
"""

import re

import pytest

import patterns


def match(pattern: str, text: str) -> bool:
    return bool(re.search(pattern, text))


# ===================================================================
# Email
# ===================================================================

EMAIL_MATCH = [
    "user@example.com",
    "first.last@sub.domain.org",
    "user+tag@gmail.com",
    "user_123@company.co.uk",
    "a@b.io",
]
EMAIL_NO_MATCH = [
    "notanemail",
    "missing@tld",
    "@nodomain.com",
    "double@@at.com",
]


@pytest.mark.parametrize("text", EMAIL_MATCH)
def test_email_matches(text):
    assert match(patterns.EMAIL["standard"], text)


@pytest.mark.parametrize("text", EMAIL_NO_MATCH)
def test_email_no_match(text):
    assert not match(patterns.EMAIL["standard"], text)


def test_email_in_text():
    assert match(patterns.EMAIL["standard"], "Contact us at info@example.com for details")


# ===================================================================
# Phone — E.164
# ===================================================================

@pytest.mark.parametrize("text", [
    "+14155552671", "+447911123456", "+33612345678", "14155552671",
])
def test_phone_e164_matches(text):
    assert match(patterns.PHONE["e164"], text)


@pytest.mark.parametrize("text", [
    "+0123",   # starts with 0
    "abc",
    "+1234",   # too short
])
def test_phone_e164_no_match(text):
    assert not match(patterns.PHONE["e164"], text)


# ===================================================================
# Phone — NANP
# ===================================================================

@pytest.mark.parametrize("text", [
    "(212) 555-1234", "800.555.0199", "212-555-1234",
    "+1 800 555 0199", "8005550199",
])
def test_phone_nanp_matches(text):
    assert match(patterns.PHONE["nanp"], text)


@pytest.mark.parametrize("text", [
    "123",              # too short
    "letters-555-1234", # non-digit area code
])
def test_phone_nanp_no_match(text):
    assert not match(patterns.PHONE["nanp"], text)


# ===================================================================
# Passport
# ===================================================================

@pytest.mark.parametrize("text", ["A12345678", "123456789", "B987654321"])
def test_passport_us_matches(text):
    assert match(patterns.PASSPORT["us"], text)


@pytest.mark.parametrize("text", ["AB12345", "1234"])
def test_passport_us_no_match(text):
    assert not match(patterns.PASSPORT["us"], text)


@pytest.mark.parametrize("text", ["123456789"])
def test_passport_uk_matches(text):
    assert match(patterns.PASSPORT["uk"], text)


@pytest.mark.parametrize("text", ["12345678", "1234567890"])
def test_passport_uk_no_match(text):
    assert not match(patterns.PASSPORT["uk"], text)


@pytest.mark.parametrize("text", ["AB123456"])
def test_passport_ca_matches(text):
    assert match(patterns.PASSPORT["canada"], text)


@pytest.mark.parametrize("text", ["A123456", "ABC123456"])
def test_passport_ca_no_match(text):
    assert not match(patterns.PASSPORT["canada"], text)


# ===================================================================
# Bitcoin
# ===================================================================

BTC_P2PKH_MATCH = [
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na",
    "1BpEi6DfDAUFd153wiGrvkiboLLaqRkZv8",
]
BTC_P2PKH_NO_MATCH = [
    "0A1zP1eP5QGefi2DMPTfTL5SLmv7Divf",    # starts with 0
    "1OlA1zP1eP5QGefi2DMPTfTL",             # contains O (invalid base58)
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",   # P2SH not P2PKH
]


@pytest.mark.parametrize("text", BTC_P2PKH_MATCH)
def test_btc_p2pkh_matches(text):
    assert match(patterns.BITCOIN["p2pkh"], text)


@pytest.mark.parametrize("text", BTC_P2PKH_NO_MATCH)
def test_btc_p2pkh_no_match(text):
    assert not match(patterns.BITCOIN["p2pkh"], text)


@pytest.mark.parametrize("text", [
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    "3Ai1JZ8pdJb2ksieUV8FsxSNVJCpoPi8W6",
])
def test_btc_p2sh_matches(text):
    assert match(patterns.BITCOIN["p2sh"], text)


def test_btc_p2sh_no_match():
    assert not match(patterns.BITCOIN["p2sh"], "1BpEi6DfDAUFd153wiGrvkiboLLaqRkZv8")


@pytest.mark.parametrize("text", [
    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    "bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9",
])
def test_btc_bech32_matches(text):
    assert match(patterns.BITCOIN["bech32"], text)


@pytest.mark.parametrize("text", [
    "bc2qar0srrr7xfkvy5l643lydnw9re59gtzzwf",  # wrong prefix
    "BC1qar0srr",                                 # too short
])
def test_btc_bech32_no_match(text):
    assert not match(patterns.BITCOIN["bech32"], text)


def test_btc_in_text():
    text = "Send to 1BpEi6DfDAUFd153wiGrvkiboLLaqRkZv8 for payment"
    assert match(patterns.BITCOIN["p2pkh"], text)


# ===================================================================
# Ethereum
# ===================================================================

ETH_MATCH = [
    "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    "0x0000000000000000000000000000000000000000",
]
ETH_NO_MATCH = [
    "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697B",    # 39 hex chars
    "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",  # non-hex
    "de0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",     # missing 0x
]


@pytest.mark.parametrize("text", ETH_MATCH)
def test_eth_matches(text):
    assert match(patterns.CRYPTO["ethereum"], text)


@pytest.mark.parametrize("text", ETH_NO_MATCH)
def test_eth_no_match(text):
    assert not match(patterns.CRYPTO["ethereum"], text)


def test_eth_in_text():
    assert match(
        patterns.CRYPTO["ethereum"],
        "Wallet 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe has 5 ETH",
    )


# ===================================================================
# Other crypto
# ===================================================================

@pytest.mark.parametrize("text", [
    "LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL",
    "M8T1B2JQ8Y4my95uxP9CgCyZe3KV2W9Lk5",
])
def test_litecoin_matches(text):
    assert match(patterns.CRYPTO["litecoin"], text)


def test_litecoin_no_match():
    assert not match(patterns.CRYPTO["litecoin"], "Xdx")  # too short
    assert not match(patterns.CRYPTO["litecoin"], "ZdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL")


@pytest.mark.parametrize("text", [
    "rN7n3473SaZBCG4dFL83w7PB3kpHp6MGHJ",
    "rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq",
])
def test_ripple_matches(text):
    assert match(patterns.CRYPTO["ripple"], text)


def test_ripple_no_match():
    assert not match(patterns.CRYPTO["ripple"], "sN7n3473SaZBCG4dFL83w7PB3kpHp6MGHJ")


@pytest.mark.parametrize("text", [
    "4" + "8" + "a" * 93,  # 95 chars: 4 + [0-9AB] + 93 base58
    "4" + "A" + "b" * 93,
])
def test_monero_matches(text):
    assert match(patterns.CRYPTO["monero"], text)


def test_monero_no_match():
    assert not match(patterns.CRYPTO["monero"], "5" + "8" + "a" * 93)  # wrong first char
    assert not match(patterns.CRYPTO["monero"], "4" + "8" + "a" * 80)  # too short


@pytest.mark.parametrize("text", [
    "D7da8KJR4ZBBv5WMt9BwX4Gm4nzhoQUGYq",
])
def test_dogecoin_matches(text):
    assert match(patterns.CRYPTO["dogecoin"], text)


def test_dogecoin_no_match():
    assert not match(patterns.CRYPTO["dogecoin"], "A7da8KJR4ZBBv5WMt9BwX4Gm4nzhoQUGYq")


def test_cardano_matches():
    assert match(patterns.CRYPTO["cardano"], "addr1" + "a" * 53)


def test_cardano_no_match():
    assert not match(patterns.CRYPTO["cardano"], "addr2" + "a" * 53)
    assert not match(patterns.CRYPTO["cardano"], "addr1" + "a" * 50)  # too short


@pytest.mark.parametrize("text", [
    "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
    "T" + "A" * 33,
])
def test_tron_matches(text):
    assert match(patterns.CRYPTO["tron"], text)


def test_tron_no_match():
    assert not match(patterns.CRYPTO["tron"], "T" + "A" * 30)  # too short
    assert not match(patterns.CRYPTO["tron"], "X" + "A" * 33)  # wrong prefix


def test_bitcoin_cash_matches():
    bch_addr = "qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy"
    assert match(patterns.CRYPTO["bitcoin_cash"], "bitcoincash:" + bch_addr)
    assert match(patterns.CRYPTO["bitcoin_cash"], bch_addr)


def test_bitcoin_cash_no_match():
    assert not match(patterns.CRYPTO["bitcoin_cash"], "z" + "a" * 41)  # wrong prefix
    assert not match(patterns.CRYPTO["bitcoin_cash"], "q" + "a" * 30)  # too short


# ===================================================================
# IPv4
# ===================================================================

IPV4_MATCH = [
    "192.168.1.1", "10.0.0.0", "255.255.255.255", "0.0.0.0", "172.16.0.1",
]
IPV4_NO_MATCH = [
    "999.0.0.1", "256.256.256.256", "192.168.1",
]


@pytest.mark.parametrize("text", IPV4_MATCH)
def test_ipv4_matches(text):
    assert match(patterns.IP["ipv4"], text)


@pytest.mark.parametrize("text", IPV4_NO_MATCH)
def test_ipv4_no_match(text):
    assert not match(patterns.IP["ipv4"], text)


def test_ipv4_in_text():
    assert match(patterns.IP["ipv4"], "C2 callback to 54.67.109.199 on port 443")
    assert match(patterns.IP["ipv4"], "Resolved to 10.0.0.1.")


@pytest.mark.parametrize("text", [
    "10.0.0.0/8", "192.168.0.0/24", "172.16.0.0/12", "8.8.8.8",
])
def test_ipv4_cidr_matches(text):
    assert match(patterns.IP["ipv4_cidr"], text)


def test_ipv4_cidr_no_match():
    assert not match(patterns.IP["ipv4_cidr"], "256.0.0.0/8")


# ===================================================================
# IPv6
# ===================================================================

@pytest.mark.parametrize("text", [
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    "fe80:0000:0000:0000:0202:b3ff:fe1e:8329",
])
def test_ipv6_standard_matches(text):
    assert match(patterns.IP["ipv6_standard"], text)


@pytest.mark.parametrize("text", [
    "2001:db8::1",          # compressed form
    "2001:0db8:85a3:zzzz",  # non-hex
])
def test_ipv6_standard_no_match(text):
    assert not match(patterns.IP["ipv6_standard"], text)


@pytest.mark.parametrize("text", [
    "2001:db8::1", "::1", "fe80::1",
    "2001:db8:85a3::8a2e:370:7334", "::ffff:192.0.2.1",
])
def test_ipv6_compressed_matches(text):
    assert match(patterns.IP["ipv6_compressed"], text)


# ===================================================================
# Social media
# ===================================================================

@pytest.mark.parametrize("text", [
    "https://www.facebook.com/profile.php?id=100004356026155",
    "facebook.com/123456789012",
])
def test_facebook_id_matches(text):
    assert match(patterns.SOCIAL["facebook_id"], text)


def test_facebook_id_no_match():
    assert not match(patterns.SOCIAL["facebook_id"], "facebook.com/1234")  # too few digits


@pytest.mark.parametrize("text", [
    "https://www.facebook.com/zuckerberg",
    "facebook.com/johnsmith",
])
def test_facebook_username_matches(text):
    assert match(patterns.SOCIAL["facebook_username"], text)


def test_facebook_username_no_match():
    assert not match(patterns.SOCIAL["facebook_username"], "facebook.com/ab")  # too short


@pytest.mark.parametrize("text", [
    "https://www.instagram.com/nasa/",
    "instagram.com/user.name_123",
])
def test_instagram_url_matches(text):
    assert match(patterns.SOCIAL["instagram_url"], text)


def test_instagram_url_no_match():
    assert not match(patterns.SOCIAL["instagram_url"], "notstagram.com/user")


def test_instagram_mention_matches():
    assert match(patterns.SOCIAL["instagram_mention"], "@nasa")


@pytest.mark.parametrize("text", [
    "https://t.me/durov", "t.me/username123", "telegram.me/channel_name",
])
def test_telegram_url_matches(text):
    assert match(patterns.SOCIAL["telegram_url"], text)


def test_telegram_url_no_match():
    assert not match(patterns.SOCIAL["telegram_url"], "t.me/1badstart")
    assert not match(patterns.SOCIAL["telegram_url"], "t.me/ab")  # too short


@pytest.mark.parametrize("text", [
    "https://vk.com/id12345", "vk.com/id999999999999999",
])
def test_vk_id_matches(text):
    assert match(patterns.SOCIAL["vk_id"], text)


def test_vk_id_no_match():
    assert not match(patterns.SOCIAL["vk_id"], "vk.com/username")  # not numeric


@pytest.mark.parametrize("text", [
    "vk.com/durov", "https://www.vk.com/team_vk",
])
def test_vk_username_matches(text):
    assert match(patterns.SOCIAL["vk_username"], text)


def test_vk_username_no_match():
    assert not match(patterns.SOCIAL["vk_username"], "vk.com/1numeric")  # starts with digit


@pytest.mark.parametrize("text", [
    "https://www.twitter.com/elonmusk/", "x.com/jack",
])
def test_twitter_url_matches(text):
    assert match(patterns.SOCIAL["twitter_url"], text)


def test_twitter_url_no_match():
    assert not match(
        patterns.SOCIAL["twitter_url"],
        "https://twitter.com/wayyyy_too_long_username_here",
    )


def test_twitter_tweet_id_matches():
    assert match(
        patterns.SOCIAL["twitter_tweet_id"],
        "https://twitter.com/user/status/1234567890123456789",
    )


def test_twitter_tweet_id_no_match():
    assert not match(patterns.SOCIAL["twitter_tweet_id"], "twitter.com/user/status/123")


@pytest.mark.parametrize("text", [
    "https://www.linkedin.com/in/johndoe/",
    "linkedin.com/in/jane-doe-123",
])
def test_linkedin_profile_matches(text):
    assert match(patterns.SOCIAL["linkedin_profile"], text)


def test_linkedin_profile_no_match():
    assert not match(patterns.SOCIAL["linkedin_profile"], "linkedin.com/in/ab")


@pytest.mark.parametrize("text", [
    "https://linkedin.com/company/google/",
    "linkedin.com/company/my-startup",
])
def test_linkedin_company_matches(text):
    assert match(patterns.SOCIAL["linkedin_company"], text)


def test_linkedin_post_matches():
    assert match(
        patterns.SOCIAL["linkedin_post"],
        "https://www.linkedin.com/feed/update/urn:li:activity:123456789",
    )


@pytest.mark.parametrize("text", [
    "https://www.tiktok.com/@charlidamelio/",
    "tiktok.com/@user.name",
])
def test_tiktok_url_matches(text):
    assert match(patterns.SOCIAL["tiktok_url"], text)


def test_tiktok_url_no_match():
    assert not match(patterns.SOCIAL["tiktok_url"], "tiktok.com/@x")  # too short


def test_tiktok_video_id_matches():
    assert match(
        patterns.SOCIAL["tiktok_video_id"],
        "https://www.tiktok.com/@user/video/123456789012345678",
    )


def test_tiktok_video_id_no_match():
    assert not match(
        patterns.SOCIAL["tiktok_video_id"],
        "tiktok.com/@user/video/12345",  # ID too short
    )


def test_tiktok_short_matches():
    assert match(patterns.SOCIAL["tiktok_short"], "https://vm.tiktok.com/ZMeABCDEF/")


def test_tiktok_short_no_match():
    assert not match(patterns.SOCIAL["tiktok_short"], "https://www.tiktok.com/ZMe")


# ===================================================================
# Credit cards
# ===================================================================

@pytest.mark.parametrize("text", [
    "4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111",
])
def test_visa_matches(text):
    assert match(patterns.CREDIT_CARD["visa"], text)


def test_visa_no_match():
    assert not match(patterns.CREDIT_CARD["visa"], "5111111111111111")


@pytest.mark.parametrize("text", [
    "5500000000000004", "5500 0000 0000 0004", "2221000000000009",
])
def test_mastercard_matches(text):
    assert match(patterns.CREDIT_CARD["mastercard"], text)


def test_mastercard_no_match():
    assert not match(patterns.CREDIT_CARD["mastercard"], "4500000000000004")


@pytest.mark.parametrize("text", [
    "378282246310005", "3714 496353 98431",
])
def test_amex_matches(text):
    assert match(patterns.CREDIT_CARD["amex"], text)


def test_amex_no_match():
    assert not match(patterns.CREDIT_CARD["amex"], "3882822463100051")  # 38 not 34/37


@pytest.mark.parametrize("text", [
    "6011111111111117", "6500000000000002",
])
def test_discover_matches(text):
    assert match(patterns.CREDIT_CARD["discover"], text)


def test_discover_no_match():
    assert not match(patterns.CREDIT_CARD["discover"], "7011111111111117")


@pytest.mark.parametrize("text", [
    "3530111333300000", "3566002020360505",
])
def test_jcb_matches(text):
    assert match(patterns.CREDIT_CARD["jcb"], text)


def test_jcb_no_match():
    assert not match(patterns.CREDIT_CARD["jcb"], "3630111333300000")  # 36 prefix = Diners


def test_unionpay_matches():
    assert match(patterns.CREDIT_CARD["unionpay"], "6200000000000005")


def test_unionpay_no_match():
    assert not match(patterns.CREDIT_CARD["unionpay"], "6300000000000005")  # 63 not 62


# ===================================================================
# SSN
# ===================================================================

@pytest.mark.parametrize("text", ["123-45-6789", "234-56-7890"])
def test_ssn_matches(text):
    assert match(patterns.SSN["standard"], text)


@pytest.mark.parametrize("text", [
    "000-45-6789",  # area 000
    "666-45-6789",  # area 666
    "900-45-6789",  # 9xx = ITIN
    "123-00-6789",  # group 00
    "123-45-0000",  # serial 0000
])
def test_ssn_no_match(text):
    assert not match(patterns.SSN["standard"], text)


def test_ssn_flexible_matches():
    assert match(patterns.SSN["flexible"], "123 45 6789")
    assert match(patterns.SSN["flexible"], "123456789")


def test_itin_matches():
    assert match(patterns.SSN["itin"], "912-34-5678")


def test_itin_no_match():
    assert not match(patterns.SSN["itin"], "812-34-5678")  # 8xx not 9xx


# ===================================================================
# MAC address
# ===================================================================

@pytest.mark.parametrize("text", [
    "00:1A:2B:3C:4D:5E", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00",
])
def test_mac_colon_matches(text):
    assert match(patterns.MAC["colon"], text)


@pytest.mark.parametrize("text", [
    "00:1A:2B:3C:4D",     # only 5 groups
    "GG:1A:2B:3C:4D:5E",  # non-hex
])
def test_mac_colon_no_match(text):
    assert not match(patterns.MAC["colon"], text)


def test_mac_hyphen_matches():
    assert match(patterns.MAC["hyphen"], "00-1A-2B-3C-4D-5E")


def test_mac_hyphen_no_match():
    assert not match(patterns.MAC["hyphen"], "00-1A-2B-3C-4D")


def test_mac_cisco_matches():
    assert match(patterns.MAC["dot_cisco"], "001A.2B3C.4D5E")


def test_mac_cisco_no_match():
    assert not match(patterns.MAC["dot_cisco"], "001A.2B3C")  # only 2 groups


def test_mac_no_sep_matches():
    assert match(patterns.MAC["no_sep"], "001A2B3C4D5E")


def test_mac_no_sep_no_match():
    assert not match(patterns.MAC["no_sep"], "001A2B3C4D5")    # 11 chars
    assert not match(patterns.MAC["no_sep"], "GG1A2B3C4D5E")   # non-hex


def test_mac_in_text():
    assert match(patterns.MAC["colon"], "ARP entry 00:1A:2B:3C:4D:5E on eth0")


# ===================================================================
# IBAN
# ===================================================================

IBAN_GENERIC_MATCH = [
    "DE89370400440532013000",
    "GB29NWBK60161331926819",
    "FR7614508059405358423980136",
    "NL91ABNA0417164300",
]
IBAN_GENERIC_NO_MATCH = [
    "DE893",            # too short
    "12NWBK60161331",   # starts with digits
]


@pytest.mark.parametrize("text", IBAN_GENERIC_MATCH)
def test_iban_generic_matches(text):
    assert match(patterns.IBAN["generic"], text)


@pytest.mark.parametrize("text", IBAN_GENERIC_NO_MATCH)
def test_iban_generic_no_match(text):
    assert not match(patterns.IBAN["generic"], text)


def test_iban_germany_matches():
    assert match(patterns.IBAN["germany"], "DE89370400440532013000")


def test_iban_germany_no_match():
    assert not match(patterns.IBAN["germany"], "FR89370400440532013000")


def test_iban_uk_matches():
    assert match(patterns.IBAN["uk"], "GB29NWBK60161331926819")


def test_iban_uk_no_match():
    assert not match(patterns.IBAN["uk"], "DE29NWBK60161331926819")


def test_iban_france_matches():
    assert match(patterns.IBAN["france"], "FR7614508059405358423980136")


def test_iban_france_no_match():
    assert not match(patterns.IBAN["france"], "GB7614508059405358423980136")


def test_iban_netherlands_matches():
    assert match(patterns.IBAN["netherlands"], "NL91ABNA0417164300")


def test_iban_netherlands_no_match():
    assert not match(patterns.IBAN["netherlands"], "DE91ABNA0417164300")


def test_iban_switzerland_matches():
    assert match(patterns.IBAN["switzerland"], "CH93 0076 2011 6238 5295 7")


# ===================================================================
# TIN
# ===================================================================

def test_tin_us_ein_matches():
    assert match(patterns.TIN["us_ein"], "12-3456789")


def test_tin_us_ein_no_match():
    assert not match(patterns.TIN["us_ein"], "1-3456789")


def test_tin_india_pan_matches():
    assert match(patterns.TIN["india_pan"], "ABCDE1234F")


def test_tin_india_pan_no_match():
    assert not match(patterns.TIN["india_pan"], "ABCD1234F")   # only 4 letters
    assert not match(patterns.TIN["india_pan"], "ABCDE123F")   # only 3 digits


def test_tin_brazil_cpf_matches():
    assert match(patterns.TIN["brazil_cpf"], "123.456.789-09")
    assert match(patterns.TIN["brazil_cpf"], "12345678909")


def test_tin_brazil_cpf_no_match():
    assert not match(patterns.TIN["brazil_cpf"], "12345678")  # too short


def test_tin_brazil_cnpj_matches():
    assert match(patterns.TIN["brazil_cnpj"], "11.222.333/0001-81")
    assert match(patterns.TIN["brazil_cnpj"], "11222333000181")


def test_tin_russia_inn_matches():
    assert match(patterns.TIN["russia_inn"], "INN: 1234567890")
    assert match(patterns.TIN["russia_inn"], "ИНН:123456789012")


def test_tin_russia_inn_no_match():
    assert not match(patterns.TIN["russia_inn"], "1234567890")  # no context keyword


# ===================================================================
# License plates
# ===================================================================

def test_license_plate_uk_matches():
    assert match(patterns.LICENSE_PLATE["uk"], "AB12 CDE")
    assert match(patterns.LICENSE_PLATE["uk"], "AB12CDE")


def test_license_plate_uk_no_match():
    assert not match(patterns.LICENSE_PLATE["uk"], "AB1 CDE")
    assert not match(patterns.LICENSE_PLATE["uk"], "ABCD EFG")


def test_license_plate_france_matches():
    assert match(patterns.LICENSE_PLATE["france"], "AB-123-CD")
    assert match(patterns.LICENSE_PLATE["france"], "AB123CD")


def test_license_plate_france_no_match():
    assert not match(patterns.LICENSE_PLATE["france"], "AB-12-CD")   # only 2 digits
    assert not match(patterns.LICENSE_PLATE["france"], "AB-1234-CD")  # 4 digits


def test_license_plate_brazil_matches():
    assert match(patterns.LICENSE_PLATE["brazil_mercosur"], "ABC1D23")


def test_license_plate_brazil_no_match():
    assert not match(patterns.LICENSE_PLATE["brazil_mercosur"], "ABC1234")


def test_license_plate_south_korea_matches():
    assert match(patterns.LICENSE_PLATE["south_korea"], "12가1234")
    assert match(patterns.LICENSE_PLATE["south_korea"], "123나5678")


def test_license_plate_germany_matches():
    assert match(patterns.LICENSE_PLATE["germany"], "B AB 1234")
    assert match(patterns.LICENSE_PLATE["germany"], "M-A 1")


def test_license_plate_canada_ontario_matches():
    assert match(patterns.LICENSE_PLATE["canada_ontario"], "ABCD 123")


def test_license_plate_canada_ontario_no_match():
    assert not match(patterns.LICENSE_PLATE["canada_ontario"], "AB 123")


# ===================================================================
# API keys
# ===================================================================

def test_aws_access_key_matches():
    assert match(patterns.API_KEY["aws_access_key"], "AKIAIOSFODNN7EXAMPLE")


def test_aws_access_key_no_match():
    assert not match(patterns.API_KEY["aws_access_key"], "BKIAIOSFODNN7EXAMPLE")


def test_aws_session_token_matches():
    assert match(patterns.API_KEY["aws_session_token"], "ASIAIOSFODNN7EXAMPLE")


def test_aws_session_token_no_match():
    assert not match(patterns.API_KEY["aws_session_token"], "AKIAIOSFODNN7EXAMPLE")


def test_gcp_api_key_matches():
    assert match(
        patterns.API_KEY["gcp_api_key"],
        "AIzaSyD-9tSrke72I6e0a8lypPRmozAb5sDg3t8",
    )


def test_gcp_api_key_no_match():
    assert not match(patterns.API_KEY["gcp_api_key"], "AIzaSyD-short")


def test_gcp_service_account_matches():
    assert match(
        patterns.API_KEY["gcp_service_account"],
        "myservice@myproject.iam.gserviceaccount.com",
    )


def test_gcp_service_account_no_match():
    assert not match(patterns.API_KEY["gcp_service_account"], "user@gmail.com")


def test_openai_legacy_matches():
    assert match(
        patterns.API_KEY["openai_legacy"],
        "sk-" + "x" * 20 + "T3BlbkFJ" + "y" * 20,
    )


def test_openai_legacy_no_match():
    assert not match(
        patterns.API_KEY["openai_legacy"],
        "sk-" + "x" * 20 + "X" * 8 + "y" * 20,
    )


def test_openai_current_matches():
    assert match(patterns.API_KEY["openai_current"], "sk-" + "a" * 40)
    assert match(patterns.API_KEY["openai_current"], "sk-proj-" + "a" * 40)


def test_openai_current_no_match():
    assert not match(patterns.API_KEY["openai_current"], "sk-short")


def test_openai_org_matches():
    assert match(patterns.API_KEY["openai_org"], "org-" + "a" * 24)


def test_openai_org_no_match():
    assert not match(patterns.API_KEY["openai_org"], "org-" + "a" * 20)


def test_anthropic_key_matches():
    assert match(patterns.API_KEY["anthropic"], "sk-ant-" + "a" * 40)


def test_anthropic_key_no_match():
    assert not match(patterns.API_KEY["anthropic"], "sk-ant-short")


def test_github_pat_classic_matches():
    assert match(patterns.API_KEY["github_pat_classic"], "ghp_" + "a" * 36)


def test_github_pat_classic_no_match():
    assert not match(patterns.API_KEY["github_pat_classic"], "ghp_" + "a" * 35)


def test_github_pat_fine_matches():
    assert match(
        patterns.API_KEY["github_pat_fine"],
        "github_pat_" + "a" * 22 + "_" + "b" * 59,
    )


def test_github_pat_fine_no_match():
    assert not match(
        patterns.API_KEY["github_pat_fine"],
        "github_pat_" + "a" * 22 + "_" + "b" * 50,  # second segment too short
    )


def test_github_oauth_matches():
    assert match(patterns.API_KEY["github_oauth"], "gho_" + "a" * 36)


def test_github_oauth_no_match():
    assert not match(patterns.API_KEY["github_oauth"], "gho_" + "a" * 30)


def test_github_app_install_matches():
    assert match(patterns.API_KEY["github_app_install"], "ghs_" + "a" * 36)


def test_github_app_install_no_match():
    assert not match(patterns.API_KEY["github_app_install"], "ghs_short")


def test_github_app_refresh_matches():
    assert match(patterns.API_KEY["github_app_refresh"], "ghr_" + "a" * 36)


def test_github_app_refresh_no_match():
    assert not match(patterns.API_KEY["github_app_refresh"], "ghr_short")


def test_gitlab_pat_matches():
    assert match(patterns.API_KEY["gitlab_pat"], "glpat-" + "a" * 20)


def test_gitlab_pat_no_match():
    assert not match(patterns.API_KEY["gitlab_pat"], "glpat-short")


def test_gitlab_pipeline_matches():
    assert match(patterns.API_KEY["gitlab_pipeline"], "glptt-" + "a" * 40)


def test_gitlab_pipeline_no_match():
    assert not match(patterns.API_KEY["gitlab_pipeline"], "glptt-" + "a" * 10)


def test_gitlab_runner_matches():
    assert match(patterns.API_KEY["gitlab_runner"], "glrt-" + "a" * 20)


def test_gitlab_runner_no_match():
    assert not match(patterns.API_KEY["gitlab_runner"], "glrt-short")


def test_slack_bot_token_matches():
    assert match(
        patterns.API_KEY["slack_bot"],
        "xoxb-1234567890-1234567890-" + "a" * 24,
    )


def test_slack_bot_token_no_match():
    assert not match(patterns.API_KEY["slack_bot"], "xoxb-123-123-abc")


def test_slack_user_token_matches():
    assert match(
        patterns.API_KEY["slack_user"],
        "xoxp-1234567890-1234567890-1234567890-" + "a" * 32,
    )


def test_slack_user_token_no_match():
    assert not match(patterns.API_KEY["slack_user"], "xoxp-123-123-123-abc")


def test_slack_webhook_matches():
    assert match(
        patterns.API_KEY["slack_webhook"],
        "https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/" + "a" * 24,
    )


def test_slack_webhook_no_match():
    assert not match(
        patterns.API_KEY["slack_webhook"],
        "https://hooks.slack.com/services/XABC/BABC/" + "a" * 24,
    )


def test_stripe_secret_live_matches():
    assert match(patterns.API_KEY["stripe_secret_live"], "sk_live_" + "a" * 24)


def test_stripe_secret_live_no_match():
    assert not match(patterns.API_KEY["stripe_secret_live"], "sk_live_short")


def test_stripe_secret_test_matches():
    assert match(patterns.API_KEY["stripe_secret_test"], "sk_test_" + "a" * 24)


def test_stripe_publishable_matches():
    assert match(patterns.API_KEY["stripe_publishable"], "pk_live_" + "a" * 24)
    assert match(patterns.API_KEY["stripe_publishable"], "pk_test_" + "a" * 24)


def test_stripe_publishable_no_match():
    assert not match(patterns.API_KEY["stripe_publishable"], "pk_prod_" + "a" * 24)


def test_stripe_restricted_matches():
    assert match(patterns.API_KEY["stripe_restricted"], "rk_test_" + "a" * 24)


def test_twilio_account_sid_matches():
    assert match(patterns.API_KEY["twilio_account_sid"], "AC" + "a" * 32)


def test_twilio_account_sid_no_match():
    assert not match(patterns.API_KEY["twilio_account_sid"], "AB" + "a" * 32)


def test_sendgrid_matches():
    assert match(patterns.API_KEY["sendgrid"], "SG." + "a" * 22 + "." + "b" * 43)


def test_sendgrid_no_match():
    assert not match(
        patterns.API_KEY["sendgrid"],
        "SG." + "a" * 21 + "." + "b" * 43,
    )


def test_mailgun_matches():
    assert match(patterns.API_KEY["mailgun"], "key-" + "a" * 32)


def test_mailgun_no_match():
    assert not match(patterns.API_KEY["mailgun"], "key-" + "a" * 31)


def test_firebase_server_key_matches():
    assert match(
        patterns.API_KEY["firebase_server_key"],
        "AAAA" + "a" * 7 + ":" + "b" * 140,
    )


def test_firebase_server_key_no_match():
    assert not match(
        patterns.API_KEY["firebase_server_key"],
        "BBBB" + "a" * 7 + ":" + "b" * 140,
    )


def test_jwt_matches():
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ"
    payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI"
    sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQ"
    assert match(patterns.API_KEY["jwt"], f"{header}.{payload}.{sig}")


def test_jwt_no_match():
    # Only two parts — missing signature
    assert not match(
        patterns.API_KEY["jwt"],
        "eyJhbGciOiJIUzI1NiJ.eyJzdWIiOiIxMjM0NTY3ODkw",
    )


def test_bearer_token_matches():
    assert match(
        patterns.API_KEY["bearer"],
        "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
    )


def test_bearer_token_no_match():
    assert not match(patterns.API_KEY["bearer"], "Bearer short")


def test_basic_auth_matches():
    assert match(patterns.API_KEY["basic_auth"], "Basic dXNlcjpwYXNzd29yZA==")


def test_basic_auth_no_match():
    assert not match(patterns.API_KEY["basic_auth"], "Basic abc")  # too short


def test_generic_kv_matches():
    assert match(patterns.API_KEY["generic_kv"], 'api_key = "abcdefghijklmnop"')
    assert match(patterns.API_KEY["generic_kv"], "token: supersecretvalue12345678")


def test_generic_kv_no_match():
    assert not match(patterns.API_KEY["generic_kv"], "unrelated = value")


def test_api_key_in_text():
    assert match(
        patterns.API_KEY["aws_access_key"],
        "Found leaked key AKIAIOSFODNN7EXAMPLE in config file",
    )
    assert match(
        patterns.API_KEY["github_pat_classic"],
        "Token: ghp_" + "a" * 36 + " was revoked",
    )


# ===================================================================
# Hashes
# ===================================================================

@pytest.mark.parametrize("text", [
    "d41d8cd98f00b204e9800998ecf8427e",
    "5d41402abc4b2a76b9719d911017c592",
])
def test_md5_matches(text):
    assert match(patterns.HASH["md5"], text)


@pytest.mark.parametrize("text", [
    "d41d8cd98f00b204e9800998ecf8427",   # 31 chars
    "d41d8cd98f00b204e9800998ecf8427eg",  # non-hex
])
def test_md5_no_match(text):
    assert not match(patterns.HASH["md5"], text)


def test_sha1_matches():
    assert match(
        patterns.HASH["sha1"],
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    )


def test_sha1_no_match():
    assert not match(
        patterns.HASH["sha1"],
        "da39a3ee5e6b4b0d3255bfef95601890afd8070",  # 39 chars
    )


def test_sha256_matches():
    assert match(
        patterns.HASH["sha256"],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )


def test_sha256_no_match():
    assert not match(
        patterns.HASH["sha256"],
        "e3b0c44298fc1c149afbf4c8996fb924",  # only 32 chars = MD5 length
    )


def test_sha512_matches():
    h = (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    )
    assert match(patterns.HASH["sha512"], h)


def test_eth_tx_hash_matches():
    assert match(
        patterns.HASH["eth_tx_hash"],
        "0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060",
    )


def test_eth_tx_hash_no_match():
    assert not match(patterns.HASH["eth_tx_hash"], "5c504ed432cb51138bcf09aa5e8a410d")


def test_combined_classifies_eth_tx_hash_fully():
    h = "0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060"
    m = re.search(patterns.HASH["combined"], h)
    assert m.group() == h


def test_combined_classifies_sha512_fully():
    h = (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    )
    m = re.search(patterns.HASH["combined"], h)
    assert m.group() == h


def test_ssdeep_matches():
    assert match(
        patterns.HASH["ssdeep"],
        "3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C",
    )


def test_tlsh_matches():
    assert match(patterns.HASH["tlsh"], "T1" + "a" * 70)
    assert match(patterns.HASH["tlsh"], "t1" + "f" * 70)


def test_tlsh_no_match():
    assert not match(patterns.HASH["tlsh"], "T2" + "a" * 70)  # wrong prefix char
    assert not match(patterns.HASH["tlsh"], "T1" + "a" * 60)  # too short


def test_hash_in_text():
    assert match(
        patterns.HASH["sha256"],
        "Sample hash: "
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
        " found in malware report",
    )
    assert match(
        patterns.HASH["md5"],
        "MD5: d41d8cd98f00b204e9800998ecf8427e",
    )
