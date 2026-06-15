"""OSINT regex patterns extracted from README, organized by category."""

EMAIL = {
    "standard": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
}

PHONE = {
    "e164": r"\+?[1-9]\d{6,14}",
    "nanp": r"(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
    "flexible": r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}",
}

PASSPORT = {
    "us": r"\b[A-Z]?\d{8,9}\b",
    "uk": r"\b\d{9}\b",
    "canada": r"\b[A-Z]{2}\d{6}\b",
    "germany": r"\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b",
    "generic": r"\b[A-Z0-9]{5,12}\b",
}

BITCOIN = {
    "p2pkh": r"\b1[1-9A-HJ-NP-Za-km-z]{25,34}\b",
    "p2sh": r"\b3[1-9A-HJ-NP-Za-km-z]{25,34}\b",
    "bech32": r"\bbc1[a-zA-HJ-NP-Z0-9]{25,62}\b",
    "bech32m": r"\bbc1p[a-zA-HJ-NP-Z0-9]{25,62}\b",
    "combined": (
        r"\b(?:1[1-9A-HJ-NP-Za-km-z]{25,34}"
        r"|3[1-9A-HJ-NP-Za-km-z]{25,34}"
        r"|bc1[a-zA-HJ-NP-Z0-9]{25,62})\b"
    ),
}

CRYPTO = {
    "ethereum": r"\b0x[0-9a-fA-F]{40}\b",
    "litecoin": r"\b[LM3][1-9A-HJ-NP-Za-km-z]{25,34}\b",
    "ripple": r"\br[1-9A-HJ-NP-Za-km-z]{24,34}\b",
    "monero": r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
    "dogecoin": r"\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b",
    "solana": r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b",
    "cardano": r"\baddr1[a-z0-9]{53,}\b",
    "tron": r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b",
    "bitcoin_cash": r"\b(?:bitcoincash:)?q[a-z0-9]{41}\b",
}

IP = {
    "ipv4": (
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv4_cidr": (
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\/(?:3[0-2]|[12]?\d))?\b"
    ),
    "ipv6_standard": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
    "ipv6_compressed": (
        r"(?:[0-9a-fA-F]{1,4}:){1,7}:"
        r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
        r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
        r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
        r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
        r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
        r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
        r"|:(?::[0-9a-fA-F]{1,4}){1,7}"
        r"|::(?:[fF]{4}(?::0{1,4})?:)?"
        r"(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}"
        r"(?:25[0-5]|(?:2[0-4]|1?\d)?\d)"
        r"|(?:[0-9a-fA-F]{1,4}:){1,4}:"
        r"(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}"
        r"(?:25[0-5]|(?:2[0-4]|1?\d)?\d)"
    ),
}

SOCIAL = {
    "facebook_id": (
        r"(?:https?://)?(?:www\.)?facebook\.com/(?:profile\.php\?id=)?(\d{5,20})"
    ),
    "facebook_username": (
        r"(?:https?://)?(?:www\.)?facebook\.com/([a-zA-Z0-9.]{5,50})(?:/|\?|$)"
    ),
    "instagram_url": (
        r"(?:https?://)?(?:www\.)?instagram\.com/([a-zA-Z0-9_.]{1,30})(?:/|\?|$)"
    ),
    "instagram_mention": r"@([a-zA-Z0-9_.]{1,30})",
    "telegram_url": (
        r"(?:https?://)?(?:t\.me|telegram\.me)/([a-zA-Z][a-zA-Z0-9_]{4,31})"
    ),
    "telegram_mention": r"@([a-zA-Z][a-zA-Z0-9_]{4,31})",
    "vk_id": r"(?:https?://)?(?:www\.)?vk\.com/id(\d{1,15})",
    "vk_username": r"(?:https?://)?(?:www\.)?vk\.com/([a-zA-Z][a-zA-Z0-9_.]{2,31})",
    "twitter_url": (
        r"(?:https?://)?(?:www\.)?(?:twitter\.com|x\.com)/([a-zA-Z0-9_]{1,15})(?:/|\?|$)"
    ),
    "twitter_mention": r"@([a-zA-Z0-9_]{1,15})",
    "twitter_tweet_id": (
        r"(?:https?://)?(?:www\.)?(?:twitter\.com|x\.com)/\w+/status/(\d{10,20})"
    ),
    "linkedin_profile": (
        r"(?:https?://)?(?:www\.)?linkedin\.com/in/([a-zA-Z0-9\-]{3,100})(?:/|\?|$)"
    ),
    "linkedin_company": (
        r"(?:https?://)?(?:www\.)?linkedin\.com/company/([a-zA-Z0-9\-]{1,100})(?:/|\?|$)"
    ),
    "linkedin_post": (
        r"(?:https?://)?(?:www\.)?linkedin\.com/(?:feed/update|posts)/[a-zA-Z0-9\-:]+"
    ),
    "tiktok_url": (
        r"(?:https?://)?(?:www\.)?tiktok\.com/@([a-zA-Z0-9_.]{2,24})(?:/|\?|$)"
    ),
    "tiktok_mention": r"@([a-zA-Z0-9_.]{2,24})",
    "tiktok_video_id": (
        r"(?:https?://)?(?:www\.)?tiktok\.com/@[a-zA-Z0-9_.]+/video/(\d{15,25})"
    ),
    "tiktok_short": r"(?:https?://)?(?:vm\.tiktok\.com)/([a-zA-Z0-9]+)",
}

CREDIT_CARD = {
    "visa": r"\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,7}\b",
    "mastercard": (
        r"\b(?:5[1-5]\d{2}|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720))"
        r"[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"
    ),
    "amex": r"\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b",
    "discover": (
        r"\b6(?:011|5\d{2}|4[4-9]\d|22(?:1(?:2[6-9]|[3-9]\d)|[2-8]\d{2}|9(?:[01]\d|2[0-5])))"
        r"[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"
    ),
    "jcb": r"\b(?:2131|1800|35\d{3})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{3,4}\b",
    "unionpay": r"\b62\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4,7}\b",
}

SSN = {
    "standard": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
    "flexible": r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b",
    "itin": r"\b9\d{2}[-\s]?\d{2}[-\s]?\d{4}\b",
}

MAC = {
    "colon": r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b",
    "hyphen": r"\b[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}\b",
    "dot_cisco": r"\b[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\b",
    "no_sep": r"\b[0-9a-fA-F]{12}\b",
}

IBAN = {
    "generic": (
        r"\b[A-Z]{2}\d{2}[-\s]?[A-Z0-9]{4}(?:[-\s]?[A-Z0-9]{4}){1,7}"
        r"(?:[-\s]?[A-Z0-9]{1,4})?\b"
    ),
    "germany": (
        r"\bDE\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{2}\b"
    ),
    "uk": (
        r"\bGB\d{2}[-\s]?[A-Z]{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{2}\b"
    ),
    "france": (
        r"\bFR\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{3}\b"
    ),
    "netherlands": r"\bNL\d{2}[-\s]?[A-Z]{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{2}\b",
    "switzerland": (
        r"\bCH\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1}\b"
    ),
}

TIN = {
    "russia_inn": r"(?:ИНН|INN)[:\s]*(\d{10}|\d{12})\b",
    "us_ein": r"\b\d{2}-\d{7}\b",
    "us_ssn_format": r"\b\d{3}-\d{2}-\d{4}\b",
    "uk_utr": r"\b\d{10}\b",
    "germany_steuer": r"\b\d{11}\b",
    "india_pan": r"\b[A-Z]{5}\d{4}[A-Z]\b",
    "brazil_cpf": r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b",
    "brazil_cnpj": r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b",
}

LICENSE_PLATE = {
    "us": r"\b[A-Z0-9]{1,4}[-\s]?[A-Z0-9]{2,5}\b",
    "uk": r"\b[A-Z]{2}\d{2}[-\s]?[A-Z]{3}\b",
    "germany": r"\b[A-ZÖÜÄ]{1,3}[-\s]?[A-Z]{1,2}[-\s]?\d{1,4}[EH]?\b",
    "france": r"\b[A-Z]{2}[-\s]?\d{3}[-\s]?[A-Z]{2}\b",
    "netherlands": r"\b\d{1,2}[-\s]?[A-Z]{1,3}[-\s]?[A-Z0-9]{1,3}\b",
    "canada_ontario": r"\b[A-Z]{4}[-\s]?\d{3}\b",
    "australia": r"\b[A-Z0-9]{1,3}[-\s]?[A-Z0-9]{1,3}[-\s]?[A-Z0-9]{1,3}\b",
    "brazil_mercosur": r"\b[A-Z]{3}\d[A-Z]\d{2}\b",
    "india": r"\b[A-Z]{2}[-\s]?\d{1,2}[-\s]?[A-Z]{1,3}[-\s]?\d{1,4}\b",
    "saudi_arabia": r"\b[A-Z]{3}[-\s]?\d{1,4}\b",
    "south_korea": r"\b\d{2,3}[가-힣]\d{4}\b",
    "turkey": r"\b\d{2}[-\s]?[A-Z]{1,3}[-\s]?\d{2,4}\b",
    "mexico": r"\b[A-Z]{3}[-\s]?\d{3,4}[-\s]?[A-Z]?\b",
}

API_KEY = {
    "aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
    "aws_secret_key": r"\b[0-9a-zA-Z/+=]{40}\b",
    "aws_session_token": r"\bASIA[0-9A-Z]{16}\b",
    "gcp_api_key": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "gcp_oauth_client": r"\b\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com\b",
    "gcp_service_account": r"\b[a-zA-Z0-9-]+@[a-zA-Z0-9-]+\.iam\.gserviceaccount\.com\b",
    "openai_legacy": r"\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b",
    "openai_current": r"\bsk-(?:proj-)?[a-zA-Z0-9_-]{30,200}\b",
    "openai_org": r"\borg-[a-zA-Z0-9]{24}\b",
    "anthropic": r"\bsk-ant-[a-zA-Z0-9_-]{32,120}\b",
    "ovh_app_key": (
        r"(?:X-Ovh-Application|ovh_application_key|OVH_AK)[:\s=][\"']?([a-zA-Z0-9]{16})[\"']?"
    ),
    "ovh_consumer_key": (
        r"(?:X-Ovh-Consumer|ovh_consumer_key|OVH_CK)[:\s=][\"']?([a-zA-Z0-9]{32})[\"']?"
    ),
    "github_pat_classic": r"\bghp_[a-zA-Z0-9]{36}\b",
    "github_pat_fine": r"\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b",
    "github_oauth": r"\bgho_[a-zA-Z0-9]{36}\b",
    "github_app_install": r"\bghs_[a-zA-Z0-9]{36}\b",
    "github_app_refresh": r"\bghr_[a-zA-Z0-9]{36}\b",
    "gitlab_pat": r"\bglpat-[a-zA-Z0-9_-]{20}\b",
    "gitlab_pipeline": r"\bglptt-[a-zA-Z0-9_-]{40}\b",
    "gitlab_runner": r"\bglrt-[a-zA-Z0-9_-]{20}\b",
    "slack_bot": r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b",
    "slack_user": r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}\b",
    "slack_webhook": (
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[a-zA-Z0-9]{24}"
    ),
    "stripe_secret_live": r"\bsk_live_[a-zA-Z0-9]{24,}\b",
    "stripe_secret_test": r"\bsk_test_[a-zA-Z0-9]{24,}\b",
    "stripe_publishable": r"\bpk_(?:live|test)_[a-zA-Z0-9]{24,}\b",
    "stripe_restricted": r"\brk_(?:live|test)_[a-zA-Z0-9]{24,}\b",
    "twilio_account_sid": r"\bAC[a-f0-9]{32}\b",
    "twilio_auth_token": r"\b[a-f0-9]{32}\b",
    "sendgrid": r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b",
    "mailgun": r"\bkey-[a-zA-Z0-9]{32}\b",
    "firebase_server_key": r"\bAAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}\b",
    "jwt": r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b",
    "generic_kv": (
        r"(?:api[_-]?key|apikey|secret|token|password|auth|credential|access[_-]?key)"
        r"[:\s=]+[\"']?([a-zA-Z0-9_\-/.+=]{16,200})[\"']?"
    ),
    "bearer": r"\bBearer\s+([a-zA-Z0-9_\-/.+=]{20,500})\b",
    "basic_auth": r"\bBasic\s+([a-zA-Z0-9+/=]{16,200})\b",
}

HASH = {
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "sha512": r"\b[a-fA-F0-9]{128}\b",
    "crc32": r"\b[a-fA-F0-9]{8}\b",
    "eth_tx_hash": r"\b0x[a-fA-F0-9]{64}\b",
    "ssdeep": r"\b\d+:[a-zA-Z0-9/+]+:[a-zA-Z0-9/+]+\b",
    "tlsh": r"\b[Tt]1[a-fA-F0-9]{70}\b",
    "combined": (
        r"\b(?:0x)?[a-fA-F0-9]{128}\b"
        r"|\b0x[a-fA-F0-9]{64}\b"
        r"|\b(?:0x)?[a-fA-F0-9]{64}\b"
        r"|\b(?:0x)?[a-fA-F0-9]{40}\b"
        r"|\b(?:0x)?[a-fA-F0-9]{32}\b"
    ),
}
