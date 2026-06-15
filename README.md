# 🔍 OSINT Regex Patterns

A comprehensive collection of regular expressions for Open Source Intelligence (OSINT) investigations. These patterns help identify and extract common identifiers, accounts, financial data, infrastructure details, and credentials from unstructured text.

> **⚠️ Disclaimer:** These patterns are provided for lawful OSINT research, security auditing, and educational purposes only. Always ensure your use complies with applicable laws and regulations. Some patterns (SSNs, credit cards, API keys) involve sensitive data — handle responsibly.

> 🧭 New to regex? Start with [Regex 101: A Field Guide for OSINT Analysts](./REGEX-101.md) — a companion guide that teaches the syntax using patterns from this reference.

---

## 📖 Table of Contents

- [Email Addresses](#-email-addresses)
- [Phone Numbers](#-phone-numbers)
- [Passport Numbers](#-passport-numbers)
- [Bitcoin Wallets](#-bitcoin-wallets)
- [Other Cryptocurrency Wallets](#-other-cryptocurrency-wallets)
- [IP Addresses](#-ip-addresses)
- [Social Media User IDs](#-social-media-user-ids)
  - [Facebook](#facebook)
  - [Instagram](#instagram)
  - [Telegram](#telegram)
  - [VK (VKontakte)](#vk-vkontakte)
  - [Twitter / X](#twitter--x)
  - [LinkedIn](#linkedin)
  - [TikTok](#tiktok)
- [Credit Card Numbers](#-credit-card-numbers)
- [Social Security Numbers (SSN)](#-social-security-numbers-ssn--united-states)
- [MAC Addresses](#-mac-addresses)
- [IBAN Numbers](#-iban-numbers)
- [Tax Identification Numbers (TIN / INN)](#-tax-identification-numbers-tin--inn)
- [License Plates](#-license-plates)
- [API Keys and Tokens](#-api-keys-and-tokens)
  - [AWS](#amazon-web-services-aws)
  - [Google Cloud](#google-cloud-platform-gcp)
  - [OpenAI / ChatGPT](#openai--chatgpt)
  - [Anthropic (Claude)](#anthropic-claude-api)
  - [OVHcloud](#ovhcloud)
  - [GitHub](#github)
  - [GitLab](#gitlab)
  - [Slack](#slack)
  - [Stripe](#stripe)
  - [Twilio](#twilio)
  - [SendGrid](#sendgrid)
  - [Mailgun](#mailgun)
  - [Firebase / FCM](#firebase--google-fcm)
  - [JWT](#json-web-tokens-jwt)
  - [Generic / Catch-All](#generic--catch-all-patterns)
- [Hashes](#%EF%B8%8F⃣-hashes)
- [Usage Tips](#-usage-tips)
- [Contributing](#-contributing)
- [License](#-license)
- [Further Resources](#-further-resources)

---

## 📧 Email Addresses

| Pattern | Description |
|---------|-------------|
| `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` | Standard email address |

> **Notes:** Covers the vast majority of real-world addresses. For strict RFC 5322 compliance, a significantly more complex pattern is needed.

---

## 📞 Phone Numbers

| Pattern | Description |
|---------|-------------|
| `\+?[1-9]\d{6,14}` | International (E.164 format) |
| `(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}` | North American (NANP) |
| `(?:\+?\d{1,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}` | Flexible / multi-format |

> **Notes:** Phone formats vary wildly by country. The flexible pattern casts a wide net but may produce false positives. Pair with country-specific validation when possible.

---

## 🛂 Passport Numbers

| Pattern | Description |
|---------|-------------|
| `\b[A-Z]?\d{8,9}\b` | United States |
| `\b\d{9}\b` | United Kingdom |
| `\b[A-Z]{2}\d{6}\b` | Canada |
| `\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b` | Germany |
| `\b[A-Z0-9]{5,12}\b` | Generic (broad match) |

> **Notes:** Passport formats are country-specific. The generic pattern is intentionally broad and will require contextual filtering to reduce false positives.

---

## ₿ Bitcoin Wallets

| Pattern | Description |
|---------|-------------|
| `\b1[1-9A-HJ-NP-Za-km-z]{25,34}\b` | Legacy (P2PKH) — starts with `1` |
| `\b3[1-9A-HJ-NP-Za-km-z]{25,34}\b` | P2SH — starts with `3` |
| `\bbc1[a-zA-HJ-NP-Z0-9]{25,62}\b` | Bech32 / SegWit — starts with `bc1` |
| `\bbc1p[a-zA-HJ-NP-Z0-9]{25,62}\b` | Bech32m / Taproot — starts with `bc1p` |
| `\b(?:1[1-9A-HJ-NP-Za-km-z]{25,34}\|3[1-9A-HJ-NP-Za-km-z]{25,34}\|bc1[a-zA-HJ-NP-Z0-9]{25,62})\b` | Combined (all types) |

> **Notes:** Bitcoin uses Base58Check (legacy/P2SH) and Bech32 (SegWit) encoding. Characters `0`, `O`, `I`, `l` are excluded from Base58 to avoid ambiguity.

---

## 🪙 Other Cryptocurrency Wallets

| Pattern | Description |
|---------|-------------|
| `\b0x[0-9a-fA-F]{40}\b` | Ethereum (ETH) / EVM chains |
| `\b[LM3][1-9A-HJ-NP-Za-km-z]{25,34}\b` | Litecoin (LTC) |
| `\br[1-9A-HJ-NP-Za-km-z]{24,34}\b` | Ripple (XRP) |
| `\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b` | Monero (XMR) |
| `\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b` | Dogecoin (DOGE) |
| `\b[1-9A-HJ-NP-Za-km-z]{32,44}\b` | Solana (SOL) |
| `\baddr1[a-z0-9]{53,}\b` | Cardano (ADA) — Shelley era |
| `\bT[1-9A-HJ-NP-Za-km-z]{33}\b` | Tron (TRX) |
| `\b(?:bitcoincash:)?q[a-z0-9]{41}\b` | Bitcoin Cash (BCH) — CashAddr |

> **Notes:** The Solana pattern is broad (Base58, 32–44 chars) and may match other Base58 strings — use surrounding context to confirm. EVM addresses are shared across Ethereum, BSC, Polygon, Avalanche C-Chain, and many L2s.

---

## 🌐 IP Addresses

| Pattern | Description |
|---------|-------------|
| `\b(?:(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\.){3}(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\b` | IPv4 |
| `\b(?:(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\.){3}(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)(?:\/(?:3[0-2]\|[12]?\d))?\b` | IPv4 with CIDR |
| `\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b` | IPv6 (standard) |

<details>
<summary><strong>IPv6 Compressed / Abbreviated (click to expand)</strong></summary>

```regex
\b(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::(?:[fF]{4}(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d)|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\b
```

</details>

> **Notes:** The full IPv6 compressed pattern handles all valid abbreviation forms including `::` shorthand and IPv4-mapped addresses.

---

## 👤 Social Media User IDs

### Facebook

| Pattern | Description |
|---------|-------------|
| `(?:https?://)?(?:www\.)?facebook\.com/(?:profile\.php\?id=)?(\d{5,20})` | Numeric User/Page ID |
| `(?:https?://)?(?:www\.)?facebook\.com/([a-zA-Z0-9.]{5,50})(?:/\|\?\|$)` | Vanity username |

### Instagram

| Pattern | Description |
|---------|-------------|
| `(?:https?://)?(?:www\.)?instagram\.com/([a-zA-Z0-9_.]{1,30})(?:/\|\?\|$)` | Username from URL |
| `@([a-zA-Z0-9_.]{1,30})` | @mention in text |

> **Notes:** Instagram usernames allow letters, numbers, periods, and underscores (30-char max). The @mention pattern is generic and overlaps with other platforms.

### Telegram

| Pattern | Description |
|---------|-------------|
| `(?:https?://)?(?:t\.me\|telegram\.me)/([a-zA-Z][a-zA-Z0-9_]{4,31})` | Username from URL |
| `@([a-zA-Z][a-zA-Z0-9_]{4,31})` | @mention in text |

> **Notes:** Telegram usernames must start with a letter, are 5–32 characters, and allow letters, numbers, and underscores.

### VK (VKontakte)

| Pattern | Description |
|---------|-------------|
| `(?:https?://)?(?:www\.)?vk\.com/id(\d{1,15})` | Numeric user ID |
| `(?:https?://)?(?:www\.)?vk\.com/([a-zA-Z][a-zA-Z0-9_.]{2,31})` | Vanity username |

> **Notes:** VK supports both numeric IDs (`vk.com/id123456`) and custom short names. Groups use `club`, `public`, or `event` prefixes.

### Twitter / X

| Pattern | Description |
|---------|-------------|
| `(?:https?://)?(?:www\.)?(?:twitter\.com\|x\.com)/([a-zA-Z0-9_]{1,15})(?:/\|\?\|$)` | Username from URL |
| `@([a-zA-Z0-9_]{1,15})` | @mention in text |
| `(?:https?://)?(?:www\.)?(?:twitter\.com\|x\.com)/\w+/status/(\d{10,20})` | Tweet/Post ID from URL |

> **Notes:** Twitter/X usernames are 1–15 characters. The @mention pattern overlaps with other platforms — use context to disambiguate. Tweet IDs are Snowflake IDs (large integers).

### LinkedIn

| Pattern | Description |
|---------|-------------|
| `(?:https?://)?(?:www\.)?linkedin\.com/in/([a-zA-Z0-9\-]{3,100})(?:/\|\?\|$)` | Public profile URL |
| `(?:https?://)?(?:www\.)?linkedin\.com/company/([a-zA-Z0-9\-]{1,100})(?:/\|\?\|$)` | Company page URL |
| `(?:https?://)?(?:www\.)?linkedin\.com/(?:feed/update\|posts)/[a-zA-Z0-9\-:]+` | Post / Activity URL |

> **Notes:** LinkedIn profile slugs use letters, numbers, and hyphens. Some older profiles may have numeric-only slugs.

### TikTok

| Pattern | Description |
|---------|-------------|
| `(?:https?://)?(?:www\.)?tiktok\.com/@([a-zA-Z0-9_.]{2,24})(?:/\|\?\|$)` | Username from URL |
| `@([a-zA-Z0-9_.]{2,24})` | @mention in text |
| `(?:https?://)?(?:www\.)?tiktok\.com/@[a-zA-Z0-9_.]+/video/(\d{15,25})` | Video ID from URL |
| `(?:https?://)?(?:vm\.tiktok\.com)/([a-zA-Z0-9]+)` | Short link |

> **Notes:** TikTok usernames are 2–24 characters. Short links (`vm.tiktok.com`) redirect to full video URLs and are commonly shared on mobile.

---

## 💳 Credit Card Numbers

| Pattern | Description |
|---------|-------------|
| `\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,7}\b` | Visa |
| `\b(?:5[1-5]\d{2}\|2(?:2[2-9]\d\|[3-6]\d{2}\|7[01]\d\|720))[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b` | Mastercard |
| `\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b` | American Express |
| `\b6(?:011\|5\d{2}\|4[4-9]\d\|22(?:1(?:2[6-9]\|[3-9]\d)\|[2-8]\d{2}\|9(?:[01]\d\|2[0-5])))[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b` | Discover |
| `\b(?:2131\|1800\|35\d{3})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{3,4}\b` | JCB |
| `\b62\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4,7}\b` | UnionPay |

> **Notes:** These match number format only — always validate with the **Luhn checksum algorithm**. Patterns allow optional spaces or hyphens between digit groups.

---

## 🔐 Social Security Numbers (SSN) — United States

| Pattern | Description |
|---------|-------------|
| `\b(?!000\|666\|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b` | Standard (XXX-XX-XXXX) |
| `\b(?!000\|666\|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b` | With or without separators |
| `\b9\d{2}[-\s]?\d{2}[-\s]?\d{4}\b` | ITIN |

> **Notes:** Excludes invalid ranges (000, 666, 9xx area numbers; 00 group; 0000 serial) per SSA rules. Numbers starting with 9xx are reserved for ITINs.

---

## 🔗 MAC Addresses

| Pattern | Description |
|---------|-------------|
| `\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b` | Colon-separated (IEEE) |
| `\b[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}\b` | Hyphen-separated |
| `\b[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\b` | Dot-separated (Cisco) |
| `\b[0-9a-fA-F]{12}\b` | No separator |

> **Notes:** The no-separator format will match other 12-char hex strings — use contextual filtering. Apply case-insensitive flag for convenience.

---

## 🏦 IBAN Numbers

| Pattern | Description |
|---------|-------------|
| `\b[A-Z]{2}\d{2}[-\s]?[A-Z0-9]{4}(?:[-\s]?[A-Z0-9]{4}){1,7}(?:[-\s]?[A-Z0-9]{1,4})?\b` | Generic (all countries) |

<details>
<summary><strong>Country-Specific Patterns (click to expand)</strong></summary>

| Pattern | Country |
|---------|---------|
| `\bDE\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{2}\b` | Germany (22 chars) |
| `\bGB\d{2}[-\s]?[A-Z]{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{2}\b` | United Kingdom (22 chars) |
| `\bFR\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{3}\b` | France (27 chars) |
| `\bNL\d{2}[-\s]?[A-Z]{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{2}\b` | Netherlands (18 chars) |
| `\bCH\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1}\b` | Switzerland (21 chars) |
| `\bSA\d{2}[-\s]?\d{2}[A-Z0-9]{2}[-\s]?[A-Z0-9]{4}[-\s]?[A-Z0-9]{4}[-\s]?[A-Z0-9]{4}[-\s]?[A-Z0-9]{4}\b` | Saudi Arabia (24 chars) |
| `\bAE\d{2}[-\s]?\d{3}\d[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{3}\b` | UAE (23 chars) |

</details>

> **Notes:** IBAN lengths vary by country (15–34 chars). Always validate with the **MOD-97 checksum** (ISO 7064).

---

## 🏛️ Tax Identification Numbers (TIN / INN)

| Pattern | Description |
|---------|-------------|
| `(?:ИНН\|INN)[:\s]*(\d{10}\|\d{12})\b` | Russia — INN (with context) |
| `\b\d{2}-\d{7}\b` | United States — EIN |
| `\b\d{3}-\d{2}-\d{4}\b` | United States — SSN-format TIN |
| `\b\d{10}\b` | United Kingdom — UTR |
| `\b\d{11}\b` | Germany — Steuer-ID |
| `\b[A-Z]{5}\d{4}[A-Z]\b` | India — PAN |
| `\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b` | Brazil — CPF (individual) |
| `\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b` | Brazil — CNPJ (company) |

> **Notes:** Short numeric TINs (10–12 digits) are highly prone to false positives. Anchor matches to context keywords like `INN`, `TIN`, `EIN`, `PAN`, `CPF`. Russian INN has built-in checksum digits that can be validated programmatically.

---

## 🚗 License Plates

| Pattern | Country |
|---------|---------|
| `\b[A-Z0-9]{1,4}[-\s]?[A-Z0-9]{2,5}\b` | United States (general) |
| `\b[A-Z]{2}\d{2}[-\s]?[A-Z]{3}\b` | United Kingdom |
| `\b[A-ZÖÜÄ]{1,3}[-\s]?[A-Z]{1,2}[-\s]?\d{1,4}[EH]?\b` | Germany |
| `\b[A-Z]{2}[-\s]?\d{3}[-\s]?[A-Z]{2}\b` | France (SIV, post-2009) |
| `\b\d{1,2}[-\s]?[A-Z]{1,3}[-\s]?[A-Z0-9]{1,3}\b` | Netherlands |
| `\b[АВЕКМНОРСТУХ]{1}\d{3}[АВЕКМНОРСТУХ]{2}[-\s]?\d{2,3}\b` | Russia |
| `\b[A-Z]{4}[-\s]?\d{3}\b` | Canada (Ontario example) |
| `\b[A-Z0-9]{1,3}[-\s]?[A-Z0-9]{1,3}[-\s]?[A-Z0-9]{1,3}\b` | Australia (general) |
| `\b[A-Z]{3}\d[A-Z]\d{2}\b` | Brazil (Mercosur) |
| `\b[A-Z]{2}[-\s]?\d{1,2}[-\s]?[A-Z]{1,3}[-\s]?\d{1,4}\b` | India |
| `\b[0-9]{1,4}[-\s]?[ぁ-ん][0-9]{1,4}\b` | Japan (plate number) |
| `\b[A-Z]{3}[-\s]?\d{1,4}\b` | Saudi Arabia (Latin) |
| `\b\d{2,3}[가-힣]\d{4}\b` | South Korea |
| `\b\d{2}[-\s]?[A-Z]{1,3}[-\s]?\d{2,4}\b` | Turkey |
| `\b[A-Z]{3}[-\s]?\d{3,4}[-\s]?[A-Z]?\b` | Mexico |

> **Notes:** License plate formats are among the most variable identifiers globally. US plates vary by state with no single reliable pattern. Russian plates use a restricted set of Cyrillic characters resembling Latin letters. Always treat plate regex as a first-pass filter.

---

## 🔑 API Keys and Tokens

### Amazon Web Services (AWS)

| Pattern | Description |
|---------|-------------|
| `\bAKIA[0-9A-Z]{16}\b` | Access Key ID |
| `\b[0-9a-zA-Z/+=]{40}\b` | Secret Access Key |
| `\bASIA[0-9A-Z]{16}\b` | Temporary Session Token (STS) |

> **Notes:** Access Key IDs always start with `AKIA` (long-term) or `ASIA` (temporary). Secret keys are 40-char Base64 — anchor with context keywords.

### Google Cloud Platform (GCP)

| Pattern | Description |
|---------|-------------|
| `\bAIza[0-9A-Za-z_-]{35}\b` | API Key |
| `\b\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com\b` | OAuth Client ID |
| `\b[a-zA-Z0-9-]+@[a-zA-Z0-9-]+\.iam\.gserviceaccount\.com\b` | Service Account Email |

> **Notes:** Google API keys consistently start with `AIza`. Service account emails are a reliable GCP infrastructure indicator.

### OpenAI / ChatGPT

| Pattern | Description |
|---------|-------------|
| `\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b` | Legacy API Key |
| `\bsk-(?:proj-)?[a-zA-Z0-9_-]{30,200}\b` | Current API Key |
| `\borg-[a-zA-Z0-9]{24}\b` | Organization ID |

> **Notes:** Legacy format contained the fixed `T3BlbkFJ` substring. Current keys use `sk-` or `sk-proj-` prefixes and are significantly longer.

### Anthropic (Claude API)

| Pattern | Description |
|---------|-------------|
| `\bsk-ant-[a-zA-Z0-9_-]{32,120}\b` | API Key (all formats) |

> **Notes:** Anthropic API keys use the `sk-ant-` prefix. Key lengths have varied across generations.

### OVHcloud

| Pattern | Description |
|---------|-------------|
| `(?:X-Ovh-Application\|ovh_application_key\|OVH_AK)[:\s=]["']?([a-zA-Z0-9]{16})["']?` | Application Key (context-anchored) |
| `(?:X-Ovh-Consumer\|ovh_consumer_key\|OVH_CK)[:\s=]["']?([a-zA-Z0-9]{32})["']?` | Consumer Key (context-anchored) |

> **Notes:** OVH keys lack distinctive prefixes — context anchoring to headers or env variable names is essential.

### GitHub

| Pattern | Description |
|---------|-------------|
| `\bghp_[a-zA-Z0-9]{36}\b` | Personal Access Token (classic) |
| `\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b` | Fine-Grained PAT |
| `\bgho_[a-zA-Z0-9]{36}\b` | OAuth Access Token |
| `\bghs_[a-zA-Z0-9]{36}\b` | App Installation Token |
| `\bghr_[a-zA-Z0-9]{36}\b` | App Refresh Token |

> **Notes:** GitHub uses distinct prefixes for each token type, making detection highly reliable.

### GitLab

| Pattern | Description |
|---------|-------------|
| `\bglpat-[a-zA-Z0-9_-]{20}\b` | Personal / Project / Group Access Token |
| `\bglptt-[a-zA-Z0-9_-]{40}\b` | Pipeline Trigger Token |
| `\bglrt-[a-zA-Z0-9_-]{20}\b` | Runner Authentication Token |

### Slack

| Pattern | Description |
|---------|-------------|
| `\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b` | Bot Token |
| `\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}\b` | User Token |
| `https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[a-zA-Z0-9]{24}` | Webhook URL |

### Stripe

| Pattern | Description |
|---------|-------------|
| `\bsk_live_[a-zA-Z0-9]{24,}\b` | Secret Key (live) |
| `\bsk_test_[a-zA-Z0-9]{24,}\b` | Secret Key (test) |
| `\bpk_(?:live\|test)_[a-zA-Z0-9]{24,}\b` | Publishable Key |
| `\brk_(?:live\|test)_[a-zA-Z0-9]{24,}\b` | Restricted Key |

### Twilio

| Pattern | Description |
|---------|-------------|
| `\bAC[a-f0-9]{32}\b` | Account SID |
| `\b[a-f0-9]{32}\b` | Auth Token |

> **Notes:** Account SIDs always start with `AC`. Auth tokens are plain 32-char hex — match alongside SID context.

### SendGrid

| Pattern | Description |
|---------|-------------|
| `\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b` | API Key |

### Mailgun

| Pattern | Description |
|---------|-------------|
| `\bkey-[a-zA-Z0-9]{32}\b` | API Key |

### Firebase / Google FCM

| Pattern | Description |
|---------|-------------|
| `\bAAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}\b` | Server Key |

### JSON Web Tokens (JWT)

| Pattern | Description |
|---------|-------------|
| `\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b` | Signed JWT (JWS) |

> **Notes:** Header and payload always start with `eyJ` (Base64 for `{"`) making this a reliable fingerprint.

### Generic / Catch-All Patterns

| Pattern | Description |
|---------|-------------|
| `(?:api[_-]?key\|apikey\|secret\|token\|password\|auth\|credential\|access[_-]?key)[:\s=]+["']?([a-zA-Z0-9_\-/.+=]{16,200})["']?` | Key-value assignment (config/.env) |
| `\bBearer\s+([a-zA-Z0-9_\-/.+=]{20,500})\b` | Bearer token (HTTP header) |
| `\bBasic\s+([a-zA-Z0-9+/=]{16,200})\b` | Basic auth (Base64) |

> **Notes:** The generic key-value pattern is intentionally aggressive. Use as a first-pass filter combined with **entropy analysis** (true secrets tend to have high Shannon entropy).

---

## #️⃣ Hashes

| Pattern | Description |
|---------|-------------|
| `\b[a-fA-F0-9]{32}\b` | MD5 (128-bit) |
| `\b[a-fA-F0-9]{40}\b` | SHA-1 (160-bit) |
| `\b[a-fA-F0-9]{64}\b` | SHA-256 (256-bit) / Bitcoin TXID |
| `\b[a-fA-F0-9]{128}\b` | SHA-512 (512-bit) |
| `\b[a-fA-F0-9]{8}\b` | CRC32 (32-bit) |
| `\b0x[a-fA-F0-9]{64}\b` | Ethereum Transaction Hash |
| `\b\d+:[a-zA-Z0-9/+]+:[a-zA-Z0-9/+]+\b` | SSDEEP (fuzzy hash) |
| `\b[Tt]1[a-fA-F0-9]{70}\b` | TLSH |

<details>
<summary><strong>Combined Auto-detect by Length (click to expand)</strong></summary>

```regex
\b(?:0x)?[a-fA-F0-9]{128}\b|\b0x[a-fA-F0-9]{64}\b|\b(?:0x)?[a-fA-F0-9]{64}\b|\b(?:0x)?[a-fA-F0-9]{40}\b|\b(?:0x)?[a-fA-F0-9]{32}\b
```

</details>

> **Notes:** Hash patterns are inherently ambiguous — SHA-256 looks identical to a Bitcoin TXID. Differentiation requires context (filenames, labels, blockchain data). CRC32 at 8 hex chars is extremely prone to false positives. SSDEEP and TLSH are fuzzy hashes used in malware analysis and threat intelligence.

---

## 🔧 Usage Tips

1. **Word boundaries (`\b`)** — Most patterns use `\b` to prevent partial matches. Behavior varies between regex engines.

2. **Case sensitivity** — Apply case-insensitive flags (`re.IGNORECASE` in Python, `/i` in JS) where noted, especially for hex-based patterns.

3. **False positives** — Broad patterns (passport numbers, Solana addresses, phone numbers) will match non-target strings. Layer regex with contextual analysis, validation checksums, or secondary lookups.

4. **Combining patterns** — For bulk scanning, combine patterns into a single alternation group or run sequentially and tag each match with its type.

5. **Regex engine differences** — Patterns target PCRE / Python `re` / JavaScript-compatible syntax. Some features may need adjustment for POSIX engines.

6. **Validation** — Regex matches format, not validity. Always follow up with algorithmic validation where available (Luhn for credit cards, MOD-97 for IBANs, checksums for Russian INN, etc.).

---

## 🤝 Contributing

Contributions are welcome! If you'd like to add new patterns, improve existing ones, or fix issues:

1. Fork this repository
2. Create a feature branch (`git checkout -b feature/add-new-pattern`)
3. Commit your changes (`git commit -am 'Add regex for XYZ'`)
4. Push to the branch (`git push origin feature/add-new-pattern`)
5. Open a Pull Request

Please include test examples (both matching and non-matching) with any new patterns.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 📚 Further Resources

- [IETF RFC 5322 — Email Syntax](https://datatracker.ietf.org/doc/html/rfc5322)
- [ITU-T E.164 — Phone Number Format](https://www.itu.int/rec/T-REC-E.164)
- [Bitcoin Address Formats — Bitcoin Wiki](https://en.bitcoin.it/wiki/Address)
- [EIP-55 — Ethereum Mixed-case Checksum](https://eips.ethereum.org/EIPS/eip-55)
- [IBAN Registry — SWIFT](https://www.swift.com/standards/data-standards/iban)
- [Luhn Algorithm — Wikipedia](https://en.wikipedia.org/wiki/Luhn_algorithm)

---

*If this resource helped your investigation, consider giving it a ⭐*
