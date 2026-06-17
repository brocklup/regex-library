# 🧭 Regex 101 — A Field Guide for OSINT Analysts

A beginner-to-working-knowledge guide to regular expressions, written as the learning companion to the [OSINT Regex Patterns](./README.md) reference. The goal is simple: by the end you should be able to **read, modify, and write** any pattern in that library instead of copy-pasting on faith.

Every construct below is taught using patterns that actually appear in the reference — so the skills transfer directly to real work.

> **⚠️ Disclaimer:** Regex matches *format*, not *truth*. A string that matches the SSN pattern is not necessarily a real SSN, and a string that fails to match is not necessarily clean. Treat regex as a first-pass filter and always confirm with context, checksums, or secondary sources. Use only for lawful OSINT research, security auditing, and education.

---

## 📖 Table of Contents

- [What Is Regex, and Why Would I Use This?](#-what-is-regex-and-why-would-i-use-this)
- [How Matching Actually Works](#-how-matching-actually-works)
- [Literal Characters](#-literal-characters)
- [Character Classes](#-character-classes)
- [Shorthand Classes](#-shorthand-classes)
- [Anchors and Boundaries](#-anchors-and-boundaries)
- [Quantifiers](#-quantifiers)
- [Greedy vs. Lazy](#-greedy-vs-lazy)
- [Groups and Alternation](#-groups-and-alternation)
- [Capturing vs. Non-Capturing](#-capturing-vs-non-capturing)
- [Lookarounds](#-lookarounds)
- [Escaping Special Characters](#-escaping-special-characters)
- [Flags / Modifiers](#-flags--modifiers)
- [Reading Real Patterns from the Library](#-reading-real-patterns-from-the-library)
- [OSINT Gotchas](#-osint-gotchas)
- [Using These Patterns in Hunchly (Go / RE2)](#-using-these-patterns-in-hunchly-go--re2)
- [How to Test Your Patterns](#-how-to-test-your-patterns)
- [Using LLMs to Generate Regex](#-using-llms-to-generate-regex)
- [Quick Reference Cheat Sheet](#-quick-reference-cheat-sheet)
- [Further Resources](#-further-resources)

---

## ❓ What Is Regex, and Why Would I Use This?

**Regex** (short for *regular expression*) is a way to describe a pattern of text so a computer can find, extract, or validate it — instead of searching for one exact string, you describe the *shape* a match should have.

Compare the two approaches:

- **Exact search:** "find the string `AKIAIOSFODNN7EXAMPLE`" — only ever finds that one literal key.
- **Regex search:** "find anything that starts with `AKIA` followed by 16 uppercase letters or digits" (`\bAKIA[0-9A-Z]{16}\b`) — finds *every* AWS access key in a dataset, even ones you've never seen before, because it matches the *format* of the identifier rather than a specific value.

That's the core idea this whole library is built on: every identifier OSINT analysts care about — emails, phone numbers, crypto wallets, IPs, API keys, hashes — has a predictable *shape*. Regex lets you encode that shape once and then sweep it across logs, leaked databases, social media dumps, malware reports, or scraped pages to pull out every matching instance automatically.

**Why this matters for OSINT work specifically:**

- **Scale.** You can't manually scan a 50,000-line paste dump for email addresses or wallet addresses — a regex does it in milliseconds.
- **Consistency.** A well-built pattern catches every valid format variation (with or without dashes, `http://` vs `https://` vs no scheme, etc.) so you don't miss matches due to formatting differences.
- **Reusability.** Once a pattern is written and tested, it works the same way across `grep`, Python, JavaScript, log analysis tools, and SIEMs — write once, run everywhere.
- **Pivoting.** Capturing groups (covered later) let you extract just the *useful part* of a match — e.g., pulling a numeric Facebook ID out of a full profile URL — so the output feeds directly into the next step of an investigation.

The rest of this guide teaches you the building blocks (literals, character classes, quantifiers, anchors, groups, lookarounds) using patterns that already exist in [the reference library](./README.md), so what you learn is immediately applicable to the patterns you'll actually use.

---

## 🔎 How Matching Actually Works

A regular expression is a tiny pattern language. The engine scans your text left to right and, at each position, asks: *"starting here, does the pattern match?"* If yes, it reports the span; if no, it slides one character right and tries again.

Two ideas to internalize early:

1. **Most characters match themselves.** The pattern `cat` matches the literal letters `c`, `a`, `t` in sequence.
2. **A small set of characters are "special"** (metacharacters): `. ^ $ * + ? { } [ ] \ | ( )`. These mean something other than themselves, which is the entire source of regex's power — and most of its confusion.

The job of this guide is to demystify those metacharacters one at a time.

---

## 🔤 Literal Characters

Anything that isn't a metacharacter is a literal — it matches itself, exactly.

| Pattern  | Matches            |
| -------- | ------------------ |
| `AKIA`   | the text `AKIA`    |
| `sk-ant-`| the text `sk-ant-` |
| `bc1`    | the text `bc1`     |

This is why prefix-based detection (your AWS, Anthropic, and GitHub token patterns) is so reliable: `\bAKIA[0-9A-Z]{16}\b` starts with four literal characters that almost never appear together by accident.

> **Notes:** Literals are case-sensitive by default. `AKIA` will not match `akia` unless you apply a case-insensitive flag (see [Flags](#-flags--modifiers)).

---

## 🎯 Character Classes

Square brackets `[ ]` define a **set** — match *any one* character from the set, exactly once.

| Pattern       | Matches                                         |
| ------------- | ----------------------------------------------- |
| `[abc]`       | a single `a`, `b`, or `c`                       |
| `[0-9]`       | any one digit (a *range*)                       |
| `[a-zA-Z]`    | any one letter, upper or lower                  |
| `[a-fA-F0-9]` | any one hex digit — the backbone of hash patterns |

A hyphen `-` inside brackets means a range *unless* it's first or last, where it's a literal hyphen. That's why your token classes write it at the end: `[a-zA-Z0-9_-]` means "letters, digits, underscore, or literal hyphen."

**Negation:** a `^` as the *first* character inside brackets inverts the set. `[^0-9]` matches any character that is *not* a digit.

> **Notes:** Base58 patterns (Bitcoin, Litecoin) use carefully pruned classes like `[1-9A-HJ-NP-Za-km-z]` — note the missing `0`, `I`, `O`, and `l`. Those characters are excluded from Base58 to avoid visual ambiguity, and the class encodes that rule directly.

---

## ⚡ Shorthand Classes

Common sets get one-character shortcuts:

| Shorthand | Equivalent      | Matches                          |
| --------- | --------------- | -------------------------------- |
| `\d`      | `[0-9]`         | any digit                        |
| `\w`      | `[a-zA-Z0-9_]`  | any "word" character             |
| `\s`      | `[ \t\r\n]`     | any whitespace                   |
| `\D`      | `[^0-9]`        | any non-digit                    |
| `\W`      | `[^a-zA-Z0-9_]` | any non-word character           |
| `\S`      | `[^ \t\r\n]`    | any non-whitespace               |
| `.`       | (almost) any    | any character except newline     |

So `\d{6,14}` in your E.164 phone pattern means "between 6 and 14 digits," and `[-.\s]?` in the NANP pattern means "an optional hyphen, dot, or whitespace separator."

> **Notes:** `\w` includes the underscore, which is why username patterns lean on it. The dot `.` is the most over-used metacharacter by beginners — it matches *almost anything*, so a literal dot must be escaped (`\.`), as in `instagram\.com`.
>
> **Unicode warning:** The table above shows the *ASCII* equivalents, but Python's `re` and JavaScript's `u`-flagged regexes make `\w` and `\d` Unicode-aware by default — `\w` matches accented letters like `é`, and `\d` matches non-Latin digit characters (e.g. Arabic-Indic digits), not just `0-9`. If you need the strict ASCII behavior the table implies, pass `re.ASCII` in Python or use explicit classes like `[a-zA-Z0-9_]` and `[0-9]`. This is especially relevant for the library's non-Latin license-plate patterns — see [OSINT Gotchas](#-osint-gotchas).

---

## ⚓ Anchors and Boundaries

Anchors match a *position*, not a character. They consume zero width.

| Anchor | Meaning                                   |
| ------ | ----------------------------------------- |
| `^`    | start of string (or line, in multiline)   |
| `$`    | end of string (or line, in multiline)     |
| `\b`   | word boundary                             |
| `\B`   | not a word boundary                       |

`\b` is everywhere in your library, and for good reason. A word boundary sits between a `\w` character and a non-`\w` character (or string edge). Wrapping a hash pattern as `\b[a-fA-F0-9]{32}\b` prevents matching a 32-hex slice out of the *middle* of a longer 64-hex string — the boundary forces the match to stand alone.

```
Without \b :  abcdef0123...  ← matches a fragment inside a longer hash
With    \b :  only matches when the hex run is bounded by spaces, punctuation, or line ends
```

> **Notes:** `\b` behaviour varies across engines and especially with Unicode text — a Cyrillic or CJK character may not interact with `\b` the way you expect. This matters for your Russia, Japan, and South Korea license-plate patterns.

---

## 🔢 Quantifiers

Quantifiers say *how many times* the preceding element repeats.

| Quantifier | Meaning                  | Library example                        |
| ---------- | ------------------------ | -------------------------------------- |
| `*`        | 0 or more                | —                                      |
| `+`        | 1 or more                | `[a-zA-Z0-9._%+-]+` (email local part) |
| `?`        | 0 or 1 (optional)        | `\+?` (optional leading plus)          |
| `{n}`      | exactly n                | `\d{2}` (exactly two digits)           |
| `{n,}`     | n or more                | `[a-zA-Z0-9]{24,}` (Stripe key)        |
| `{n,m}`    | between n and m          | `\d{6,14}` (E.164 phone digits)        |

The quantifier always binds to the **single element immediately to its left** — one character, one class, or one group. So `bc1[a-zA-HJ-NP-Z0-9]{25,62}` means "literal `bc1`, then 25–62 Base32 characters."

> **Notes:** `{n,m}` ranges are how you encode the *length rules* of an identifier. Bitcoin addresses are 25–34 chars after the prefix; an MD5 hash is exactly 32 hex chars. Getting these bounds right is most of what separates a precise pattern from a noisy one.

---

## 🪤 Greedy vs. Lazy

By default quantifiers are **greedy** — they grab as much as possible, then give characters back only if the rest of the pattern fails to match. Adding `?` after a quantifier makes it **lazy** (match as little as possible).

```
Text:     "key=abc123; token=xyz789;"
Greedy:   =.*;   → matches  =abc123; token=xyz789;   (whole span)
Lazy:     =.*?;  → matches  =abc123;                 (stops at first ;)
```

This matters when you extract values from config or `.env` content. A greedy `.*` can swallow far more than intended; a lazy `.*?` stops at the first delimiter.

> **Notes:** Greediness is a common cause of "my regex matches way too much." If a key-value extraction grabs the rest of the line, suspect a greedy quantifier first.

---

## 🧩 Groups and Alternation

Parentheses `( )` group elements so a quantifier or alternation applies to the whole unit. The pipe `|` means **OR**.

`(?:twitter\.com|x\.com)` matches either domain. The group bounds the alternation — without parentheses, `twitter\.com|x\.com` would mean "`twitter\.com` OR `x\.com`" at the top level, which here is the same, but in `(?:\+?1[-.\s]?)?` the group is essential to make the *entire* country-code chunk optional.

Your IPv4 octet is a textbook alternation:

```
(?:25[0-5]|2[0-4]\d|[01]?\d\d?)
   └ 250-255 ┘ └ 200-249 ┘ └ 0-199 ┘
```

Three branches, tried left to right, together matching exactly 0–255. Order matters: the engine takes the first branch that works, so the most specific cases come first.

---

## 📦 Capturing vs. Non-Capturing

There are two flavours of group:

- **Capturing** `( ... )` — remembers what it matched so you can extract it later (as group 1, 2, 3...).
- **Non-capturing** `(?: ... )` — groups for structure only, captures nothing.

Look at your Facebook pattern:

```
(?:https?://)?(?:www\.)?facebook\.com/(?:profile\.php\?id=)?(\d{5,20})
 └─ non-capturing, optional ─┘                              └ capturing ┘
```

The `(?:...)` groups handle the optional `https://`, `www.`, and `profile.php?id=` scaffolding — you don't care about those. The single capturing group `(\d{5,20})` isolates the thing you actually want: **the numeric user ID**. When you run this in code, group 1 hands you the ID with the URL noise stripped off.

> **Notes:** This capture-the-payload, scaffold-the-rest pattern is the single most useful technique in the whole library for pivoting. Every social-media URL pattern uses it. If you only learn one structural trick, learn this one.

---

## 👁️ Lookarounds

Lookarounds assert that something does (or doesn't) appear *adjacent* to the current position, **without consuming characters**. They're invisible conditions.

| Syntax    | Name                | Meaning                          |
| --------- | ------------------- | -------------------------------- |
| `(?=...)` | positive lookahead  | followed by ...                  |
| `(?!...)` | negative lookahead  | NOT followed by ...              |
| `(?<=...)`| positive lookbehind | preceded by ...                  |
| `(?<!...)`| negative lookbehind | NOT preceded by ...              |

Your SSN pattern is the showcase:

```
\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b
   └─ not 000/666/9xx ─┘ └ not 00 ┘      └ not 0000 ┘
```

Read it as: a word boundary, then — *without moving the cursor* — assert the next three digits are **not** `000`, `666`, or `9xx`; only then actually consume three digits; require a hyphen; assert the group isn't `00`; consume two digits; and so on. The lookaheads bake the SSA's invalid-range rules straight into the pattern, dramatically cutting false positives.

> **Notes:** Lookbehind support is uneven across engines. JavaScript only gained reliable lookbehind relatively recently, and some POSIX engines lack it entirely. Lookahead is far more portable. PCRE and Python `re` support both.

---

## 🛡️ Escaping Special Characters

To match a metacharacter *literally*, put a backslash in front of it.

| You want to match | Write     | Why                                    |
| ----------------- | --------- | -------------------------------------- |
| a literal dot     | `\.`      | bare `.` means "any character"         |
| a literal plus    | `\+`      | bare `+` means "one or more"           |
| a literal `(`     | `\(`      | bare `(` opens a group                 |
| a literal `?`     | `\?`      | bare `?` means "optional"              |

This is why `facebook\.com` escapes the dot — `facebook.com` would also match `facebookXcom`, `facebook9com`, etc. And why the NANP pattern writes `\(?` and `\)?` — those are *literal, optional* parentheses around the area code, not regex groups.

> **Notes:** Inside a character class, most metacharacters lose their power and don't need escaping — `[.+*]` matches a literal dot, plus, or asterisk. The exceptions inside `[ ]` are `]`, `\`, `^` (when first), and `-` (when between characters).

---

## 🚩 Flags / Modifiers

Flags change how the whole pattern behaves. They're set outside the pattern (engine-dependent syntax shown):

| Flag | Name           | Effect                                            | Python              | JavaScript |
| ---- | -------------- | ------------------------------------------------- | ------------------- | ---------- |
| `i`  | case-insensitive | `A` matches `a`                                 | `re.IGNORECASE`     | `/.../i`   |
| `g`  | global         | find all matches, not just the first              | (default in `findall`) | `/.../g` |
| `m`  | multiline      | `^` and `$` match at line breaks                  | `re.MULTILINE`      | `/.../m`   |
| `s`  | dotall         | `.` also matches newlines                         | `re.DOTALL`         | `/.../s`   |

For your hex-based patterns (MAC addresses, hashes, Twilio tokens), the case-insensitive flag lets a single pattern like `[a-f0-9]` cover both `DEADBEEF` and `deadbeef` without writing `[a-fA-F0-9]` — though writing both ranges explicitly, as the library does, is more portable.

> **Notes:** Don't confuse the global flag with the pattern. `g` is about *how many* matches you collect; it doesn't change *what* matches.

---

## 🧪 Reading Real Patterns from the Library

Putting it together. Here's how to decode three patterns from the reference end to end.

### Email — `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`

| Chunk                | Reads as                                            |
| -------------------- | --------------------------------------------------- |
| `[a-zA-Z0-9._%+-]+`  | one or more local-part characters                   |
| `@`                  | a literal at-sign                                   |
| `[a-zA-Z0-9.-]+`     | one or more domain characters                       |
| `\.`                 | a literal dot before the TLD                        |
| `[a-zA-Z]{2,}`       | a TLD of two or more letters                        |

### Bitcoin Legacy — `\b1[1-9A-HJ-NP-Za-km-z]{25,34}\b`

| Chunk                       | Reads as                                  |
| --------------------------- | ----------------------------------------- |
| `\b`                        | word boundary (stand-alone match)         |
| `1`                         | literal `1` — the P2PKH version prefix    |
| `[1-9A-HJ-NP-Za-km-z]{25,34}` | 25–34 Base58 characters                 |
| `\b`                        | word boundary                             |

### Anthropic API Key — `\bsk-ant-[a-zA-Z0-9_-]{32,120}\b`

| Chunk                  | Reads as                                       |
| ---------------------- | ---------------------------------------------- |
| `\b`                   | word boundary                                  |
| `sk-ant-`              | literal prefix (the reliable fingerprint)      |
| `[a-zA-Z0-9_-]{32,120}`| 32–120 key characters (hyphen literal at end)  |
| `\b`                   | word boundary                                  |

Once you can narrate a pattern in plain English like this, you can also *edit* it — widen a length bound, add an alternation branch, or anchor it to a context keyword.

---

## ⚠️ OSINT Gotchas

1. **Format ≠ validity.** Matching the credit-card pattern doesn't mean the number passes Luhn. Matching the IBAN pattern doesn't mean it passes MOD-97. Always layer algorithmic validation on top.

2. **Broad patterns flood you with false positives.** A bare `[a-fA-F0-9]{32}` matches any 32-hex string — MD5, a truncated SHA-256, a GUID, random hex. Anchor with context (`AC` prefix for Twilio SIDs, `INN:` keyword for Russian tax IDs) wherever possible.

3. **Greedy quantifiers over-match.** When extracting from config files, prefer lazy `.*?` and tight delimiters.

4. **Engine differences are real.** PCRE, Python `re`, JavaScript, Go's RE2, and POSIX engines differ on lookbehind, `\b` with Unicode, named groups, and backreferences. RE2 (used in some scanners) deliberately omits lookarounds for performance — your SSN pattern won't run there unmodified.

5. **Unicode and `\b`.** Cyrillic, Arabic, CJK, and accented text interact with `\d`, `\w`, and `\b` differently depending on whether the engine is in Unicode mode. Test your non-Latin license-plate and Cyrillic patterns against real samples.

6. **Catastrophic backtracking.** Nested quantifiers on overlapping classes (e.g. `(a+)+`) can hang an engine on crafted input. Keep alternations and quantifiers as specific as possible — this is a denial-of-service risk if you run patterns on untrusted bulk text.

---

## 🦫 Using These Patterns in Hunchly (Go / RE2)

[Hunchly](https://hunch.ly/) implements custom regex highlighting using **Go's `regexp` package**, which is built on **RE2** rather than PCRE. RE2 trades some features for guaranteed linear-time matching (no catastrophic backtracking — a real plus for scanning live web pages). The tradeoff: **RE2 does not support lookaheads, lookbehinds, or backreferences** at all — a pattern using `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`, or `\1`-style backreferences will fail to compile in Hunchly with a syntax error.

**What this means for this library:**

- The vast majority of patterns here use only literals, character classes, quantifiers, anchors (`\b`, `^`, `$`), and non-capturing/capturing groups — all of which RE2 supports natively. **Drop these into Hunchly as-is.**
- The two exceptions are **`SSN["standard"]`** and **`SSN["flexible"]`**, which rely on negative lookaheads (`(?!000|666|9\d{2})`, `(?!00)`, `(?!0000)`) to bake in the SSA's invalid-range rules. These will **not compile in Hunchly**.

**Case-insensitive matching with `(?i)`:** RE2 supports the inline flag `(?i)` for case-insensitive matching. This is useful for hex-based patterns (MAC addresses, hashes, Ethereum addresses) where you want `[a-f0-9]` to also match uppercase `A-F`. The library writes `[a-fA-F0-9]` for maximum portability, but in Hunchly you can simplify to `(?i)[a-f0-9]` instead. For example:

```regex
(?i)\b[a-f0-9]{32}\b
```

matches both `deadbeef...` and `DEADBEEF...` without needing the `A-F` range. The `(?i)` flag applies to the entire pattern when placed at the start, or you can scope it to a group with `(?i:group)`.

**RE2-compatible SSN workaround** — drop the lookaheads and accept some false positives (matches the right *shape* but won't exclude `000-xx-xxxx`, `666-xx-xxxx`, `9xx-xx-xxxx`, group `00`, or serial `0000`):

```regex
\b\d{3}-\d{2}-\d{4}\b
```

Use this looser pattern for the initial Hunchly capture, then apply the full lookahead-based pattern (`SSN["standard"]`) in a downstream Python/PCRE pass to filter out the invalid ranges.

**General rule of thumb:** before adding a new pattern to this library, check it doesn't introduce `(?=`, `(?!`, `(?<=`, `(?<!`, or numbered backreferences if Go/RE2 compatibility matters for your workflow — or note in the pattern's description that it requires a PCRE-class engine.

---

## 🔧 How to Test Your Patterns

- **[regex101.com](https://regex101.com/)** — interactive tester with a live explanation pane; set the flavour (PCRE2 / Python / JavaScript) to match your target engine. Indispensable for learning.
- **Python** — `re.findall(pattern, text)` for quick checks; compile with `re.IGNORECASE | re.MULTILINE` as needed.
- **JavaScript** — `text.match(/pattern/gi)` in a browser console.
- **`ripgrep` / `grep -P`** — test against real files on the command line; `rg -o 'pattern' file` prints just the matches.

Always test with **both** a sample that *should* match and one that *should not*. The repo's contributing guidelines ask for exactly this — positive and negative test cases — and it's the fastest way to catch an over-broad pattern before it reaches an investigation.

---

## 🤖 Using LLMs to Generate Regex

LLMs like Claude are surprisingly good at writing regex patterns from plain-language descriptions, and they can save you real time when you need a custom extractor for Hunchly or any other tool. Instead of memorizing syntax, describe what you want to match — "a pattern for Australian Business Numbers: 11 digits, optionally separated by spaces in groups of 2-3-3-3" — and the LLM will produce a working pattern. The key is to **tell the LLM about your engine constraints up front.** If you're writing patterns for Hunchly, include something like *"generate a case-insensitive Go RE2-compatible regex — no lookaheads, no lookbehinds, no backreferences, use `(?i)` for case insensitivity"* in your prompt. Without that constraint the LLM will happily hand you a PCRE pattern full of `(?=...)` constructs that silently fails to compile in Hunchly's Go regex engine. Once you have a candidate pattern, **always validate it**: paste it into [regex101.com](https://regex101.com/) with the Golang flavour selected, test against real positive and negative samples, and check that the match boundaries are tight (word boundaries `\b`, start/end anchors) so you don't drown in false positives during an investigation. Treat LLM-generated regex the same way you'd treat LLM-generated code — a useful first draft that needs human review before it goes into production.

---

## 📋 Quick Reference Cheat Sheet

| Token        | Meaning                          | Token       | Meaning                       |
| ------------ | -------------------------------- | ----------- | ----------------------------- |
| `.`          | any char except newline          | `\d`        | digit `[0-9]`                 |
| `\w`         | word char `[A-Za-z0-9_]`         | `\s`        | whitespace                    |
| `\D \W \S`   | negations of the above           | `\b`        | word boundary                 |
| `[abc]`      | one of a, b, c                   | `[^abc]`    | none of a, b, c               |
| `[a-z]`      | range                            | `a|b`       | a OR b                        |
| `^`          | start of string/line             | `$`         | end of string/line            |
| `*`          | 0 or more                        | `+`         | 1 or more                     |
| `?`          | 0 or 1 (optional)                | `*? +?`     | lazy versions                 |
| `{n}`        | exactly n                        | `{n,m}`     | between n and m               |
| `( )`        | capturing group                  | `(?: )`     | non-capturing group           |
| `(?= )`      | positive lookahead               | `(?! )`     | negative lookahead            |
| `(?<= )`     | positive lookbehind              | `(?<! )`    | negative lookbehind           |
| `\. \+ \(`   | escaped literals                 | `\\`        | a literal backslash           |

---

## 📚 Further Resources

- [regex101.com](https://regex101.com/) — interactive tester and explainer
- [RexEgg — Regex Tutorial](https://www.rexegg.com/) — deep dives on lookarounds and engine internals
- [Python `re` module docs](https://docs.python.org/3/library/re.html)
- [MDN — Regular Expressions (JavaScript)](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions)
- [Google RE2 syntax](https://github.com/google/re2/wiki/Syntax) — the linear-time engine used in many scanners
- [OWASP — Regular Expression Denial of Service (ReDoS)](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)

---

*Companion to [OSINT Regex Patterns](./README.md). Learn the syntax here, look up the patterns there.*
