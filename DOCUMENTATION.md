# Technical Specification & Security Manual: Phishing URL Detector

**Author**: Security Engineering Pair Programmer  
**Version**: 1.0.0  
**Classification**: Open Source Security Tool  
**Environment**: Client-side Browser Sandbox (Vanilla JavaScript)

---

## 1. Executive Summary

Phishing attacks remain the primary initial access vector in cybersecurity breaches. Attackers manipulate URLs through visual homoglyphs, lexical padding, token spoofing, and obscure protocol structures to trick users into divulging credentials or downloading malicious payloads.

The **Phishing URL Detector** provides immediate, privacy-preserving lexical and structural URL analysis without transmitting queries over the network. This document provides a complete technical deep dive into the underlying heuristic mechanisms, the Levenshtein dynamic programming implementation, and operational usage.

---

## 2. Theoretical Background & Security Rationale

### 2.1 RFC 3986 Authority Section & The `@` Obfuscation Attack
Under Section 3.2 of **RFC 3986** (Uniform Resource Identifier Generic Syntax):
```
URI = scheme ":" ["//" authority] path ["?" query] ["#" fragment]
authority = [userinfo "@"] host [":" port]
```
When a URL contains an `@` sign (e.g., `https://google.com@phish-domain.com/login`), the segment preceding the `@` symbol (`google.com`) is treated as `userinfo` (credentials). Web browsers strictly connect to `phish-domain.com`. Users scanning the link casually only notice `google.com` at the beginning.

### 2.2 Homograph Attacks & Punycode (`xn--`)
Attackers register Internationalized Domain Names (IDNs) containing visually indistinguishable Unicode characters from different scripts (e.g., Cyrillic 'а' U+0430 instead of Latin 'a' U+0061). To ensure interoperability, the DNS converts these to ASCII-Compatible Encoding (ACE) with the `xn--` prefix (RFC 3492). Detecting `xn--` flags domains attempting visual homograph deception.

### 2.3 Top-Level Domain (TLD) Abuse
Threat intelligence reports from organizations like Spamhaus, APWG, and ICANN consistently show that specific registries with zero-cost or lax identity validation (e.g., `.tk`, `.xyz`, `.top`, `.click`, `.loan`) harbor a disproportionately high ratio of malicious domains relative to legitimate commercial registrations.

---

## 3. Mathematical Analysis: Dynamic Programming Levenshtein Distance

### 3.1 Problem Definition
Given string $A$ (candidate domain core) of length $m$ and string $B$ (known brand target) of length $n$, compute the minimum number of single-character operations (insertions, deletions, substitutions) required to convert $A$ into $B$.

### 3.2 Dynamic Programming Recurrence
Let $dp[i][j]$ be the edit distance between prefix $A[1 \dots i]$ and prefix $B[1 \dots j]$.

$$
dp[i][j] = \begin{cases}
i & \text{if } j = 0 \\
j & \text{if } i = 0 \\
dp[i-1][j-1] & \text{if } A[i] = B[j] \\
1 + \min \begin{cases}
dp[i-1][j] & \text{(Deletion of } A[i]\text{)} \\
dp[i][j-1] & \text{(Insertion of } B[j]\text{)} \\
dp[i-1][j-1] & \text{(Substitution of } A[i] \text{ with } B[j]\text{)}
\end{cases} & \text{if } A[i] \ne B[j]
\end{cases}
$$

### 3.3 Complexity
- **Time Complexity**: $\mathcal{O}(m \cdot n)$ operations per brand comparison. With $N \approx 19$ brands and average length $\approx 7$, total operations per inspection $\approx 19 \times 7 \times 7 \approx 931$ operations, executing in $< 0.5\text{ ms}$.
- **Space Complexity**: $\mathcal{O}(m \cdot n)$ matrix storage (or $\mathcal{O}(\min(m, n))$ if row-compressed).

---

## 4. Code Architecture & Component Breakdown

### 4.1 Input Normalizer & Parser (`app.js`)
```javascript
let urlString = raw;
if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(urlString)) {
    urlString = 'http://' + urlString;
}
const parsedUrl = new URL(urlString);
```
- Ensures robust parsing of bare domains (`example.com`), subpaths (`paypa1.tk/login`), and fully qualified URIs (`https://...`).
- Handles malformed edge cases without unhandled exceptions.

### 4.2 Feature Extraction
- **Host**: `parsedUrl.hostname.toLowerCase()`
- **Parts**: `host.split('.').filter(Boolean)`
- **TLD**: `parts[parts.length - 1]`
- **Domain Core**: `parts[parts.length - 2]` (or `parts[0]` if single segment)

### 4.3 Candidate Token Expansion for Hyphenated Brand Spoofing
Attackers frequently append terms like `-security` or `-verify` to misspelled brand names (e.g. `paypa1-security.tk`). The engine checks both the entire core segment and individual hyphen-delimited sub-tokens:
```javascript
const candidates = [coreClean, ...coreClean.split('-').filter(t => t.length >= 3)];
```

---

## 5. Scoring Matrix & Risk Verdicts

### Point Breakdown Summary
- **Raw IP Host**: `+25`
- **@ Symbol**: `+20`
- **Punycode**: `+20`
- **Typosquatting ($\le 2$ edit distance)**: `+28`
- **Risky TLD**: `+12`
- **Keyword Stacking**: `+5` (single) or `+14` (multiple)
- **URL Shortener**: `+15`
- **Excess Subdomains ($> 3$)**: `+10`
- **Multiple Hyphens ($\ge 2$)**: `+10`
- **No HTTPS**: `+10`
- **Excessive Length ($> 75$ chars)**: `+8`
- **Special Characters ($\ge 3$)**: `+6`

### Verdict Classification
```
Total Score = Math.min(Sum of points, 100)

[ 0  -  19 ] ---> LOW RISK    (Emerald Stamp)
[ 20 -  49 ] ---> SUSPICIOUS  (Amber Stamp)
[ 50 - 100 ] ---> HIGH RISK   (Red Stamp)
```

---

## 6. Verification and Test Results

Automated headless tests confirm 100% compliance across all detection heuristics:

```text
[PASS] Levenshtein DP: paypa1 -> paypal (Distance: 1)
[PASS] Levenshtein DP: g00gle -> google (Distance: 2)
[PASS] Levenshtein DP: apple  -> apple  (Distance: 0 - skipped as exact)
[PASS] Raw IP Host Detection
[PASS] @ Symbol Obfuscation
[PASS] Punycode homograph flag
[PASS] Risky TLD (.tk) flag
[PASS] Keyword stacking (+14)
[PASS] URL Shortener (+15)
[PASS] Subdomain depth (> 3 parts)
[PASS] Multiple hyphen flag
[PASS] Unencrypted HTTP flag
[PASS] Length threshold (> 75 chars)
[PASS] Special characters threshold
[PASS] Graceful error alert on malformed inputs
[PASS] Score clamping at 100
```

---

## 7. Recommended Workflow for Security Analysts

When a suspicious URL is reported:
1. Copy the raw link text from the email or ticket (do not click it).
2. Open the **Phishing URL Detector** via [`launch.bat`](file:///c:/Users/Admin/Downloads/phishing%20URL%20detector/launch.bat) or [index.html](file:///c:/Users/Admin/Downloads/phishing%20URL%20detector/index.html).
3. Paste the URL into the input field and press <kbd>Enter</kbd>.
4. Examine the **Risk Stamp** and review individual **Findings Tags**:
   - `FLAG`: Critical threat indicator. Strong likelihood of phishing.
   - `NOTE`: Suspicious structural anomaly. Requires context verification.
   - `INFO`: Neutral observation (e.g., long query string).
   - `CLEAR`: Clean heuristic profile.
