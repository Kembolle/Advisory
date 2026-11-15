# Security Advisory — Authentication Brute-Force Protection Bypass via Session-Stored Counter in Scriptor

> **Identifier:** RS-ADV-2026-016 / CVE-YYYY-NNNNN (pending)  
> **Publication date:** 2026-11-15  
> **Last updated:** 2026-11-15  
> **Severity:** Medium  
> **CVSS:** 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`  
> **CWE:** CWE-307 — Improper Restriction of Excessive Authentication Attempts  
> **Status:** No fix yet / Reported to maintainer: [pending]

<!-- Internal mapping: finding #2 of the Scriptor review. -->

---

## 1. Executive summary

A vulnerability was identified in **Scriptor** (`bigin/Scriptor`), version **2.2.0**, that allows **an unauthenticated attacker** to **bypass the editor login's brute-force lockout entirely**, enabling unlimited online password-guessing attempts.

The only anti-brute-force control, `LoginAttempts`, stores its failed-attempt counter in the **editor session**. Because the session is keyed by the client's session cookie, an attacker who simply does not send a session cookie (or sends a fresh one on each request) receives a new, empty counter every time, so the lockout threshold is never reached.

Successful exploitation **facilitates credential compromise** by removing the rate limit that is supposed to make online password guessing impractical.

The responsible organization has not yet been notified; see the timeline for current status.

---

## 2. Affected products

| Product / Component | Affected versions | Fixed version | Status |
|---|---:|---:|---|
| Scriptor (`bigin/Scriptor`) — `boot/Editor/Auth/LoginAttempts.php`, `boot/Editor/Auth/AuthModule.php` | 2.2.0 (and earlier using the same flow) | None | Affected |

### Unaffected products

- Not assessed. The analysis was limited to the version above.

---

## 3. Vulnerability description

The vulnerability is caused by **persisting the failed-login counter in the client-scoped session instead of in server-side storage keyed by the client**.

`LoginAttempts` (`boot/Editor/Auth/LoginAttempts.php`) is the sole brute-force defence (the maintainer's own note in `boot/Cli/InstallCommand.php` calls it "the real defence against brute [force]", and uses it to justify an 8-character minimum password). Its state is read from and written to the editor session:

```php
private const SESSION_KEY = 'login_attempts';
// ...
private function state(string $ip): array
{
    $stored = $this->session->get(self::SESSION_KEY);
    if (\is_array($stored) && ($stored['ip'] ?? null) === $ip && \is_int($stored['attempts'] ?? null)) {
        return [ /* attempts, locked_until from the SESSION */ ];
    }
    $fresh = ['ip' => $ip, 'attempts' => 0, 'locked_until' => 0];
    $this->session->set(self::SESSION_KEY, $fresh);
    return $fresh;   // a request with no session => fresh 0 every time
}
```

`AuthModule::loginAction()` checks `isAllowed($ip)` and records failures into that session state. The counter is therefore bound to the session cookie, which the client controls. There is **no** server-side (file/SQLite/database) record of failed attempts per IP or per account; a review of the codebase found `LoginAttempts` to be the only such control.

An attacker scripting the login endpoint without preserving cookies starts every request with a brand-new empty session, so `attempts` is always `0`, `isAllowed()` always returns true, and the lockout (default 5 attempts / 5 minutes) never triggers.

### Required conditions

- Network access to the editor login endpoint (`/editor/auth/`). No authentication and no special configuration required.

---

## 4. Impact

Exploitation may allow:

- Unlimited online password-guessing attempts against the editor login.
- Defeat of the control the maintainer relies on to justify the minimum password length.

### Confidentiality impact

Low (indirect). The flaw does not disclose data by itself; it removes the rate limit that protects password-based authentication, materially increasing the chance of account compromise — which would then expose the application (see RS-ADV-2026-015 for the post-authentication impact).

### Integrity impact

None directly.

### Availability impact

None directly.

---

## 5. Classification

### CVSS

- **Score:** 5.3
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

> **Scoring note:** Scored as a facilitator — it weakens authentication rather than granting access by itself. Passwords are stored with bcrypt, so online guessing is still bounded by server CPU cost; the practical risk rises sharply against weak or default passwords.

### CWE

- **CWE-307 — Improper Restriction of Excessive Authentication Attempts**
- Related: CWE-837 (reliance on a single, client-controllable factor for the lockout).

### CAPEC, when applicable

- **CAPEC-49 — Password Brute Forcing**

---

## 6. Exploitation scenario

1. The attacker targets the editor login (`/editor/auth/`) of a Scriptor site, with a known or guessed username.
2. The attacker sends login POST requests in a loop, **without** persisting cookies between requests (each request carries no `Scriptor` session cookie, or a fresh one).
3. Each request is evaluated against a brand-new session counter of `0`, so the lockout never engages.
4. The attacker continues guessing passwords without limit until one succeeds.

---

## 7. Technical evidence

### Affected component

```text
boot/Editor/Auth/LoginAttempts.php — counter persisted in the editor session (SESSION_KEY = 'login_attempts')
boot/Editor/Auth/AuthModule.php    — the only caller; no server-side per-IP/per-account record exists
```

### Result (static analysis, authorised environment)

Source review confirms the lockout state is stored in and read from the session (`SessionStore::get/set`), keyed only by a value that lives inside that same session. No persistent, server-side attempt store exists elsewhere in the codebase. A client that discards the session cookie between attempts is therefore never rate-limited.

This finding is **independent of the web server**: it reproduces on the project's own bundled demo stack (`docker compose up -d --build`) exactly as it would on any Apache or nginx deployment, because the defect is in the application's session-bound counter, not in the front-end configuration.

> **Note:** No third-party systems were accessed; the behaviour is demonstrable locally against disposable test accounts (see §8), observing that the "remaining attempts" never decrements across cookie-less requests.

---

## 8. Proof of concept

In an authorized lab environment:

1. Install Scriptor 2.2.0 and note the test admin username.
2. Send 10+ login POST requests to `/editor/auth/` with a deliberately wrong password, **without** storing or resending the session cookie between requests (e.g. a fresh client/cookie jar each time).
3. **Verification:** every response still offers the login form (never the lockout message), and the server never returns the "too many attempts" state — confirming the limit is not enforced across cookie-less requests. Repeating the same with a persistent cookie jar does trigger the lockout after 5 attempts, isolating the session-binding as the cause.

### Expected result

```text
Cookie-less requests: the lockout never engages; unlimited attempts are accepted.
Persistent-cookie requests: lockout after the configured threshold — showing the
control only works when the attacker chooses to keep the cookie.
```

### PoC limitations

- Uses disposable lab accounts; no real credentials.
- Demonstrates the missing limit only; does not perform a real password-cracking run.
- Does not automate mass exploitation.

---

## 9. Reproduction steps

1. Deploy Scriptor 2.2.0.
2. Script repeated failed logins against `/editor/auth/` without preserving cookies.
3. Observe that the lockout never triggers and remaining-attempts never decrements.
4. Repeat with a persistent cookie jar and observe the lockout after the threshold.
5. Compare with the expected secure behaviour: the limit should hold regardless of client-supplied cookies.

---

## 10. Mitigation

Until a fixed version is available:

- Place the login behind a reverse-proxy / WAF rate limit keyed by source IP.
- Enforce strong, unique administrator passwords (so unlimited online guessing remains impractical).
- Add network-level fail2ban-style blocking on repeated failed logins in the web-server logs.

> Mitigations reduce the risk but may not fully eliminate the vulnerability.

---

## 11. Fix

Persist the failed-attempt counter in server-side storage that the client cannot reset, keyed by source IP (and ideally by target username), rather than in the session.

```text
- Store attempts/locked_until in the SQLite database (or a server-side file store),
  keyed by client IP (+ username), with timestamps.
- Check and increment that store in AuthModule::loginAction() before verifying the password.
- Optionally add per-account lockout and exponential backoff, and account for
  proxy-forwarded client IPs via a trusted-proxy configuration.
```

### Implemented change

[To be completed if/when the vendor releases a fix.]

---

## 12. Detection and indicators

- A high volume of `POST /editor/auth/` requests from one source with no session cookie or a changing cookie.
- Many failed-login log lines without a corresponding lockout.

### Sample log search

```text
grep -E "POST /editor/auth" access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head
```

---

## 13. Disclosure timeline

| Date | Event |
|---|---|
| 2026-11-15 | Vulnerability identified during source code review |
| 2026-11-15 | Confirmed as the only brute-force control, session-bound |
| 2026-11-15 | Advisory drafting |
| _pending_ | First notification sent to the maintainer |
| _pending_ | Receipt acknowledged |
| _pending_ | CVE requested |
| _pending_ | Fix released |
| _pending_ | Advisory published |

---

## 14. Vendor communication

- **Vendor:** bigin (Juri Ehret), Scriptor
- **Channel used:** GitHub Security Advisory / repository issues (https://github.com/bigin/Scriptor)
- **Date of first notification:** [pending]
- **Response status:** [pending]
- **Vendor position:** [pending]

---

## 15. Credits

The vulnerability was identified and reported by:

- **Researcher:** Kembolle Amilkar
- **Contact:** contato@kembolle.com.br
- **Profile:** https://github.com/Kembolle

Acknowledgments:

- bigin (project maintainer)

---

## 16. References

- Project: https://github.com/bigin/Scriptor
- Affected file: https://github.com/bigin/Scriptor/blob/master/boot/Editor/Auth/LoginAttempts.php
- CWE-307: https://cwe.mitre.org/data/definitions/307.html
- CWE-837: https://cwe.mitre.org/data/definitions/837.html
- CAPEC-49: https://capec.mitre.org/data/definitions/49.html
- OWASP — Blocking Brute Force Attacks: https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1

---

## 17. Revision history

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-11-15 | Initial draft |

---

## 18. Legal notice

This advisory is published for educational, defensive and security-improvement purposes. Testing was conducted in an authorized, controlled lab environment. It must not be used to access systems without explicit authorization.

---

## 19. Contact

- **Email:** contato@kembolle.com.br
- **Website:** https://kembolle.com.br
