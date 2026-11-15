# Security Advisory — Authentication Brute-Force Protection Bypass via Session-Stored Counter in Scriptor

**Internal ID:** RS-ADV-2026-016
**CVE:** pending (not assigned)
**Status:** draft for disclosure

---

## 1. Executive summary

An **Authentication Brute-Force Protection Bypass** vulnerability was identified in *Scriptor* (`bigin/Scriptor`), version `2.2.0`, in `boot/Editor/Auth/LoginAttempts.php`. The only anti-brute-force control stores its failed-attempt counter in the editor **session**. Because the session is keyed by the client's session cookie, an unauthenticated attacker who does not send a session cookie (or sends a fresh one each request) receives a new, empty counter every time, so the lockout threshold is never reached — enabling unlimited online password-guessing attempts. Confirmed by source review.

---

## 2. Affected products

- **Product:** Scriptor (`bigin/Scriptor`)
- **Analyzed version:** `2.2.0` (last commit 2026-06-01)
- **Component:** `boot/Editor/Auth/LoginAttempts.php` (session-stored counter), `boot/Editor/Auth/AuthModule.php` (sole caller)
- **Endpoint:** `POST /editor/auth/` (editor login)
- **Access vector:** network, unauthenticated — https://github.com/bigin/Scriptor

**Unaffected products/versions:** not assessed. The analysis was limited to the version above.

---

## 3. Vulnerability description

`LoginAttempts` is the sole brute-force defence (the maintainer's note in `boot/Cli/InstallCommand.php` calls it "the real defence against brute [force]"). Its state is read from and written to the editor session:

```php
private const SESSION_KEY = 'login_attempts';

private function state(string $ip): array {
    $stored = $this->session->get(self::SESSION_KEY);
    if (\is_array($stored) && ($stored['ip'] ?? null) === $ip && \is_int($stored['attempts'] ?? null)) {
        return [ /* attempts, locked_until from the SESSION */ ];
    }
    $fresh = ['ip' => $ip, 'attempts' => 0, 'locked_until' => 0];
    $this->session->set(self::SESSION_KEY, $fresh);
    return $fresh;   // a request with no session => fresh 0 every time
}
```

- **Source:** the client's session cookie (or its absence), which the attacker controls, decides which counter state is loaded.
- **Sink:** the login decision in `AuthModule::loginAction()`, which calls `isAllowed($ip)` and records failures into that session-bound state.
- **Missing sanitization:** there is no server-side (file/SQLite/database) record of failed attempts per IP or per account; the counter's persistence is entirely client-controlled.
- **Only restriction:** with a persistent session cookie the lockout does engage after 5 attempts — but the attacker is not obliged to keep the cookie.
- **Relevant observation:** the maintainer relies on this control to justify an 8-character minimum password; defeating it undermines that assumption. `AuthModule` sources the client IP correctly, but the IP only tags the state that itself lives in the session.
- **Null byte:** not applicable.

**Required conditions:** network access to the editor login endpoint. No authentication and no special configuration required.

---

## 4. Impact (C/I/A)

- **Confidentiality (Low, indirect):** the flaw does not disclose data by itself; it removes the rate limit that protects password-based authentication, materially increasing the chance of account compromise (which would then expose the application — see RS-ADV-2026-015).
- **Integrity (None):** no direct impact.
- **Availability (None):** no direct impact.

Passwords are stored with bcrypt, so online guessing remains bounded by server CPU cost; the practical risk rises sharply against weak or default passwords.

---

## 5. Classification

- **CWE:** CWE-307 — Improper Restriction of Excessive Authentication Attempts; additional: CWE-837 (reliance on a single, client-controllable factor for the lockout)
- **CAPEC:** CAPEC-49 — Password Brute Forcing
- **CVSS v3.1 (base):** **5.3 (Medium)**
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
  - *Note:* scored as a facilitator — it weakens authentication rather than granting access by itself.

---

## 6. Exploitation scenario

An attacker targets `/editor/auth/` with a known or guessed username and sends login POST requests in a loop **without** persisting cookies between requests. Each request is evaluated against a brand-new session counter of `0`, so the lockout never engages, and the attacker guesses passwords without limit until one succeeds.

---

## 7. Technical evidence

- **Affected component:** `boot/Editor/Auth/LoginAttempts.php` (counter persisted in the editor session, `SESSION_KEY = 'login_attempts'`); `boot/Editor/Auth/AuthModule.php` (only caller; no server-side per-IP/per-account record exists)
- **Data flow:**
  - *Source:* the client's session cookie (present / absent / rotated) selects the counter state
  - *Missing sanitization:* no persistent, server-side attempt store keyed by IP or account
  - *Sink:* `isAllowed($ip)` gate in `AuthModule::loginAction()`

**7.1. Confirmed by source review**
The lockout state is stored in and read from the session (`SessionStore::get/set`), keyed only by a value that lives inside that same session. No persistent server-side attempt store exists elsewhere in the codebase. A client that discards the session cookie between attempts is therefore never rate-limited. This finding is **independent of the web server** and reproduces on the project's own bundled demo stack.

**7.2. Dynamic demonstration (recommended for the report — pending capture)**
Two loops of failed logins: with a persistent cookie jar the lockout engages after 5 attempts; without a cookie jar the lockout never engages and "remaining attempts" never decrements — isolating the session-binding as the cause.

> Note: No third-party systems were accessed; demonstrable locally against disposable test accounts.

---

## 8. Proof of concept (PoC)

In an authorized lab environment:

1. Install Scriptor 2.2.0 and note the test admin username.
2. Send 10+ login POST requests to `/editor/auth/` with a wrong password, **without** storing/resending the session cookie between requests.
3. **Verification:** every response still offers the login form (never the lockout message). Repeating with a persistent cookie jar triggers the lockout after 5 attempts, isolating the cause.

**PoC limitations:** uses disposable lab accounts (no real credentials); demonstrates the missing limit only (no real cracking run); does not automate mass exploitation.

---

## 9. Reproduction steps

1. Deploy Scriptor 2.2.0.
2. Script repeated failed logins against `/editor/auth/` without preserving cookies.
3. Observe the lockout never triggers and remaining-attempts never decrements.
4. Repeat with a persistent cookie jar and observe the lockout after the threshold.
5. Compare with secure behaviour: the limit should hold regardless of client-supplied cookies.

---

## 10. Mitigation

- Place the login behind a reverse-proxy / WAF rate limit keyed by source IP.
- Enforce strong, unique administrator passwords.
- Add network-level fail2ban-style blocking on repeated failed logins in the web-server logs.

---

## 11. Fix

Persist the failed-attempt counter in server-side storage the client cannot reset, keyed by source IP (and ideally username), rather than in the session:

```text
- Store attempts/locked_until in the SQLite database (or a server-side file store),
  keyed by client IP (+ username), with timestamps.
- Check and increment that store in AuthModule::loginAction() before verifying the password.
- Optionally add per-account lockout and exponential backoff, and account for
  proxy-forwarded client IPs via a trusted-proxy configuration.
```

Complementary measures: add a short artificial delay on failure; consider CAPTCHA after N failures.

---

## 12. Detection and indicators

- A high volume of `POST /editor/auth/` requests from one source with no session cookie or a changing cookie; many failed-login lines without a corresponding lockout.
  ```
  grep -E "POST /editor/auth" access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head
  ```

---

## 13. Disclosure timeline

| Date | Event |
|------|-------|
| 2026-11-15 | Source code identification and analysis |
| 2026-11-15 | Confirmed as the only brute-force control, session-bound |
| 2026-11-15 | Advisory drafting |
| _pending_ | Vendor contact |
| _pending_ | Vendor confirmation |
| _pending_ | Fix availability |
| _pending_ | Public disclosure |

---

## 14. Vendor communication

- **Intended channel:** GitHub Security Advisory / repository issues at https://github.com/bigin/Scriptor (no security.txt or dedicated security contact published)
- **Status:** pending opening.

> Additional observations in the same area, to be assessed separately:
> - None at this time; the finding is self-contained in the login throttling control.

---

## 15. Credits

The vulnerability was identified and reported by:

- **Researcher:** Kembolle Amilkar
- **Contact:** contato@kembolle.com.br
- **Profile:** https://github.com/Kembolle

---

## 16. References

- CWE-307: https://cwe.mitre.org/data/definitions/307.html
- CWE-837: https://cwe.mitre.org/data/definitions/837.html
- CAPEC-49: https://capec.mitre.org/data/definitions/49.html
- OWASP — Blocking Brute Force Attacks: https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- Project: https://github.com/bigin/Scriptor

---

## 17. Revision history

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-11-15 | Initial version |

---

## 18. Legal notice

This advisory is for **educational and defensive** purposes. Testing was conducted in an authorized, controlled lab environment. It must not be used to access systems without explicit authorization.

---

## 19. Contact

- **Researcher:** Kembolle Amilkar / kembolle.com.br
