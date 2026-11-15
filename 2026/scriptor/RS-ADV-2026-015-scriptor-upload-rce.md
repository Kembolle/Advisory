# Security Advisory — Authenticated Arbitrary File Upload leading to Remote Code Execution in Scriptor

**Internal ID:** RS-ADV-2026-015
**CVE:** pending (not assigned)
**Status:** draft for disclosure

---

## 1. Executive summary

An **Authenticated Arbitrary File Upload → Remote Code Execution** vulnerability was identified in *Scriptor* (`bigin/Scriptor`), version `2.2.0`, in `boot/Editor/Api/UploadEndpoint.php`, the `POST /editor/api/upload` endpoint. The upload policy (allowed extensions / MIME types) is selected from the **client-declared MIME type**; any value that does not begin with `image/` selects a permissive default whose allow-lists are empty, and in the `imanager` dependency an empty allow-list permits anything. The file is stored under `public/uploads/` — inside the web root — keeping its original extension. An authenticated editor user (any role) can upload a `.php` file and, on the Apache + mod_php deployment the shipped `.htaccess` targets, execute it. Confirmed by source review across Scriptor 2.2.0 and imanager 2.2.1.

---

## 2. Affected products

- **Product:** Scriptor (`bigin/Scriptor`)
- **Analyzed version:** `2.2.0` (last commit 2026-06-01)
- **Component:** `boot/Editor/Api/UploadEndpoint.php` (`constraintsFor()`), with dependency `bigin/imanager` `2.2.1` (`src/Files/UploadConstraints.php`)
- **Endpoint:** `POST /editor/api/upload`
- **Access vector:** authenticated editor panel (`/editor/`); any editor account, as the router gates `/editor/api/*` on `isLoggedIn()` only (no role check) — https://github.com/bigin/Scriptor

**Unaffected products/versions:** not assessed. The analysis was limited to the versions above.

---

## 3. Vulnerability description

In `UploadEndpoint::handlePost()` the upload constraint set is chosen from the client-declared MIME type:

```php
$upload      = UploadedFile::fromPhpUpload($entry);   // declaredMime = $_FILES['file']['type'] (client-controlled)
$constraints = self::constraintsFor($upload->declaredMime);

private static function constraintsFor(string $mime): UploadConstraints {
    return str_starts_with($mime, 'image/')
        ? UploadConstraints::images()   // strict: gif/jpg/jpeg/png/webp
        : new UploadConstraints();      // permissive default — empty allow-lists
}
```

In imanager, empty allow-lists mean "allow any":

```php
public function permitsExtension(string $e): bool { if ($this->allowedExtensions === []) return true; /* ... */ }
public function permitsMime(string $m): bool      { if ($this->allowedMimes === [])      return true; /* ... */ }
```

- **Source:** `$_FILES['file']['type']` (client-declared MIME) and `$_FILES['file']['name']` (filename/extension).
- **Sink:** `FileStorage::put()` writing to `public/uploads/<itemId>/<fieldId>/<name>`, then direct execution by the web server when the file is requested.
- **Missing sanitization:** no server-side extension/MIME allow-list on the non-image path; the policy is chosen from attacker input; the filename sanitiser (`Sanitizer::filename()`) only runs `basename()` and strips `/ \` and control characters, **preserving the extension** (so `shell.php` stays `shell.php`); no execution guard on the storage directory.
- **Only restriction:** a declared MIME of `image/*` selects the strict image policy — but the attacker simply declares a non-image MIME (e.g. `application/octet-stream`) to escape it.
- **Relevant observation:** the maintainer hardened the bundled nginx demo (`docker/nginx.conf` returns 404 for `.php` outside `index.php`) but **not** the Apache path the shipped `public/.htaccess` targets, where a real `.php` under `uploads/` is served and executed.
- **Null byte:** not applicable; no truncation is needed — the dangerous extension is accepted directly.

**Required conditions:** an authenticated editor session (any role) and a valid CSRF token (obtainable from the page-edit form), a valid `itemId`/`fieldId`, and a web server that executes PHP under `public/uploads/` (the default for the Apache/mod_php deployment the shipped `.htaccess` assumes; README lists Apache and `docs/install-shared-hosting.md`).

---

## 4. Impact (C/I/A)

- **Confidentiality (High):** arbitrary code execution lets the attacker read any file/data the web-server user can reach, including the SQLite database (credential hashes, content).
- **Integrity (High):** the attacker can modify application data, content and files.
- **Availability (High):** the attacker can delete data or disrupt the service.

The application-level flaw (accepting an arbitrary extension/MIME from the client and storing it in the web root) is present in every deployment; whether it reaches code execution depends on the web server (full RCE on Apache/mod_php; arbitrary file upload — e.g. hosting attacker HTML/SVG for stored XSS/phishing — where the server blocks PHP execution in `uploads/`).

---

## 5. Classification

- **CWE:** CWE-434 — Unrestricted Upload of File with Dangerous Type; additional: CWE-430 (reliance on client-supplied MIME), CWE-552 (files in a web-accessible directory)
- **CAPEC:** CAPEC-650 — Upload a Web Shell to a Web Server
- **CVSS v3.1 (base):** **8.8 (High)**
  `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
  - *Note:* PR:L because the endpoint authorises any authenticated editor account regardless of role. If an install only ever has the single `siteadmin` account, PR:H → `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7.2). A deployment that disables PHP execution under `public/uploads/` removes the code-execution step, leaving an arbitrary-file-upload issue.

---

## 6. Exploitation scenario

An authenticated editor opens a page-edit form (obtaining a CSRF token), then sends a multipart `POST /editor/api/upload` with a `file` part whose filename ends in `.php` and whose part `Content-Type` is a non-image value (e.g. `application/octet-stream`), plus the CSRF token and a valid `itemId`/`fieldId`. Scriptor selects the permissive default policy; imanager accepts the file; it is stored at `public/uploads/<itemId>/<fieldId>/<name>.php`. The attacker requests that URL under `/uploads/...`; on Apache + mod_php the web server executes the PHP, yielding code execution.

---

## 7. Technical evidence

- **Affected component:** `boot/Editor/Api/UploadEndpoint.php`, `constraintsFor()` / `handlePost()`; `imanager src/Files/UploadConstraints.php`; storage target `public/uploads/<itemId>/<fieldId>/<name>` (inside the web root)
- **Data flow:**
  - *Source:* `$_FILES['file']['type']` (client-declared MIME) and `$_FILES['file']['name']`
  - *Missing sanitization:* no server-side extension/MIME allow-list on the non-image path; policy chosen from attacker input; extension preserved; no execution guard on the storage directory
  - *Sink:* `FileStorage::put()` → file under `public/uploads/...` → direct execution by the web server

**7.1. Confirmed by source review (Scriptor 2.2.0 + imanager 2.2.1)**
The declared MIME is client-controlled (`UploadedFile::fromPhpUpload()` reads `$_FILES['file']['type']`); a non-image declaration selects `new UploadConstraints()`; empty allow-lists return `true` for every extension and MIME; `Sanitizer::filename()` preserves the extension; storage is the public `uploads/` directory; the shipped `public/.htaccess` serves real files directly (`RewriteCond %{REQUEST_FILENAME} !-f`) with no PHP-execution guard.

**7.2. Deployment-dependent execution (two stacks, two outcomes — pending per-stack confirmation)**
- **Bundled nginx demo** (`docker compose up -d --build`): the `.php` is accepted and written under `public/uploads/...`, but requesting it returns **404** (`docker/nginx.conf`: `location ~ \.php$ { return 404; }`). Confirms arbitrary file upload; no code execution.
- **Apache + mod_php** (the stack the shipped `public/.htaccess` targets): the same uploaded `.php` under `uploads/` is **executed** when requested → RCE.

> Note: No third-party systems were accessed; testing uses a local, isolated instance and disposable accounts. A benign marker file (code that only prints a fixed string) is sufficient to demonstrate execution; no web-shell contents are used.

---

## 8. Proof of concept (PoC)

In an authorized lab environment:

1. Install Scriptor 2.2.0 on an Apache + mod_php stack and log in to the editor.
2. Open a page-edit form and read the CSRF token issued for the upload widget.
3. Send a multipart `POST /editor/api/upload` with: `file` = a small `.php` whose body only prints a fixed marker; part `Content-Type: application/octet-stream`; a valid `itemId`/`fieldId`; `tokenName`/`tokenValue`.
4. **Verification:** request the returned `url` (under `/uploads/...`) and observe the marker string — proving the uploaded PHP executed.

**PoC limitations:** requires an authenticated editor session and a valid CSRF token; uses a benign marker payload (no web shell); does not automate mass exploitation.

---

## 9. Reproduction steps

1. Deploy Scriptor 2.2.0 (Apache + mod_php or php-fpm) and log in.
2. Create/open a page so a valid `itemId`/`fieldId` exists; capture the CSRF token.
3. Upload a `.php` via `/editor/api/upload` declaring a non-image `Content-Type`.
4. Browse to the returned `/uploads/...` URL and observe the PHP executing.
5. Compare with secure behaviour: the server should reject the extension/MIME or store the file where it cannot be executed.

---

## 10. Mitigation

- Disable PHP execution under the uploads directory — e.g. `public/uploads/.htaccess` with `php_flag engine off` / `RemoveHandler .php .phtml .phar` / `<FilesMatch> SetHandler none`; for nginx, do not pass `/uploads/` to the PHP handler.
- Restrict editor accounts to trusted users and rotate credentials.
- Monitor `public/uploads/` for files with executable extensions.

---

## 11. Fix

Enforce a strict, server-side allow-list independent of the client-declared MIME, and keep uploads non-executable:

```php
$constraints = new UploadConstraints(
    maxSizeBytes: 8 * 1024 * 1024,
    allowedExtensions: ['gif', 'jpg', 'jpeg', 'png', 'webp', 'pdf', 'txt'],
    allowedMimes:      ['image/gif', 'image/jpeg', 'image/png', 'image/webp', 'application/pdf', 'text/plain'],
);
// Validate the SNIFFED mime (UploadHandler already sniffs) against this list,
// and reject executable extensions explicitly (php, phtml, phar, ...).
```

Complementary measures: store uploads outside the web root (or serve via a script forcing `Content-Disposition: attachment`); treat an empty allow-list in imanager's `UploadConstraints` as "deny"; ship a `public/uploads/.htaccess` that disables script execution.

---

## 12. Detection and indicators

- Files with executable extensions (`.php`, `.phtml`, `.phar`) under `public/uploads/`.
- `POST /editor/api/upload` requests whose multipart filename ends in an executable extension; requests to `/uploads/...php` in the access log.
  ```
  grep -E "POST /editor/api/upload" access.log
  find public/uploads -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \)
  ```

---

## 13. Disclosure timeline

| Date | Event |
|------|-------|
| 2026-11-15 | Source code identification and analysis |
| 2026-11-15 | Full chain confirmed by static analysis (Scriptor 2.2.0 + imanager 2.2.1) |
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
> - The permissive default behaviour originates in the `bigin/imanager` dependency (empty allow-list = allow any); a fix may be warranted there too.

---

## 15. Credits

The vulnerability was identified and reported by:

- **Researcher:** Kembolle Amilkar
- **Contact:** contato@kembolle.com.br
- **Profile:** https://github.com/Kembolle

---

## 16. References

- CWE-434: https://cwe.mitre.org/data/definitions/434.html
- CWE-552: https://cwe.mitre.org/data/definitions/552.html
- CAPEC-650: https://capec.mitre.org/data/definitions/650.html
- OWASP — Unrestricted File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- Project: https://github.com/bigin/Scriptor — Dependency: https://github.com/bigin/imanager

---

## 17. Revision history

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-11-15 | Initial version (static analysis + deployment-dependence note) |

---

## 18. Legal notice

This advisory is for **educational and defensive** purposes. Testing was conducted in an authorized, controlled lab environment. It must not be used to access systems without explicit authorization.

---

## 19. Contact

- **Researcher:** Kembolle Amilkar / kembolle.com.br
