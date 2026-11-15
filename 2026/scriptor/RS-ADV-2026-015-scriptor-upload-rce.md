# Security Advisory — Authenticated Arbitrary File Upload leading to Remote Code Execution in Scriptor

> **Identifier:** RS-ADV-2026-015 / CVE-YYYY-NNNNN (pending)  
> **Publication date:** 2026-11-15  
> **Last updated:** 2026-11-15  
> **Severity:** High  
> **CVSS:** 8.8 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`  
> **CWE:** CWE-434 — Unrestricted Upload of File with Dangerous Type  
> **Status:** No fix yet / Reported to maintainer: [pending]

<!-- Internal mapping: finding #1 of the Scriptor review. -->

---

## 1. Executive summary

A vulnerability was identified in **Scriptor** (`bigin/Scriptor`), version **2.2.0**, that allows **an authenticated editor user** to **upload a file with an arbitrary extension (including `.php`) into the public web root and execute it**, resulting in remote code execution on the server.

The editor upload endpoint selects its upload-policy (allowed extensions / MIME types) based on the **client-declared MIME type** of the uploaded part. Any declared type that does not begin with `image/` selects a permissive default policy whose allow-lists are empty, and in the underlying `imanager` library an empty allow-list means "allow anything". The file is then stored under `public/uploads/` — inside the document root — keeping its original extension, where the shipped `.htaccess` serves real files directly and the web server executes `.php`.

Successful exploitation results in **arbitrary code execution** with the privileges of the web-server process (full confidentiality, integrity and availability impact on the application and its data).

The responsible organization has not yet been notified; see the timeline for current status.

---

## 2. Affected products

| Product / Component | Affected versions | Fixed version | Status |
|---|---:|---:|---|
| Scriptor (`bigin/Scriptor`) — `boot/Editor/Api/UploadEndpoint.php` | 2.2.0 (and earlier using the same upload flow) | None | Affected |
| Dependency: imanager (`bigin/imanager`) — `src/Files/UploadConstraints.php` | 2.2.1 | — | Enabling behaviour (empty allow-list = allow-any) |

### Unaffected products

- Not assessed. The analysis was limited to the versions above.

---

## 3. Vulnerability description

The vulnerability is caused by **choosing the upload-validation policy from the attacker-controlled declared MIME type, combined with a permissive default policy and storage inside the web root**.

The endpoint `POST /editor/api/upload` (`boot/Editor/Api/UploadEndpoint.php`) builds its constraint set like this:

```php
$upload      = UploadedFile::fromPhpUpload($entry);   // declaredMime = $_FILES['file']['type'] (client-controlled)
$constraints = self::constraintsFor($upload->declaredMime);
// ...
private static function constraintsFor(string $mime): UploadConstraints
{
    return str_starts_with($mime, 'image/')
        ? UploadConstraints::images()     // strict: gif/jpg/jpeg/png/webp
        : new UploadConstraints();        // permissive default
}
```

`declaredMime` is taken verbatim from `$_FILES['file']['type']` (`UploadedFile::fromPhpUpload()`), i.e. the `Content-Type` of the multipart part, which the client sets. Declaring any non-image type (e.g. `application/octet-stream`) selects `new UploadConstraints()`.

In imanager (`src/Files/UploadConstraints.php`), the default constructor leaves both allow-lists empty, and an empty allow-list is treated as "any":

```php
public function permitsExtension(string $extension): bool {
    if ($this->allowedExtensions === []) { return true; }   // empty = allow any
    // ...
}
public function permitsMime(string $mime): bool {
    if ($this->allowedMimes === []) { return true; }         // empty = allow any
    // ...
}
```

`UploadHandler::handle()` therefore performs no effective extension or MIME restriction. The filename is passed through `Sanitizer::filename()`, which calls `basename()` and strips `/`, `\` and control characters but **preserves the extension** (so `shell.php` stays `shell.php`). The bytes are written to `public/uploads/<itemId>/<fieldId>/<name>` — inside the document root (confirmed by the editor's storage wiring: "public base `/uploads`, `public/uploads/` on disk").

The shipped `public/.htaccess` routes only non-existent paths to the front controller (`RewriteCond %{REQUEST_FILENAME} !-f`); a real file under `uploads/` is served directly, and there is no `.htaccess`, `php_flag engine off`, `RemoveHandler` or `<FilesMatch>` disabling PHP execution in the uploads directory. On the Apache + PHP stack the project's `.htaccess` targets, the uploaded `.php` is executed.

### Required conditions

- An authenticated editor session. The router (`boot/Editor/EditorRouter.php`) gates `/editor/api/*` on `isLoggedIn()` only — it does **not** check the user's `role`, so any editor account suffices.
- A valid CSRF token (obtainable from the page-edit form that any logged-in editor can open).
- A valid `itemId` / `fieldId` (an existing page/field; a logged-in editor can create one).
- A server that executes PHP under `public/uploads/` — the default for the Apache/PHP deployment the shipped `.htaccess` assumes.

---

## 4. Impact

Exploitation may allow:

- Execution of arbitrary PHP code with the web-server's privileges (web shell).
- Full read/write access to the application, its SQLite database and files.
- Lateral movement and persistence on the host.

### Confidentiality impact

High. The attacker can read any file and data accessible to the web-server user, including the SQLite database (credential hashes, content).

### Integrity impact

High. Arbitrary code execution lets the attacker modify application data, content and files.

### Availability impact

High. The attacker can delete data or disrupt the service.

### Deployment dependence (stated for accuracy)

The application-level flaw — accepting an arbitrary extension/MIME based on the client-declared type and storing the file inside the web root — is present in every deployment and is the core issue reported here. Whether it reaches **code execution** depends on the web server:

- **Apache + mod_php / php-fpm** (the stack the shipped `public/.htaccess` targets, listed as supported in the README and `docs/install-shared-hosting.md`): a real `.php` file under `uploads/` is served and executed → full RCE. This is a common, officially supported configuration (shared hosting in particular).
- **The project's bundled nginx demo** (`docker/nginx.conf`): the catch-all `location ~ \.php$ { return 404; }` means an uploaded `.php` is still accepted and stored under `public/uploads/`, but returns 404 when requested — so there the impact is reduced to **arbitrary file upload** (e.g. hosting attacker-controlled HTML/SVG for stored XSS or phishing), not RCE.

This advisory is deliberately transparent about that split: the maintainer hardened the nginx demo but not the Apache path they ship an `.htaccess` for, which is precisely why the fix belongs in the application (strict allow-list; non-executable storage) rather than relying on each deployment's web-server configuration. Reviewers should reproduce both behaviours (see §7) rather than assuming universal RCE.

---

## 5. Classification

### CVSS

- **Score:** 8.8
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

> **Scoring note:** PR:L reflects that the upload endpoint authorises any authenticated editor account regardless of role. If an installation only ever has the single `siteadmin` account, the privilege required is higher (PR:H → `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`, 7.2). A deployment that disables PHP execution under `public/uploads/` removes the code-execution step, leaving an arbitrary-file-upload / stored-file issue.

### CWE

- **CWE-434 — Unrestricted Upload of File with Dangerous Type**
- Contributing: CWE-430 (reliance on the client-supplied MIME), CWE-552 (files stored in a web-accessible directory).

### CAPEC, when applicable

- **CAPEC-650 — Upload a Web Shell to a Web Server**

---

## 6. Exploitation scenario

1. The attacker authenticates to the editor (any editor account) and opens a page-edit form, obtaining a valid CSRF token.
2. The attacker sends a multipart `POST /editor/api/upload` with a `file` part whose filename ends in `.php` and whose part `Content-Type` is a non-image value (e.g. `application/octet-stream`), plus the CSRF token and a valid `itemId`/`fieldId`.
3. Scriptor selects the permissive default policy (declared MIME is not `image/*`); imanager accepts the file (empty allow-lists); it is stored under `public/uploads/<itemId>/<fieldId>/<name>.php`.
4. The attacker requests that URL under `/uploads/...`; the web server executes the PHP.
5. The attacker obtains code execution on the server.

---

## 7. Technical evidence

### Affected component

```text
boot/Editor/Api/UploadEndpoint.php — constraintsFor() selects the policy from $upload->declaredMime
imanager src/Files/UploadConstraints.php — empty allow-lists permit any extension / MIME
storage target: public/uploads/<itemId>/<fieldId>/<name>  (inside the web root)
```

### Data flow

- *Source:* `$_FILES['file']['type']` (client-declared MIME) and `$_FILES['file']['name']` (filename/extension).
- *Missing control:* no server-side extension/MIME allow-list on the non-image path; policy is chosen from attacker input; no execution guard on the storage directory.
- *Sink:* `FileStorage::put()` writing to `public/uploads/...`, then direct execution by the web server.

### Result (static analysis, authorised environment)

The full chain was confirmed by source review across Scriptor 2.2.0 and imanager 2.2.1: the declared MIME is client-controlled; a non-image declaration selects `new UploadConstraints()`; empty allow-lists return `true` for every extension and MIME; the filename sanitiser preserves the extension; storage is the public `uploads/` directory; the shipped `.htaccess` serves real files directly with no PHP-execution guard.

### Two deployments, two observed outcomes (recommended for the report)

To keep the claim honest and precise, reproduce the upload on both of the project's own stacks and record both results:

- **Bundled nginx demo** (`docker compose up -d --build`): the `.php` is accepted and written under `public/uploads/...`, but requesting its URL returns **404** (nginx blocks `.php` outside `index.php`). Confirms the arbitrary-file-upload flaw; no code execution here.
- **Apache + mod_php** (the stack the shipped `public/.htaccess` targets, e.g. `docs/install-shared-hosting.md`): the same uploaded `.php` under `uploads/` is **executed** when requested → RCE.

> **Note:** No third-party systems were accessed; testing uses a local, isolated instance and disposable accounts. A benign marker file (code that only prints a fixed string) is sufficient to demonstrate execution; no web-shell contents are used or included.

---

## 8. Proof of concept

In an authorized lab environment:

1. Install Scriptor 2.2.0 on an Apache + PHP stack and log in to the editor.
2. Open a page-edit form and read the CSRF token it issues for the upload widget.
3. Send a multipart `POST /editor/api/upload` with:
   - `file`: a small PHP file whose body is a harmless marker (e.g. prints a fixed string), named `poc.php`;
   - part `Content-Type: application/octet-stream`;
   - `itemId`, `fieldId` for an existing page/field;
   - `tokenName`, `tokenValue` (the CSRF token).
4. **Verification:** request the returned `url` (under `/uploads/...`) and observe the marker string in the response — proving the uploaded PHP executed.

### Expected result

```text
The uploaded .php file is stored under /uploads/<itemId>/<fieldId>/ and,
when requested, is executed by the web server (the marker string is returned),
confirming remote code execution.
```

### PoC limitations

- Requires an authenticated editor session and a valid CSRF token.
- Uses a benign marker payload; no web shell, no data access, no persistence.
- Does not automate mass exploitation.

---

## 9. Reproduction steps

1. Deploy Scriptor 2.2.0 (Apache + mod_php or php-fpm) and log in.
2. Create or open a page so a valid `itemId`/`fieldId` exists; capture the CSRF token.
3. Upload a `.php` file via `/editor/api/upload` declaring a non-image `Content-Type`.
4. Browse to the returned `/uploads/...` URL.
5. Observe the PHP executing.
6. Compare with the expected secure behaviour: the server should reject the extension/MIME, or store the file where it cannot be executed.

---

## 10. Mitigation

Until a fixed version is available:

- Disable PHP execution under the uploads directory — e.g. add `public/uploads/.htaccess` with `php_flag engine off` (Apache/mod_php) or `RemoveHandler .php .phtml .php3 .php4 .php5 .phar` / a `<FilesMatch>` `SetHandler none`; for nginx, do not pass `/uploads/` to the PHP handler.
- Restrict editor accounts to trusted users and rotate credentials.
- Monitor `public/uploads/` for files with executable extensions.

> Mitigations reduce the risk but may not fully eliminate the vulnerability.

---

## 11. Fix

Enforce a strict, server-side allow-list independent of the client-declared MIME, and keep uploads non-executable.

```php
// Always apply an explicit allow-list — never choose the policy from client input.
$constraints = new UploadConstraints(
    maxSizeBytes: 8 * 1024 * 1024,
    allowedExtensions: ['gif', 'jpg', 'jpeg', 'png', 'webp', 'pdf', 'txt'],
    allowedMimes:      ['image/gif', 'image/jpeg', 'image/png', 'image/webp', 'application/pdf', 'text/plain'],
);
// Validate the SNIFFED mime (already done by UploadHandler) against this list,
// and reject executable extensions explicitly (php, phtml, phar, ...).
```

Additional hardening:
- Store uploads outside the web root, or serve them through a script that forces `Content-Disposition: attachment` and a safe content type.
- Treat an empty allow-list in imanager's `UploadConstraints` as "deny", not "allow any", or require callers to pass explicit lists.
- Ship a `public/uploads/.htaccess` that disables script execution as defence in depth.

### Implemented change

[To be completed if/when the vendor releases a fix.]

---

## 12. Detection and indicators

- Files with executable extensions (`.php`, `.phtml`, `.phar`) under `public/uploads/`.
- `POST /editor/api/upload` requests whose multipart filename ends in an executable extension.
- Requests to `/uploads/...php` in the access log.

### Sample log search

```text
grep -E "POST /editor/api/upload" access.log
find public/uploads -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \)
```

---

## 13. Disclosure timeline

| Date | Event |
|---|---|
| 2026-11-15 | Vulnerability identified during source code review |
| 2026-11-15 | Full chain confirmed by static analysis (Scriptor 2.2.0 + imanager 2.2.1) |
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
- Affected file: https://github.com/bigin/Scriptor/blob/master/boot/Editor/Api/UploadEndpoint.php
- Dependency: https://github.com/bigin/imanager (src/Files/UploadConstraints.php, src/Files/UploadHandler.php)
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
- CWE-552: https://cwe.mitre.org/data/definitions/552.html
- CAPEC-650: https://capec.mitre.org/data/definitions/650.html
- OWASP — Unrestricted File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
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
