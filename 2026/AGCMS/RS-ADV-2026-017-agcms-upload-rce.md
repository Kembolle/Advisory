# Security Advisory — Authenticated Arbitrary File Upload leading to Remote Code Execution in AGcms

**Internal ID:** RS-ADV-2026-017
**CVE:** pending (not assigned)
**Status:** draft for disclosure

---

## 1. Executive summary

An **Authenticated Arbitrary File Upload → Remote Code Execution** vulnerability was identified in *AGcms* (`AJenbo/agcms`), in `application/inc/Services/UploadHandler.php`, reached via `POST /admin/explorer/files/`. The upload handler takes the file extension from the client-supplied original filename (`UploadedFile::getClientOriginalExtension()`), lower-cases it and preserves it, with **no allow-list or block-list of extensions anywhere in the flow**. Non-image files (whose sniffed MIME is not `image/jpeg|gif|png`) are stored unprocessed under `/files/` or `/images/`, which sit inside the web root; the nginx configuration the project ships passes every `.php` under the root to PHP-FPM with no exclusion. A backend user (any `accessLevel > 0`) can therefore upload a `.php` file and execute it. Confirmed by source review of the shipped code and Docker configuration.

---

## 2. Affected products

- **Product:** AGcms (`AJenbo/agcms`)
- **Analyzed version:** commit `a4e1f75` (2026-09-07, latest on `master`)
- **Component:** `application/inc/Services/UploadHandler.php` (`process()` / `insertFile()`), reached from `application/inc/Http/Controllers/Admin/ExplorerController.php` (`fileUpload()`)
- **Endpoint:** `POST /admin/explorer/files/` (multipart; field `upload`, parameter `dir`)
- **Access vector:** authenticated backend (`/admin/`); any account with `accessLevel > 0` (the `Auth` middleware only checks that, and `ExplorerController` adds no per-level check) — https://github.com/AJenbo/agcms

**Unaffected products/versions:** not assessed. The analysis was limited to the version above.

---

## 3. Vulnerability description

`UploadHandler::process()` derives the stored file's extension from the client-supplied filename:

```php
$fileName = $uploadedFile->getClientOriginalName();
$fileName = pathinfo($fileName, PATHINFO_FILENAME);     // base name only
$this->baseName = $this->fileService->cleanFileName($fileName);

$fileExtension = $uploadedFile->getClientOriginalExtension();   // client-controlled
$this->extension = mb_strtolower($fileExtension);               // no allow/deny-list
```

`processFile()` re-encodes only images (`getMimeType()` in `image/jpeg|gif|png`); anything else is kept as-is. `insertFile()` then moves the file to `$targetDir/baseName.extension`:

```php
$path = $this->targetDir . '/' . $this->getFilename();   // getFilename() = baseName . '.' . extension
$this->fileService->checkPermittedTargetPath($path);
$this->file->move(app()->basePath($this->targetDir), $this->getFilename());
```

- **Source:** the multipart upload — `getClientOriginalExtension()` (extension) and the `dir` request parameter (target folder).
- **Sink:** `UploadedFile::move()` writing the file under the web root, then execution by the web server when the file is requested.
- **Missing sanitization:** no extension allow-list or block-list anywhere (`cleanFileName()` sanitises only the base name and does not touch the appended extension); non-image files are not re-encoded; no guard prevents an executable extension (`php`, `phtml`, `phar`).
- **Only restriction:** `FileService::checkPermittedPath()` confines `dir` to `/files/` or `/images/` and blocks `../` (realpath must equal the joined path). This stops path traversal but **not** the dangerous extension — and both `/files/` and `/images/` are under the document root.
- **Relevant observation:** the shipped `docker/nginx-default.conf` has `root /var/www/html;` and `location ~ \.php$ { fastcgi_pass php:9000; ... }` with **no** exclusion for `/files/` or `/images/`, so a `.php` written there is executed.
- **Null byte:** not applicable; the dangerous extension is accepted directly.

**Required conditions:** an authenticated backend session with `accessLevel > 0`; a web server that executes PHP under `/files/` or `/images/` (the default for the Docker/nginx configuration the project ships).

---

## 4. Impact (C/I/A)

- **Confidentiality (High):** arbitrary code execution lets the attacker read any file/data the web-server user can reach, including the database (credential hashes, customer/catalogue data).
- **Integrity (High):** the attacker can modify application data, content and files.
- **Availability (High):** the attacker can delete data or disrupt the service.

The application-level flaw (accepting an arbitrary extension and storing it in the web root) is present in every deployment; whether it reaches code execution depends on the web server executing PHP under the upload directories — which the shipped nginx configuration does.

---

## 5. Classification

- **CWE:** CWE-434 — Unrestricted Upload of File with Dangerous Type; additional: CWE-430 (handling of the client-supplied extension), CWE-552 (files stored in a web-accessible directory)
- **CAPEC:** CAPEC-650 — Upload a Web Shell to a Web Server
- **CVSS v3.1 (base):** **8.8 (High)**
  `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
  - *Note:* PR:L because the `Auth` middleware authorises any account with `accessLevel > 0` and the controller adds no further check. If an installation effectively has a single administrator level, PR:H → `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (7.2). On a freshly installed instance with no administrator yet, the privilege can be obtained without prior authentication (see §14), pushing the realistic impact toward unauthenticated RCE.

---

## 6. Exploitation scenario

A backend user opens the file explorer and sends `POST /admin/explorer/files/` with `dir=/files` and a multipart `upload` field whose filename ends in `.php` and whose content is PHP. `UploadHandler` preserves the `.php` extension (non-image, so not re-encoded) and writes the file to `/files/<name>.php`. The attacker requests that URL; the shipped nginx passes it to PHP-FPM, which executes it — yielding code execution with the web-server's privileges.

---

## 7. Technical evidence

- **Affected component:** `application/inc/Services/UploadHandler.php` (`process()` preserves `getClientOriginalExtension()`; `insertFile()` moves to `$targetDir/base.ext`); storage confined to `/files/` or `/images/` by `FileService::checkPermittedPath()`; execution enabled by `docker/nginx-default.conf`
- **Data flow:**
  - *Source:* multipart upload — client-supplied extension (`getClientOriginalExtension()`) and the `dir` parameter
  - *Missing sanitization:* no extension allow/deny-list; non-image files not re-encoded; no execution guard on `/files/`, `/images/`
  - *Sink:* `UploadedFile::move()` → file under the web root → executed by nginx/PHP-FPM

**7.1. Confirmed by source review (commit `a4e1f75`)**
A grep of the whole application found no extension allow-list or block-list; the extension comes verbatim (lower-cased) from the client filename; `cleanFileName()` sanitises only the base name; `checkPermittedPath()` confines the target to `/files/` or `/images/` but does not restrict the extension; the shipped `docker/nginx-default.conf` executes every `.php` under `root /var/www/html` with no path exclusion, and `application/files` / `application/images` are under that root. The upload route `POST /admin/explorer/files/` is behind the `Auth` middleware, which admits any `accessLevel > 0`.

**7.2. Live demonstration (pending capture)**
Stand up the shipped Docker stack, authenticate to `/admin/`, upload a `.php` file containing a benign marker (code that only prints a fixed string) with `dir=/files`, then request `/files/<name>.php` and observe the marker in the response, proving execution. (Not yet captured in this draft; §8 gives the procedure.)

> Note: No third-party systems were accessed. Any live test must use a local, isolated instance and a benign marker only — no web-shell content.

---

## 8. Proof of concept (PoC)

In an authorized lab environment:

1. Run the shipped Docker stack (`composer install` in `application/`, then `docker compose up -d`) and, on a fresh instance, register the first account at `/admin/users/new/` (it is granted administrator — see §14). Log in to `/admin/`.
2. Via the file explorer, upload a `.php` file whose body is a harmless marker, e.g. `<?php echo "RCE-OK:" . (41 + 1);`, targeting `dir=/files`. If the UI filters the extension client-side, replay the same request through an intercepting proxy using the session cookie — the server performs no extension check.
3. **Verification:** request `/files/<name>.php`; the response contains `RCE-OK:42`, proving the uploaded PHP executed.

**PoC limitations:** requires a backend session; uses a benign marker (no web shell); does not automate mass exploitation.

---

## 9. Reproduction steps

1. Deploy AGcms (commit `a4e1f75`) on nginx + PHP-FPM as the shipped `docker-compose.yml` does.
2. Obtain a backend account (`accessLevel > 0`); on a fresh instance the first `/admin/users/new/` registration suffices.
3. Upload a `.php` file via `POST /admin/explorer/files/` with `dir=/files`.
4. Request the resulting `/files/<name>.php`.
5. Observe the PHP executing. Compare with secure behaviour: the server should reject the extension/MIME or store uploads where they cannot be executed.

---

## 10. Mitigation

- Block script execution in the upload directories — add an nginx rule so `/files/` and `/images/` never reach the PHP handler (or an `.htaccess` disabling PHP there on Apache).
- Restrict backend accounts to trusted users; review `accessLevel` assignments.
- Monitor `/files/` and `/images/` for files with executable extensions.

---

## 11. Fix

Enforce a strict extension/MIME allow-list in `UploadHandler`, independent of the client-supplied name, and reject executable extensions:

```php
$allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'mp4', 'webm', 'txt'];
$extension = mb_strtolower($uploadedFile->getClientOriginalExtension());
if (!in_array($extension, $allowedExtensions, true)) {
    throw new InvalidInput(_('File type not allowed.'));
}
// Reject executable extensions explicitly (php, phtml, php3-8, phar, phps, ...) and
// verify the sniffed MIME matches the extension.
```

Complementary measures: store uploads outside the web root (or serve them through a script forcing `Content-Disposition: attachment`); ship a server rule disabling PHP execution under `/files/` and `/images/`.

### Implemented change

[To be completed if/when the vendor releases a fix.]

---

## 12. Detection and indicators

- Files with executable extensions (`.php`, `.phtml`, `.phar`) under `application/files/` or `application/images/`.
- `POST /admin/explorer/files/` requests whose multipart filename ends in an executable extension; requests to `/files/...php` or `/images/...php` in the access log.
  ```
  grep -E "POST /admin/explorer/files/" access.log
  find application/files application/images -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \)
  ```

---

## 13. Disclosure timeline

| Date | Event |
|------|-------|
| 2026-11-15 | Source code identification and analysis (commit `a4e1f75`) |
| 2026-11-15 | Chain confirmed by source review |
| 2026-11-15 | Advisory drafting |
| _pending_ | Vendor contact |
| _pending_ | Vendor confirmation |
| _pending_ | Fix availability |
| _pending_ | Public disclosure |

---

## 14. Vendor communication

- **Intended channel:** GitHub issues / Security Advisory at https://github.com/AJenbo/agcms — the project's README invites reporting security vulnerabilities as a GitHub issue, to be promptly addressed.
- **Status:** pending opening.

> Additional observations in the same codebase, to be assessed separately:
> - **Unauthenticated privilege acquisition on a fresh install.** The `Auth` middleware exempts `POST /admin/users/new/`, and `UserController::create()` grants `User::ADMINISTRATOR` to the first account registered when no user with `access != 0` exists (`$firstUser ? ADMINISTRATOR : NO_ACCESS`). On an instance where no administrator has been created yet, an unauthenticated attacker who registers first becomes administrator and can then chain the file upload above — i.e. **unauthenticated RCE within the bootstrap window**. On a configured instance, self-registration yields `NO_ACCESS` (0), which the middleware rejects.
> - **No CSRF tokens** were found on the admin state-changing POST routes. Modern browsers' default `SameSite=Lax` cookie behaviour mitigates a pure cross-site POST, so this is reported as a secondary weakness rather than a reliable CSRF→RCE vector.

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
- Project: https://github.com/AJenbo/agcms

---

## 17. Revision history

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-11-15 | Initial version (static analysis; live PoC pending) |

---

## 18. Legal notice

This advisory is for **educational and defensive** purposes. Testing was conducted in an authorized, controlled lab environment. It must not be used to access systems without explicit authorization.

---

## 19. Contact

- **Researcher:** Kembolle Amilkar / kembolle.com.br
