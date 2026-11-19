# Security Advisory — Arbitrary File Upload leading to Remote Code Execution in `admin/upload.php`

**Internal ID:** RS-ADV-2026-019
**CVE:** pending (not assigned)
**Status:** draft for disclosure

---

## 1. Executive summary

An **arbitrary file upload** vulnerability leading to **remote code execution** was identified in the administrative panel of *php-basic-photo-cms*, in `admin/upload.php` via `Photograph::attach_file()`/`save()`. The uploaded file name is taken directly from the client (`basename($_FILES['upload']['name'])`) with no extension allow-list, no MIME validation, and no image re-encoding, and the file is written under `upload/images/` — a directory **inside the web root**. An attacker with an administrative session (or, chained with the unauthenticated SQL injection in RS-ADV-2026-018, with no credentials at all) can upload a `.php` file and execute arbitrary code by requesting it.

---

## 2. Affected products

- **Product:** php-basic-photo-cms (dahaltn/php-basic-photo-cms)
- **Analyzed version:** `master` @ commit `02746c9` (2019-11-09; no tagged releases)
- **Component:** `admin/upload.php` → `include/photograph.php` (`attach_file()` lines 56-72, `save()` lines 77-108)
- **Endpoint:** `POST /admin/upload.php` (multipart field `upload`)
- **Access vector:** authenticated administrative panel (`/admin/`) — https://github.com/dahaltn/php-basic-photo-cms

**Unaffected products/versions:** not assessed. The analysis was limited to the version above.

---

## 3. Vulnerability description

In the upload action, the client-supplied file name is stored verbatim and later written under the web root:

```php
// admin/upload.php
if(isset($_POST['submit'])){
    $photograph = new Photograph();
    $photograph->caption = $_POST['caption'];
    $photograph->attach_file($_FILES['upload']);
    if($photograph->save()){ ... }
}

// include/photograph.php:56  attach_file()
$this->temp_path = $file['tmp_name'];
$this->filename  = basename($file['name']);   // client-controlled name, no checks
$this->type      = $file['type'];              // client-controlled MIME

// include/photograph.php:92  save()
$target_path = ROOT."upload".DS.$this->upload_dir.DS.$this->filename;  // upload_dir = 'images'
if(move_uploaded_file($this->temp_path, $target_path)){ ... }
```

`ROOT` is defined in `include/include.php` as `dirname(dirname(__FILE__))` — the application root, which is also the web root — so `upload/images/` is directly servable.

- **Source:** `$_FILES['upload']['name']` (client-controlled) → `basename()` only.
- **Sink:** `move_uploaded_file($tmp, ROOT."upload/images/".$filename)` on line 97.
- **Missing sanitization:** no extension allow-list, no MIME/content verification, no `getimagesize()`, no server-side rename/randomization. The `type` field is also taken from the client. The only transformation is `basename()`, which strips directory components but preserves the extension.
- **Only restriction:** a client-side `MAX_FILE_SIZE` hidden field and a server-side caption length check — neither restricts file type or content.
- **Relevant observation:** the shipped `upload/images/` directory has no `.htaccess` or handler restriction, so `.php` files placed there are executed by the web server.
- **Null byte:** not required; the extension is preserved as-is, so `.php` is kept directly.

**Required conditions:** an authenticated administrative session. This condition is removable by chaining RS-ADV-2026-018 (unauthenticated SQL injection / login bypass), yielding pre-authentication RCE.

---

## 4. Impact (C/I/A)

- **Confidentiality (High):** executed code can read application source, the database configuration (`include/config.php`), and any file readable by the web process.
- **Integrity (High):** arbitrary code execution allows modification of application files and data.
- **Availability (High):** executed code can disrupt or disable the service.

Arbitrary file upload into an executable web-root directory is a direct path to full server-side compromise of the application context.

---

## 5. Classification

- **CWE:** CWE-434 — Unrestricted Upload of File with Dangerous Type; additional: CWE-862 — Missing Authorization (no per-action check beyond the session flag)
- **CAPEC:** CAPEC-17 — Using Malicious Files
- **CVSS v3.1 (base):** **8.8 (High)**
  `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
  - *Note:* chained with RS-ADV-2026-018 the privilege requirement drops to none (PR:N), giving `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8, Critical).

---

## 6. Exploitation scenario

An attacker authenticates to `/admin/` (with valid or SQLi-bypassed credentials) and submits a multipart POST to `admin/upload.php` with the `upload` field set to a file named `marker.php`. The application stores it at `upload/images/marker.php` under the web root without inspecting its extension or content. The attacker then requests `GET /upload/images/marker.php`, and the server executes the PHP, demonstrating code execution in the application context.

---

## 7. Technical evidence

- **Affected component:** `admin/upload.php`; `include/photograph.php` `attach_file()` (lines 56-72) and `save()` (lines 77-108)
- **Data flow:**
  - *Source:* `$_FILES['upload']['name']`
  - *Missing sanitization:* `basename()` only — no extension allow-list, no MIME/content check, no rename
  - *Sink:* `move_uploaded_file($tmp, ROOT."upload/images/".basename($name))` → file served and executed from the web root

**7.1. Confirmed sink (source-level, benign reproduction)**
The exact filename/target-path logic from the source was reproduced in isolation (no server), confirming a `.php` name is preserved and placed under the web root with no filter:
```
client filename: marker.php
stored as:       <WEBROOT>/upload/images/marker.php
extension 'php' blocked by app? NO
```

**7.2. Live execution (confirmed — screenshot evidence)**
In the lab (PHP + MariaDB), a session was obtained via the SQLi login bypass (RS-ADV-2026-018;
username `' OR '1'='1' -- -`, arbitrary password), reaching the administrative panel with no valid
credential (evidence `03_login_bypass_admin.png`). A benign proof-of-execution marker — not a web
shell — was then uploaded:
```php
# marker.php
<?php echo "LAB-MARKER-".(2+2); ?>
```
```http
POST /admin/upload.php HTTP/1.1          (multipart field: upload=marker.php)   [04_upload_done.png]
Cookie: <session from the SQLi bypass>

GET /upload/images/marker.php HTTP/1.1
=> 200 OK, body: LAB-MARKER-4                                                    [05_rce_marker_exec.png]
```
The response **`LAB-MARKER-4`** confirms the uploaded PHP was executed by the server. The marker
only prints an arithmetic result; it issues no commands and is not a shell. Chained with
RS-ADV-2026-018 this demonstrates **unauthenticated** remote code execution end to end.

---

## 8. Proof of concept (PoC)

In an authorized lab environment (see the accompanying Docker lab):

1. Authenticate to `/admin/` (seeded creds, or via RS-ADV-2026-018).
2. On `admin/upload.php`, upload `marker.php` containing `<?php echo "LAB-MARKER-".(2+2); ?>`.
3. Request `GET /upload/images/marker.php`.
4. **Verification:** the response body `LAB-MARKER-4` proves arbitrary PHP execution. Remove the marker afterward.

**PoC limitations:** benign marker only (no shell, no OS commands); requires an administrative session unless chained with RS-ADV-2026-018; demonstrated against the lab only.

---

## 9. Reproduction steps

1. Deploy the lab (PHP 7.4 + MySQL 5.7).
2. Log in to `/admin/`.
3. Upload a `.php` file via the gallery upload form.
4. Request the stored file under `/upload/images/` and observe execution.

---

## 10. Mitigation

- Enforce a server-side extension **allow-list** (`jpg`, `jpeg`, `png`, `gif`) and verify content with `getimagesize()`; reject everything else.
- Rename stored files to a server-generated name; never trust `$_FILES['name']` or the client `type`.
- Store uploads **outside the web root**, or disable script execution in the upload directory (e.g. `php_admin_flag engine off` / drop handler mappings).
- Add per-action authorization and CSRF protection on the upload endpoint.

---

## 11. Fix

```php
// include/photograph.php — attach_file()
$allowed = ['jpg','jpeg','png','gif'];
$ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
$info = @getimagesize($file['tmp_name']);
if (!in_array($ext, $allowed, true) || $info === false) {
    $this->errors[] = "Invalid image file";
    return false;
}
$this->filename = bin2hex(random_bytes(8)).'.'.$ext;   // server-generated name
```

Complementary measures: serve uploads from a non-executable location and validate the real MIME, not the client-supplied `type`.

---

## 12. Detection and indicators

- Look for non-image files written under `upload/images/`:
  ```
  find upload/images -type f ! -iregex '.*\.\(jpg\|jpeg\|png\|gif\)$'
  ```
- Alert on requests to `/upload/images/*.php` in access logs.

---

## 13. Disclosure timeline

| Date | Event |
|------|-------|
| 2026-11-18 | Source code identification and analysis |
| 2026-11-18 | Upload → code execution confirmed in lab (benign `LAB-MARKER` executed; unauth via SQLi-bypassed session; screenshots) |
| 2026-11-18 | Advisory drafting |
| _pending_ | Vendor contact |
| _pending_ | Vendor confirmation |
| _pending_ | Fix availability |
| _pending_ | Public disclosure |

---

## 14. Vendor communication

- **Intended channel:** GitHub issues on the project repository and the maintainer's GitHub profile (the project publishes no security.txt or dedicated security contact).
- **Status:** pending opening.

> Additional observations in the same codebase, to be assessed separately:
> - Unauthenticated SQL injection / login bypass (RS-ADV-2026-018) removes the authentication precondition for this finding.
> - The client-supplied `type` is persisted to the database and later emitted; review output contexts.
> - No CSRF token on administrative forms.

---

## 15. Credits

The vulnerability was identified and reported by:

- **Researcher:** Kembolle Amilkar
- **Contact:** contato@kembolle.com.br
- **Profile:** https://github.com/Kembolle

---

## 16. References

- CWE-434: https://cwe.mitre.org/data/definitions/434.html
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- CAPEC-17: https://capec.mitre.org/data/definitions/17.html
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- NVD (product search): https://nvd.nist.gov/vuln/search?keyword=php-basic-photo-cms&resultType=records
- Project: https://github.com/dahaltn/php-basic-photo-cms

---

## 17. Revision history

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-11-18 | Initial version (static analysis + benign sink reproduction + lab marker procedure) |
| 1.1 | 2026-11-18 | Added live lab evidence (benign marker executed; screenshots 03-05) |

---

## 18. Legal notice

This advisory is for **educational and defensive** purposes. Testing was conducted in an authorized, controlled lab environment. It must not be used to access systems without explicit authorization.

---

## 19. Contact

- **Researcher:** Kembolle Amilkar / kembolle.com.br
