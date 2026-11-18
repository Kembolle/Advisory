# Security Advisory — Stored Cross-Site Scripting (XSS) in `public/handlers/functions.php` and admin article views of CorelyPHP

**Internal ID:** RS-ADV-2026-019
**CVE:** pending (not assigned)
**Status:** draft for disclosure

---

## 1. Executive summary

A **Stored Cross-Site Scripting (XSS)** vulnerability was identified in *CorelyPHP* (`Dominik-developer/CorelyPHP`). The article `title` (and `text`) supplied through the administrative panel is stored as-is and later echoed into HTML **without output encoding** in the public blog listing (`public/handlers/functions.php`, `all_articles()`, line 39) and in the administrative article list (`admin/all_articles.alg.php`, line 33), as well as in the article edit form (`admin/window_functions.php`, lines 132, 140, 147). The only transformation applied to the title on creation is `mysqli_real_escape_string()`, an SQL escaping function that provides no HTML protection. Script injected into an article therefore executes in the browser of **every visitor of the blog home page** and of **every administrator** who opens the article list — where the session cookie is readable by JavaScript (no `HttpOnly`), enabling session hijacking. Execution was **confirmed live** in an isolated lab with a benign marker payload on both `/public/main.php` and `/admin/panel.php?window=all-articles`.

---

## 2. Affected products

- **Product:** CorelyPHP — PHP CMS for blogs (`Dominik-developer/CorelyPHP`)
- **Analyzed version:** `v1.2.0` (latest tag, commit `3d2b3f4`, 2025-03-14); the same sinks are present in `v1.1.0` (commit `483762f`, 2025-02-25 — public sink in `public/functions.php`, line 41). Both are listed as *supported* in the project's `SECURITY.md`.
- **Component:**
  - Public: `public/handlers/functions.php`, `all_articles()` (lines 39 and 47)
  - Admin: `admin/all_articles.alg.php`, `all()` (lines 33, 35, 37); `admin/window_functions.php`, `editArticle()` (lines 132, 140, 147)
- **Endpoints:**
  - Injection: `POST /admin/algo/new.alg.php` (field `title`; file `textUpload`) and `POST /admin/algo/edit.alg.php` (fields `new_title`, `new_text`)
  - Execution: `GET /public/main.php` (any visitor, unauthenticated), `GET /admin/panel.php?window=all-articles`, `GET /admin/panel.php?window=edit-article` (administrator)
- **Access vector:** content injected through the authenticated administrative panel (`/admin/`); payload executed for unauthenticated visitors and for administrators — https://github.com/Dominik-developer/CorelyPHP

**Unaffected products/versions:** not assessed. The analysis was limited to the versions above.

---

## 3. Vulnerability description

On article creation (`admin/algo/new.alg.php`), the title is escaped for SQL only and stored with a prepared statement:

```php
72   $title = mysqli_real_escape_string($conn, $_POST['title']);   // SQL escaping, not HTML encoding
73   $textUpload = file_get_contents($_FILES['textUpload']['tmp_name']);
...
123  $sql_insert = "INSERT INTO articles (title, text, photo_path) VALUES (?, ?, ?)";
125  $stmt_insert->bind_param('sss', $title, $textUpload, $target_file);
```

On edit (`admin/algo/edit.alg.php`, lines 30-31), `$_POST['new_title']` and `$_POST['new_text']` are stored with no transformation at all (lines 145/151).

The stored values are then printed raw. Public listing, `public/handlers/functions.php`:

```php
35   echo '
36       <article class="wrapper">
37           <a href="single.php?title=' . urlencode($sanitized_title) . '" ...>
38               <div class="articleTitle">
39                   '. $row['title'] . '<br>
40               </div>
...
47               <td>' . substr($row['text'], 0, 50) . '...<td>
```

Admin list, `admin/all_articles.alg.php`:

```php
33   echo '<td>' . $row['title'] . '</td>';
35   echo '<td>' . substr($row['text'], 0, 50) . '...</td>';
37   echo '<td><a class="custom-button green" href="../public/single.php?title='.$row['title'].'" target="_blank">View</a></td>';
```

Admin edit form, `admin/window_functions.php`:

```php
132  <input type="text" id="new_title" name="new_title" ... value="<?php echo $articleData['title']; ?>">
140  <textarea id="new_text" name="new_text" ...><?php  echo $articleData['text']; ?></textarea>
147  <img name="old_photo" src="..." alt="<?php echo $articleData['title']; ?> photo" ...>
```

- **Source:** `$_POST['title']` (new.alg.php, line 72); the content of the uploaded `textUpload` file (line 73); `$_POST['new_title']` / `$_POST['new_text']` (edit.alg.php, lines 30-31).
- **Sink:** unencoded `echo` of `$row['title']` / `$row['text']` / `$articleData[...]` into HTML element content, attribute values (`value`, `alt`, `href`) and `<textarea>` content (lines listed above).
- **Missing sanitization:** no `htmlspecialchars()` / `htmlentities()` on output in any of these sinks; no Content-Security-Policy header (the CSP meta tag in `admin/panel.php`, line 40, is commented out).
- **Only restriction:** `mysqli_real_escape_string()` on the title at creation, which prefixes quotes with a backslash. It does not encode `<`, `>` or `&`, so it does not prevent HTML/script injection; it only forces payloads to avoid quotes (e.g. by using unquoted attributes and JavaScript template literals). It is **not** applied in `edit.alg.php`. The title column is `varchar(255)`, which bounds but does not prevent the payload. In the listings, `text` is truncated to 50 characters, which limits — but does not eliminate — that vector.
- **Relevant observation:** the article detail page (`public/handlers/single.alg.php`, lines 29, 33, 37, 42) **does** apply `htmlspecialchars()` to the same fields; the control exists in the project but is applied inconsistently.
- **Null byte:** not applicable.

**Required conditions:** the ability to create or edit an article (administrator session, or a forged request carried by the administrator's browser — see §5 note and §7.2); a victim (visitor or administrator) loading one of the affected pages.

---

## 4. Impact (C/I/A)

- **Confidentiality (Low):** script runs in the origin of the site; in the admin panel it can read the session cookie (`PHPSESSID` is not `HttpOnly`) and page content, enabling session hijacking of the administrator.
- **Integrity (Low):** script can alter page content shown to visitors (defacement, phishing, malicious redirects) and, in the admin context, perform actions as the administrator (no anti-CSRF tokens are required by any admin action).
- **Availability (None):** no direct impact.

Because the payload is persisted in the database and rendered on the blog home page, it affects **every visitor** without further interaction beyond loading the page. In the administrative context, combined with the missing `HttpOnly` flag and the absence of CSRF tokens, a successful execution can lead to full takeover of the administrator session — and from there to remote code execution through the unrestricted photo upload (RS-ADV-2026-018).

---

## 5. Classification

- **CWE:** CWE-79 — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'); additional: CWE-116 — Improper Encoding or Escaping of Output
- **CAPEC:** CAPEC-592 — Stored XSS
- **CVSS v3.1 (base):** **4.8 (Medium)**
  `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`
  - *Note:* PR:H because injection requires an administrator session; S:C because the script executes in the browsers of other users (visitors and other administrator sessions). If the injection is delivered through cross-site request forgery against a logged-in administrator — no anti-CSRF token is required by `new.alg.php` and the session cookie sets no `SameSite` attribute — the attacker needs no privileges: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (6.1). Browsers that apply `SameSite=Lax` by default (e.g. Chromium) block this cross-site POST; the chained scenario has **not** been confirmed live (see §7.2). Installations that keep the seeded default credentials (`admin` / `pass`) also lower the effective privilege barrier.

---

## 6. Exploitation scenario

An actor holding an administrator session — or able to make a logged-in administrator's browser submit the article form (CSRF) — creates an article whose title contains a `<script>` element. The title is stored unchanged (apart from backslash-escaping of quotes). Every visitor who opens the blog home page (`/public/main.php`) receives the script inline in the article card and executes it in the site's origin, allowing defacement, phishing overlays or redirection. When an administrator opens **All articles** or **Edit article**, the same script runs inside the admin panel, where it can read the non-`HttpOnly` session cookie or perform administrative actions on the administrator's behalf.

---

## 7. Technical evidence

- **Affected component:** `public/handlers/functions.php` (`all_articles()`, lines 39, 47); `admin/all_articles.alg.php` (lines 33, 35, 37); `admin/window_functions.php` (`editArticle()`, lines 132, 140, 147)
- **Data flow:**
  - *Source:* `$_POST['title']` (new.alg.php:72), `textUpload` file content (new.alg.php:73), `$_POST['new_title']` / `$_POST['new_text']` (edit.alg.php:30-31)
  - *Missing sanitization:* only `mysqli_real_escape_string()` (SQL context) on creation; nothing on edit; no output encoding; no CSP
  - *Sink:* `echo` of `title` / `text` into HTML content and attributes on public and admin pages

**7.1. Confirmed stored XSS (live, benign marker)**
Lab: CorelyPHP `v1.2.0` on `php:8.3-apache` (PHP 8.3.36, Apache 2.4.69) and `mysql:8.4`, Docker / OrbStack (macOS, aarch64), isolated on `localhost`.
After authenticating as `admin`, an article was created with the following title (238 characters; quote-free to survive `mysqli_real_escape_string()`):
```html
XSS<script>document.body.insertAdjacentHTML(`afterbegin`,`<h2 style=background:#b00020;color:#fff;padding:12px>XSS-POC: JS executado em ${location.pathname} | PHPSESSID legivel por JS: ${/PHPSESSID=/.test(document.cookie)}</h2>`)</script>
```
```http
POST /admin/algo/new.alg.php HTTP/1.1
Host: localhost:8080
Cookie: PHPSESSID=<session>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="title"

XSS<script>document.body.insertAdjacentHTML(`afterbegin`, ...)</script>
------X
Content-Disposition: form-data; name="textUpload"; filename="poc.txt"
...
------X
Content-Disposition: form-data; name="photoUpload"; filename="xss_poc_20261118005751.png"
Content-Type: image/png
...
------X--
```
The article was stored (ID 3, `date_of_publish` 2026-11-18 00:57:51 UTC) and the `<script>` element was present verbatim in the HTML returned by `GET /public/main.php`. Loading the pages in a browser produced the marker banner, proving execution:

- `GET /public/main.php` → banner `XSS-POC: JS executado em /public/main.php | PHPSESSID legivel por JS: true` (screenshot `poc_xss_publico_corelyphp.jpg`)
- `GET /admin/panel.php?window=all-articles` → banner `XSS-POC: JS executado em /admin/panel.php | PHPSESSID legivel por JS: true` (screenshot `poc_xss_admin_corelyphp.jpg`)

For contrast, the article detail renderer (`public/handlers/single.alg.php`, lines 29 and 37) applies `htmlspecialchars()` to the same fields (verified by source review), confirming the inconsistent encoding. The marker only writes a banner into the page; it does not read out or transmit the cookie value. The test article was deleted afterwards.

**7.2. CSRF-delivered injection (pending individual validation)**
`POST /admin/algo/new.alg.php` requires no anti-CSRF token, and the session cookie is issued without a `SameSite` attribute. A cross-site page auto-submitting a multipart form (title payload + text file + image) to that endpoint while an administrator is logged in is expected to store the payload without the attacker holding any credentials. This has been verified by source review and header inspection only; whether the cross-site POST carries the session cookie depends on the browser's default `SameSite` behaviour (Chromium applies `Lax` by default, which blocks it). A live capture per browser must be recorded separately before the PR:N score in §5 is claimed.

> Note: No third-party systems were accessed. All tests used a local, isolated instance and a benign marker that neither displays nor exfiltrates session data.

---

## 8. Proof of concept (PoC)

In an authorized lab environment:

1. Deploy CorelyPHP `v1.2.0` as documented and log in at `/admin/panel.login.php`.
2. Open **Add article** (`panel.php?window=add-article`).
3. Set the title to a benign marker that avoids quotes, e.g.:
   ```html
   XSS<script>document.body.prepend(`XSS-POC-OK`)</script>
   ```
   attach any `.txt` file as the text and any PNG/JPEG as the photo, tick the confirmation box and submit.
4. **Verification:** open `/public/main.php` (also in a private window, as an unauthenticated visitor) and `/admin/panel.php?window=all-articles`; the text `XSS-POC-OK` is inserted at the top of both pages by the injected script. Viewing the page source shows the `<script>` element unencoded inside `<div class="articleTitle">`.
5. Clean up: delete the article in the panel and remove its photo from `articles_photos/` (deleting an article does not remove the file).

**PoC limitations:** injection requires an administrator session (the CSRF delivery in §7.2 is not yet confirmed); title payloads are limited to 255 characters and must avoid quotes when created via `new.alg.php`; the `text` vector is limited to the first 50 characters in the listings. The marker does not exfiltrate data.

---

## 9. Reproduction steps

1. Log in to the administrative panel.
2. Create (or edit) an article whose title contains `<script>…</script>` (or an element with an event handler).
3. Open the blog home page `/public/main.php`.
4. Observe the injected script executing; repeat on `/admin/panel.php?window=all-articles`.
5. Expected secure behaviour: the title is displayed literally (HTML-encoded), as it already is on `/public/single.php`.

---

## 10. Mitigation

- Until a fix is available, treat article titles and texts as untrusted and review existing articles for HTML/script content:
  ```sql
  SELECT ID, title FROM articles WHERE title REGEXP '<|>' OR text REGEXP '<script|on[a-z]+=';
  ```
- Set the session cookie flags (`session.cookie_httponly = 1`, `session.cookie_samesite = Strict`) to prevent cookie theft and cross-site form submission.
- Add a restrictive Content-Security-Policy header (e.g. `default-src 'self'; script-src 'self'`) to block inline script on public and admin pages.
- Restrict administrator access and change the default `admin` / `pass` credentials.

---

## 11. Fix

Encode every database value at output time for the context in which it is used, for example in `public/handlers/functions.php`:

```php
$title = htmlspecialchars($row['title'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$text  = htmlspecialchars(mb_substr($row['text'], 0, 50), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$photo = htmlspecialchars($row['photo_path'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

echo '<div class="articleTitle">' . $title . '<br></div>';
```

Apply the same encoding to `admin/all_articles.alg.php` (lines 33, 35, 36, 37 — use `urlencode()` for the `title` query parameter in the `href`, then HTML-encode the whole URL) and to `admin/window_functions.php` (lines 121, 125, 132, 140, 147, 161). Remove the `mysqli_real_escape_string()` call from `new.alg.php` line 72: the value is already bound through a prepared statement, and the extra escaping corrupts stored titles (adds backslashes) without providing XSS protection. Complementary measures: a central `e()` helper for output encoding, a Content-Security-Policy without `unsafe-inline`, and anti-CSRF tokens on all admin forms.

### Implemented change

[To be completed if/when the vendor releases a fix.]

---

## 12. Detection and indicators

- Article titles or texts containing markup:
  ```sql
  SELECT ID, title, date_of_publish FROM articles
   WHERE title REGEXP '<[a-z/!]' OR text REGEXP '<script|javascript:|on[a-z]+[[:space:]]*=';
  ```
- `POST /admin/algo/new.alg.php` or `/admin/algo/edit.alg.php` whose `Referer`/`Origin` is not the site itself (possible CSRF delivery):
  ```
  grep -E "POST /admin/algo/(new|edit)\.alg\.php" access.log
  ```
- Unexpected outbound requests from visitors' browsers or unexpected admin sessions originating from unknown IPs.

---

## 13. Disclosure timeline

| Date | Event |
|------|-------|
| 2026-11-17 | Source code identification and analysis (`v1.2.0`; `v1.1.0` also affected) |
| 2026-11-17 | Stored XSS confirmed live on public and admin pages (benign marker) |
| 2026-11-17 | Advisory drafting |
| _pending_ | CSRF-delivered injection validation (§7.2) |
| _pending_ | Vendor contact |
| _pending_ | Vendor confirmation |
| _pending_ | Fix availability |
| _pending_ | Public disclosure |

---

## 14. Vendor communication

- **Intended channel:** GitHub issue at https://github.com/Dominik-developer/CorelyPHP, as required by the project's `SECURITY.md` (title containing "Vulnerability", affected part — *user* and *admin* — and severity; tag the maintainer `Dominik-developer`; one vulnerability per issue). The policy publishes no private channel; consider requesting one (e.g. GitHub private vulnerability reporting, if enabled) before posting payload details publicly.
- **Status:** _pending opening._

> Additional observations in the same codebase, to be assessed separately:
> - **Unrestricted file upload → RCE** in `new.alg.php` / `edit.alg.php` — reported as RS-ADV-2026-018. Stored XSS in the admin panel provides a path to that issue through administrator session takeover.
> - **Missing CSRF protection** on every state-changing admin form, and session cookie issued without `HttpOnly` and `SameSite`.
> - **Upload persisted after failed insert** — in `new.alg.php` the photo is moved to `articles_photos/` before the `INSERT`; when the insert fails (e.g. title longer than 255 characters) the file remains on disk. Deleting an article (`delate.alg.php`) also leaves its photo behind.
> - **Double escaping of titles** — `mysqli_real_escape_string()` combined with a prepared statement stores backslash-escaped quotes in the database (data integrity issue).

---

## 15. Credits

The vulnerability was identified and reported by:

- **Researcher:** Kembolle Amilkar
- **Contact:** contato@kembolle.com.br
- **Profile:** https://github.com/Kembolle

---

## 16. References

- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- CWE-116: https://cwe.mitre.org/data/definitions/116.html
- CAPEC-592: https://capec.mitre.org/data/definitions/592.html
- OWASP — Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- PHP — `htmlspecialchars()`: https://www.php.net/manual/en/function.htmlspecialchars.php
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- NVD (product search): https://nvd.nist.gov/vuln/search?keyword=CorelyPHP&resultType=records
- Project: https://github.com/Dominik-developer/CorelyPHP
- Affected release: https://github.com/Dominik-developer/CorelyPHP/releases/tag/v1.2.0
- Related: RS-ADV-2026-018 — Authenticated Arbitrary File Upload leading to RCE in CorelyPHP

---

## 17. Revision history

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-11-17 | Initial version (unified: static analysis + live PoC evidence; CSRF delivery pending) |

---

## 18. Legal notice

This advisory is for **educational and defensive** purposes. Testing was conducted in an authorized, controlled lab environment. It must not be used to access systems without explicit authorization.

---

## 19. Contact

- **Researcher:** Kembolle Amilkar / kembolle.com.br
