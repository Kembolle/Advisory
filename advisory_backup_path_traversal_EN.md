# Security Advisory — Path Traversal / Arbitrary File Read in `admin/backup.php`

**Internal ID:** RS-ADV-2026-012
**CVE:** pending (not assigned)
**Status:** draft for disclosure

---

## 1. Executive summary

A **Path Traversal / Arbitrary File Read** vulnerability was identified in the administrative panel of *modified eCommerce Shopsoftware*, in `admin/backup.php`, `download` action. The `file` parameter (`$_GET['file']`) is concatenated directly into an `fopen()`/`fread()` operation without path normalization (`basename()`, `realpath()`) or any check for `../` sequences. An authenticated administrator can escape the backup directory and read the contents of any file on the host whose name ends in `.sql`, `.gz`, or `.zip`, including full database dumps and sensitive compressed files. Directory traversal was confirmed in the lab using an external canary file.

---

## 2. Affected products

- **Product:** modified eCommerce Shopsoftware (xt-commerce / osCommerce base)
- **Analyzed version:** `3.3.0-r16825`
- **Component:** `admin/backup.php` (revision `$Id: backup.php 16672 2025-12-04`)
- **Endpoint:** `admin/backup.php?action=download&file=<path>`
- **Access vector:** https://github.com/modified-shop/modified-shop

**Unaffected products/versions:** not assessed. The analysis was limited to the version above.

---

## 3. Vulnerability description

In the `download` action (lines 90-104), the flow is:

```php
case 'download':
  $extension = substr($_GET['file'], -3);
  if ( ($extension == 'zip') || ($extension == '.gz') || ($extension == 'sql') ) {
    if ($fp = fopen(DIR_FS_BACKUP . $_GET['file'], 'rb')) {
      $buffer = fread($fp, filesize(DIR_FS_BACKUP . $_GET['file']));
      fclose($fp);
      header('Content-type: application/x-octet-stream');
      header('Content-disposition: attachment; filename=' . $_GET['file']);
      echo $buffer;
      exit;
    }
  }
```

- **Source:** `$_GET['file']` (lines 91, 93, 94, 97).
- **Sink:** `fopen(DIR_FS_BACKUP . $_GET['file'], 'rb')` on line 93, with the content returned to the client via `echo $buffer` (line 98).
- **Missing sanitization:** no `basename()`, `realpath()`, or `../` blocking. The final path is a plain concatenation of the base directory with user input, allowing navigation outside `DIR_FS_BACKUP` via `../` sequences.
- **Only restriction:** the extension, checked by `substr($_GET['file'], -3)`, which must be `zip`, `.gz`, or `sql`. This limits reading to files ending in those suffixes but does **not** prevent directory traversal (CWE-22). Sensitive files whose names do not end in those extensions (e.g., `configure.php`, `/etc/passwd`) are not directly readable; however, SQL dumps, gzipped logs, and archives are.
- **Relevant observation:** the `deleteconfirm` action (line 106) of the same file **does** validate the presence of `..` (`if (strpos($_GET['file'], '..') !== false)`), but the `download` action does **not** apply the same protection — evidence of inconsistent control within the same file.
- **Null byte:** `%00` does not truncate the string in PHP ≥ 5.3.4; it is not a valid vector here.

**Required conditions:** an authenticated session in the administrative panel with access to the backup module.

---

## 4. Impact (C/I/A)

- **Confidentiality (High):** reading of any `.sql`/`.gz`/`.zip` file accessible to the web process, including SQL dumps (customer data, orders, password hashes) and compressed logs/backups outside the intended directory.
- **Integrity (None):** the vulnerability only reads files.
- **Availability (None):** no direct impact.

The extension restriction (`sql`/`gz`/`zip`) limits which files can be read but does not reduce the impact for database dumps, which are exactly the most sensitive artifact within reach of this endpoint.

---

## 5. Classification

- **CWE:** CWE-22 — *Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')*; additional: CWE-200 — *Exposure of Sensitive Information to an Unauthorized Actor*
- **CAPEC:** CAPEC-126 — *Path Traversal*
- **CVSS v3.1 (base):** **4.9 (Medium)**
  `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N`
  - *Note:* if the backup module is accessible to a lower-privileged administrative role (PR:L), the vector rises to **6.5 (Medium)**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`.

---

## 6. Exploitation scenario

An authenticated backend operator (or a lower-privileged account with access to the backup module) requests the download endpoint supplying a path with directory traversal that points to a `.sql`/`.gz`/`.zip` file outside the backup directory — for example, a database dump from another application on the same host or a compressed log. The content is returned in full in the response body, resulting in sensitive information disclosure.

---

## 7. Technical evidence

- **Affected component:** `admin/backup.php`, `download` action (lines 90-104)
- **Data flow:**
  - *Source:* `$_GET['file']`
  - *Missing sanitization:* no `basename()`/`realpath()`/`..` blocking; the only filter is the extension
  - *Sink:* `fopen(DIR_FS_BACKUP . $_GET['file'], 'rb')` → `fread()` → `echo`

**7.1. Confirmed path traversal (external canary)**
A controlled canary file was placed outside the configured backup directory:
```
rs-traversal-test.sql
```
The following request was issued through the authenticated endpoint:
```http
GET /admin/backup.php?action=download&file=../rs-traversal-test.sql HTTP/1.1
Cookie: <admin session>
```
The endpoint successfully retrieved the canary file located outside the intended backup directory, confirming that the application does not enforce path containment during backup downloads.

**7.2. Database backup disclosure (pending individual validation)**
A request targeting a SQL dump outside the backup directory was prepared:
```http
GET /admin/backup.php?action=download&file=../../modified-shop-3.3.0-r16825.sql HTTP/1.1
Cookie: <admin session>
```
The traversal mechanism is confirmed (§7.1). Successful retrieval of this specific database backup must be recorded separately; credential/hash extraction and account compromise have not been independently demonstrated.

---

## 8. Proof of concept (PoC)

In an authorized lab environment:

1. Authenticate to the panel (`/admin/`).
2. Place a canary file with a permitted extension (e.g., `rs-traversal-test.sql` containing an identifiable text) one level above the backup directory.
3. Request `admin/backup.php?action=download&file=../rs-traversal-test.sql`.
4. **Verification:** the download returns the content of the file outside the backup directory, confirming traversal. For real-impact evidence, demonstrate retrieval of a legitimate `.sql` dump located outside `DIR_FS_BACKUP`.

**PoC limitations:** restricted to files ending in `.sql`, `.gz`, or `.zip`; requires an administrative session; does not bypass authentication.

---

## 9. Reproduction steps

1. Log in to the administrative panel.
2. Access the backup module.
3. Invoke the `download` action with `file` containing directory traversal to a target file with a permitted extension.
4. Observe the returned file content in the download.

---

## 10. Mitigation

- Restrict access to the backup module to strictly necessary administrators.
- As an emergency measure, apply the same `..` check already present in the `deleteconfirm` action to the `download` action.
- Monitor requests to `backup.php?action=download` containing `../` or absolute paths.
- Store sensitive backup files outside the publicly accessible web root whenever possible.

---

## 11. Fix

Validate that the requested file resides within `DIR_FS_BACKUP` before opening it, for example:

```php
$baseDir       = realpath(DIR_FS_BACKUP);
$requestedFile = realpath(DIR_FS_BACKUP . $_GET['file']);

if ($baseDir === false || $requestedFile === false
    || !str_starts_with($requestedFile, $baseDir . DIRECTORY_SEPARATOR)
    || !is_file($requestedFile)) {
    $messageStack->add(ERROR_DOWNLOAD_LINK_NOT_ACCEPTABLE, 'error');
    break;
}
// validate the extension only after path containment is established
```

Complementary measures: use `basename($_GET['file'])` to discard any directory component and validate the name against an allowlist of backup files actually generated by the application, rather than relying on the extension alone.

---

## 12. Detection and indicators

- Search the access log for download requests with traversal:
  ```
  grep -iE "backup\.php.*action=download" access.log | grep -E "\.\./|%2e%2e"
  ```
- Alert on `file` values containing `../`, `%2e%2e`, or absolute paths.

---

## 13. Disclosure timeline

| Date | Event |
|------|-------|
| 2026-11-11 | Source code identification and analysis |
| 2026-11-11 | Path traversal confirmed with external canary |
| 2026-11-12 | Advisory drafting |
| _pending_ | Vendor contact |
| _pending_ | Vendor confirmation |
| _pending_ | Fix availability |
| _pending_ | Public disclosure |

---

## 14. Vendor communication

- **Intended channel:** official project forum/repository/issues and the maintainer's contact email (the project publishes no security.txt or dedicated security contact).
- **Status:** _pending opening._

> Additional observations in the same file, to be assessed separately:
> - `restorelocalnow` action (line 117): `xtc_try_upload('sql_file', DIR_FS_BACKUP, '777', array('sql','gz'))` writes uploads with `777` permissions, restricted to `sql`/`gz`. Combined with the restore functionality (SQL execution), it represents an additional vector.
> - Line 97: `$_GET['file']` is reflected in the `Content-disposition` header. CRLF header injection is blocked by modern PHP's `header()`, but it is worth recording.

---

## 15. Credits

- **Researcher:** Kembolle Amilkar
- **Program:** RedScan Academy — Offensive Security (CVE Report 2.0 course)

---

## 16. References

- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- CAPEC-126: https://capec.mitre.org/data/definitions/126.html
- PHP realpath(): https://www.php.net/manual/en/function.realpath.php
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- NVD (product search): https://nvd.nist.gov/vuln/search?keyword=modified%20ecommerce&resultType=records
- Project: https://github.com/modified-shop/modified-shop

---

## 17. Revision history

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-11-12 | Initial version (unified: static analysis + external-canary traversal evidence) |

---

## 18. Legal notice

This advisory is for **educational and defensive** purposes. Testing was conducted in an authorized, controlled lab environment. It must not be used to access systems without explicit authorization.

---

## 19. Contact

- **Researcher:** Kembolle Amilkar / kembolle.com.br
- **Via:** RedScan Academy
