# Security Advisory — SQL Injection via unsafe placeholder substitution in `Database::query()`

> **Identifier:** RS-ADV-2026-013 / CVE pending (not assigned)  
> **Publication date:** [YYYY-MM-DD]  
> **Last updated:** 2026-11-15  
> **Severity:** Critical  
> **CVSS:** 9.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`  
> **CWE:** CWE-89 — Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')  
> **Status:** No fix (project appears unmaintained) / Under investigation

<!-- Internal mapping: finding #2 of the Simple PHP Framework review. -->

---

## 1. Executive summary

A vulnerability was identified in **Simple PHP Framework** (`tylerhall/simple-php-framework`), in the master branch (commit `4ae734d`, 2020-10-11, latest), that allows **an attacker who controls the value of a query parameter** to **inject arbitrary SQL** into statements built with the framework's documented "prepared arguments" feature.

The `Database::query()` method does not use real prepared statements. It substitutes each named placeholder (`:name`) into the SQL string with an iterative `str_replace()`. Because the substitution re-scans text that was already inserted, the (correctly escaped) value of one parameter can reintroduce the placeholder token of a later parameter, and the next substitution injects a second value inside the first value's quotes, breaking out of the string literal.

Successful exploitation may result in **unauthorized reading of arbitrary database contents and, for data-modifying statements, tampering with records** (authentication bypass, data exfiltration, data alteration), depending on how the consuming application uses the method.

The responsible organization has not yet been notified; the project shows no commits since 2020 and publishes no security contact.

---

## 2. Affected products

| Product / Component | Affected versions | Fixed version | Status |
|---|---:|---:|---|
| Simple PHP Framework — `includes/class.database.php` (`query()`) | master branch, commit `4ae734d` (2020-10-11) and earlier | None | Affected |

### Unaffected products

- Not assessed. The analysis was limited to the version above.

---

## 3. Vulnerability description

The vulnerability is caused by **string-based placeholder substitution instead of parameterized queries**.

The component **`Database::query()`** advertises a prepared-argument API (see its own docblock: `query("... WHERE id = :id", array('id' => $some_val))`) but implements it by escaping each value and splicing it into the SQL text with `str_replace()`, inside a loop over the supplied arguments:

```php
public function query($sql, $args_to_prepare = null, $exception_on_missing_args = true)
{
    if(!$this->isConnected()) $this->connect();

    // Allow for prepared arguments. Example:
    // query("SELECT * FROM table WHERE id = :id", array('id' => $some_val));
    if(is_array($args_to_prepare))
    {
        foreach($args_to_prepare as $name => $val)
        {
            $val = $this->quote($val);               // mysqli_real_escape_string + wrapping quotes
            $sql = str_replace(":$name", $val, $sql, $count);
            if($exception_on_missing_args && (0 == $count))
                throw new Exception(":$name was not found in prepared SQL query.");
        }
    }

    $this->queries[] = $sql;
    $this->result = mysqli_query($this->db, $sql) or $this->notify();
    return $this->result;
}
```

Although each value is individually escaped, two properties make the substitution unsafe:

1. **Re-scanning of already-substituted text.** `str_replace()` is applied to the whole SQL string on every iteration. After the first parameter's value is inserted, a later iteration searches the *entire* string — including the text just inserted — for its own placeholder.
2. **Placeholder tokens inside attacker data are honored.** If a first (attacker-controlled) parameter's value contains the literal token `:nextparam`, the iteration for `nextparam` will replace that occurrence *inside the first value*, splicing a second quoted string into the middle of the first value and terminating its literal.

The net effect is that the surrounding quotes produced by `quote()` for the first value are neutralized, and the attacker's content escapes the string literal — classic SQL injection (CWE-89). Because the framework presents this method as the safe, parameterized way to query, applications that follow the documentation are affected whenever an earlier parameter in a multi-parameter query carries user input.

A secondary weakness compounds this: the placeholder match `":$name"` is not delimited by word boundaries, so a placeholder such as `:id` also matches inside `:identifier`, producing further unintended substitutions.

### Required conditions

- No authentication required at the framework level; reachability depends on the consuming application exposing a `query()` call whose argument array contains **two or more** placeholders where an **earlier** one receives attacker-controlled input.
- Remote / network access to the application endpoint that triggers the query.
- No user interaction or special configuration required.

---

## 4. Impact

Exploitation may allow:

- Reading arbitrary tables via UNION-based or boolean/blind injection.
- Bypassing authentication and authorization checks implemented as SQL conditions.
- Altering the WHERE clause of data-modifying statements (`UPDATE`, `DELETE`, `REPLACE`) that use the same method, affecting records the attacker should not reach.
- Enumerating database schema and extracting credentials/password hashes stored by the application.

### Confidentiality impact

High. Through injection into `SELECT` statements, an attacker can read data from any table accessible to the database user, including the `users` table.

### Integrity impact

High. `query()` is also used for `INSERT`/`UPDATE`/`DELETE`/`REPLACE` (e.g. `set_option()`, `DBSession`, `DBObject::delete()`); injection into the predicate of such statements can modify or remove unintended rows. Note: the MySQLi connection uses `mysqli_query()`, which does not execute stacked queries, so direct multi-statement injection is not available.

### Availability impact

None assessed as a direct, reliable consequence.

---

## 5. Classification

### CVSS

- **Score:** 9.1
- **Severity:** Critical
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

> **Scoring note:** The score above reflects the worst-case, documented usage where an unauthenticated endpoint reaches a vulnerable multi-parameter `query()` call. The effective score in a given deployment depends on reachability and on whether the affected statement reads or writes data. A read-only, authentication-required deployment would be closer to `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5, Medium).

### CWE

- **CWE-89 — Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')**

### CAPEC, when applicable

- **CAPEC-66 — SQL Injection**

---

## 6. Exploitation scenario

A possible exploitation scenario unfolds as follows:

1. The attacker identifies an application endpoint built on Simple PHP Framework that calls `Database::query()` with a parameter array containing two or more placeholders.
2. The attacker supplies, in the earlier user-controlled parameter, a value that embeds the token of a later placeholder (e.g. `…:otherparam…`).
3. The application passes both values to `query()`; the iterative `str_replace()` reintroduces the later placeholder inside the first value and substitutes it, terminating the first value's string literal.
4. The attacker's SQL fragment is executed as part of the statement.
5. As a consequence, the attacker reads or alters data outside the intended scope.

---

## 7. Technical evidence

### Affected component

```text
includes/class.database.php — Database::query(), the foreach ($args_to_prepare) substitution loop
```

### Result (controlled lab, authorized environment)

Using a local test database and test-only accounts, a query written exactly as the framework documents — two named parameters, both passed through the "prepared" API — was issued:

```text
query(
  "SELECT username, level FROM users WHERE username = :u AND level = :level",
  array('u' => <value A>, 'level' => <value B>)
)
```

When the first parameter's value embeds the second parameter's token and the second parameter's value supplies a boolean-true fragment, the string produced and sent to the database collapses the first literal's quoting, so the `WHERE` clause no longer constrains `username`. The statement returns **every** row of the test table instead of the single intended row. The same construction against the single-parameter form behaves correctly, isolating the loop/re-scan behavior as the root cause.

> **Note:** No third-party systems were accessed. The demonstration used only local, disposable test data and accounts created for the test. Representative payload strings are intentionally omitted from this section and kept in the private PoC package; the root cause and effect above are sufficient for triage.

---

## 8. Proof of concept

The proof of concept demonstrates only the vulnerable behavior and must be used exclusively in authorized environments.

```bash
# In an isolated lab with a disposable database and test accounts only:
# 1. Seed two or more rows in a test table.
# 2. Invoke Database::query() using its documented multi-parameter
#    "prepared arguments" form, supplying an earlier parameter whose
#    value embeds the name token of a later parameter.
# 3. Observe that the generated SQL (visible via Database::lastQuery())
#    contains the later value spliced inside the earlier value's quotes.
```

### Expected result

```text
The statement returned by Database::lastQuery() shows the first parameter's
string literal terminated early, and the query returns rows outside the
intended WHERE constraint (e.g. all rows instead of one).
```

### PoC limitations

- Does not intentionally cause denial of service.
- Does not delete or modify third-party data.
- Does not create persistence or backdoors.
- Does not contain real credentials.
- Does not automate mass exploitation.

---

## 9. Reproduction steps

1. Deploy an application (or minimal harness) using Simple PHP Framework at commit `4ae734d`.
2. Create a test table with at least two rows.
3. Call `Database::query()` with a two-placeholder statement, binding user-influenced input to the earlier placeholder.
4. Supply an earlier value that embeds the later placeholder's token and a later value that provides an always-true condition.
5. Observe, via `Database::lastQuery()` and the result set, that the earlier literal is broken and the predicate is bypassed.
6. Compare with the expected behavior: a true prepared statement would treat both values as opaque data and return only matching rows.

---

## 10. Mitigation

Until a definitive fix is applied, it is recommended to:

- Avoid the `$args_to_prepare` feature of `Database::query()` for any statement that incorporates user input; where unavoidable, ensure no user-controlled value precedes another placeholder in the same call.
- Add input allowlisting/validation at the application layer for every value that reaches `query()`.
- Deploy a WAF rule to flag SQL metacharacters and placeholder tokens (`:` followed by a word) in request parameters, as a detection aid only.
- Grant the database account least privilege (read-only where possible) to limit integrity impact.
- Enable and review query logging for anomalous statements.

> Mitigations reduce the risk but may not fully eliminate the vulnerability.

---

## 11. Fix

Replace string substitution with genuine parameterized queries, or, at minimum, perform a single-pass substitution that never re-scans inserted text.

### Recommended fix — real prepared statements

```php
// Bind values as parameters so the database driver treats them strictly as data.
$stmt = mysqli_prepare($this->db, 'SELECT username, level FROM users WHERE username = ? AND level = ?');
mysqli_stmt_bind_param($stmt, 'ss', $username, $level);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
```

(PDO with bound parameters is an equivalent, often simpler, option.)

### Minimal interim fix — single-pass placeholder substitution

If the named-placeholder API must be preserved, substitute each placeholder exactly once over the *original* template, without re-scanning inserted text:

```php
if (is_array($args_to_prepare)) {
    $sql = preg_replace_callback('/:([a-zA-Z_][a-zA-Z0-9_]*)/', function ($m) use ($args_to_prepare, $exception_on_missing_args) {
        $name = $m[1];
        if (!array_key_exists($name, $args_to_prepare)) {
            if ($exception_on_missing_args) {
                throw new Exception(":$name was not found in prepared SQL query.");
            }
            return $m[0];
        }
        return $this->quote($args_to_prepare[$name]);
    }, $sql);
}
```

This resolves both the re-scan problem (each placeholder is replaced once, against the original string) and the word-boundary problem (`:id` no longer matches inside `:identifier`). Real prepared statements remain the preferred solution.

### Implemented change

[To be completed if/when the vendor releases a fix.]

---

## 12. Detection and indicators

Possible indicators of exploitation:

- Requests whose parameter values contain a colon followed by a word (`:name`) where the application does not expect one.
- Application or database errors referencing malformed SQL near string literals.
- Unexpected large result sets or data-modifying statements in query logs.
- Entries in `Database::$queries` / query logs where a value literal appears to contain a second quoted value.

### Sample log search

```text
grep -E "[?&][^=]+=[^&]*:[A-Za-z_]" access.log
# and review DB general/query log for statements where a quoted value contains an embedded quote-break
```

---

## 13. Disclosure timeline

| Date | Event |
|---|---|
| 2026-11-15 | Vulnerability identified during source code review |
| 2026-11-15 | Vulnerability validated in controlled lab |
| 2026-11-15 | Advisory drafting |
| _pending_ | First notification sent to the maintainer |
| _pending_ | Receipt acknowledged |
| _pending_ | CVE requested (MITRE, as the project has no CNA) |
| _pending_ | Fix released |
| _pending_ | Advisory published |

---

## 14. Vendor communication

- **Vendor:** Tyler Hall (`tylerhall`), Simple PHP Framework
- **Channel used:** GitHub issues / repository contact (no security.txt or SECURITY.md published)
- **Date of first notification:** [pending]
- **Response status:** No response (project shows no activity since 2020)
- **Vendor position:** [pending]

---

## 15. Credits

The vulnerability was identified and reported by:

- **Researcher:** Kembolle Amilkar
- **Organization:** RedScan Academy — Offensive Security
- **Contact:** [EMAIL]
- **Profile:** [GitHub / LinkedIn / website]

Acknowledgments:

- Tyler Hall (project maintainer)

---

## 16. References

- Project: https://github.com/tylerhall/simple-php-framework
- Affected file: https://github.com/tylerhall/simple-php-framework/blob/master/includes/class.database.php
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- CAPEC-66: https://capec.mitre.org/data/definitions/66.html
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- PHP mysqli prepared statements: https://www.php.net/manual/en/mysqli.prepare.php
- NVD (product search): https://nvd.nist.gov/vuln/search?keyword=simple%20php%20framework&resultType=records

---

## 17. Revision history

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-11-15 | Initial draft |

---

## 18. Legal notice

This advisory is published for educational, defensive and security-improvement purposes.

The information presented was obtained in an authorized environment and disclosed responsibly or in a coordinated manner. The author does not encourage the use of this information for unauthorized access, service disruption, privacy violations or any illegal activity.

Use of the information in this document is the sole responsibility of the reader.

---

## 19. Contact

For corrections, updates or additional information:

- **Email:** [EMAIL]
- **Website:** [WEBSITE]
- **PGP key:** [LINK OR FINGERPRINT]
