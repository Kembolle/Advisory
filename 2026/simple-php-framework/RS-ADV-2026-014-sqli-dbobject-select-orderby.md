# Security Advisory — SQL Injection via unescaped identifiers/ORDER BY in `DBObject::select()`

> **Identifier:** RS-ADV-2026-014 / CVE pending (not assigned)  
> **Publication date:** [YYYY-MM-DD]  
> **Last updated:** 2026-11-15  
> **Severity:** High  
> **CVSS:** 7.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  
> **CWE:** CWE-89 — Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')  
> **Status:** No fix (project appears unmaintained) / Under investigation

<!-- Internal mapping: finding #3 of the Simple PHP Framework review. -->

---

## 1. Executive summary

A vulnerability was identified in **Simple PHP Framework** (`tylerhall/simple-php-framework`), in the master branch (commit `4ae734d`, 2020-10-11, latest), that allows **an attacker who controls the column, ordering column or sort direction of a record lookup** to **inject arbitrary SQL** through `DBObject::select()`.

The method concatenates the `$order_by` and `$sort_direction` arguments directly into the SQL statement with no escaping, and places `$column` between backticks after passing it only through `mysqli_real_escape_string()`, which does not neutralize the backtick character. Any of these three inputs, when derived from user input (a common pattern for sortable listings and flexible lookups), reaches the query as executable SQL.

Successful exploitation may result in **unauthorized reading of arbitrary database contents** (schema enumeration, data and credential-hash extraction).

The responsible organization has not yet been notified; the project shows no commits since 2020 and publishes no security contact.

---

## 2. Affected products

| Product / Component | Affected versions | Fixed version | Status |
|---|---:|---:|---|
| Simple PHP Framework — `includes/class.dbobject.php` (`select()`) | master branch, commit `4ae734d` (2020-10-11) and earlier | None | Affected |

### Unaffected products

- Not assessed. The analysis was limited to the version above.

---

## 3. Vulnerability description

The vulnerability is caused by **inserting SQL identifiers and clauses into a query without escaping or allowlisting**.

The component **`DBObject::select()`** builds its statement as follows:

```php
public function select($id, $column = null, $order_by = null, $sort_direction = 'DESC')
{
    $db = Database::getDatabase();

    if(is_null($column)) $column = $this->idColumnName;
    $column = $db->escape($column);   // mysqli_real_escape_string — does NOT escape backticks

    if(isset($order_by) && isset($sort_direction)) {
        $db->query("SELECT * FROM `{$this->tableName}` WHERE `$column` = :id ORDER BY `$order_by` $sort_direction LIMIT 1", array('id' => $id));
    } else {
        $db->query("SELECT * FROM `{$this->tableName}` WHERE `$column` = :id LIMIT 1", array('id' => $id));
    }
    // ...
}
```

Three injection points exist:

1. **`$sort_direction`** — concatenated completely raw (no backticks, no escaping, no allowlist). Any string is placed verbatim after `ORDER BY \`$order_by\``.
2. **`$order_by`** — placed inside backticks but not escaped; a value containing a backtick terminates the identifier quoting and injects into the `ORDER BY` clause (which supports subqueries in some configurations and boolean/error/time-based extraction).
3. **`$column`** — passed through `mysqli_real_escape_string()` and wrapped in backticks, but `mysqli_real_escape_string()` escapes quotes and control characters, **not** backticks. A `$column` value containing a backtick escapes the identifier quoting.

Only `$id` is handled through the (separate) placeholder mechanism; the three identifier/clause inputs are not. This is a textbook `ORDER BY` / identifier SQL injection (CWE-89). `ORDER BY` and column names cannot be parameterized by prepared statements, so they must be validated against an allowlist — which the method does not do.

### Required conditions

- No authentication required at the framework level; reachability depends on the consuming application passing user-controlled input to `$column`, `$order_by` or `$sort_direction` (common in "sort by column / direction" listings and generic lookups such as `select($value, $userColumn)`).
- Remote / network access to the application endpoint that triggers the lookup.
- No user interaction or special configuration required.

---

## 4. Impact

Exploitation may allow:

- Extraction of arbitrary table data via subquery/boolean/time-based techniques in the `ORDER BY` clause.
- Enumeration of database schema (table and column names).
- Disclosure of stored credentials and password hashes.
- Inference of data even when query output is not directly reflected (blind injection).

### Confidentiality impact

High. An attacker can derive the contents of tables accessible to the database user.

### Integrity impact

None assessed as a reliable direct consequence. The sink is a `SELECT`, and the MySQLi connection does not execute stacked statements, so injection into this method does not directly run `INSERT`/`UPDATE`/`DELETE`.

### Availability impact

None assessed as a direct, reliable consequence (time-based techniques may cause query delays but are used for inference, not denial of service).

---

## 5. Classification

### CVSS

- **Score:** 7.5
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

> **Scoring note:** Reflects an unauthenticated endpoint exposing a sortable/parametric lookup. In deployments where the vulnerable lookup is only reachable by an authenticated user, the vector moves to `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (6.5, Medium).

### CWE

- **CWE-89 — Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')**

### CAPEC, when applicable

- **CAPEC-66 — SQL Injection**

---

## 6. Exploitation scenario

A possible exploitation scenario unfolds as follows:

1. The attacker finds a listing or lookup endpoint that forwards a user-supplied sort column and/or direction into `DBObject::select()` (for example, `?sort=<column>&dir=<direction>`).
2. The attacker supplies a `$sort_direction` (or `$order_by`/`$column`) value containing an SQL fragment instead of a valid identifier or `ASC`/`DESC`.
3. The framework concatenates the value into the `ORDER BY` clause and executes it.
4. The attacker uses boolean/time-based or subquery techniques to read data outside the intended record.
5. As a consequence, sensitive information is disclosed.

---

## 7. Technical evidence

### Affected component

```text
includes/class.dbobject.php — DBObject::select(), construction of the ORDER BY clause and the `$column` identifier
```

### Result (static analysis + controlled lab, authorized environment)

Static review shows `$sort_direction` concatenated with no escaping, `$order_by` inside backticks without escaping, and `$column` escaped with `mysqli_real_escape_string()` (ineffective against backticks) before being wrapped in backticks. In a local lab with disposable test data, supplying a non-`ASC`/`DESC` value as the sort direction produced a statement whose `ORDER BY` clause carried attacker-controlled SQL, confirming the injection point. Only the `$id` value is bound separately and is not the affected input.

> **Note:** No third-party systems were accessed; only local, disposable test data was used. Weaponized extraction payloads are kept in the private PoC package and omitted here; the identified sinks and their lack of escaping are sufficient for triage.

---

## 8. Proof of concept

The proof of concept demonstrates only the vulnerable behavior and must be used exclusively in authorized environments.

```bash
# In an isolated lab with disposable test data only:
# 1. Instantiate a DBObject subclass (e.g. the shipped User class).
# 2. Call select() passing a user-style value as $sort_direction
#    (or $order_by / $column) that is not a valid identifier/keyword.
# 3. Inspect Database::lastQuery() to confirm the value is concatenated
#    unescaped into the ORDER BY clause / identifier position.
```

### Expected result

```text
Database::lastQuery() shows the supplied sort-direction/order-by/column
value placed verbatim into the SQL statement, outside any parameter binding,
demonstrating the injection point.
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
2. Create a `DBObject` subclass bound to a test table with at least two rows.
3. Call `select($id, $column, $order_by, $sort_direction)` passing a crafted, non-identifier value in `$sort_direction` (and/or `$order_by`, `$column`).
4. Inspect `Database::lastQuery()` and the result/behavior.
5. Observe that the crafted value is embedded in the SQL without escaping or allowlisting.
6. Compare with the expected behavior: identifiers and sort direction should be validated against a fixed allowlist before use.

---

## 10. Mitigation

Until a definitive fix is applied, it is recommended to:

- Never pass user input directly as `$column`, `$order_by` or `$sort_direction`; map user choices to a fixed server-side allowlist first.
- Constrain sort direction to exactly `ASC` or `DESC` at the application layer.
- Grant the database account least privilege (read-only where possible).
- Enable query logging and review `ORDER BY` clauses for unexpected content.

> Mitigations reduce the risk but may not fully eliminate the vulnerability.

---

## 11. Fix

Validate identifiers against the object's known columns and restrict the sort direction to an allowlist, before building the statement.

```php
public function select($id, $column = null, $order_by = null, $sort_direction = 'DESC')
{
    $db = Database::getDatabase();

    if (is_null($column)) $column = $this->idColumnName;

    // Allowlist identifiers against the object's real columns (+ id column).
    $valid = array_merge(array_keys($this->columns), array($this->idColumnName));
    if (!in_array($column, $valid, true)) {
        throw new InvalidArgumentException('Invalid column');
    }

    $orderSql = '';
    if (isset($order_by)) {
        if (!in_array($order_by, $valid, true)) {
            throw new InvalidArgumentException('Invalid order_by column');
        }
        $dir = (strtoupper($sort_direction) === 'ASC') ? 'ASC' : 'DESC';
        $orderSql = " ORDER BY `$order_by` $dir";
    }

    $db->query(
        "SELECT * FROM `{$this->tableName}` WHERE `$column` = :id$orderSql LIMIT 1",
        array('id' => $id)
    );
    // ...
}
```

Because `ORDER BY` and column names cannot be bound as prepared-statement parameters, allowlisting against the known column set is the correct defense.

### Implemented change

[To be completed if/when the vendor releases a fix.]

---

## 12. Detection and indicators

Possible indicators of exploitation:

- Sort/column request parameters containing SQL keywords, parentheses, backticks, or whitespace beyond a bare identifier or `ASC`/`DESC`.
- Database errors referencing malformed `ORDER BY` clauses.
- Unusually slow lookups (possible time-based blind injection).
- Query logs showing non-identifier content in `ORDER BY` or identifier positions.

### Sample log search

```text
grep -iE "[?&](sort|order|dir|column|col)=[^&]*(select|sleep|\(|%28|`|%60| )" access.log
```

---

## 13. Disclosure timeline

| Date | Event |
|---|---|
| 2026-11-15 | Vulnerability identified during source code review |
| 2026-11-15 | Injection point validated in controlled lab |
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
- Affected file: https://github.com/tylerhall/simple-php-framework/blob/master/includes/class.dbobject.php
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- CAPEC-66: https://capec.mitre.org/data/definitions/66.html
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- OWASP — Testing for SQL Injection (ORDER BY): https://owasp.org/www-community/attacks/SQL_Injection
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
