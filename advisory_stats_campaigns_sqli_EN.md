# Security Advisory — SQL Injection in `admin/stats_campaigns.php` (`campaigns` class)

**Internal ID:** RS-ADV-2026-013
**CVE:** pending (not assigned)
**Status:** draft for disclosure

---

## 1. Executive summary

An **authenticated SQL Injection** vulnerability was identified in the campaign report of the *modified eCommerce Shopsoftware* administrative panel. The `admin/stats_campaigns.php` endpoint collects `GET` parameters and forwards them to the `campaigns` class (`admin/includes/classes/campaigns.php`), where the `campaign` and `status` values are concatenated directly into SQL statements without escaping (`xtc_db_input`) or parameterization. An authenticated administrator can inject arbitrary SQL. In the `campaign` path, the query result is reflected back on the page (campaign name), enabling data extraction via `UNION SELECT`; conditional time-based behaviour was confirmed at the database level.

---

## 2. Affected products

- **Product:** modified eCommerce Shopsoftware (xt-commerce / osCommerce base)
- **Analyzed version:** `3.3.0-r16825`
- **Components:**
  - `admin/stats_campaigns.php` (revision `$Id: stats_campaigns.php 14517 2022-06-11`)
  - `admin/includes/classes/campaigns.php` (revision `$Id: campaigns.php 15998 2024-07-02`)
- **Endpoint:** `admin/stats_campaigns.php` (`GET` method)
- **Access vector:** https://github.com/modified-shop/modified-shop

**Unaffected products/versions:** not assessed. The analysis was limited to the version above.

---

## 3. Vulnerability description

`stats_campaigns.php` collects the report parameters and packs them into `$campaign_array` without sanitization, forwarding them to the `campaigns` class:

```php
'status'   => ((isset($_GET['status'])   && $_GET['status']   != '') ? $_GET['status']   : 0),  // line 528
'campaign' => ((isset($_GET['campaign']) && $_GET['campaign'] != '') ? $_GET['campaign'] : 0),  // line 529
$campaign = new campaigns($campaign_array);                                                       // line 531
```

In the class constructor the values are assigned without treatment (lines 64-65) and used in two query points:

**Sink 1 — `campaign` parameter (string context, with output reflection):**
```php
// admin/includes/classes/campaigns.php, getSelectedCampaign(), line 206
$campaign_query = "SELECT * FROM ".TABLE_CAMPAIGNS." WHERE campaigns_refID='".$this->campaign."'";
```
Triggered when `$_GET['campaign'] != "0"` (lines 68-72). The result feeds `SelectArray`, whose `campaigns_name` field is printed on the page (`stats_campaigns.php`, line 657), enabling exfiltration via `UNION SELECT`. Note that `campaigns_refID` is a **string** column (see §7), so the injection occurs inside single quotes and the `UNION` path is viable.

**Sink 2 — `status` parameter (blind):**
```php
// getTotalSells(), lines 239-240
if ($this->status > 0)
  $status = " AND o.orders_status='".$this->status."'";
```
Same pattern repeated in `getSells()` (line 296). The `$this->status > 0` check is a loose comparison that does not sanitize the value. The result is a `count(*)` reflected as a number, characterizing a **blind** injection (boolean/time-based).

**Controls in place (not affected):** all date parameters (`startD/M/Y`, `endD/M/Y`) go through `mktime()` and `xtc_db_input(date("Y-m-d", ...))` (lines 59, 63, 226-227, 248-249, among others) and are not injectable. The use of `campaign` in `getSells()`/`getHits()`/`getLeads()` (lines 304, 316, 369, 410) is second-order, reassigned from the database inside the loop (lines 85-86), and is not a direct injection; the exploitable entry point is `getSelectedCampaign()`.

**Required conditions:** an authenticated session in the administrative panel with access to the campaign report.

---

## 4. Impact (C/I/A)

- **Confidentiality (High):** through the `campaign` parameter, `UNION SELECT` allows reading arbitrary database data (password hashes, customer PII, orders), rendered on the page as a campaign name. Blind inference via `status` is an additional channel.
- **Integrity (None):** `xtc_db_query` executes one query per call (no stacked queries in MySQLi), making direct writes unlikely in this context.
- **Availability (None):** no direct impact (time-based queries may cause localized slowness but not unavailability).

---

## 5. Classification

- **CWE:** CWE-89 — *Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')*
- **CAPEC:** CAPEC-66 — *SQL Injection*
- **CVSS v3.1 (base):** **4.9 (Medium)**
  `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N`
  - *Note:* if the report is accessible to a lower-privileged administrative role (PR:L), the vector rises to **6.5 (Medium)**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`.

---

## 6. Exploitation scenario

An authenticated operator requests the campaign report supplying, in the `campaign` parameter, a payload that closes the quote of the `WHERE campaigns_refID='...'` clause and appends a `UNION SELECT` matching the column count of the campaigns table, placing the target data in the column reflected as `campaigns_name`. The extracted value is rendered in the report table as a campaign name. Alternatively, the `status` parameter allows blind injection, inferring data from the variation of the report counters.

---

## 7. Technical evidence

- **Affected component:** `campaigns` class, methods `getSelectedCampaign()` (line 206) and `getTotalSells()`/`getSells()` (lines 240, 296)
- **Data flow:**
  - *Source:* `$_GET['campaign']`, `$_GET['status']` (`stats_campaigns.php`, lines 528-529)
  - *Forwarding:* `$campaign_array` → `new campaigns(...)` (line 531) → `$this->campaign`, `$this->status` (lines 64-65)
  - *Sink:* raw concatenation in `xtc_db_query` (lines 206, 240/250, 296/305/317)

**7.1. Column type of `campaigns_refID`**
The `campaigns` table was inspected in the lab; the reference identifier is stored as a string:
```
campaigns_refID  campaigns_name
aaa              aa
```
This confirms the injection occurs inside a single-quoted string context.

**7.2. Conditional execution confirmed at the database level**
Using a non-existent reference (`zzz`) so the initial condition is false, the following statement was executed directly against MariaDB and timed:
```sql
SELECT campaigns_id FROM campaigns
WHERE campaigns_refID = 'zzz' OR IF(1=1,SLEEP(5),0) OR 'x'='y';
```
```
real    0m5.104s
```
MariaDB evaluated the `SLEEP(5)` expression, producing the expected ~5-second delay. **Limitation:** this test was run directly against the database; it proves the SQL behaviour but not, on its own, that the payload traverses the HTTP endpoint.

**7.3. HTTP validation (pending)**
End-to-end confirmation requires sending the payload through the authenticated endpoint and comparing timings against a control request:
```
GET /admin/stats_campaigns.php?campaign=zzz'%20OR%20IF(1=1,SLEEP(5),0)%20OR%20'x'='y&report=1&startD=1&startM=10&startY=2026&endD=31&endM=10&endY=2026&status=0 HTTP/1.1
Cookie: <admin session>
```
Compare against the control `campaign=zzz`, with repeated measurements to rule out normal latency variation.

---

## 8. Proof of concept (PoC)

In an authorized lab environment:

1. Authenticate to the panel (`/admin/`).
2. **Syntax break check:** send a single quote in the `campaign` parameter and observe the change in behaviour/error of the `getSelectedCampaign()` query.
3. **Time-based confirmation (HTTP):** send the conditional payload shown in §7.3 and compare the response time against the `campaign=zzz` control, repeating measurements.
4. **Column discovery:** determine the campaigns table column count (e.g., via `ORDER BY n`) up to the valid limit.
5. **Extraction proof (UNION):** build a `UNION SELECT` with the matching column count, placing an **identifiable marker** in the position reflected as `campaigns_name`. If the marker appears in the report, data extraction is proven.
6. **Blind channel (`status`):** as an alternative control, use `status` with a boolean condition and observe the variation of the report counters.

**PoC limitations:** requires an administrative session; does not bypass authentication. The recommended proof uses a benign marker to demonstrate reflection, without mass extraction of sensitive data.

---

## 9. Reproduction steps

1. Log in to the administrative panel.
2. Access `admin/stats_campaigns.php`.
3. Supply, via `GET`, the `campaign` parameter with an injection payload (plus valid `report`/dates).
4. Observe the change in the query result reflected in the report, and/or the time delay of the time-based payload.
5. Repeat via the `status` parameter to confirm the blind channel.

---

## 10. Mitigation

- Restrict access to the statistics/report module to strictly necessary administrators.
- Monitor requests to `stats_campaigns.php` with injection characters (`'`, `UNION`, `--`, `/*`) in the `campaign` and `status` parameters.

---

## 11. Fix

Treat the externally-controlled values as data. Because `campaigns_refID` is a **string**, do **not** cast `campaign` with `(int)` (it would break legitimate lookups) — escape it with `xtc_db_input` or, preferably, use a prepared statement. The `(int)` cast is only appropriate for the numeric `status` (`orders_status_id`).

```php
// getSelectedCampaign(), line 206 — escape (string refID)
$campaign_query = "SELECT * FROM ".TABLE_CAMPAIGNS." WHERE campaigns_refID='".xtc_db_input($this->campaign)."'";

// getTotalSells()/getSells(), lines 240 and 296 — numeric status
$status = " AND o.orders_status='".(int)$this->status."'";
```

Preferred, more robust approach — parameterized query:
```php
$stmt = $pdo->prepare("SELECT * FROM campaigns WHERE campaigns_refID = :campaign");
$stmt->execute([':campaign' => $this->campaign]);
```

Additionally: validate inputs against their expected format (complementary to, never a replacement for, parameterization), review the remaining methods of the `campaigns` class that reuse externally-sourced values, and avoid returning detailed SQL errors to the end user.

---

## 12. Detection and indicators

- Search the access log for report requests with injection patterns:
  ```
  grep -iE "stats_campaigns\.php" access.log | grep -iE "union|select|'|%27|--|/\*|sleep"
  ```
- Alert on non-numeric values in the `campaign` and `status` parameters.
- Monitor SQL errors correlated with this endpoint in the database logs.

---

## 13. Disclosure timeline

| Date | Event |
|------|-------|
| 2026-11-11 | Source code identification and analysis |
| 2026-11-11 | Conditional behaviour confirmed at the database level |
| 2026-11-11 | Advisory drafting |
| _pending_ | HTTP end-to-end validation |
| _pending_ | Vendor contact |
| _pending_ | Vendor confirmation |
| _pending_ | Fix availability |
| _pending_ | Public disclosure |

---

## 14. Vendor communication

- **Intended channel:** official project repository/issues and the maintainer's contact email.
- **Status:** _pending opening._

---

## 15. Credits

- **Researcher:** Kembolle Amilkar
- **Program:** RedScan Academy — Offensive Security (CVE Report 2.0 course)

---

## 16. References

- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- CAPEC-66: https://capec.mitre.org/data/definitions/66.html
- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- NVD (product search): https://nvd.nist.gov/vuln/search?keyword=modified%20ecommerce&resultType=records
- Project: https://github.com/modified-shop/modified-shop

---

## 17. Revision history

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-11-11 | Initial version (unified: static analysis + DB-level time-based evidence) |

---

## 18. Legal notice

This advisory is for **educational and defensive** purposes. Testing was conducted in an authorized, controlled lab environment. It must not be used to access systems without explicit authorization.

---

## 19. Contact

- **Researcher:** Kembolle Amilkar / kembolle.com.br
- **Via:** RedScan Academy
