# Security Advisory — Stored XSS in `admin/geo_zones.php`

**Internal ID:** RS-ADV-2026-011
**CVE:** pending (not assigned)
**Status:** draft for disclosure

---

## 1. Executive summary

A **Stored Cross-Site Scripting (Stored XSS)** vulnerability was identified in the administrative panel of *modified eCommerce Shopsoftware*, in the file `admin/geo_zones.php`. The **name** and **description** fields of a *geo zone* are persisted without HTML encoding and later rendered across several panel screens without output encoding. An authenticated administrative user can store HTML/JavaScript that will execute in the browser of any operator who views the zone listing, detail view, edit form, or deletion confirmation. The impact is script execution in the context of the administrative panel.

---

## 2. Affected products

- **Product:** modified eCommerce Shopsoftware (xt-commerce / osCommerce base)
- **Analyzed version:** `3.3.0-r16825`
- **Component:** `admin/geo_zones.php`
- **Access vector:** authenticated administrative panel (`/admin/`)

**Unaffected products/versions:** not assessed. The analysis was limited to the version above; earlier versions sharing the same output flow are likely affected as well but were not verified.

---

## 3. Vulnerability description

The `geo_zone_name` and `geo_zone_description` parameters are received via `POST` and processed by `xtc_db_prepare_input()`, which only performs `trim()` + `stripslashes()` — there is **no** HTML entity encoding:

- `insert_zone`: lines **89-90**
- `save_zone`: lines **125-126**

```php
$geo_zone_name        = xtc_db_prepare_input($_POST['geo_zone_name']);
$geo_zone_description = xtc_db_prepare_input($_POST['geo_zone_description']);
```

The values are persisted via `xtc_db_perform()` (lines **110-117** and **146-153**). This path applies **SQL** escaping (`xtc_db_input`), which prevents SQL injection but does not neutralize the content for an HTML context — the characters `<`, `>`, and `"` remain intact in the database.

On output, none of the points below apply `htmlspecialchars()` / `xtc_output_string()`. The intermediate function `parse_multi_language_value()` only decodes the multi-language format and returns the raw text:

| Line | Output context | Field |
|------|----------------|-------|
| 315 | Zone listing (HTML body, `<span>`) | `geo_zone_name` |
| 434 | infoBox heading (HTML body, `<b>`) | `geo_zone_name` |
| 428 | Deletion confirmation (HTML body, `<b>`) | `geo_zone_name` |
| 442 | Description in infoBox (HTML body) | `geo_zone_description` |
| 411 | Edit form (`value="..."` attribute) | `geo_zone_name` |
| 414 | Edit form (`value="..."` attribute) | `geo_zone_description` |

There are therefore two distinct contexts: **HTML body** (315, 428, 434, 442) and **HTML attribute** (411, 414, via `xtc_draw_input_field()`, which does not escape quotes).

**Required conditions:** an authenticated session in the administrative panel with permission to access the geo zones module.

---

## 4. Impact (C/I/A)

- **Confidentiality (Low):** a script executed in the panel context can read data displayed in the operator's session and content reachable via the DOM.
- **Integrity (Low):** the script can trigger administrative actions in the victim's browser (create/modify records), limited to the operator's privileges.
- **Availability (None):** no direct availability impact.

Persistence increases the risk: the payload fires automatically for any operator who opens the affected screens, with no interaction beyond normal viewing.

---

## 5. Classification

- **CWE:** CWE-79 — *Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)*
- **CAPEC:** CAPEC-592 — *Stored XSS*
- **CVSS v3.1 (base):** **4.8 (Medium)**
  `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`
  - *Note:* if the module is accessible to a lower-privileged administrative role (PR:L), the vector rises to **5.4 (Medium)**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`.

---

## 6. Exploitation scenario

An operator with backend access (or a compromised/lower-privileged account with access to the module) creates or edits a geo zone by inserting malicious markup in the name or description. The content is stored. When a higher-privileged administrator opens the zone listing, the detail view, the edit form, or the deletion confirmation, the script executes in the panel context — allowing, for example, use of the administrator's session/CSRF token to perform actions on their behalf.

---

## 7. Technical evidence

- **Affected component:** `admin/geo_zones.php` (version `3.3.0-r16825`)
- **Data flow:**
  - *Source:* `$_POST['geo_zone_name']`, `$_POST['geo_zone_description']` (lines 89-90 / 125-126)
  - *Missing sanitization:* `xtc_db_prepare_input()` does not HTML-encode; `xtc_db_perform()` escapes for SQL only
  - *Sinks:* lines 315, 411, 414, 428, 434, 442 (no `htmlspecialchars`/`xtc_output_string`)
- **Sample request (structure):**
  ```
  POST /admin/geo_zones.php?action=insert_zone HTTP/1.1
  Cookie: <admin session>
  Content-Type: application/x-www-form-urlencoded

  geo_zone_name[EN]=<test markup>&geo_zone_description[EN]=<test markup>
  ```
- **Observed result:** the submitted markup is returned literally in the HTML of the listed screens (not as `&lt;...&gt;`), confirming the absence of output encoding.

---

## 8. Proof of concept (PoC)

In an authorized lab environment:

1. Authenticate to the panel (`/admin/`).
2. In geo zones, create/edit a zone and insert, **one field at a time**, benign test HTML content (a simple tag that only triggers a verification `alert()`, with no exfiltration).
3. Save and open the listing (line 315), the detail view (434/442), the edit form (411/414), and the deletion confirmation (428).

**Verification:** if the browser renders/executes the markup instead of displaying it as text, the vulnerability is confirmed. Inspect in DevTools → **Elements** that the value was output without escaping, and in **Network** the `POST` request with the real `action` and parameters.

**PoC limitations:** restricted to an authenticated admin; it does not bypass authentication. The PoC described is verification-only (benign alert), with no real-impact payload.

---

## 9. Reproduction steps

1. Log in to `/admin/geo_zones.php`.
2. `Insert` → fill name/description with test markup → save.
3. Open the zone listing and select the created zone.
4. Observe script execution on the listing, detail, edit, and deletion screens.
5. Confirm in DevTools the absence of output encoding.

---

## 10. Mitigation

- Restrict access to the geo zones module to strictly necessary operators.
- Apply a Content-Security-Policy (CSP) in the panel that limits inline script execution, reducing impact until the definitive fix is applied.
- Review existing geo zone records for stored markup.

---

## 11. Fix

Apply **output encoding** at all sinks, keeping the data intact in the database. Example:

```php
echo htmlspecialchars(
  parse_multi_language_value($zones['geo_zone_name'], $_SESSION['language_code']),
  ENT_QUOTES, 'UTF-8'
);
```

Or use the native `xtc_output_string()` helper with quote handling at:

- HTML body: lines **315, 428, 434, 442**
- `value="..."` attribute: lines **411, 414** (ensure double-quote escaping)

Encoding must occur on **output**, not on input, to avoid corrupting legitimate data or the multi-language format (`CODE::value||CODE::value`).

---

## 12. Detection and indicators

- Search the geo zone tables for values containing `<`, `>`, `script`, `onerror`, `onload`, `javascript:`.
- Example access-log search (adjust to the environment):
  ```
  grep -iE "geo_zones\.php.*(action=insert_zone|action=save_zone)" access.log
  ```
- Monitor geo zone creations/edits outside the expected operational window.

---

## 13. Disclosure timeline

| Date | Event |
|------|-------|
| 2026-11-10 | Source code identification and analysis |
| 2026-11-10 | Advisory drafting |
| _pending_ | Vendor contact |
| _pending_ | Vendor confirmation |
| _pending_ | Fix availability |
| _pending_ | Public disclosure |

---

## 14. Vendor communication

- **Intended channel:** official project repository/issues and the maintainer's contact email.
- **Status:** _pending opening._

> Note: the `insert`/`save`/`delete` handler (lines 41-166) shows no visible anti-CSRF token validation (CWE-352), which eases planting the payload via a forged request. Confirm with the vendor whether global CSRF protection exists via `xtc_draw_form()` before treating this as an independent finding.

---

## 15. Credits

- **Researcher:** Kembolle Amilkar
- **Program:** RedScan Academy — Offensive Security (CVE Report 2.0 course)

---

## 16. References

- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- CWE-352: https://cwe.mitre.org/data/definitions/352.html
- CAPEC-592: https://capec.mitre.org/data/definitions/592.html
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- NVD (product search): https://nvd.nist.gov/vuln/search?keyword=modified%20ecommerce&resultType=records
- Project: https://github.com/modified-shop/modified-shop

---

## 17. Revision history

| Version | Date | Change |
|---------|------|--------|
| 1.0 | 2026-11-10 | Initial version |

---

## 18. Legal notice

This advisory is for **educational and defensive** purposes. Testing was conducted in an authorized, controlled lab environment. It must not be used to access systems without explicit authorization.

---

## 19. Contact

- **Researcher:** Kembolle Amilkar / kembolle.com.br
- **Via:** RedScan Academy
