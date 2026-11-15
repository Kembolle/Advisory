# Security Advisory — [VULNERABILITY CLASS] in `[affected/file.ext]`

**Internal ID:** [RS-ADV-YYYY-NNN]
**CVE:** [pending (not assigned) / CVE-YYYY-NNNNN]
**Status:** [draft for disclosure / reported / fixed]

---

## 1. Executive summary

A **[Vulnerability class]** vulnerability was identified in [the administrative panel / component] of *[product]*, in `[file]`, `[action/parameter]`. [One-line root cause: the `[param]` parameter (`$_GET['param']`) is concatenated directly into `[sink]` without `[missing control]`.] An [attacker profile: authenticated administrator / unauthenticated user] can [impact: escape the intended directory and read any file …], including [most sensitive artefact reachable]. [How it was confirmed: traversal was confirmed in the lab using an external canary file.]

---

## 2. Affected products

- **Product:** [product name] ([base/fork, if relevant])
- **Analyzed version:** `[version]`
- **Component:** `[file]` (revision `[$Id / commit / date]`)
- **Endpoint:** `[path?action=…&param=<value>]`
- **Access vector:** [authenticated administrative panel (`/admin/`) / network, unauthenticated] — [repository URL, e.g. https://github.com/owner/repo]

**Unaffected products/versions:** [not assessed. The analysis was limited to the version above.]

---

## 3. Vulnerability description

In the `[action]` action (lines [start]-[end]), the flow is:

```[language]
[minimal vulnerable code excerpt, with line numbers referenced in the text]
```

- **Source:** `[$_GET['param']]` (lines [n], [n]).
- **Sink:** `[dangerous_call(BASE . $_GET['param'])]` on line [n], with the content returned to the client via `[echo/readfile]` (line [n]).
- **Missing sanitization:** [no `basename()`, `realpath()`, or `../` blocking. The final path is a plain concatenation of the base directory with user input, allowing navigation outside `[BASE]` via `../` sequences.]
- **Only restriction:** [the extension / filter that exists and why it does NOT prevent the attack (e.g. an extension check does not prevent CWE-22).]
- **Relevant observation:** [e.g. the `[otherAction]` action DOES validate `..`, but this action does not — inconsistent control within the same file.]
- **Null byte:** [`%00` does not truncate the string in PHP ≥ 5.3.4; not a valid vector here.]

**Required conditions:** [an authenticated session in the administrative panel with access to the [module].]

---

## 4. Impact (C/I/A)

- **Confidentiality ([None | Low | High]):** [reading of any `[.ext]` file accessible to the web process, including [sensitive artefacts].]
- **Integrity ([None | Low | High]):** [the vulnerability only reads files / what can be modified.]
- **Availability ([None | Low | High]):** [no direct impact / what can be disrupted.]

[Paragraph: what the extension/other restriction limits, and what remains most sensitive within reach of this endpoint.]

---

## 5. Classification

- **CWE:** [CWE-XXX — Name]; additional: [CWE-YYY — Name]
- **CAPEC:** [CAPEC-XXX — Name]
- **CVSS v3.1 (base):** **[score] ([None | Low | Medium | High | Critical])**
  `[CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_]`
  - *Note:* [alternative scenario that changes the score, e.g. if the module is reachable at a lower privilege (PR:L), the vector rises to [score]: `[vector]`.]

---

## 6. Exploitation scenario

[A realistic narrative: an authenticated operator (or lower-privileged account) requests the endpoint supplying [a path with directory traversal pointing to a `[.ext]` file outside the base directory]. The content is returned in full in the response body, resulting in [sensitive information disclosure].]

---

## 7. Technical evidence

- **Affected component:** `[file]`, `[action]` action (lines [start]-[end])
- **Data flow:**
  - *Source:* `[$_GET['param']]`
  - *Missing sanitization:* [no `basename()`/`realpath()`/`..` blocking; the only filter is [the extension]]
  - *Sink:* `[call(BASE . $_GET['param'])]` → `[read]` → `[echo]`

**7.1. [Confirmed evidence title — e.g. Confirmed path traversal (external canary)]**
[A controlled canary file was placed outside the configured base directory:]
```
[canary-filename.ext]
```
[The following request was issued through the authenticated endpoint:]
```http
[GET /path?action=…&param=../canary-filename.ext HTTP/1.1]
Cookie: <session>
```
[The endpoint successfully returned the canary located outside the intended directory, confirming the application does not enforce path containment.]

**7.2. [Additional evidence title] ([confirmed | pending individual validation])**
[A request targeting [a real sensitive file] was prepared:]
```http
[GET /path?action=…&param=../../target.ext HTTP/1.1]
Cookie: <session>
```
[State explicitly what was and was NOT demonstrated: the traversal mechanism is confirmed (§7.1); successful retrieval of this specific file must be recorded separately.]

---

## 8. Proof of concept (PoC)

In an authorized lab environment:

1. [Authenticate to the panel (`/admin/`).]
2. [Place a canary file with a permitted [extension] one level above the base directory.]
3. [Request `[path?action=…&param=../canary.ext]`.]
4. **Verification:** [the download returns the content of the file outside the base directory, confirming traversal. For real-impact evidence, demonstrate retrieval of a legitimate `[.ext]` file outside `[BASE]`.]

**PoC limitations:** [restricted to files ending in `[.ext]`; requires an administrative session; does not bypass authentication.]

---

## 9. Reproduction steps

1. [Log in to the administrative panel.]
2. [Access the [module].]
3. [Invoke the `[action]` action with `[param]` containing directory traversal to a target file with a permitted extension.]
4. [Observe the returned file content in the response.]

---

## 10. Mitigation

- [Restrict access to the [module] to strictly necessary administrators.]
- [As an emergency measure, apply the same `..` check already present in the `[otherAction]` action to this action.]
- [Monitor requests to `[endpoint]` containing `../` or absolute paths.]
- [Store sensitive files outside the publicly accessible web root whenever possible.]

---

## 11. Fix

[Validate that the requested file resides within `[BASE]` before opening it, for example:]

```[language]
[$baseDir       = realpath(BASE);]
[$requestedFile = realpath(BASE . $_GET['param']);]
[
if ($baseDir === false || $requestedFile === false
    || !str_starts_with($requestedFile, $baseDir . DIRECTORY_SEPARATOR)
    || !is_file($requestedFile)) {
    // refuse
}
]
```

Complementary measures: [use `basename()` to discard any directory component and validate the name against an allow-list of files the application actually generated, rather than relying on the extension alone.]

---

## 12. Detection and indicators

- [Search the access log for requests with traversal:]
  ```
  [grep -iE "endpoint.*action=download" access.log | grep -E "\.\./|%2e%2e"]
  ```
- [Alert on `[param]` values containing `../`, `%2e%2e`, or absolute paths.]

---

## 13. Disclosure timeline

| Date | Event |
|------|-------|
| [YYYY-MM-DD] | Source code identification and analysis |
| [YYYY-MM-DD] | [Vulnerability] confirmed [with external canary] |
| [YYYY-MM-DD] | Advisory drafting |
| _pending_ | Vendor contact |
| _pending_ | Vendor confirmation |
| _pending_ | Fix availability |
| _pending_ | Public disclosure |

---

## 14. Vendor communication

- **Intended channel:** [official project forum/repository/issues and the maintainer's contact email (the project publishes no security.txt or dedicated security contact).]
- **Status:** [pending opening.]

> Additional observations in the same file, to be assessed separately:
> - [related finding 1 (action, line, short description)]
> - [related finding 2]

---

## 15. Credits

The vulnerability was identified and reported by:

- **Researcher:** Kembolle Amilkar
- **Contact:** contato@kembolle.com.br
- **Profile:** https://github.com/Kembolle

---

## 16. References

- CWE-XXX: https://cwe.mitre.org/data/definitions/[XXX].html
- CWE-YYY: https://cwe.mitre.org/data/definitions/[YYY].html
- CAPEC-XXX: https://capec.mitre.org/data/definitions/[XXX].html
- [Relevant language/function documentation]
- CVSS v3.1 calculator: https://www.first.org/cvss/calculator/3.1
- NVD (product search): https://nvd.nist.gov/vuln/search?keyword=[product]&resultType=records
- Project: [project URL]

---

## 17. Revision history

| Version | Date | Change |
|---------|------|--------|
| 1.0 | [YYYY-MM-DD] | Initial version ([unified: static analysis + evidence]) |

---

## 18. Legal notice

This advisory is for **educational and defensive** purposes. Testing was conducted in an authorized, controlled lab environment. It must not be used to access systems without explicit authorization.

---

## 19. Contact

- **Researcher:** Kembolle Amilkar / kembolle.com.br
