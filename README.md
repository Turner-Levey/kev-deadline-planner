# CISA KEV / BOD 22-01 Deadline Planner

Free no-tracking browser worksheet for matching pasted CVEs against a bundled CISA Known Exploited Vulnerabilities catalog snapshot and planning BOD 22-01 remediation due dates.

- Extracts CVE IDs from pasted scanner output, CSV rows, tickets, or notes.
- Matches the bundled CISA KEV catalog snapshot.
- Sorts matched entries by overdue and due-soon status.
- Flags entries marked by CISA as known ransomware campaign use.
- Reports pasted CVEs that are absent from the bundled KEV snapshot instead of performing general CVE lookup.
- Exports Markdown, CSV, and ICS planning holds.
- Includes BOD 22-01 caveats so teams verify applicability, exposure, and vendor remediation guidance before treating a due date as a compliance obligation.

Live site: https://kev-deadline-planner.vercel.app/

Source: https://github.com/Turner-Levey/kev-deadline-planner

Preview image: https://kev-deadline-planner.vercel.app/preview.png

![CISA KEV / BOD 22-01 Deadline Planner preview](https://kev-deadline-planner.vercel.app/preview.png)

Project notes: https://kev-deadline-planner.vercel.app/about.html

h4cker threat-intelligence tools listing: https://github.com/The-Art-of-Hacking/h4cker/blob/master/cybersecurity-domains/defensive-security/threat-intelligence/tools.md

Tiny Tool Town listing: https://www.tinytooltown.com/tools/cisa-kev-deadline-planner/

Awesome Compliance listing: https://github.com/theopenlane/awesome-compliance#open-source-platforms

No-Login Tools listing (pending review): https://nologin.tools/tool/kev-deadline-planner-vercel-app/

No-Login Tools badge (pending verification): https://nologin.tools/badge/kev-deadline-planner-vercel-app/

Catalog snapshot: CISA KEV `2026.05.14`, released `2026-05-14T16:47:45.3703Z`, with 1,591 entries.

Latest snapshot addition: `CVE-2026-20182` for Cisco Catalyst SD-WAN, due `2026-05-17`.

Sources:

- CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA KEV JSON feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- CISA BOD 22-01: https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities
- CISA kev-data mirror: https://github.com/cisagov/kev-data

The tool runs entirely in the browser with a bundled local catalog file. It has no signup, cookies, analytics, beacons, uploads, browser storage, or external scripts. CVEs absent from the bundled KEV snapshot are reported as not found rather than checked against general CVE, NVD, scanner, exploit, or vendor databases.

This is an unofficial informational worksheet. It is not CISA affiliation, legal advice, security advice, remediation advice, BOD 22-01 compliance advice, a scanner, a vulnerability validation service, or a guarantee that any finding applies to a specific environment. Verify current CISA catalog data, BOD 22-01 applicability, product applicability, asset exposure, and vendor remediation guidance before acting.
