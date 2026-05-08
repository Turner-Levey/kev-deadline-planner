# CISA KEV Deadline Planner

Free no-tracking browser worksheet for matching pasted CVEs against a bundled CISA Known Exploited Vulnerabilities catalog snapshot.

- Extracts CVE IDs from pasted scanner output, CSV rows, tickets, or notes.
- Matches the bundled CISA KEV catalog snapshot.
- Sorts matched entries by overdue and due-soon status.
- Flags entries marked by CISA as known ransomware campaign use.
- Exports Markdown, CSV, and ICS planning holds.

Live site: https://kev-deadline-planner.vercel.app/

Source: https://github.com/Turner-Levey/kev-deadline-planner

Preview image: https://kev-deadline-planner.vercel.app/preview.png

Project notes: https://kev-deadline-planner.vercel.app/about.html

Catalog snapshot: CISA KEV `2026.05.07`, released `2026-05-07T15:36:05.3318Z`, with 1,589 entries.

Sources:

- CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA KEV JSON feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- CISA BOD 22-01: https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities
- CISA kev-data mirror: https://github.com/cisagov/kev-data

The tool runs entirely in the browser with a bundled local catalog file. It has no signup, cookies, analytics, beacons, uploads, browser storage, or external scripts.

This is an unofficial informational worksheet. It is not CISA affiliation, legal advice, security advice, remediation advice, a scanner, a vulnerability validation service, or a guarantee that any finding applies to a specific environment. Verify current CISA catalog data, product applicability, asset exposure, and vendor remediation guidance before acting.
