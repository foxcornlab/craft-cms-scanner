# `craft-cms-scanner`

Local triage for the `Craft CMS` November 2026 batch, headlined by `CVE-2026-123488`, an unauthenticated `SQL` injection that hands any visitor read and write access to the application database. Give it a `Craft` version you own, or a project directory, and it tells you whether that install is still open. It never touches the network, never probes a server, never sends a crafted request.

## `The flaw`

`CVE-2026-123488` is an unauthenticated `SQL` injection (`CWE-89`) in the element search endpoint. The `attribute` parameter is concatenated into the query unsanitized, and because `Craft` runs `PDO` with emulated prepared statements, stacked statements execute. An unauthenticated remote attacker gets read and write access to the database. The vendor advisory demonstrates the write primitive by setting the admin flag on user `ID 1` and reading it back. `Craft` short-circuits its permission checks on that single column, so no further change is needed, and the same primitive can overwrite any account's password hash. That is administrator takeover with no login step anywhere in the sequence.

The same `4.18.9` / `5.11.2` releases fix three more flaws. `CVE-2026-123489` is a blind `SQL` injection in the sandbox-exposed `getNext()` and `getPrev()` methods, which pass arbitrary criteria arrays to `Craft::configure()` without removing `SQL`-bearing properties. It needs an authenticated control panel user. `CVE-2026-123490` is a privilege escalation through `getOwners()`, which applies caller criteria without cleansing the query configuration, letting an authenticated control panel user invoke attacker-selected static `PHP` callables and promote every account to administrator. It affects `Craft 5` only, from `5.8.17`. `CVE-2026-123491` is a second unauthenticated `SQL` injection, this time in `GraphQL` eager-loading: arguments on eager-loadable nodes absent from the public schema are copied into `EagerLoadPlan` criteria without cleansing, and a parenthesized `select` argument injects `SQL` expressions to read arbitrary database content, including password hashes and session tokens.

The fix shipped on `17 September 2026` in `4.18.9` and `5.11.2`. The vendor advisory followed on `22 October`. The `CVE` records did not appear until `6 November`, seven weeks after the patch, with a public proof of concept published the same day. A patch trigger that watches only `CVE` feeds had nothing to act on for seven weeks. The flaw is not in `CISA KEV` and there is no confirmed in-the-wild exploitation as of `7 November`, but the proof of concept is public and the bug is trivially reachable, so a version check the day the `CVE` lands is worth doing.

`VulnCheck` (the `CNA`) scores `CVE-2026-123488` at `CVSS 3.1 9.8` (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) and `CVSS 4.0 9.3`. This tool uses the `3.1` score as the headline and notes where the `4.0` figure differs.

## `The traps`

| `Signal` | `Grade` | `Why` |
| --- | --- | --- |
| `Craft 5` on `5.8.16` | `VULNERABLE` | **The scope trap.** `CVE-2026-123490` only affects `5.8.17` and later, so `5.8.16` grades `NOT-AFFECTED` for that one `CVE`. The other three still apply, so the install is still `VULNERABLE`. A check that reads `5.8.17` as the fix for the whole batch wrongly clears every `5.0.0` to `5.8.16` install. |
| `Craft 4` on `4.18.9` | `PATCHED` | `4.18.9` is the fix, but it is also the final `4.x` release. `Craft 4` reached end of security support on `30 April 2026`. Patch, then plan the move to `Craft 5`: this install gets no further security fixes. |
| A `4.x` version graded against `5.11.2`, or the reverse | `UNKNOWN` | The two branches are independent lines with different fixed releases. A `4.x` install is never graded against the `5.x` fix. |
| A bare version with no patch number, for example `5.11` | `UNKNOWN` | The patch number is part of the version. Without it the install has not been cleared, only left ungraded. |
| `Craft 3`, for example `3.9.0` | `UNKNOWN` | End of life and outside the advisory table, which covers `4.x` and `5.x` only. There is no published mapping for it. Migrate to a supported line. Do not treat it as safe. |
| A `CVE`-feed-only patch trigger | Missed it for seven weeks | The fix existed from `17 September`. The `CVE` record arrived `6 November`. If your trigger is a `CVE` feed, you had nothing to act on until the proof of concept was already public. |

## `What it checks`

- `One install` (`--version 5.11.1`): graded against the whole four-`CVE` batch, with a per-`CVE` table
- `One install from its project` (`--local /var/www/craft`): reads the installed `craftcms/cms` version from `composer.lock`, no version string needed
- `A version file` (`--version-file version.txt`): first line is the version
- `A fleet, offline` (`--inventory-json sites.json`): a `JSON` list of `{label, version}` or `{label, local}` entries
- `The full table` (`--list`): both branches and their fixed releases
- `Machine output` (`--json`): the same grades as `JSON`

```sh
python3 craftcms_scanner.py --version 5.11.1
python3 craftcms_scanner.py --version 4.18.9
python3 craftcms_scanner.py --local /var/www/craft
python3 craftcms_scanner.py --inventory-json sites.json
```

```json
[
  {"label": "shop", "version": "5.11.1"},
  {"label": "blog", "local": "/var/www/blog"}
]
```

Exit codes: `0` nothing vulnerable found, `2` vulnerable finding, `1` scan error. `UNKNOWN` does not change the exit code, but it is not clean.

Find your `Craft` version in the control panel footer or under `Utilities > System Report`, or read the `craftcms/cms` package version in your project's `composer.lock`. This tool reads version strings you supply; it does not log in to a site to fetch one.

## `The table`

| `CVE` | `Score` | `Auth` | `Affected` | `Fixed in` |
| --- | --- | --- | --- | --- |
| `CVE-2026-123488` | `9.8` | Unauthenticated | `4.0.0` to `4.18.8`, `5.0.0` to `5.11.1` | `4.18.9` / `5.11.2` |
| `CVE-2026-123489` | `7.1` | Authenticated control panel user | `4.0.0` to `4.18.8`, `5.0.0` to `5.11.1` | `4.18.9` / `5.11.2` |
| `CVE-2026-123490` | `8.8` | Authenticated control panel user | `5.8.17` to `5.11.1` only | `5.11.2` |
| `CVE-2026-123491` | `8.2` | Unauthenticated | `4.0.0` to `4.18.8`, `5.0.0` to `5.11.1` | `4.18.9` / `5.11.2` |

## `What this tool does not do`

It does not test the injection. Testing it would mean sending crafted `SQL` to a live site, which is an attack, not a version check. It does not scan the network for `Craft` installs, and it does not grade an install from a banner or a login page: `Craft` version fingerprinting without authentication is unreliable, and guessing wrong in either direction is worse than refusing to grade. It does not fetch or use the public proof of concept.

## `Tests`

```sh
python3 -m unittest discover -s tests -v
```

`36` tests, all passing: version parsing, the bare-version trap, every fixed and boundary build on both branches, the `CVE-2026-123490` scope trap (`5.8.16` vs `5.8.17`), `Craft 3` and future-branch `UNKNOWN` grades, `composer.lock` detection (including the `v`-prefixed version and `packages-dev`), version-file reading, `CLI` exit codes, `JSON` output, and inventory grading.

## `Sources`

- `CVE-2026-123488` record, published `6 November 2026` (`CNA VulnCheck`): affected `4.0.0` before `4.18.9` and `5.0.0` before `5.11.2`, `CVSS 3.1 9.8` (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), `CVSS 4.0 9.3`, `CWE-89`
- Vendor advisory `GHSA-qcvp-ggx3-97r6`, published `22 October 2026`: the element search `SQL` injection, the admin-flag write primitive, the fix in `4.18.9` / `5.11.2`
- `CVE-2026-123489`, `GHSA-f6gf-r952-rxg6`: blind `SQL` injection via `getNext`/`getPrev`, `7.1` (`CVSS 4.0`, `VulnCheck`), authenticated control panel user
- `CVE-2026-123490`, `GHSA-r56r-f696-c8w9`: privilege escalation via `getOwners()`, `5.8.17` before `5.11.2`, `CWE-915`, `CVSS 3.1 8.8` from the published vector, `8.7` on `CVSS 4.0`
- `CVE-2026-123491`, `GHSA-mjj9-pjh4-r48g`: unauthenticated `SQL` injection via `GraphQL` eager-load select, `CVSS 3.1 8.2` from the published vector, `8.8` on `CVSS 4.0`, `CWE-89`
- `ThreatAft`, `7 November 2026`: fix released `17 September 2026`, `Craft 4` end of security support `30 April 2026`, public proof of concept `fixedbyreboot/CVE-2026-123488-POC` published `6 November`, no confirmed in-the-wild exploitation, not in `CISA KEV`

Three disagreements to note. First, the scores: `VulDB` scores `CVE-2026-123488` at `7.3`, well below the `CNA`'s `9.8`; this tool follows the `CNA`. `CVE-2026-123490` is `8.8` on `CVSS 3.1` (from its published vector) and `8.7` on `CVSS 4.0`; `CVE-2026-123491` is `8.2` on `CVSS 3.1` and `8.8` on `CVSS 4.0`. The `3.1` figure is the headline in each case. The `7.1` for `CVE-2026-123489` is the `CVSS 4.0` figure; its `3.1` figure was not individually confirmed. Second, the vendor advisory's summary calls the element search flaw authenticated, while its own impact text and the `CVE` record describe unauthenticated access; this tool follows the `CVE` record, and the proof of concept notes that any unauthenticated route feeding request input into an element query search is exposed. Third, the fix date: `17 September 2026` comes from the `ThreatAft` write-up; the vendor advisory itself does not pin the release date in the text this tool read.

No public detection-only scanner for this batch was found at publication time: no `nuclei` template exists for `CVE-2026-123488`, and one tracker lists `0%` detection coverage with `0` deployable rules. The only public code is the proof-of-concept repository, which is exploit code, not a scanner. No `foxcornlab` repo covered `Craft CMS` before this one.

## `Disclaimer`

Defensive triage only, for systems you own or are authorized to assess. This tool grades exposure from version strings you supply. It does not exploit anything, and it is not a substitute for the vendor update.

## `Thanks to`

- `Craft CMS` security team for the advisories and the fixed releases
- `VulnCheck` (`CNA`) for the `CVE` records and scoring
- The reporter (`GHSA` Report ID `1900`) for the element search finding

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
