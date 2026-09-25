
# Sentinel Sign-in Threat Map & Behavior Scoring

A Microsoft Sentinel workbook that maps risky, failed, and anonymized (VPN / proxy / Tor) sign-ins on a geo map, then scores every **successful** risky sign-in against that user's own history, to separate a traveling employee on a VPN from an attacker using stolen credentials.

### GEO Map of Anonymized IP Address:
<img width="1455" height="767" alt="Anonymized IP Address" src="https://github.com/user-attachments/assets/443fb48a-efdf-4607-9e3a-49fa95542d81" />

### Exploring the bubble for more Data:
<img width="1411" height="442" alt="Map_View_Detailed Data" src="https://github.com/user-attachments/assets/50714e88-7f89-4e3a-ad55-f6dfa49e8933" />

### Threat Scoring Table:
<img width="1437" height="392" alt="MoreData" src="https://github.com/user-attachments/assets/3d6f2209-56d6-464e-8f05-0a27e1f1fb6b" />

### More Table Data:
<img width="1444" height="702" alt="ThreatScoringData" src="https://github.com/user-attachments/assets/8d4463d0-62de-46a9-bfc3-3cdb8d60bd0c" />

---

## Why I built this

I was working in my Sentinel lab and decided to build a workbook that monitors **anonymized IP addresses**: sign-ins coming through proxies or VPNs. Plotting them on a map was the easy part. The harder question came right after:

> If a sign-in came through a VPN, what about the people who legitimately travel or work remotely on one? And what if they mistyped their password once or twice?

Flagging every VPN sign-in would bury real attacks under false positives. The project became about answering: **"Is this login consistent with how this user normally works?"**

---

## How it evolved: concerns and solutions

I used AI (Claude) as a brainstorming and drafting partner. I brought the use case, sample data, and requirements; the AI suggested approaches and draft KQL; I tested everything in my workspace, pushed back when solutions were more complex than needed, and refined the query over several rounds. The table below is the actual path the project took.

| # | Concern | Solution |
|---|---|---|
| 1 | I wanted a geo map of where sign-in threats come from, modeled on an existing network-flow TI map. | Roll up `SigninLogs` per source IP, then geo-enrich with `geo_info_from_ip_address()`. Fall back to Entra's own `LocationDetails` coordinates when the IP can't be placed, instead of dropping the row. |
| 2 | Many "failures" in the logs aren't attacks. The most common non-zero code in my sample was 50140 ("Keep me signed in" prompt), plus MFA prompts. | Use an explicit list of attack-relevant failure codes (bad password, lockout, disabled or non-existent account) instead of "anything not 0". |
| 3 | I needed a simple way to identify VPN / proxy sign-ins. The first ideas pulled in external VPN lists and ASN watchlists, which was more than I needed. | Use Entra ID Protection's built-in `anonymizedIPAddress` risk detection, which is already in `SigninLogs`. Nothing external to maintain. |
| 4 | My first attempt to add the anonymizer column to the map query failed. | The column was dropped by the final `project` statement before the `order by`. Lesson learned: check every step of the pipeline, and verify before shipping. |
| 5 | **Travelers and remote workers on a VPN who fumble a password would look like attackers.** | Build a 14-day per-user baseline (networks, countries, operating systems) and score only *successful* risky sign-ins against it. Failed attempts never add points. Device signals are weighted higher than location, because real employees change locations far more often than devices. |
| 6 | A login that succeeds is where it matters. How do I tell whether it came from a company machine? | Check Entra's managed/compliant device flags, and match the sign-in IP against Defender for Endpoint's `DeviceInfo.PublicIP` (which includes company laptops' VPN exit IPs). |
| 7 | The scoring logic was beyond my KQL experience at first. | Broke it down section by section until I understood every line, and documented the scoring in the workbook itself so any analyst can read it. |
| 8 | The map and the scoring started as two separate queries. | Combined them: each map bubble now carries the highest behavior score of any risky sign-in that succeeded from that IP, and a companion grid shows the per-user breakdown. |

---

## How the behavior score works

Each successful risky or anonymized sign-in is compared with the user's successful sign-ins in the **14 days before** the selected time range.

| Signal | Points | Why |
|---|---|---|
| `NewASN`: internet provider not seen for this user | 1 | Travelers change networks too, so it's weak evidence |
| `NewCountry`: country not seen for this user | 1 | Common for legitimate travel |
| `NewOS`: operating system not seen for this user | 2 | Real employees rarely change devices |
| Not a `CompanyDevice`: not managed/compliant, not a Defender device IP | 2 | Attackers use their own machines |
| `SingleFactor`: signed in without MFA | 1 | A password alone is easier to steal |

| Score | Assessment |
|---|---|
| 5 to 7 | Likely malicious: investigate |
| 3 to 4 | Review |
| 0 to 2 | Consistent with user history |

**Example:** an employee traveling abroad on their company laptop with MFA scores about **2** (new network and new country). An attacker using stolen credentials from their own PC typically scores **6 or 7**.

---

## What's in the workbook

1. **Threat map.** One bubble per source IP. Size = sign-in attempts; color = behavior score (green to red). Hover labels show IP, location, assessment, score, and success/failure counts.
2. **Scoring explainer.** A plain-language table of what each point means.
3. **Behavior detail grid.** One row per user and IP for successful risky sign-ins, showing exactly which checks triggered.

Each IP also gets a **Verdict**: *Risky sign-in succeeded*, *Failed then succeeded*, *Blocked as malicious IP*, *Failed only*, or *Risky, not successful*.

---

## Repository contents

**View online:** [KQL query](https://github.com/marcusj12/Azure-SignInLog-Workbook/blob/main/query.md) · [Workbook JSON](https://github.com/marcusj12/Azure-SignInLog-Workbook/blob/main/workbook.md)

```
├── docs/query.md                              # Query page
├── docs/workbook.md                           # Workbook JSON page
├── workbook/SignIn-Threat-Map-Workbook.json   # Import into Sentinel
├── queries/signin-threat-map.kql              # Map query (IP rollup + geo + score)
├── queries/behavior-score-detail.kql          # Per-user score breakdown
└── images/                                    # Screenshots
```

---

## Prerequisites

- Microsoft Sentinel with the **Microsoft Entra ID** data connector sending `SigninLogs`
- **Entra ID P2** (ID Protection) for `RiskLevelDuringSignIn` and `RiskEventTypes_V2`
- **Microsoft Defender for Endpoint** data in the workspace for `DeviceInfo`. If you don't have it, remove the `CompanyDeviceIPs` block and its `set_has_element` line; the Entra managed/compliant checks still work.
- At least 44 days of log retention (30-day view + 14-day baseline)

## Deploy

1. In Sentinel, go to **Workbooks → Add workbook → Edit → Advanced Editor**.
2. Paste the contents of `workbook/SignIn-Threat-Map-Workbook.json` and click **Apply**.
3. Click **Save** and choose your workspace.

The query widgets use a fixed 90-day data window on purpose. The queries still filter to the selected time range, but the baseline needs to see the 14 days before it.

## Test the queries in Logs

The `.kql` files use workbook parameters. To run them in the Logs blade, replace:

- `todatetime('{TimeRange:start}')` → `ago(1d)`
- `where TimeGenerated {TimeRange}` → `where TimeGenerated > ago(1d)`

---

## Known limitations

- **Shared VPN IPs.** The company-device check matches any Defender device's public IP. Commercial VPN exit IPs are shared by many people, so an attacker on the same VPN server as an employee can receive the "company device" credit and drop from *Likely malicious* to *Review*. Treat *Review* on anonymized IPs as worth a look.
- **New users** have no baseline, so they score as new on network, country, and OS.
- **Lab-tested.** Built and validated in a lab workspace, not at enterprise scale. For large tenants, consider limiting the baseline join to successful risky sign-ins only.
- **Map aggregation.** Bubble color and legend use **Max** aggregation so co-located IPs show the highest score. If your workbook renders colors incorrectly, switch both to **Sum** in the map settings.

## Next steps

- Pivot from high-scoring users to post-login endpoint activity in Defender for Endpoint: suspicious PowerShell in `DeviceProcessEvents`, and PowerShell outbound connections (`RemoteIP` / `RemotePort`) in `DeviceNetworkEvents`.
- Tie the company-device match to the specific user rather than any device.
- Correlate high-scoring sign-ins with follow-on changes in `AuditLogs` (role assignments, MFA method changes) and `AzureActivity`.

---

## A note on using AI

AI was a tool in this project, not the author of it. I used it to brainstorm approaches, draft KQL, and explain logic I hadn't worked with before. I defined the problem, raised the traveler/VPN false-positive concern that shaped the design, rejected over-engineered suggestions in favor of simpler ones, tested every version in my lab, and made sure I could explain each line before publishing.
