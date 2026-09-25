# Sign-in Threat Map: Workbook JSON

[← Back to README](../README.md) · [← KQL Query](query.md)

**To deploy:** in Sentinel, go to **Workbooks → Add workbook → Edit → Advanced Editor**, replace the contents with the JSON below, click **Apply**, then **Save** to your workspace. All tenant-specific IDs have been removed; the workbook runs against the workspace you save it to.

```json
{
    "version": "Notebook/1.0",
    "items": [
        {
            "type": 1,
            "content": {
                "json": "# 🚨 Sign-in Threat Map & Behavior Scoring\n\nShows every source IP in `SigninLogs` with **credential failures**, **Entra ID Protection risk**, or **VPN/proxy (anonymizer) use**, and scores each **successful** risky sign-in against that user's own history, so traveling employees on VPN are separated from likely attackers.\n\n> Benign interrupts (50140 Keep-me-signed-in, 50074/50072 MFA prompts) are not counted as failures. Geo comes from `geo_info_from_ip_address()`, falling back to Entra's `LocationDetails`."
            },
            "name": "header",
            "id": "1a2b3c4d-0001-4a00-9000-000000000001"
        },
        {
            "type": 9,
            "content": {
                "version": "KqlParameterItem/1.0",
                "parameters": [
                    {
                        "id": "tr",
                        "version": "KqlParameterItem/1.0",
                        "name": "TimeRange",
                        "label": "Time range",
                        "type": 4,
                        "isRequired": true,
                        "value": {
                            "durationMs": 2592000000
                        },
                        "typeSettings": {
                            "selectableValues": [
                                {
                                    "durationMs": 3600000
                                },
                                {
                                    "durationMs": 14400000
                                },
                                {
                                    "durationMs": 43200000
                                },
                                {
                                    "durationMs": 86400000
                                },
                                {
                                    "durationMs": 604800000
                                },
                                {
                                    "durationMs": 2592000000
                                }
                            ]
                        }
                    }
                ],
                "style": "pills"
            },
            "name": "parameters",
            "id": "1a2b3c4d-0002-4a00-9000-000000000002"
        },
        {
            "type": 1,
            "content": {
                "json": "## Sign-in threat map\n\n**Bubble size** = sign-in attempts from the IP. **Color** = highest behavior score of a risky sign-in that *succeeded* from it (green 0 = nothing got in or it matched the user's history, red 7 = strongly unlike the user). Hover a bubble for the IP, location, assessment, score, and success/failure counts."
            },
            "name": "text-map",
            "id": "1a2b3c4d-0003-4a00-9000-000000000003"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// === Sign-in threat map + behavior score ===\n// Bubble = source IP with failures, risk, or anonymizer (VPN/proxy) use.\n// Size = attempts. Color = highest behavior score of a risky sign-in that SUCCEEDED from that IP (0-7).\nlet FailureCodes = dynamic([\n    \"50126\",   // invalid username or password\n    \"50053\",   // locked out / blocked as malicious IP\n    \"50057\",   // disabled account\n    \"50055\",   // expired password\n    \"16003\", \"50020\", \"50034\"   // account doesn't exist in tenant (enumeration)\n]);\nlet Lookback    = 14d;\nlet WindowStart = todatetime('{TimeRange:start}');\n// Each user's \"normal\": successful sign-ins in the 14 days BEFORE the selected time range\nlet Baseline = SigninLogs\n    | where TimeGenerated between ((WindowStart - Lookback) .. WindowStart)\n    | where ResultType == \"0\"\n    | summarize KnownASNs      = make_set(AutonomousSystemNumber),\n                KnownCountries = make_set(tostring(LocationDetails.countryOrRegion)),\n                KnownOS        = make_set(tostring(DeviceDetail.operatingSystem))\n             by UserId;\n// Public IPs of Defender-onboarded company devices (includes their VPN exit IPs)\nlet CompanyDeviceIPs = toscalar(DeviceInfo\n    | where TimeGenerated > WindowStart - Lookback\n    | where isnotempty(PublicIP)\n    | summarize make_set(PublicIP));\nSigninLogs\n| where TimeGenerated {TimeRange}\n| where isnotempty(IPAddress)\n| extend IsSuccess    = ResultType == \"0\",\n         IsFailure    = ResultType in (FailureCodes),\n         IsAnonymized = RiskEventTypes_V2 has \"anonymizedIPAddress\"\n| extend IsRisky      = RiskLevelDuringSignIn in (\"low\", \"medium\", \"high\") or IsAnonymized\n// Compare every sign-in to the user's baseline\n| join kind=leftouter Baseline on UserId\n| extend HasBaseline   = isnotnull(KnownASNs),\n         SignInCountry = tostring(LocationDetails.countryOrRegion),\n         OS            = tostring(DeviceDetail.operatingSystem)\n| extend NewASN        = not(HasBaseline) or not(set_has_element(KnownASNs, AutonomousSystemNumber)),\n         NewCountry    = not(HasBaseline) or not(set_has_element(KnownCountries, SignInCountry)),\n         NewOS         = not(HasBaseline) or not(set_has_element(KnownOS, OS)),\n         CompanyDevice = tobool(DeviceDetail.isManaged) == true\n                      or tobool(DeviceDetail.isCompliant) == true\n                      or set_has_element(CompanyDeviceIPs, IPAddress),\n         SingleFactor  = AuthenticationRequirement == \"singleFactorAuthentication\"\n// Score only successful risky/anonymized sign-ins (failed attempts never add points)\n| extend BehaviorScore = iff(IsSuccess and IsRisky,\n                             toint(NewASN) + toint(NewCountry) + 2*toint(NewOS)\n                             + 2*toint(not(CompanyDevice)) + toint(SingleFactor),\n                             int(null))\n// Roll up per source IP (one geo lookup per IP)\n| summarize Attempts          = count(),\n            Successes         = countif(IsSuccess),\n            Failures          = countif(IsFailure),\n            RiskySignIns      = countif(IsRisky),\n            RiskySuccesses    = countif(IsRisky and IsSuccess),\n            MaliciousIPBlocks = countif(ResultType == \"50053\"),\n            AnonymizedSignIns = countif(IsAnonymized),\n            MaxBehaviorScore  = max(BehaviorScore),\n            FlaggedUsers      = make_set_if(UserPrincipalName, BehaviorScore >= 3, 10),\n            Users             = dcount(UserPrincipalName),\n            UserList          = make_set(UserPrincipalName, 10),\n            Apps              = make_set(AppDisplayName, 10),\n            FailureReasons    = make_set_if(ResultDescription, IsFailure, 5),\n            ASN               = take_any(AutonomousSystemNumber),\n            EntraCountry      = take_any(SignInCountry),\n            EntraCity         = take_any(tostring(LocationDetails.city)),\n            EntraLat          = take_any(toreal(LocationDetails.geoCoordinates.latitude)),\n            EntraLon          = take_any(toreal(LocationDetails.geoCoordinates.longitude)),\n            FirstSeen         = min(TimeGenerated),\n            LastSeen          = max(TimeGenerated)\n         by IPAddress\n| where Failures > 0 or RiskySignIns > 0\n| extend BehaviorScore = coalesce(MaxBehaviorScore, 0),\n         Assessment = case(isnull(MaxBehaviorScore),  \"No risky sign-in succeeded\",\n                           MaxBehaviorScore >= 5,     \"Likely malicious - investigate\",\n                           MaxBehaviorScore >= 3,     \"Review\",\n                                                      \"Consistent with user history\"),\n         Verdict = case(RiskySuccesses > 0,             \"1 - Risky sign-in succeeded\",\n                        Failures > 0 and Successes > 0, \"2 - Failed, then succeeded\",\n                        MaliciousIPBlocks > 0,          \"3 - Blocked as malicious IP\",\n                        Failures > 0,                   \"4 - Failed only\",\n                                                        \"5 - Risky, not successful\")\n// Geo-enrich from the IP, falling back to Entra's own location\n| extend geo = geo_info_from_ip_address(IPAddress)\n| extend Latitude  = coalesce(toreal(geo.latitude),  EntraLat),\n         Longitude = coalesce(toreal(geo.longitude), EntraLon),\n         Country   = coalesce(tostring(geo.country), EntraCountry),\n         City      = coalesce(tostring(geo.city), EntraCity)\n| where isnotempty(Latitude) and isnotempty(Longitude)\n| extend MapLabel = strcat(IPAddress, \" (\", City, \", \", Country, \") - \", Assessment,\n                           \" [score \", BehaviorScore, \"] - \", Successes, \" ok / \", Failures, \" failed\")\n| project Latitude, Longitude, MapLabel, BehaviorScore, Assessment, Verdict, Attempts,\n          Successes, Failures, RiskySignIns, AnonymizedSignIns, FlaggedUsers, Users, UserList,\n          Apps, FailureReasons, ASN, IPAddress, Country, City, FirstSeen, LastSeen\n| order by BehaviorScore desc, Verdict asc",
                "size": 0,
                "title": "Sign-in sources - size = attempts, color = behavior score of successful risky sign-ins",
                "timeContext": {
                    "durationMs": 7776000000
                },
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "map",
                "mapSettings": {
                    "locInfo": "LatLong",
                    "latitude": "Latitude",
                    "longitude": "Longitude",
                    "sizeSettings": "Attempts",
                    "sizeAggregation": "Sum",
                    "labelSettings": "MapLabel",
                    "legendMetric": "BehaviorScore",
                    "legendAggregation": "Max",
                    "itemColorSettings": {
                        "nodeColorField": "BehaviorScore",
                        "colorAggregation": "Max",
                        "type": "heatmap",
                        "heatmapPalette": "greenRed"
                    }
                }
            },
            "name": "map-signin",
            "id": "1a2b3c4d-0004-4a00-9000-000000000004"
        },
        {
            "type": 1,
            "content": {
                "json": "## How the behavior score works\n\nEach successful risky or anonymized sign-in is compared to the user's successful sign-ins in the **14 days before** the selected time range. Failed attempts never add points, so a traveler who mistyped a password is not penalized.\n\n| Signal | Points | Why |\n|---|---|---|\n| `NewASN` - internet provider not seen for this user | 1 | Travelers change networks too, so weak evidence |\n| `NewCountry` - country not seen for this user | 1 | Same: common for legitimate travel |\n| `NewOS` - operating system not seen for this user | 2 | Real employees rarely change devices |\n| Not a `CompanyDevice` - not managed/compliant and not a Defender device IP | 2 | Attackers use their own machines |\n| `SingleFactor` - signed in without MFA | 1 | Password alone is easier to steal |\n\n**5-7** Likely malicious - investigate · **3-4** Review · **0-2** Consistent with user history. Users with no sign-in history in the lookback are treated as new on network, country, and OS."
            },
            "name": "text-score",
            "id": "1a2b3c4d-0006-4a00-9000-000000000006"
        },
        {
            "type": 3,
            "content": {
                "version": "KqlItem/1.0",
                "query": "// === Behavior score detail: one row per user + IP for successful risky sign-ins ===\nlet FailureCodes = dynamic([\n    \"50126\",   // invalid username or password\n    \"50053\",   // locked out / blocked as malicious IP\n    \"50057\",   // disabled account\n    \"50055\",   // expired password\n    \"16003\", \"50020\", \"50034\"   // account doesn't exist in tenant (enumeration)\n]);\nlet Lookback    = 14d;\nlet WindowStart = todatetime('{TimeRange:start}');\n// Each user's \"normal\": successful sign-ins in the 14 days BEFORE the selected time range\nlet Baseline = SigninLogs\n    | where TimeGenerated between ((WindowStart - Lookback) .. WindowStart)\n    | where ResultType == \"0\"\n    | summarize KnownASNs      = make_set(AutonomousSystemNumber),\n                KnownCountries = make_set(tostring(LocationDetails.countryOrRegion)),\n                KnownOS        = make_set(tostring(DeviceDetail.operatingSystem))\n             by UserId;\n// Public IPs of Defender-onboarded company devices (includes their VPN exit IPs)\nlet CompanyDeviceIPs = toscalar(DeviceInfo\n    | where TimeGenerated > WindowStart - Lookback\n    | where isnotempty(PublicIP)\n    | summarize make_set(PublicIP));\nSigninLogs\n| where TimeGenerated {TimeRange}\n| where isnotempty(IPAddress)\n| extend IsSuccess    = ResultType == \"0\",\n         IsFailure    = ResultType in (FailureCodes),\n         IsAnonymized = RiskEventTypes_V2 has \"anonymizedIPAddress\"\n| extend IsRisky      = RiskLevelDuringSignIn in (\"low\", \"medium\", \"high\") or IsAnonymized\n// Compare every sign-in to the user's baseline\n| join kind=leftouter Baseline on UserId\n| extend HasBaseline   = isnotnull(KnownASNs),\n         SignInCountry = tostring(LocationDetails.countryOrRegion),\n         OS            = tostring(DeviceDetail.operatingSystem)\n| extend NewASN        = not(HasBaseline) or not(set_has_element(KnownASNs, AutonomousSystemNumber)),\n         NewCountry    = not(HasBaseline) or not(set_has_element(KnownCountries, SignInCountry)),\n         NewOS         = not(HasBaseline) or not(set_has_element(KnownOS, OS)),\n         CompanyDevice = tobool(DeviceDetail.isManaged) == true\n                      or tobool(DeviceDetail.isCompliant) == true\n                      or set_has_element(CompanyDeviceIPs, IPAddress),\n         SingleFactor  = AuthenticationRequirement == \"singleFactorAuthentication\"\n// Score only successful risky/anonymized sign-ins (failed attempts never add points)\n| extend BehaviorScore = iff(IsSuccess and IsRisky,\n                             toint(NewASN) + toint(NewCountry) + 2*toint(NewOS)\n                             + 2*toint(not(CompanyDevice)) + toint(SingleFactor),\n                             int(null))\n| where isnotnull(BehaviorScore)\n| summarize SignIns = count(), Apps = make_set(AppDisplayName, 5), LastSeen = max(TimeGenerated)\n         by UserPrincipalName, IPAddress, SignInCountry, OS,\n            NewASN, NewCountry, NewOS, CompanyDevice, SingleFactor, BehaviorScore\n| extend Assessment = case(BehaviorScore >= 5, \"Likely malicious - investigate\",\n                           BehaviorScore >= 3, \"Review\",\n                                               \"Consistent with user history\")\n| project Assessment, BehaviorScore, UserPrincipalName, IPAddress, SignInCountry, OS,\n          NewASN, NewCountry, NewOS, CompanyDevice, SingleFactor, SignIns, Apps, LastSeen\n| order by BehaviorScore desc, LastSeen desc",
                "size": 0,
                "title": "Successful risky sign-ins scored against each user's history",
                "timeContext": {
                    "durationMs": 7776000000
                },
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
                "visualization": "table",
                "gridSettings": {
                    "formatters": [
                        {
                            "columnMatch": "BehaviorScore",
                            "formatter": 8,
                            "formatOptions": {
                                "min": 0,
                                "max": 7,
                                "palette": "greenRed"
                            }
                        }
                    ]
                }
            },
            "name": "grid-score",
            "id": "1a2b3c4d-0005-4a00-9000-000000000005"
        }
    ],
    "fallbackResourceIds": [
        "/subscriptions/<subscription-id>/resourcegroups/<resource-group>/providers/microsoft.operationalinsights/workspaces/<workspace-name>"
    ],
    "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
}
```
