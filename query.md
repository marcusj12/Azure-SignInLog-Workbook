# Sign-in Threat Map: KQL Query

[← Back to README](../README.md) · [Workbook JSON →](workbook.md)

The combined map query: rolls up `SigninLogs` per source IP, scores successful risky sign-ins against each user's 14-day baseline, and geo-enriches each IP.

**To run it in the Logs blade**, replace:

- `todatetime('{TimeRange:start}')` → `ago(1d)`
- `where TimeGenerated {TimeRange}` → `where TimeGenerated > ago(1d)`

```kusto
// Workbook query: {TimeRange} and {TimeRange:start} are workbook parameters.
// To test in the Logs blade, replace  todatetime('{TimeRange:start}')  with  ago(1d)
// and  where TimeGenerated {TimeRange}  with  where TimeGenerated > ago(1d)
// === Sign-in threat map + behavior score ===
// Bubble = source IP with failures, risk, or anonymizer (VPN/proxy) use.
// Size = attempts. Color = highest behavior score of a risky sign-in that SUCCEEDED from that IP (0-7).
let FailureCodes = dynamic([
    "50126",   // invalid username or password
    "50053",   // locked out / blocked as malicious IP
    "50057",   // disabled account
    "50055",   // expired password
    "16003", "50020", "50034"   // account doesn't exist in tenant (enumeration)
]);
let Lookback    = 14d;
let WindowStart = todatetime('{TimeRange:start}');
// Each user's "normal": successful sign-ins in the 14 days BEFORE the selected time range
let Baseline = SigninLogs
    | where TimeGenerated between ((WindowStart - Lookback) .. WindowStart)
    | where ResultType == "0"
    | summarize KnownASNs      = make_set(AutonomousSystemNumber),
                KnownCountries = make_set(tostring(LocationDetails.countryOrRegion)),
                KnownOS        = make_set(tostring(DeviceDetail.operatingSystem))
             by UserId;
// Public IPs of Defender-onboarded company devices (includes their VPN exit IPs)
let CompanyDeviceIPs = toscalar(DeviceInfo
    | where TimeGenerated > WindowStart - Lookback
    | where isnotempty(PublicIP)
    | summarize make_set(PublicIP));
SigninLogs
| where TimeGenerated {TimeRange}
| where isnotempty(IPAddress)
| extend IsSuccess    = ResultType == "0",
         IsFailure    = ResultType in (FailureCodes),
         IsAnonymized = RiskEventTypes_V2 has "anonymizedIPAddress"
| extend IsRisky      = RiskLevelDuringSignIn in ("low", "medium", "high") or IsAnonymized
// Compare every sign-in to the user's baseline
| join kind=leftouter Baseline on UserId
| extend HasBaseline   = isnotnull(KnownASNs),
         SignInCountry = tostring(LocationDetails.countryOrRegion),
         OS            = tostring(DeviceDetail.operatingSystem)
| extend NewASN        = not(HasBaseline) or not(set_has_element(KnownASNs, AutonomousSystemNumber)),
         NewCountry    = not(HasBaseline) or not(set_has_element(KnownCountries, SignInCountry)),
         NewOS         = not(HasBaseline) or not(set_has_element(KnownOS, OS)),
         CompanyDevice = tobool(DeviceDetail.isManaged) == true
                      or tobool(DeviceDetail.isCompliant) == true
                      or set_has_element(CompanyDeviceIPs, IPAddress),
         SingleFactor  = AuthenticationRequirement == "singleFactorAuthentication"
// Score only successful risky/anonymized sign-ins (failed attempts never add points)
| extend BehaviorScore = iff(IsSuccess and IsRisky,
                             toint(NewASN) + toint(NewCountry) + 2*toint(NewOS)
                             + 2*toint(not(CompanyDevice)) + toint(SingleFactor),
                             int(null))
// Roll up per source IP (one geo lookup per IP)
| summarize Attempts          = count(),
            Successes         = countif(IsSuccess),
            Failures          = countif(IsFailure),
            RiskySignIns      = countif(IsRisky),
            RiskySuccesses    = countif(IsRisky and IsSuccess),
            MaliciousIPBlocks = countif(ResultType == "50053"),
            AnonymizedSignIns = countif(IsAnonymized),
            MaxBehaviorScore  = max(BehaviorScore),
            FlaggedUsers      = make_set_if(UserPrincipalName, BehaviorScore >= 3, 10),
            Users             = dcount(UserPrincipalName),
            UserList          = make_set(UserPrincipalName, 10),
            Apps              = make_set(AppDisplayName, 10),
            FailureReasons    = make_set_if(ResultDescription, IsFailure, 5),
            ASN               = take_any(AutonomousSystemNumber),
            EntraCountry      = take_any(SignInCountry),
            EntraCity         = take_any(tostring(LocationDetails.city)),
            EntraLat          = take_any(toreal(LocationDetails.geoCoordinates.latitude)),
            EntraLon          = take_any(toreal(LocationDetails.geoCoordinates.longitude)),
            FirstSeen         = min(TimeGenerated),
            LastSeen          = max(TimeGenerated)
         by IPAddress
| where Failures > 0 or RiskySignIns > 0
| extend BehaviorScore = coalesce(MaxBehaviorScore, 0),
         Assessment = case(isnull(MaxBehaviorScore),  "No risky sign-in succeeded",
                           MaxBehaviorScore >= 5,     "Likely malicious - investigate",
                           MaxBehaviorScore >= 3,     "Review",
                                                      "Consistent with user history"),
         Verdict = case(RiskySuccesses > 0,             "1 - Risky sign-in succeeded",
                        Failures > 0 and Successes > 0, "2 - Failed, then succeeded",
                        MaliciousIPBlocks > 0,          "3 - Blocked as malicious IP",
                        Failures > 0,                   "4 - Failed only",
                                                        "5 - Risky, not successful")
// Geo-enrich from the IP, falling back to Entra's own location
| extend geo = geo_info_from_ip_address(IPAddress)
| extend Latitude  = coalesce(toreal(geo.latitude),  EntraLat),
         Longitude = coalesce(toreal(geo.longitude), EntraLon),
         Country   = coalesce(tostring(geo.country), EntraCountry),
         City      = coalesce(tostring(geo.city), EntraCity)
| where isnotempty(Latitude) and isnotempty(Longitude)
| extend MapLabel = strcat(IPAddress, " (", City, ", ", Country, ") - ", Assessment,
                           " [score ", BehaviorScore, "] - ", Successes, " ok / ", Failures, " failed")
| project Latitude, Longitude, MapLabel, BehaviorScore, Assessment, Verdict, Attempts,
          Successes, Failures, RiskySignIns, AnonymizedSignIns, FlaggedUsers, Users, UserList,
          Apps, FailureReasons, ASN, IPAddress, Country, City, FirstSeen, LastSeen
| order by BehaviorScore desc, Verdict asc
```
