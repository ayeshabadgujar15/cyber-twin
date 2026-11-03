# IntelBase and Epieos: technical research for Cyber Twin

Research date: 8 October 2026. This report distinguishes vendor documentation,
readable open-source implementation, historical reports, and inference. It is
not a claim to have obtained either vendor's private backend or tested their paid
results. No personal targets were queried, accounts created, or controls bypassed.

## Findings that change our implementation decisions

These products combine several collectors rather than retrieve a universal
digital history. A registration check can establish account existence without
finding its profile. A public profile can disclose a date without disclosing a
login. A coordinate can identify a reviewed place without locating a device.
Our own system must preserve those distinctions rather than flatten them into
one unqualified "last seen" or "GPS" field.

The strongest new code-level finding is that the inspected GHunt master has
disabled sections that old tutorials still describe as functioning. Installing
the package is not evidence that those capabilities will work.

## 1. IntelBase: what its public contract reveals

The API exposes separate email, username, and module-list endpoints. Its email
response separates enriched accounts from registration-only results, and may
also contain breach and infostealer sections. Module fields vary. Lookups run th
with a time budget; unfinished modules can be omitted. Authentication needs a
paid API key and an allowed outgoing IP. Date summaries derive from account
dates; identity matching uses profile signals and produces probable groupings.
These are vendor-documented behaviors, not independently audited guarantees.
[API reference](https://intelbase.is/docs).

The policy says results are assembled by querying public platform endpoints and
third-party providers on demand. It also permits separate retention of lookup
results after user-account deletion. Provider names and collector internals are
not disclosed. Consequently, an apparent real-time result may mix live account
metadata with older historical records.
[Privacy policy](https://intelbase.is/privacy-policy).

I found a public IntelBase CLI repository. Its Python file sends requests to
IntelBase's API and uses an API token. It does not implement the underlying
Google, registration, or location collectors. Unrelated GitHub hits named
IntelBase refer to Intel compiler tooling and are not relevant.
[Wrapper source](https://github.com/cons0le7/IntelBase-CLI/blob/main/intelbase.py).

## 2. Epieos: evidence of its current product

Epieos advertises reverse email/phone lookup, live results, no query/result
logging, and no notification to the searched person. Those are vendor claims;
they are not an independent reliability or privacy audit.
[Homepage](https://epieos.com/).

Its public pricing page names separate Google, email-checker, GitHub, Strava,
Chess.com, Proton Mail, Gravatar, and other modules. This supports a modular
architecture, not a single omniscient data source. Platform-count marketing
should not be read as guaranteed coverage for every identifier.
[Module listing](https://epieos.com/pricing).

Its April 2026 guide describes tiered coverage, JSON/CSV/PDF exports, and an API
available by request. Following its API-documentation link redirected to sign-in.
I therefore did not invent endpoint paths, credentials, or response schemas for
an Epieos integration. Public guides are enough to identify the architecture but
not enough to implement their API client faithfully.
[Official guide](https://epieos.com/blog/features/how-to-use-epieos-for-your-osint-investigations),
[API documentation entry](https://epieos.com/docs/api).

Its privacy policy distinguishes customer/account/browsing data from the
processing of investigation data on clients' behalf. The no-query-logging claim
does not imply that Epieos holds no billing, account, or technical usage data.
[Privacy policy](https://epieos.com/privacy).

## 3. Email-to-account discovery: the mechanism

Holehe is a inspectable example of this class of collector. Its project describes
account checks through registration, login, recovery, and other site-specific
methods. Normalized results include existence, rate-limit status, and sometimes
masked recovery metadata. This demonstrates the method, but does not establish
that either vendor currently runs Holehe unchanged.
[Holehe project](https://github.com/megadose/holehe).

Conceptually, the collector reads whether a platform recognizes an identifier.
It does not authenticate as that account or obtain its session. A blocked,
timed-out, or changed response must mean "unknown", rather than "not registered".
Some web flows have side effects, so a new adapter needs a verified interaction
contract before we run it. Existing packages' no-notification claims should not
be transferred automatically to every present-day endpoint.

Username collectors are a different mechanism. Sherlock's source uses
site-specific status, response, and redirect detection, including handling for
blocked responses. WhatsMyName is a maintained dataset of known-positive and
known-negative detection rules. Both are useful architecture examples; neither
proves that matching usernames belong to the same person.
[Sherlock source](https://github.com/sherlock-project/sherlock/blob/master/sherlock_project/sherlock.py),
[WhatsMyName](https://github.com/WebBreacher/WhatsMyName).

## 4. Google identity enrichment: an inspectable analogue

GHunt's email module authenticates a collector, performs a People lookup, checks
for a public-profile container, and pivots through the returned Google account
identifier into Maps and other modules. It explicitly prints "Last profile edit"
when a profile timestamp exists. Activated-service metadata does not demonstrate
active recent use of every listed service.
[Email-module source](https://github.com/mxrch/GHunt/blob/master/ghunt/modules/email.py).

The People adapter uses a client-facing lookup with collector authentication and
extended Google fields. This is different from simply using a Gmail read-only
OAuth token against Google's documented public People API. It is a fragile
integration surface, not a public promise of arbitrary email-to-profile lookup.
[People adapter](https://github.com/mxrch/GHunt/blob/master/ghunt/apis/peoplepa.py).

The parser obtains its profile timestamp from `lastUpdatedMicros`. The name
parser in the inspected revision is disabled and comments that Google patched
names. This directly contradicts tutorials promising that all historical fields
always remain available.
[Parser source](https://github.com/mxrch/GHunt/blob/master/ghunt/parsers/people.py).

Google's supported `searchContacts` API searches the authenticated user's
contacts, with contact-specific authorization. It is not a global public email
directory. Cyber Twin's `gmail.readonly` permission does not automatically grant
this scope or the capabilities of GHunt's collector session.
[Google People documentation](https://developers.google.com/people/api/rest/v1/people/searchContacts).

Relationship caveat: GHunt's own README links its online offering to
OSINT.industries, not Epieos or IntelBase. Historical forum comments associate
Epieos with GHunt/Holehe-style methods, but these do not identify its current
private implementation. Similar output is evidence of a similar data surface,
not proof of source-code reuse.
[GHunt README](https://github.com/mxrch/GHunt).

## 5. Location: exactly what we can and cannot establish

IntelBase's demo associates Maps review/photo places with coordinates and shows
a centroid plus a spread radius. It also separately shows profile location.
Its sample is illustrative; it does not prove that a particular live lookup can
retrieve every displayed field.
[Public demo](https://intelbase.is/).

GHunt's Maps helper preserves a historical algorithm that groups contributions
within a radius, ranks groups using counts and date spans, averages coordinates,
and reverse-geocodes a representative point. In the inspected master revision,
the detailed review/photo fetching loop and the output call to the estimator are
commented out; the live path returns contribution statistics. This code explains
how the old estimate worked, not IntelBase's exact algorithm or a functioning
current full collector.
[Maps-helper source](https://github.com/mxrch/GHunt/blob/master/ghunt/helpers/gmaps.py).

Google confirms that Maps reviews/photos are public contributions, with profile
visibility controls. Place-associated coordinates can therefore become geographic
evidence without access to private location history.
[Maps contribution visibility](https://support.google.com/maps/answer/9514690?hl=en-GB).

Google also states that information associated with contributions can include
capture time and precise location. This makes actual image/location metadata a
possible evidence class, but does not prove either vendor extracts original GPS
metadata from every displayed photo.
[Google content policy](https://support.google.com/contributionpolicy/answer/7412443?hl=en).

GHunt has a separate BSSID-geolocation module: it requires a Wi-Fi access-point
identifier or network observations, rather than an email address. Google's
Geolocation API likewise accepts observed Wi-Fi/cell data and returns coordinates
with an accuracy radius. Finding that code does not establish that Epieos or
IntelBase uses it, nor that an email reveals nearby networks.
[GHunt geolocation module](https://github.com/mxrch/GHunt/blob/master/ghunt/modules/geolocate.py),
[Google Geolocation API](https://developers.google.com/maps/documentation/geolocation/overview).

IP geolocation is another possible location class. MaxMind explicitly says it
cannot identify a household, individual, or street address; a VPN can locate an
exit server rather than the user. A coordinate with many decimal places can
still be an approximate database centroid.
[MaxMind accuracy guidance](https://support.maxmind.com/knowledge-base/articles/maxmind-geolocation-accuracy).

Private Google Timeline is a separate system: Google describes device-based
visits/routes and encrypted backups. Public Maps contributions should never be
presented as access to that private history.
[Google Timeline documentation](https://support.google.com/maps/answer/6258979?co=GENIE.Platform%3DDesktop&hl=en-NL).

No reviewed source establishes a general live-GPS-from-email capability.

## 6. Other useful discoveries

Gravatar documents email-hash-to-profile lookup using SHA-256, with public profile
data and rate limits. It notes that a profile resolves for the primary email
hash, whereas avatar behavior can differ. This is a supported candidate for our
own email enrichment rather than an undocumented registration flow.
[Gravatar profile API](https://docs.gravatar.com/sdk/profiles/).

Holehe's Proton module extracts a timestamp from a public-key response and labels
it as creation. Proton's documentation allows additional keys after address
creation. The defensible interpretation is "public-key creation timestamp",
unless independent evidence establishes account creation. This illustrates how
OSINT interfaces can overstate a technically real date.
[Holehe Proton module](https://github.com/megadose/holehe/blob/master/holehe/modules/mails/protonmail.py),
[Proton key documentation](https://proton.me/support/download-public-private-key).

Recent GHunt issues report email lookup failures and differences between the
released package and current source. These reports corroborate fragility, but
individual reports are not a test of every account or the commercial products.
[Lookup issue, April 2026](https://github.com/mxrch/GHunt/issues/591),
[Maps visibility issue](https://github.com/mxrch/GHunt/issues/549).

## 7. Concrete consequences for Cyber Twin

The previous implementation covers only a small subset of these mechanisms.
Our independent public adapters use user-supplied usernames; they do not resolve
arbitrary emails to those usernames. The optional IntelBase adapter is a vendor
integration, not a reproduction of its private collectors. Its current allowlist
also omits registration-only hits, Google IDs, nested Maps observations, and
unrecognized provider fields. We should not advertise vendor feature parity.

Recommended implementation sequence:

1. Add per-adapter capability and coverage metadata: checked, found, absent,
   unknown, blocked, timed out, and last validated. Never equate no result with
   absence.
2. Add supported Gravatar email enrichment and verified profile links, preserving
   the supplied identifier and evidence for each match.
3. Add a Google profile/contribution source only through a permitted, validated
   adapter or user-supplied public profile/export. Keep collector credentials
   separate from Gmail authorization. Do not promise that installing GHunt
   automatically restores Maps collection.
4. Represent each geographic observation independently: source, place ID,
   coordinates, coordinate meaning, observation/capture date, retrieval date,
   precision, and identity linkage. Distinguish reviewed-place location, photo
   metadata, declared location, IP estimate, and consented device position.
5. Derive geographic clusters only when enough comparable observations exist.
   Use deduplication, spherical/geodesic calculations, geographic spread, and
   evidence counts. A centroid is not a home address. Counts and repeated
   observations are not calibrated probabilities.
6. Preserve date semantics: account created, key created, profile updated,
   contribution published, email received, last online, and confirmed login
   should be separate event classes or explicit timestamp bases.
7. Validate against controlled accounts before each adapter is enabled: known
   positive/negative accounts, no-contribution profiles, private profiles,
   renamed accounts, blocked responses, malformed data, and rate limits.

Missing evidence that would resolve remaining vendor-specific questions:
authenticated result/export samples for controlled accounts, accessible Epieos
API schemas, per-module field definitions, original source URLs, and repeated
controlled comparisons. This requires legitimate access, not private backend
intrusion. No vendor source code, undisclosed data suppliers, or live GPS access
was obtained in this research.
