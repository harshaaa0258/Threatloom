# Campaign suggestions, model data, and evidence actors

## Reviewed classifier data

The built-in email corpus is synthetic demonstration data and is not suitable
for measuring production detection quality. To train on reviewed data, set
`EMAIL_ML_TRAINING_CSV` to a UTF-8 CSV with `text,label` columns. Supported
labels are `legitimate`, `suspicious`, `impersonated`, `phishing`, and `fraud`.
The loader accepts up to 20,000 rows and requires at least 15 examples, two
labels, and three examples for each included label.

Set `EMAIL_ML_REQUIRE_REVIEWED_DATA=true` in deployments that must not fall
back to the synthetic corpus. If the CSV is missing or invalid, classification
fails explicitly instead of returning results from demonstration data. Evaluate
reviewed datasets on a separate held-out sample before using model scores for
operational decisions; reported classifier scores are not calibrated
probabilities.

## Campaign suggestions

`GET /campaigns/suggestions` proposes clusters from repeated exact sender
addresses, public origin IPs, reply domains, and URL domains. It requires an
exact sender or origin match, or at least two distinct shared indicators.
Suggestions are heuristic leads, not confirmed campaigns. An operator reviews
a suggestion and can create a campaign case, which attaches the listed
investigations transactionally.

## Open-relay indicators

Open-relay matching uses operator-maintained IP indicators. Configure
`OPEN_RELAY_IPS` with comma- or whitespace-separated addresses, or
`OPEN_RELAY_IPS_FILE` with a local text file containing one IP per line; lines
beginning with `#` are ignored. Keep this list refreshed from a source whose
provenance and licensing you have reviewed. A match is only an infrastructure
indicator and does not prove that an email traversed the server.

## Authenticated custody events

Set `EVIDENCE_ACTOR_TOKENS` to a JSON object mapping actor names to distinct,
random bearer tokens of at least 32 characters, for example:

```text
EVIDENCE_ACTOR_TOKENS={"analyst-a":"<unique-random-token-of-at-least-32-characters>"}
```

Configure tokens only in the backend environment or secret manager, never in
source control. The evidence panel accepts a token for the current browser
session and sends it only when recording a custody event. The server derives
the actor name from the matching token; a caller-supplied actor label is not
trusted. HTTPS is required when using this over a network.

This token check protects evidence-event writes only; it is not general API
authentication. Evidence actor tokens do not establish a legal identity, and
database administrators can still alter SQLite files outside the API.

## DKIM verification

Analysis verifies up to five DKIM signatures cryptographically against DNS
keys using the original message bytes. `pass` means at least one signature
verified; individual signatures and their From-domain alignment are reported.
If there are more than five signatures and none of the checked signatures
passed, the result is `partial`. `fail` means all signatures were checked and
none verified; `error` means verification could not complete (for example,
due to DNS availability). A verified, aligned DKIM signature is one
authentication signal, not proof that the account or message is benign.
