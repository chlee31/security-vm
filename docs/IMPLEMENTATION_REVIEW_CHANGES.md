# Implementation Review Changes

Implemented after the final-report technical review.

## Suricata Ingestion Reliability

- Added a persistent SQLite checkpoint containing the EVE source, path, inode, byte offset, and update time.
- The checkpoint advances only when the application acknowledges a record after case assessment completes.
- Added EVE rotation and truncation detection. Replacement files are read from byte zero.
- Added a canonical SHA-256 event fingerprint and partial unique database index.
- Replayed event content reuses the existing alert instead of creating a duplicate row.
- Added `suricata.start_position`, with `end` as the first-run default and `beginning` available for intentional replay.

## Detection-Type Labelling

- Replaced broad substring checks with explicit bounded patterns.
- Generic DNS, SYN, login, and SSH references now remain `unknown`.
- Explicit port-scan, DNS-tunnelling, beaconing/C2, and brute-force language retains specialized labels.
- Preserved Suricata signature IDs in normalized in-memory evidence for future SID-based mappings.

Detection types remain a rule-based implementation heuristic. They are not presented as a trained classifier.

## Correlation Policy

- Versioned the current policy as `correlation-v1`.
- Made rule strengths configurable in `config.yaml`.
- Changed dashboard wording from correlation confidence to **rule strength**.
- Documented default windows: 10 seconds cross-sensor, 300 seconds same-sensor behavior, and 120 seconds Zeek context.
- Added boundary coverage for the same-sensor aggregation window and configured strength values.

These values remain design choices. Experimental work should measure missed correlations and incorrect merges under alternative windows.

## Scoring Auditability

- Versioned the score as `deterministic-score-v1`.
- Store category maxima and an explicit statement that the score is an investigation-priority heuristic, not a probability of compromise.
- The six existing category weights remain unchanged so prior cases and tests retain comparable behavior.

The report should state that the weights require sensitivity, ablation, and analyst-review validation.

## Registered IP Terminology

- Updated visible dashboard labels to use **registered IP**, **assigned role**, **business importance**, and **registered IP importance**.
- Retained historical internal names such as the SQLite `assets` table and API field `asset_score` for migration compatibility.

## Legacy and Security Boundaries

- PCAP, active firewall response, and notification paths remain retired from the evaluated analysis runtime.
- Some schema structures remain so existing SQLite databases can migrate without destructive changes.
- The dashboard continues to bind to `127.0.0.1` by default and warns when `0.0.0.0` is selected.
- The prototype still has no built-in authentication and must use localhost or a restricted management network.

## Verification Coverage

New tests cover:

- Suricata checkpoint resume;
- replay of a read but unacknowledged event after restart;
- EVE file rotation;
- content-based duplicate prevention;
- explicit positive detection labels;
- generic protocol terms remaining unknown;
- correlation-window boundaries;
- configurable rule strengths; and
- migration of older databases to the new Suricata fields and checkpoint table.
