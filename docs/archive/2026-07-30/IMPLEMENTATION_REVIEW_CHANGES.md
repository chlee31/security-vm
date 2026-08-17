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

## Qualitative Classification

- Retired deterministic alert scoring and model-provided numerical adjustments.
- The model now returns only `Safe`, `Analyst Review Required`, or `Dangerous`, plus qualitative confidence, evidence-based reasoning, threat-intelligence interpretation, and investigation steps.
- Python validates the response and maps it to `log_only`, `human_review`, or `escalate`.
- Missing or invalid classifications, Low-confidence conclusions, and materially disputed sensor findings are forced to Analyst Review Required.
- Historical score columns and tables may remain only in upgraded SQLite databases so migrations are non-destructive. New installations omit them, and compatibility values in older databases are never exposed through the API or prompt.
- Removed heuristic MITRE ATT&CK mapping. Investigation context now comes from observed Suricata and Zeek records and threat-intelligence evidence.

## Retired Inventory

- Removed the registered-IP and asset-inventory interface from the active evaluated workflow.
- Retained the historical SQLite `assets` table name for migration compatibility; numerical importance is no longer collected or used.

## Legacy and Security Boundaries

- Packet-capture and tshark processing code has been removed from the application, APIs, schema for new databases, and documentation.
- Historical packet-capture columns in existing SQLite databases are left untouched rather than destructively dropped.
- Packet-filtering response code, temporary allowlisting, Gmail notifications, controls, routes, and router bootstrap helpers have been removed.
- Historical response-era tables in an upgraded SQLite database are preserved rather than destructively dropped, but new installations do not create them.
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
