# Portal API observations — 2026-09-14

These observations came from the authenticated ThreatLocker portal and disposable
synthetic applications in the authorized organization. They describe observed
behavior, not a vendor-supported API contract. No policies were attached to the fixtures.

## Application scope

The engine validates the CSV application using `GET /Application/ApplicationGetById`
and checks its returned application ID, organization, and OS. Every file query uses
`GET /ApplicationFile/ApplicationFileGetByApplicationId` with that same `applicationId`.
Selective mode also sets `searchText` to the requested hash; it does not search all
applications. Returned records are checked for exact hash equality and hash-only type.

The portal's observed rule deletion used:

```
POST /ApplicationFile/ApplicationFileDeleteById
```

Its JSON body included the file record, application ID, application name, organization,
and OS. The engine follows this pattern and explicitly sets the application ID from
the validated CSV scope. Each matching file ID requires one deletion request.

## Candidate shortcuts that did not work

- The portal's application-save DTO contains `removeApplicationFileIds`. Sending two
  synthetic file IDs in this array to `PUT /Application/ApplicationUpdateById` returned
  HTTP 200, but a complete read-back still found both records. It is not used as a
  bulk-delete shortcut.
- Adding file updates through that same PUT also returned HTTP 200 without inserting
  the test rule. A successful HTTP response alone is not sufficient verification.
- `showTotalCount=true` returned a list without reliable explicit total-count metadata
  in the inspected response. The engine does not rely on it to establish completeness.
- Large application-create bodies lost their connections. Exact-name reconciliation
  did not resolve those attempted fixtures, so those writes were not blindly retried.
  The successful 100,000-record fixture used an empty application and bounded,
  individually journaled file inserts, followed by a complete manifest comparison.

No functioning bulk file-delete endpoint was established. The verified optimization
is less local database work plus bounded concurrent calls to the observed endpoint,
not changing the endpoint based on an unverified response.

## Safety boundaries

Reads continue to an empty terminal page, rejecting repeated file IDs across pages.
This detects overlapping pages but cannot guarantee a snapshot if another operator
edits the application concurrently or if the server silently omits records. Local
application locks coordinate this app's processes on one machine only.

Normal selective verification searches the original hash and checks whether its file
ID remains in that result. It assumes no concurrent rule edits. Recovery always scans
the application because a still-existing file ID may have changed its hash.

Authorization remained in memory and is not included in source, build artifacts,
benchmarks, or audit exports. Synthetic fixtures remain available for inspection;
the test workflow does not remove application definitions or change policies.
