# Performance and correctness results — 2026-09-14

## Live ThreatLocker test: 100,000 records, 50,000 deletions

An isolated macOS application was populated with 100,000 unique random 64-character
hexadecimal hashes. A full read-back matched the generated manifest before deletion.
The CSV contained the exact application ID, hash, and OS for every target. No policies
were attached to the synthetic fixtures.

Four disjoint runs used the same revised production engine as the dashboard and CLI.
Each run required an exact dry-run target count before true execution. All used Bulk
discovery, Bulk verification, page size 10,000, and durable logging batches of 256.

| Targets | Workers | Preparation | Deletion | Deletions/sec | Verification |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 2,000 | 6 | 31.32 s | 23.28 s | 85.91 | 74.97 s |
| 2,000 | 10 | 43.70 s | 12.29 s | 162.73 | 41.57 s |
| 2,000 | 16 | 40.84 s | 11.47 s | 174.37 | 57.81 s |
| 44,000 | 16 | 37.95 s | 159.15 s | 276.47 | 14.30 s |

All 50,000 requests were accepted, all 50,000 target file IDs were verified absent,
and no HTTP 429 throttling was recorded. The final independent full scan found exactly
50,000 remaining records. Their **file-ID-to-hash mapping** exactly matched the original
untargeted records. This comparison does not assert equality of every metadata field.

A separate synthetic application held copies of two hashes in the deletion list.
Both copies retained their original file IDs and hashes after the test, demonstrating
cross-application isolation even when the hash values are identical.

Summed deletion time was 206.19 seconds. Summed preparation, deletion, and verification
time was 548.65 seconds (about 9 minutes 9 seconds), excluding fixture creation, the
additional final audit, and small orchestration overheads. This tuning experiment
performed four dry runs and four verification scans; it is not a single-run timing.

The 44,000-target run took about 212 seconds across its three measured phases. It
used 344 deletion-phase commits, instead of the approximately 88,001 that batch size
1 would require in this implementation. Intentions were committed before requests;
SQLite WAL and synchronous FULL remained enabled.

## Interpretation and settings

Sixteen workers was the fastest **tested** deletion setting. Ten workers achieved
most of that throughput in the short comparisons. The later sustained run was faster
than the short runs, so network/server variability, warm connections, and application
size can influence results. These are observations, not proof of a global optimum.

For a similarly large deletion list, the validated configuration is Bulk discovery,
Bulk verification, page size 10,000, batch size 256, and up to 16 workers. The UI keeps
the conservative default of six workers; increase deliberately while monitoring errors.
Stop on throttling or ambiguous writes and reconcile rather than blindly replaying POSTs.

For a small deletion list inside a huge application, choose **Selective** discovery:
each hash search still includes its CSV application ID and avoids fetching the entire
application to the client. Auto verification uses selective reads for up to 1,000
dispatched records. That threshold is a heuristic, not a measured cost model. Server-side
query cost for a million-record application has not been measured. Recovery deliberately
uses a full scan to detect saved file IDs whose hash or rule type changed.

## Local million-row and durability probes

`python tests/performance_probe.py` uses generated records and a fake API, with no live
network deletion. On this machine:

- Importing 1,000,000 CSV rows into SQLite: 18.63 seconds.
- Matching 1,000 requested hashes against 1,000,000 generated application records:
  4.54 seconds of preparation.
- 2,000 simulated deletions, batch size 1: 15.68 seconds and 4,001 commits.
- The same simulated count, batch size 256: 0.18 seconds and 16 commits.

These measurements isolate local work and must not be presented as real API throughput
or as a comparable speedup for a live million-record application. The fixture uploader
was active during local probes, so host activity may have affected timings.

## Verification coverage and limits

The automated suite passed all 24 tests, including application/organization/OS mismatch,
cross-application isolation, exact hash-only eligibility, overlapping pagination,
expired previews, cancellation, ambiguous POST handling, durable batching, local locks,
and recovery from simulated uncertain states. Recovery checks also reject changed hashes
and changed rule types. Crash behavior was simulated; a live production process was not killed.

The live 100,000-record test is not a certification of million-record production
performance. No functioning bulk-delete API was established; see API-FINDINGS.md.
Portal/internal APIs may change. Avoid concurrent application edits from another machine
or the portal while running this automation. No schedule or automatic credential refresh
was installed. The CLI is available for an external scheduler with current credentials.

Machine-readable live results and synthetic manifests are kept in the local workspace
under `outputs/v2-test-20260914-150058`; they are not bundled with credentials or committed
to this application's repository. The remaining test records and small diagnostic
applications have been left available for inspection.
