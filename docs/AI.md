# Reslark agent contract (schema version 1)

Reslark is an external-process CLI. It has no npm runtime dependencies. Capture requires mitmdump; direct HTTP(S) downloads do not. Inspect `reslark --help` for the executable interface.

Install the npm package `reslark-capture` with `npm install -g reslark-capture`, or use `npx reslark-capture`. The installed executable is named `reslark`.

## Recommended procedure

1. Run `reslark doctor --json`. If `mitmdump.available` is false, report the missing executable or provide `--mitmdump`. Do not assume a successful Node installation means capture works.
2. Create a **fresh** output directory via `capture --out DIR --domain HOST --related --background --json`. Use repeated domains or `--pid` / `--process` for an application. `--all` explicitly selects all traffic arriving at the proxy.
3. Save `session_id`, `proxy_url`, `ca_path`, `capabilities`, and `limitations` from the result. A ready proxy is not proof that the target program uses it or trusts its CA.
4. Configure or launch the intended client. `run --out DIR -- PROGRAM ARGS` supplies proxy and CA environment variables; application support varies. Certificate installation and system-proxy changes require explicit commands/options.
5. Read `events SESSION --after SEQ --limit N`; persist the largest delivered `seq`. Use `resources SESSION --cursor OFFSET --limit N --json` and `inspect RESOURCE --json` to inspect files and provenance.
6. To actively fetch discovered assets, use `download RESOURCE`, or create the session with `--related --complete`. Only GET/HEAD resources can be replayed, and downloads use GET. Cross-origin requests strip Cookie/Authorization and other origin-specific headers.
7. Wait for the relevant condition and stop the session. `idle` only means inactivity for the requested interval. `stop` drains downloads for up to `--drain-timeout`; `--no-drain` cancels them while retaining resumable checkpoints.
8. Export JSON/HAR or inspect the filesystem. Use `retry SESSION` for incomplete selected resources after a failure.

## Output protocol

Result commands write JSON to stdout with `schema_version: 1`. `--json` selects compact output. Events always use one JSON object per line. Foreground capture/run emits the ready result and remains running until its stop condition. Background capture returns immediately after readiness.

```json
{"schema_version":1,"session_id":"s_0123456789abcdef0123","state":"ready","proxy_url":"http://127.0.0.1:49152","output_dir":"/absolute/output"}
```

```json
{"schema_version":1,"seq":1,"type":"session.ready","session_id":"s_0123456789abcdef0123","time":"2026-11-16T00:00:00.000Z"}
```

Errors go to stderr:

```json
{"schema_version":1,"error":{"code":"BACKEND_UNAVAILABLE","message":"mitmdump is required","retryable":false}}
```

| Exit code | Meaning |
| --- | --- |
| 0 | Command succeeded; inspect resource/task states for per-item failures |
| 2 | Invalid argument or contradictory options |
| 3 | Missing prerequisite, missing session/resource, or offline controller |
| 4 | Runtime/HTTP/download failure |
| 5 | Wait timeout |

Resource and download IDs are opaque. A resource's `complete: true` and `path` indicate that a full selected response body was saved. `.partial`, `state: partial`, `state: filtered`, and discovered URLs are not completed downloads. A later partial/cache response does not erase an already saved complete object; `last_response` records the newer incomplete observation.

`resources.jsonl` and `downloads.jsonl` are append-only **change logs**. Read the final record for each ID, or use CLI query commands. `requests.jsonl` records individual selected HTTP responses. Files remain separate from the metadata; HAR exports do not embed bodies or authentication values.

## Selection, decryption and privacy

`--domain example.com` is exact. `--domain '*.example.com'` includes the root and its subdomains. Exclusions take priority. `--related` decrypts all non-excluded HTTP(S) connections delivered to the session, then selects files using source relationships. In regular mode this may include unrelated applications if the user points them at the same proxy. Process mode narrows traffic at the mitmdump backend.

Do not treat a same-time request as proof of a source relationship. Inspect `relations.jsonl`; `evidence` is `explicit` for parsed references/redirects/browser initiators and `inferred` for Referer/Origin/text URLs. A parsed URL can still be unrelated application data.

Metadata output redacts common credentials. Original URLs/headers, WebSocket contents and program logs live under restricted `.state` files. Downloaded response bodies can contain secrets. Do not upload an entire capture automatically.

## Idempotency and recovery

Provide a stable `--request-id` when retrying capture creation. The same ID and options return the original session, including after it has stopped. Reusing it with different options returns `IDEMPOTENCY_CONFLICT`.

If a controller becomes unreachable, `status` reports `interrupted`. `recover` checks ownership of locks/proxy settings. It never sends signals to a stored PID because that PID may have been reused. A still-live orphan requires explicit operator review; recovery does not blindly delete its lock.

`events --follow` ends when a session ends. Use `--limit` to bound output. `wait --until queue-empty` does not mean capture has stopped. `wait --until files --count N` counts saved file objects, including partial objects; query resource completeness when completeness matters.
