# Pinned Fengrubei template access

`buaa fengrubei` retrieves one exact upstream community-template release. It does not claim that the template is an official or current competition format, and it never unpacks, executes, compiles or relicenses the archive.

## Inspect provenance and caveats

```sh
buaa fengrubei info
```

The command is offline and reports:

- repository `GFCYqw/Fengrubei_LaTeX_Template`;
- tag `v1.0.3`, pinned commit `20e27c67ebf09cc730d8988d7395d9a8d34acf47`;
- release asset `v1.0.3.Fengrubei_LaTeX_Template.zip`;
- byte length `52,816,733` and SHA-256 `08b9ab2e06e440e462b6d8a65e77d579277613fe3cfb31b4bded7cd34e7177d1`;
- upstream license `LPPL-1.3c-or-later` and explicit usage caveats.

The upstream README and release instructions identify XeLaTeX and a Windows `make.bat` workflow. The observed archive contains template source, examples, prior formatting documents and font files including Times New Roman, Courier New, STKxinwei and STKzhongsong variants. Font licensing and platform availability require separate operator review. BUAA CLI does not redistribute these files as MIT project source and does not invoke the build/cleanup script.

Always compare with the current official competition notice and formatting rules. A pinned community release is reproducible access, not a guarantee of current compliance.

## Fetch the original release archive

```sh
# Cache only; the destination must be a new absolute path.
printf '%s\n' '{"output":"/home/operator/private/template-v1.0.3.zip"}' \
  | buaa fengrubei fetch

# Explicitly permit public upstream retrieval on a private-cache miss.
printf '%s\n' '{"output":"/home/operator/private/template-v1.0.3.zip"}' \
  | buaa fengrubei fetch --online
```

The default never makes a network request. The output parent must already exist, be owner-controlled, reject group/other writes, and contain no symlink path components. The output is never overwritten and is created through a pinned parent descriptor with mode `0600`; its final device/inode binding is checked before success. The original ZIP stays packed. On every cache read and output copy, exact size and SHA-256 are verified before success.

The private cache is fixed under the effective user's passwd home; it is not source/worktree state. A corrupt or conflicting cache fails rather than being silently replaced. Output diagnostics do not echo signed redirect URLs or response bodies.

## Network safety

A cache-miss retrieval uses the shared process-wide governor. The observed GitHub release flow requires four separately governed reads, each spaced at least five seconds after completion:

1. GitHub robots policy;
2. the exact release URL, which must return one redirect;
3. the exact `release-assets.githubusercontent.com` robots policy;
4. the validated HTTPS asset redirect.

Only the fixed GitHub release URL and one HTTPS redirect to the exact GitHub release-asset host are accepted. The client disables automatic redirects, proxies, cookies, decompression, referrers, connection reuse and automatic retries. TLS validation remains enabled. Robots denial, authentication rejection, reliable challenge signals and 429 cooldowns fail through the same governor latch/backoff rules as other sources.

The asset is streamed to a private atomic temporary file with a 64 MiB bound, verified against the pinned size/hash, then renamed and directory-synchronized while the request lease is still held. It is not held in one large memory buffer.

## Evidence and limits

A one-time governed observation downloaded the public v1.0.3 release and established the pinned 52,816,733-byte SHA-256 above. No campus request, login or mutation occurred. The archive was inspected as an archive, not executed or compiled.

Synthetic loopback tests exercise robots checks, explicit redirect validation, four request leases with unchanged five-second spacing, streaming integrity, cache-only reuse, no cookies, no overwrite, corrupt-cache rejection, unsafe-output-parent rejection and cache-allocation failure before the final network lease. Actual CLI proof copied the governed observed artifact from a verified private cache to an owner-controlled private directory, confirmed byte/hash equality, denied `/tmp` as an unsafe parent (exit 5), rejected a relative `--online` path before network/cache work (exit 2), and rejected an existing output path. The CLI smoke made no network request.

This feature does not retrieve official current BUAA rules, submit work, compile TeX, clean directories, install fonts or grant rights to redistribute the upstream archive. Those remain operator responsibilities.
