# SweeTTY Feature Tree

Coverage index of implemented behaviour. Each entry states an invariant and cites
the test that verifies it; an entry whose cited test is absent is a defect in this
file. Design rationale lives in the companion docs ([VISION.md](./VISION.md),
[ARCHITECTURE.md](./ARCHITECTURE.md), [TESTING.md](./TESTING.md),
[AGENTS.md](./AGENTS.md)); this file records only what is verified. Citations read
`package: TestName`.

## Verify

- `go build ./...` compiles every package and the embedded fakeroots.
- `go test ./...` is the full gate; every cited entry is one of these tests.
- `go vet ./...` and `gofmt -l .` report nothing.
- Boundary subsets:
  - `go test ./internal/safety/` (import guardrail).
  - `go test ./internal/proto/telnet/ -run 'TestNoOutboundConnectionOrExec|TestShellWritesNoHostByte|TestOverlayEvaporatesAcrossSessions'` (egress, host-disk, overlay lifetime).
  - `go test ./internal/crosscheck/` (one persona across services).

## Per-instance identity (VISION §7)

- **Every identity field is populated on first run**: hostname, domain, internal range, neighbours, kernel, software versions, secrets, boot time. _internal/persona: TestGenerateIsComplete_
- **Every identifying field varies between instances**; profiles and software versions are drawn from pools and vary across runs. _internal/persona: TestTwoPersonasDiffer, TestEveryIdentityFieldVaries, TestProfileVarietyAcrossRuns, TestSoftwareVersionsVaryAndAreInPool_
- **Profiles select a service set**: web, edge, infra, legacy, ftp; `full` exposes every protocol; an unknown name falls back to random. _internal/persona: TestGenerateProfileFullHasEveryProtocol, TestGenerateProfileNamed, TestUnknownProfileFallsBackToRandom_
- **The legacy profile is aarch64 end to end**; server profiles are x86_64; only arch differs by profile. _internal/persona: TestLegacyProfileIsEmbeddedARM, TestServerProfilesStayX86, TestOSImageOnlyArchDiffersByProfile_
- **Only the per-instance password authenticates**; passwords differ between instances. _internal/persona: TestAcceptOnlyPerInstancePasswords, TestPasswordsVaryPerInstance_
- **The SSH host key is stable across restarts** from a persisted seed. _internal/persona: TestSSHHostKeyStableAndValid_
- **Persona persistence is generate-on-first-run, regenerate-if-empty, never-clobber-if-corrupt**. _internal/persona: TestLoadOrCreateGeneratesOnFirstRun, TestLoadOrCreateRegeneratesEmptyFile, TestLoadOrCreateRefusesToClobberInvalidFile_

## Virtual filesystem coherence (VISION §1)

- **One tree backs every file command**: content equals reported size, metadata overrides apply, symlinks resolve, directory order is sorted and stable, missing paths error. _internal/vfs: TestContentAndSizeAgree, TestMetadataOverrides, TestSymlinkResolution, TestReadDirSortedAndDeterministic, TestMissingPaths_
- **Stub binaries report as ELF** to `file`. _internal/vfs: TestStubBinaryELF_
- **The per-session overlay is copy-on-write**; writes and deletions are session-local; cwd tracks. _internal/vfs: TestCopyOnWriteOverlay, TestCwdAndChdir_
- **The embedded tree renders the instance identity**: no residual placeholders, two instances differ, ownership matches `/etc/passwd` and `/etc/group`, modes consistent. _internal/fakehost: TestLoadRendersInstanceIdentity, TestNoResidualPlaceholders, TestTwoInstancesDiffer, TestOwnershipMatchesPasswdAndGroup, TestCoherentOwnershipAndModes_
- **`/proc` identity is synthetic and per-arch**, not the host's. _internal/fakehost: TestProcIdentityRendersPerArch_

## Shell coherence

- **ls and cat agree; root reads shadow; a missing file errors**. _internal/proto/telnet: TestFilesystemCoherence_
- **cd updates cwd and the prompt**. _internal/proto/telnet: TestStatefulCdAndPwd_
- **The parser handles chaining, quoting, env-assignment prefixes, pipes, redirects, and variable expansion**. _internal/shell: TestParseChainingQuotingEnv; internal/proto/telnet: TestParsingShapes_
- **head and tail honour line and byte counts**. _internal/shell: TestHeadTailHonorLineCount_
- **ls reports real hard-link counts, dot entries, and the total line**. _internal/shell: TestLsLinkCounts, TestLsDotEntriesAndTotal_
- **Generated output derives from session state**: disk story, process start versus uptime, systemctl main PID versus ps, listeners versus persona services. _internal/shell: TestDiskStoryIsCoherent, TestProcessStartCoherentWithUptime, TestSystemctlMainPidMatchesPs, TestListenersMatchPersonaServices_
- **Arch is consistent across /proc, uname, lscpu, and the disk**, including the ARM board. _internal/shell: TestArchIsOneStoryAcrossSources, TestEmbeddedDiskStoryIsCoherent; internal/proto/telnet: TestEmbeddedDeviceSessionIsCoherentlyARM_
- **Disk geometry varies between instances and is stable within one**. _internal/shell: TestDiskGeometryVariesPerInstance, TestDiskGeometryIsStableWithinInstance_

## Cross-service coherence (VISION §1)

- **Banners, uname, /etc/\*, and the prompt agree across telnet, ssh, http, and ftp**. _internal/crosscheck: TestEveryServiceTellsOnePersonaStory_
- **Identity is consistent across sources within a live session**. _internal/proto/telnet: TestCrossSourceIdentityCoherence, TestMetadataViewsAgree_

## Safety boundary (VISION §2)

- **No attacker-reachable package imports `os/exec`, a network dialer, or the host filesystem**; the build fails if a new proto or handler package is unguarded. _internal/safety: TestHandlersHaveNoCapabilityImports, TestEveryProtoPackageIsGuarded, TestEveryAttackerReachablePackageIsGuarded_
- **No download or exec vector opens an outbound connection**: each is pointed at a listener that flags any connect; intent is logged, nothing connects or runs. _internal/proto/telnet: TestNoOutboundConnectionOrExec, TestDownloadFetchesNothing_
- **`wget -O- ... | sh` is logged as an exec attempt and not executed**. _internal/proto/telnet: TestPipeToShellIsExecAttempt_
- **Shell writes touch only the in-memory overlay, which is discarded per session**. _internal/proto/telnet: TestShellWritesNoHostByte, TestOverlayEvaporatesAcrossSessions; internal/vfs: TestCopyOnWriteOverlay_
- **A full session (login, recon, mutate, faked download) stays inside the boundary**. _internal/proto/telnet: TestVerticalSliceIsCoherentEndToEnd_
- **Post-RCE containment**: Linux seccomp is installed at startup and the release binary is PIE. Built in `cmd/sweetty/seccomp_linux*.go` and `scripts/build-release.sh`; no runtime test (the filter forbids syscalls the process never issues after setup).

## Faked operations (VISION §2)

Faked operations report success and leave overlay state, without fetching from the
network, executing attacker input, or writing to the host disk.

- **wget and curl -O complete and write an inert payload to the overlay; running the dropped file is logged as an exec, not reported missing**. _internal/proto/telnet: TestDownloadLandsAndRuns_
- **apt and pip report a successful install and leave a `/usr/bin` stub**, so which, ls, and dpkg remain consistent. _internal/proto/telnet: TestInstallsComplete_
- **`crontab -e` round-trips through `crontab -l`; an authorized_keys append survives a re-read**. _internal/proto/telnet: TestPersistenceSticks_
- **scp and rsync report a completed transfer without opening a connection**, capturing the destination and credentials. _internal/proto/telnet: TestExfilCompletes_

## Bait and honeytokens (VISION §8)

- **ssh to the backup host named in the breadcrumb trail reaches a second coherent host; the pivot credential is captured**. _internal/proto/telnet: TestPivotToJustinTimberlakeHost_
- **Bait files live at a randomized per-instance path (`persona.LootPath`) reached via the shell history; ls, stat, and file report a normal image**. _internal/proto/telnet: TestPivotToJustinTimberlakeHost_
- **Any read of a bait image (cat, base64, an ASCII image viewer) returns the embedded colour-ANSI reveal, not file bytes, and logs a HONEYTOKEN**. _internal/proto/telnet: TestBaitImageRevealsTheGag_
- **Running the fake vault or wallet logs a HONEYTOKEN**. _internal/proto/telnet: TestHoneytokenVaultIsTracked_

## Resource limits and tarpits (VISION §5)

- **A hold-open tarpit releases its goroutine and fd on disconnect, and returns immediately in fast mode**. _internal/server: TestHoldOpenReleasesOnDisconnect, TestHoldOpenFastModeReturnsImmediately_
- **A process-wide connection cap backstops the per-IP cap**. _internal/server: TestConnLimiterCapsConcurrency_
- **ReadLine and the HTTP header loop are length-bounded**. _internal/server: TestReadLineIsBounded; internal/proto/http: TestHTTPHeaderFloodIsBounded_
- **A handler panic ends only its session; SESSION_END still fires**. _internal/server: TestSessionEndSurvivesPanic_
- **Hostile input does not hang or crash a handler**: unterminated subnegotiation, self-referential `sh -c`, base64-decoded command, repeated pivot. _internal/proto/telnet: TestUnterminatedSubnegotiationDoesNotHang, TestSelfReferentialExecDoesNotCrash, TestBase64DecodedCommandDoesNotCrash, TestPivotIsSingleHop_
- **Progress bars advance over a fixed duration**. _internal/server: TestProgressBar_

## Telnet

- **Connect emits an IAC option burst** (DO NAWS, WILL SGA, DO TTYPE, multiple triplets) and an agetty-style `<host> login:`. _internal/proto/telnet: TestIACNegotiationOnConnect_
- **Option negotiation refuses offered options, declines client options, acks its own burst silently, and does not loop on a NAWS ack**. _internal/proto/telnet: TestTelnetRefusesOfferedOption, TestTelnetDeclinesClientOption, TestTelnetAcksItsOwnBurstSilently, TestTelnetDoesNotLoopOnNawsAck_
- **Login validates like sshd**: correct per-instance password accepted; wrong password re-prompts with "Login incorrect"; empty username re-prompts; disconnect at the password prompt logs no credential. _internal/proto/telnet: TestCorrectPasswordIsAccepted, TestWrongPasswordRePromptsLoginIncorrect, TestEmptyUsernameRePrompts, TestPasswordDisconnectLogsNoCredential_
- **Credentials are captured with verdict; inbound IAC is stripped from the username**. _internal/proto/telnet: TestCredentialCapture, TestInboundIACStrippedFromUsername_
- **Ubuntu MOTD on login; `quit` is not a builtin**. _internal/proto/telnet: TestUbuntuWelcomeAndMOTD, TestQuitIsNotABuiltin_

## SSH

- **Banner is exact on the wire, followed by silence before kex, and drawn from an OpenSSH-grammar pool**. _internal/proto/ssh: TestSSHBannerExactWire, TestSSHEmitsBannerThenSilenceBeforeKex, TestSSHBannerPoolMatchesOpenSSHGrammar_
- **A completed handshake yields an interactive shell over the same VFS; kex and client are captured**. _internal/proto/ssh: TestInteractiveShellSession, TestSSHKexCaptured, TestSSHBannerFromPersonaAndClientCapture_
- **The exec channel runs the shell, reports exit status, and captures download intent without fetching**. _internal/proto/ssh: TestInteractiveExecRunsTheShell, TestExecReportsExitStatus, TestSSHExecCapturesIntentWithoutFetching_
- **Wrong password and unknown user are rejected**. _internal/proto/ssh: TestWrongPasswordRejected, TestUnknownUserRejected_
- **Cooked-TTY line discipline edits and terminates lines, swallows CRLF, and ends on Ctrl-D**. _internal/proto/ssh: TestCookedTTYEditsAndTerminatesLines, TestCookedTTYSwallowsCRLF, TestCookedTTYCtrlDEndsSession_

## HTTP, HTTPS, FTP

- **HTTP responses match the configured stack** (nginx, apache, tomcat, wordpress): header content and order, Date/Server placement, method handling (405 without Allow, per-daemon unknown method), WordPress REST link and login signature, HEAD headers-only. _internal/proto/http: TestNginxServerHeaderIsBareAndBeforeDate, TestApacheEmitsDateBeforeServer, TestTomcatSendsNoServerHeader, TestPerStackHeaderOrder, TestNginxNonGetMethodIs405WithoutAllow, TestUnknownMethodIsPerDaemon, TestWordPressFrontPageHasRestApiLink, TestWordPressLoginSignatureHeaders, TestHeadReturnsHeadersOnly, TestNginxServesExactDefaultIndex, TestTomcatEmptyReasonAndDefault404_
- **POST bodies are hashed (SHA); routes resolve per stack**. _internal/proto/http: TestPostIsLoggedWithSHA, TestPostShaMatchesBody, TestRootResponseByStyle, TestWordPressRoutes, TestTomcatRoutes, TestNginxRoutes, TestParseRequestLine_
- **HTTPS captures the TLS ClientHello and writes no application bytes**. _internal/proto/https: TestHTTPSNeverWritesBytesAndCapturesHello, TestTLSHelloCaptured_
- **FTP matches the configured daemon and captures credentials** (vsftpd, proftpd, pureftpd; banner; QUIT). _internal/proto/ftp: TestFTPVsftpdBehaviour, TestFTPPureFTPdBehaviour, TestFTPProFTPdBehaviour, TestFTPBannerAndCredentialCapture, TestFTPQuit_

## Source attribution and scan detection

- **A bare connect that sends nothing is logged as a port scan and dropped**. _internal/server: TestBareConnectIsPortScan_
- **PROXY protocol v1 and v2 recover the real source; no header is left unparsed; unknown and malformed headers are handled**. _internal/proxyproto: TestV1Recovers, TestV2Recovers, TestNoHeaderUntouched, TestV1UnknownIsNoAddress, TestMalformedV1IsError; internal/server: TestProxyProtocolRecoversRealSource, TestProxyProtocolFallsBackWithoutHeader, TestProxyProtocolMalformedIsDropped_

## Logging (VISION §4)

- **Concurrent writes stay whole and unforgeable**. _internal/event: TestConcurrentLogWritesStayWholeAndUnforgeable_
- **Embedded newlines and control bytes cannot forge a second event**. _internal/event: TestLogInjectionIsEscaped_
- **Each line stamps time and sensor; the file is not world-readable; a write failure is counted, not swallowed**. _internal/event: TestLogStampsTimeAndSensor, TestLogFileIsNotWorldReadable, TestLogWriteFailureIsCountedNotSwallowed_
- **A stable session id correlates a whole connection**. _internal/proto/telnet: TestSessionIdCorrelatesWholeConnection_
- **Control bytes are neutralised for console and portal display**. _internal/util: TestSanitizeDisplay_

## Geo enrichment

- **Country lookup reads an optional database** (range, integer, and CIDR row forms), claims no country without one, skips malformed rows, survives a recoverable CSV error without truncation, and classifies address scope. _internal/geo: TestCountryLookupRangeForm, TestCountryLookupIntegerAndCIDRForms, TestNoCountryWithoutDatabase, TestMalformedRowsAreSkipped, TestRecoverableCsvErrorDoesNotTruncate, TestScopeClassification_

## Session recording and replay

- **Each session can be recorded as a valid asciinema v2 cast** when `record_dir` is set; a nil recorder is a no-op. _internal/record: TestCastIsValidAsciinema, TestNilRecorderIsSafe; internal/server: TestSessionRecordingWritesCast_
- **A recorded cast is served by id; a bad id is rejected**. _internal/portal: TestCastServesRecording, TestCastRejectsBadID_

## Portal (VISION §6)

- **The portal binds loopback and serves the dashboard over plain HTTP with no application auth**: the root and every data route answer directly with no cookie and no login redirect, the served HTML reaches nothing off-host, and every script-referenced element id resolves. _internal/portal: TestNoAuthServesDashboardDirectly, TestServedHTMLReachesNothingOffHost, TestDashboardScriptElementIDsResolve_
- **The SSE feed uses byte-offset ids, resumes from Last-Event-ID, skips history on a fresh connect, ignores an unusable id, and streams appended lines**. _internal/portal: TestEventsFeedIDIsByteOffset, TestEventsFeedResumesFromLastEventID, TestEventsFeedFreshConnectSkipsExisting, TestEventsFeedIgnoresUnusableLastEventID, TestEventsFeedStreamsAppendedLines_
- **Analytics aggregate the overview (with a busy-sensor cap), honeytokens, the filtered log query, and the recordings list**. _internal/portal: TestOverviewAggregates, TestOverviewCapsBusySensor, TestHoneytokensAggregates, TestLogQueryFilters, TestRecordingsListsCastIDsOnly_
- **The admin console proxy serves a local upstream over the same SSH tunnel, strips the prefix, hides the target, refuses a non-local target, and redirects bare to slash**. _internal/portal: TestAdminConsoleProxiesToLocalUpstream, TestAdminConsoleStripPrefix, TestAdminConsoleListHidesTarget, TestAdminConsoleRefusesNonLocalTarget, TestAdminConsoleBareRedirectsToSlash_

## Configuration and secrets

- **Config is generated from the persona with a per-instance portal port**. _internal/config: TestGenerateFromPersona, TestPortalPortVaries_
- **Writing the default config refuses to overwrite an existing file**. _internal/config: TestWriteDefaultConfigRefusesOverwrite_

## Build wiring

- **The builder turns the config service set into live listeners for every configured protocol**. _cmd/sweetty: TestBuildProtocolWiresEveryConfiguredProtocol_

## Out of scope and limitations

- **No malware detonation or analysis**: payloads and intent are captured, not executed or emulated (VISION non-goal); the safety boundary is the proof.
- **No blocking or filtering**: the sensor observes, it does not act on traffic (VISION non-goal).
- **Bare `curl url | sh` and `python -c` downloads do not land a file**: these vectors log intent and fail; only wget and curl -O/-o land a payload. Deliberate scope.
