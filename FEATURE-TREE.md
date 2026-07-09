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
- **Hostnames are believable and varied per instance**: drawn from several real naming schools (role/env, region-coded, cloud ip-in-name, themed codename, scale-set node) over a wide vocabulary, with appliances (the IoT/legacy profile) getting device-style names instead of server names, so there is no shared shape to fingerprint as the sweetty default. _internal/persona: TestServerHostnamesAreVariedAndNonEmpty, TestApplianceHostnamesLookLikeDevices, TestProfileRoutesHostnameStyle, TestHostnameBaseSkipsShortStubs_
- **Every identifying field varies between instances**; profiles and software versions are drawn from pools and vary across runs, and the OpenSSH package version carries a matching Ubuntu release, kernel, and toolchain story. _internal/persona: TestTwoPersonasDiffer, TestEveryIdentityFieldVaries, TestProfileVarietyAcrossRuns, TestSoftwareVersionsVaryAndAreInPool, TestOpenSSHVersionCarriesMatchingUbuntuRelease_
- **The filesystem population seed is persisted with the persona** and varies between generated instances. _internal/persona: TestFSSeedIsPopulatedAndVaries_
- **Profiles select a service set**: web, edge, infra, legacy, ftp; `full` exposes every protocol; an unknown name falls back to random. _internal/persona: TestGenerateProfileFullHasEveryProtocol, TestGenerateProfileNamed, TestUnknownProfileFallsBackToRandom_
- **The legacy profile is aarch64 end to end**; server profiles are x86_64; only arch differs by profile. _internal/persona: TestLegacyProfileIsEmbeddedARM, TestServerProfilesStayX86, TestOSImageOnlyArchDiffersByProfile_
- **Only the per-instance password authenticates**; passwords differ between instances. _internal/persona: TestAcceptOnlyPerInstancePasswords, TestPasswordsVaryPerInstance_
- **Optional brute-force policy lets a persistent guesser in coherently**: off by default; when enabled, the real credential still wins, and only after enough attempts over enough time does a source get let in (probabilistically) with the credential it tried against a real account, which is then remembered per source so a reconnect with it still works. An appliance (IoT/legacy) persona additionally accepts well-known factory default root passwords outright, the way real devices do, so Mirai-class loaders reach a shell fast; server personas do not. _internal/persona: TestAcceptFromRealCredentialAlwaysWins, TestAcceptFromDisabledRejectsGuesses, TestAcceptFromLetsPersistentGuesserIn, TestAcceptFromGates, TestApplianceAcceptsDefaultCredsFast, TestServerPersonaRejectsIoTDefaults_
- **The SSH host key is stable across restarts** from a persisted seed. _internal/persona: TestSSHHostKeyStableAndValid_
- **Persona persistence is generate-on-first-run, regenerate-if-empty, never-clobber-if-corrupt**. _internal/persona: TestLoadOrCreateGeneratesOnFirstRun, TestLoadOrCreateRegeneratesEmptyFile, TestLoadOrCreateRefusesToClobberInvalidFile_

## Virtual filesystem coherence (VISION §1)

- **One tree backs every file command**: content equals reported size, metadata overrides apply, symlinks resolve, directory order is sorted and stable, missing paths error. _internal/vfs: TestContentAndSizeAgree, TestMetadataOverrides, TestSymlinkResolution, TestReadDirSortedAndDeterministic, TestMissingPaths_
- **Stub binaries report as ELF** to `file`. _internal/vfs: TestStubBinaryELF_
- **The per-session overlay is copy-on-write**; writes and deletions are session-local; cwd tracks. _internal/vfs: TestCopyOnWriteOverlay, TestCwdAndChdir_
- **The embedded tree renders the instance identity**: no residual placeholders, two instances differ, ownership matches `/etc/passwd` and `/etc/group`, modes consistent, and release files render the persona's OS, kernel, and toolchain identity on both the main host and NAS pivot. _internal/fakehost: TestLoadRendersInstanceIdentity, TestNoResidualPlaceholders, TestTwoInstancesDiffer, TestOwnershipMatchesPasswdAndGroup, TestCoherentOwnershipAndModes, TestReleaseFilesRenderPersonaRelease, TestNASReleaseFileRendersPersonaRelease_
- **The embedded tree is populated per instance** from the persisted filesystem seed: package footprint and log content vary between instances, remain stable within one instance, carry mtimes inside the persona boot window, and home clutter is owned by the account named in `/etc/passwd`. _internal/fakehost: TestPopulationVariesPerInstance, TestPopulationIsStableWithinInstance, TestPopulatedMtimesFollowBootEpoch, TestHomeClutterOwnedByUser_
- **`/proc` identity is synthetic and per-arch**, not the host's. _internal/fakehost: TestProcIdentityRendersPerArch_

## Shell coherence

- **ls and cat agree; root reads shadow; a missing file errors**. _internal/proto/telnet: TestFilesystemCoherence_
- **cd updates cwd and the prompt**. _internal/proto/telnet: TestStatefulCdAndPwd_
- **The parser handles chaining, quoting, env-assignment prefixes, pipes, redirects, and variable expansion**. _internal/shell: TestParseChainingQuotingEnv; internal/proto/telnet: TestParsingShapes_
- **Loader recon runs convincingly**: command substitution `$(...)` and backticks (including `ls -lh $(which ls)` and `var=$(cmd)` capture), the `[`/`test` builtin, `( )` subshells and `{ }` groups inline, newline-separated multi-line scripts, BusyBox multicall (run an applet, `applet not found` for the Mirai presence probe), absolute `/bin` path resolution, multi-flag `uname`, `nproc`, and `/proc/uptime`, so the multi-fallback fingerprint scripts come back populated instead of blank. _internal/shell: TestParseNewlineAndGroups; internal/proto/telnet: TestCommandSubstitution, TestBracketTestBuiltin, TestSubshellsGroupsNewlines, TestBusyboxAndPathResolution, TestUnameNprocUptime_
- **The BusyBox echo-loader reconstructs its dropper**: `echo -e`/`-ne` decodes backslash escapes (above all `\xHH`), and `>>` appends to the overlay rather than overwriting, so a payload written one chunk at a time accumulates the real bytes instead of literal `\x..` text or only the last chunk. _internal/shell: TestDecodeEchoEscapes, TestEchoInterpretsEscapesOnlyWithDashE; internal/proto/telnet: TestEcholoaderReconstructsDropper_
- **A reconstructed dropper is captured as an indicator**: a file an attacker assembles in place and then runs (`sh dropper`, `./dropper`) is logged as a DROPPER event with its content and a sha256, the real payload when nothing was fetched over the wire. _internal/proto/telnet: TestDropperContentCaptured_
- **The post-break-in loader commands are covered**: tftp and ftpget log the fetch host as a download attempt (the BusyBox fetch fallback) instead of terminating; chpasswd, useradd, and usermod report the silent success their real counterparts give, so a loader believes it persisted; and su prompts for and captures the password a Hajime-class loader offers. _internal/proto/telnet: TestTftpAndFtpgetLogDownloads, TestPersistenceCommandsReportSuccess, TestSuCapturesPassword_
- **The appliance persona treats the Mirai menu-escape as a silent shell transition**: `enable`/`system`/`shell`/`linuxshell` (the tokens a loader fires to break out of a restricted IoT CLI) succeed silently on the IoT profile, leaving a working shell so the loader proceeds to recon and the payload pull instead of bailing on a bash error; a server persona keeps "command not found", which is coherent for a real Linux box. The tokens are inert no-ops: no exec, no fetch, no write. _internal/proto/telnet: TestApplianceMenuEscapeIsSilentShellTransition, TestServerMenuEscapeStaysCommandNotFound_
- **head and tail honour line and byte counts**. _internal/shell: TestHeadTailHonorLineCount_
- **ls reports real hard-link counts, dot entries, and the total line**. _internal/shell: TestLsLinkCounts, TestLsDotEntriesAndTotal_
- **Generated output derives from session state**: disk story, process start versus uptime, systemctl main PID versus ps, listeners versus persona services. _internal/shell: TestDiskStoryIsCoherent, TestProcessStartCoherentWithUptime, TestSystemctlMainPidMatchesPs, TestListenersMatchPersonaServices_
- **Installed packages agree across attacker-visible views**: `dpkg -l` reads the VFS package database and every listed package command resolves through `which` to a VFS path. _internal/shell: TestInstalledPackagesAgreeWithDpkgAndWhich_
- **Arch is consistent across /proc, uname, lscpu, and the disk**, including the ARM board. _internal/shell: TestArchIsOneStoryAcrossSources, TestEmbeddedDiskStoryIsCoherent; internal/proto/telnet: TestEmbeddedDeviceSessionIsCoherentlyARM_
- **Disk geometry varies between instances and is stable within one**. _internal/shell: TestDiskGeometryVariesPerInstance, TestDiskGeometryIsStableWithinInstance_

## Cross-service coherence (VISION §1)

- **Banners, uname, /etc/\*, and the prompt agree across telnet, ssh, http, and ftp**. _internal/crosscheck: TestEveryServiceTellsOnePersonaStory_
- **Identity is consistent across sources within a live session**. _internal/proto/telnet: TestCrossSourceIdentityCoherence, TestMetadataViewsAgree_

## Adversary gate

- **The anti-detection gate probes live services over their wire surfaces**: SSH algorithm offers match the advertised OpenSSH release and stay stable across handshakes; service banners tell one persona story; `ls -l` and `cat` agree from a real SSH session; repeated listings stay byte-stable; responses do not leak the real host identity. _internal/adversary: TestSSHAlgorithmOfferMatchesBanner, TestSSHOfferIsStableAcrossHandshakes, TestBannersAgreeAcrossServices, TestListingAndReadNeverDisagree, TestRepeatedListingsAreStable, TestNoServiceLeaksHostIdentity_

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
- **On-box reads of a bait image (cat, an ASCII image viewer, the vault command) render the embedded colour-ANSI reveal immediately; base64 (the exfil channel) hands over a real Justin Timberlake JPEG so an attacker who copies the blob and decodes it locally opens a picture of JT off-box rather than any real secret. Every path logs a HONEYTOKEN**. _internal/proto/telnet: TestBaitImageRevealsTheGag_
- **The reveal art is upper-half-block 256-colour rendering of the source photos, so the portrait reads as a photo rather than glyph noise, resets colour per line, and stays within a standard terminal width**. _internal/shell: TestRevealArtIsWellFormed, TestRandomRevealReturnsArt_
- **Running the fake vault or wallet logs a HONEYTOKEN**. _internal/proto/telnet: TestHoneytokenVaultIsTracked_

## Resource limits and tarpits (VISION §5)

- **A hold-open tarpit releases its goroutine and fd on disconnect, and returns immediately in fast mode**. _internal/server: TestHoldOpenReleasesOnDisconnect, TestHoldOpenFastModeReturnsImmediately_
- **A process-wide connection cap backstops the per-IP cap**. _internal/server: TestConnLimiterCapsConcurrency_
- **ReadLine, aggregate HTTP/Docker/Redis request memory, and the HTTP header loop are length-bounded**. _internal/server: TestReadLineIsBounded, TestInputBudgetReleasesAndEnforcesBothCaps; internal/proto/http: TestHTTPHeaderFloodIsBounded, TestHTTPHeaderBytesAreBounded_
- **Portal projections, source classifiers, replay listings, and browser source bookkeeping cap attacker-controlled cardinality; oversized live-feed lines are discarded without unbounded buffering**. _internal/portal: TestPortalProjectionsBoundAttackerCardinality, TestSourceAnalyzerVisitsAreBounded_
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
- **The interactive SSH algorithm offer derives from the persona's advertised OpenSSH release**: the server KEXINIT KEX/cipher/MAC lists match the parsed banner version, unknown versions fall back to the newest profile, profiles vary across releases, every offered name completes a real handshake, and a skeptic's post-login probe sees one release story across banner, `/etc/os-release`, `uname`, `/proc/version`, compiler, interpreter, DNS, and apt output. _internal/proto/ssh: TestProfileForParsesVersion, TestCryptoProfileMatchesBannerVersion, TestCryptoProfileVariesAcrossVersions, TestOfferedAlgorithmsAreImplemented, TestSkepticProbesSeeOneReleaseStory_
- **A completed handshake yields an interactive shell over the same VFS; kex and client are captured**. _internal/proto/ssh: TestInteractiveShellSession, TestSSHKexCaptured, TestSSHBannerFromPersonaAndClientCapture_
- **The exec channel runs the shell, reports exit status, and captures download intent without fetching**. _internal/proto/ssh: TestInteractiveExecRunsTheShell, TestExecReportsExitStatus, TestSSHExecCapturesIntentWithoutFetching_
- **Wrong password and unknown user are rejected**. _internal/proto/ssh: TestWrongPasswordRejected, TestUnknownUserRejected_
- **An offered public key is recorded as a credential attempt (with its fingerprint), not a command**, so a pubkey-spray bot that never gets a shell does not inflate command counts or falsely reach the post-login phase. _internal/proto/ssh: TestPublicKeyOfferLoggedAsCredentialNotCommand_
- **Cooked-TTY line discipline edits and terminates lines, swallows CRLF, and ends on Ctrl-D**. _internal/proto/ssh: TestCookedTTYEditsAndTerminatesLines, TestCookedTTYSwallowsCRLF, TestCookedTTYCtrlDEndsSession_
- **The handshake survives a PROXY header glued to the client banner**: bytes the header parse buffered are replayed into the key exchange rather than dropped, so a client that races the parse behind the HAProxy edge is not disconnected mid-kex. _internal/proto/ssh: TestHandshakeSurvivesProxyHeaderReadAhead_

## HTTP, HTTPS, FTP, ADB, Redis, Docker, MySQL

- **HTTP responses match the configured stack** (nginx, apache, tomcat, wordpress): header content and order, Date/Server placement, method handling (405 without Allow, per-daemon unknown method), WordPress REST link and login signature, HEAD headers-only. _internal/proto/http: TestNginxServerHeaderIsBareAndBeforeDate, TestApacheEmitsDateBeforeServer, TestTomcatSendsNoServerHeader, TestPerStackHeaderOrder, TestNginxNonGetMethodIs405WithoutAllow, TestUnknownMethodIsPerDaemon, TestWordPressFrontPageHasRestApiLink, TestWordPressLoginSignatureHeaders, TestHeadReturnsHeadersOnly, TestNginxServesExactDefaultIndex, TestTomcatEmptyReasonAndDefault404, TestTomcatHomeSingleVersionHeading_
- **POST bodies are hashed (SHA); routes resolve per stack**. _internal/proto/http: TestPostIsLoggedWithSHA, TestPostShaMatchesBody, TestRootResponseByStyle, TestWordPressRoutes, TestTomcatRoutes, TestNginxRoutes, TestParseRequestLine_
- **A recognised HTTP RCE is routed through the inert shell**: the injected command (a PHP-CGI/CVE-2024-4577 base64 or `system()` payload, a ThinkPHP `invokefunction`, or a router `goform`/`GponForm` command injection) is extracted and run through the same shell telnet and ssh use, so the loader's C2 URL is captured as a DOWNLOAD_ATTEMPT rather than buried in the POST body, and the response echoes the verification marker the scanner checks for (the CVE-2024-4577 md5). It executes nothing: the routed shell reaches neither the wire nor the host, ordinary traffic falls through to the stack responder, and a prompting or hostile command aborts cleanly without hanging the handler. _internal/proto/http: TestExtractRCE, TestExtractRCEIgnoresBenign, TestHTTPRCECapturesRouterC2, TestHTTPRCEReturnsMarkerAndCapturesC2, TestHTTPRCEHandlesHostileInputInert, TestHTTPNonExploitFallsThrough, TestHTTPRCENilFSSkipsBridge_
- **WordPress admin "gives" after persistent credential-stuffing, in two tiers**: wp-login rejects a one-shot bot, but a source that keeps trying is let in (its guessed credential captured and logged as brute-forced), handed a logged-in cookie, and landed in a wp-admin dashboard with an embedded reveal; keep digging through wp-admin and a deeper second reveal replaces the first. Per-source state is mutex-guarded and capped, and reaching the reveal is logged as a HONEYTOKEN once per source (a "90s JT Reveal", tracked in the console alongside the shell-loot reveals). So persistent attackers earn a payoff and a louder log trail instead of an endless 302. _internal/proto/http: TestWPGateLetsInPersistentGuesser, TestWPLoginRevealsOnlyAfterWork, TestWPDeepRevealAfterLotsOfWork, TestWPRevealLoggedOncePerSource, TestJTArtEmbedded_
- **HTTPS captures the TLS ClientHello and writes no application bytes**. _internal/proto/https: TestHTTPSNeverWritesBytesAndCapturesHello, TestTLSHelloCaptured_
- **An HTTPS session's cast records a readable classification of the hello (kind plus hex dump), never the raw binary record**, so the live watch and replay show terminal text instead of mojibake; the faithful hex stays in the TLS_HELLO event. _internal/proto/https: TestCastRecordsReadableHelloNotRawBytes_
- **FTP matches the configured daemon and captures credentials** (vsftpd, proftpd, pureftpd; banner; QUIT). _internal/proto/ftp: TestFTPVsftpdBehaviour, TestFTPPureFTPdBehaviour, TestFTPProFTPdBehaviour, TestFTPBannerAndCredentialCapture, TestFTPQuit_
- **ADB exposes an appliance-style TCP 5555 surface**: the CNXN banner derives from the persona, `shell:` payloads run through the inert shared shell and capture download intent without dialing, `sync:` pushes are logged as droppers without touching the host filesystem, concurrent streams and retained payload bytes are bounded, malformed packets reach no command path, and legacy/full profiles wire the service. _internal/proto/adb: TestADBBannerMatchesPersona, TestADBShellCapturesKillChainWithoutDialing, TestADBSyncPushIsLoggedAsDropperAndHostUntouched, TestADBSyncStreamsAndPayloadAreBounded, TestADBDropsMalformedPacketsWithoutCommandEvents; internal/persona: TestLegacyProfileExposesADB, TestGenerateProfileFullHasEveryProtocol; cmd/sweetty: TestBuildProtocolWiresEveryConfiguredProtocol_
- **Redis exposes the unauthenticated write-primitive chain inertly**: INFO advertises the persona Redis/Linux story, AUTH and SELECT accept, CONFIG SET plus SET plus SAVE logs the payload as a dropper at the configured target, URL-bearing values log download intent without dialing, malformed RESP stays out of the payload paths, and infra/full profiles wire the service. _internal/proto/redis: TestRedisInfoMatchesPersona, TestRedisCapturesWritePrimitiveAsDropper, TestRedisURLPayloadLogsDownloadWithoutDialing, TestRedisMalformedRESPStaysInert; internal/persona: TestInfraProfileExposesRedis, TestGenerateProfileFullHasEveryProtocol, TestSoftwareVersionsVaryAndAreInPool; cmd/sweetty: TestBuildProtocolWiresEveryConfiguredProtocol_
- **Docker exposes the unauthenticated Engine API inertly**: discovery endpoints advertise a coherent Linux and Docker persona, image pulls log the requested registry reference without dialing it, privileged container-create bodies are captured as intent without execution, malformed requests stay out of the pull and create paths, and infra/full profiles wire TCP 2375. _internal/proto/docker: TestDockerVersionInfoAndListingsMatchPersona, TestDockerImagePullLogsDownloadWithoutDialing, TestDockerContainerCreateCapturesEscapeAttempt, TestDockerMalformedRequestStaysInert; internal/persona: TestInfraProfileExposesDocker, TestGenerateProfileFullHasEveryProtocol, TestSoftwareVersionsVaryAndAreInPool; cmd/sweetty: TestBuildProtocolWiresEveryConfiguredProtocol_
- **MySQL exposes a protocol-10 credential trap inertly**: the server-first handshake advertises the persona MySQL version and mysql_native_password while varying its auth salt per connection, login packets log the username and scrambled auth response as a rejected credential, malformed packets stay out of credential and capability paths, and infra/full profiles wire TCP 3306. _internal/proto/mysql: TestMySQLHandshakeMatchesPersona, TestMySQLHandshakeSaltVariesPerConnection, TestMySQLCapturesLoginAndRejects, TestMySQLMalformedPacketStaysInert; internal/persona: TestInfraProfileExposesMySQL, TestGenerateProfileFullHasEveryProtocol, TestSoftwareVersionsVaryAndAreInPool; cmd/sweetty: TestBuildProtocolWiresEveryConfiguredProtocol_

## Source attribution and scan detection

- **A bare connect that sends nothing is logged as a port scan and dropped**. _internal/server: TestBareConnectIsPortScan_
- **PROXY protocol v1 and v2 recover the real source; no header is left unparsed; unknown and malformed headers are handled**. _internal/proxyproto: TestV1Recovers, TestV2Recovers, TestNoHeaderUntouched, TestV1UnknownIsNoAddress, TestMalformedV1IsError; internal/server: TestProxyProtocolRecoversRealSource, TestProxyProtocolFallsBackWithoutHeader, TestProxyProtocolMalformedIsDropped_

## Logging (VISION §4)

- **Concurrent writes stay whole and unforgeable**. _internal/event: TestConcurrentLogWritesStayWholeAndUnforgeable_
- **Embedded newlines and control bytes cannot forge a second event**. _internal/event: TestLogInjectionIsEscaped_
- **Each line stamps time and sensor; the file is not world-readable; a write failure is counted, not swallowed**. _internal/event: TestLogStampsTimeAndSensor, TestLogFileIsNotWorldReadable, TestLogWriteFailureIsCountedNotSwallowed_
- **A stable session id correlates a whole connection**. _internal/proto/telnet: TestSessionIdCorrelatesWholeConnection_
- **The `hapwatch` helper turns the optional HAProxy edge's stick-table into `FLOOD_BLOCKED` events**: it parses `show table` output and reports each source over the rate threshold once per cooldown, forgetting sources that calm down. _internal/haproxy: TestParseStickTable, TestWatcherReportsAndCoolsDown_
- **Control bytes are neutralised for console and portal display**. _internal/util: TestSanitizeDisplay_

## Geo enrichment

- **Country lookup reads an optional database** (range, integer, and CIDR row forms), claims no country without one, skips malformed rows, survives a recoverable CSV error without truncation, and classifies address scope. _internal/geo: TestCountryLookupRangeForm, TestCountryLookupIntegerAndCIDRForms, TestNoCountryWithoutDatabase, TestMalformedRowsAreSkipped, TestRecoverableCsvErrorDoesNotTruncate, TestScopeClassification_
- **ASN/ISP lookup reads an optional `start,end,asn,org` database** (dotted or integer bounds, org may contain commas), tags a global address with its autonomous system and operator, claims none without a database or for special-use scope, and the portal rolls sources up by ISP. _internal/geo: TestLoadASNAndLocate, TestASNNotResolvedWithoutDBOrForSpecialUse; internal/portal: TestOverviewEnrichesISP_

## Session recording and replay

- **Session recording is opt-in (`record: true`) and each cast plus the recording directory has storage quotas; ids cannot escape the recording directory and a nil recorder is a no-op**. _internal/config: TestRecordingDefaultsOff; internal/record: TestCastIsValidAsciinema, TestNilRecorderIsSafe, TestRecorderRejectsUnsafeAndDuplicateIDs, TestDirectoryQuotaAccountingIsBounded; internal/server: TestSessionRecordingWritesCast_
- **A recorded cast is served by id; a bad id is rejected**. _internal/portal: TestCastServesRecording, TestCastRejectsBadID_

## Portal (VISION §6)

- **The portal binds loopback and serves the dashboard over plain HTTP with no application auth**: the root and every data route answer directly with no cookie and no login redirect, the served HTML reaches nothing off-host, and every script-referenced element id resolves. _internal/portal: TestNoAuthServesDashboardDirectly, TestServedHTMLReachesNothingOffHost, TestDashboardScriptElementIDsResolve_
- **The SSE feed uses byte-offset ids, resumes from Last-Event-ID, skips history on a fresh connect, ignores an unusable id, and streams appended lines**. _internal/portal: TestEventsFeedIDIsByteOffset, TestEventsFeedResumesFromLastEventID, TestEventsFeedFreshConnectSkipsExisting, TestEventsFeedIgnoresUnusableLastEventID, TestEventsFeedStreamsAppendedLines_
- **Feed events carry source context attached at read time (country and operator, visit count, returning flag, classifier verdict)**, on both the backfill query and streamed SSE frames, rendered in the live feed as country and history chips; the on-disk log line stays untouched. _internal/portal: TestFeedBackfillCarriesSourceContext, TestEventsFeedFramesCarrySourceContext_
- **Analytics aggregate the overview (with a busy-sensor cap), honeytokens, the filtered log query, and the recordings list**. _internal/portal: TestOverviewAggregates, TestOverviewCapsBusySensor, TestHoneytokensAggregates, TestLogQueryFilters, TestRecordingsListsCastIDsOnly_
- **The dashboard-polled analytics are served from an incremental projection over the log, not a per-request full-log parse**: each log line is folded exactly once (byte-offset tailing, like the SSE feed), incremental folds match a from-scratch fold byte for byte, a rotated log refolds from the start, a mid-write partial line folds only once complete, and the live-rail projection drops ended and stale sessions instead of holding every session id the log has seen. The drill-down endpoints (log query, per-IP, per-session) stream the file with bounded retention, and the per-IP verdict still reads the full history. _internal/portal: TestStoreIncrementalFoldMatchesFreshFold, TestStoreRefoldsAfterRotation, TestStoreFoldsPartialLineOnlyOnceComplete, TestLiveProjectionDropsEndedAndStale, TestLogQueryKeepsNewestUnderLimit_
- **The live-feed stat cards are whole-UTC-day counts computed server-side over the full log (a `today` block in the overview), not from the browser's capped event buffer, so a busy sensor's cards are not undercounted; a Today / All-time toggle switches them to the cumulative totals, both already in the overview rollup; a notable event (a JT reveal or a payload pull) refreshes the cards promptly so the counter ticks up in step with the confetti, while high-volume events stay on the slow timer**. _internal/portal: TestOverviewTodayCounts, TestDashboardHasStatScopeToggle, TestDashboardRefreshesCardsOnNotableEvent_
- **Payload pulls have a dedicated page**: every DOWNLOAD_ATTEMPT (an attacker's faked wget/curl/tftp of a second-stage binary) rolls up per source with geo/operator attribution and the captured URLs, plus a distinct-URL roll-up: the honeypot's highest-value IOC feed, answering who fetched what. Only download events appear; management-plane noise is excluded. _internal/portal: TestPayloadsAggregatesWhoPulledWhat_
- **Inline droppers appear on the same page**: a payload assembled in place (a DROPPER event, filename and sha256) shows alongside over-the-wire fetches and counts in `dropper_total`, so the page stays meaningful on a sensor whose loaders deliver inline. _internal/portal: TestPayloadsIncludesInlineDroppers_
- **A honeytoken trip flashes the celebration portrait in the console**: the prize moment that fires the confetti and the "it's gonna be ME" toast (only on a HONEYTOKEN, a JT reveal) also flashes an embedded portrait full-screen for about two seconds and fades it out. The image is embedded and served same-origin, so the console still reaches nothing off-host. _internal/portal: TestJTPrizeImageServed, TestDashboardFlashesJTOnReveal_
- **The admin console proxy serves a local upstream over the same SSH tunnel, strips the prefix, hides the target, refuses a non-local target, and redirects bare to slash**. _internal/portal: TestAdminConsoleProxiesToLocalUpstream, TestAdminConsoleStripPrefix, TestAdminConsoleListHidesTarget, TestAdminConsoleRefusesNonLocalTarget, TestAdminConsoleBareRedirectsToSlash_
- **Each source is read for what it is**: its events segment into visits across a 30-minute idle gap, and a conservative verdict reads loader/persistence commands, a honeypot-probe credential, or a BusyBox presence probe as a bot, a scan-only source as a scanner, varied human-paced typing with no bot tell as a tentative human, and everything else as unknown, carrying the evidence and the phases reached alongside. _internal/portal: TestAnalyzeLoaderScriptIsBotLoader, TestAnalyzeSentinelCredIsBot, TestAnalyzeBusyboxProbeIsLoader, TestAnalyzeScanOnlyIsScanner, TestAnalyzeHumanPacingIsTentativeHuman, TestAnalyzeBotDoesNotShowHumanReason, TestAnalyzeZeroGapBurstKeepsCadenceZero, TestAnalyzeSegmentsVisitsAndReturning_
- **The per-IP drill-down returns that assessment alongside the raw entries**, so the drawer can show what a source is and why without a second request. _internal/portal: TestByIPReturnsAssessment_
- **The overview rollup tags every source with its kind, visit count, and a returning flag** from the same analyzer, so the Sources list shows what each source is and which ones have come back without a per-row request. _internal/portal: TestOverviewMarksReturningAndKind_
- **The Sources view shows each source's kind and a returning badge, and filters by them**: a coloured kind chip (loader, brute, scan, human?), a visit-count badge on repeat visitors, All / Returning / Bots / Human? filter buttons, a country dropdown, and a free-text search over IP, country, and ISP, all composing client-side. _internal/portal: TestDashboardHasSourceFilters_
- **The per-IP drawer leads with an assessment panel**: the verdict and confidence, the evidence behind it, a phase ribbon (recon, brute, access, exploit), and a visit timeline, all from the byIP profile. _internal/portal: TestDashboardRendersAssessmentPanel_
- **The console shows the sensor's own configured surface, not only observed traffic**: an Exposed services panel lists every configured listener with the public port an attacker reaches (falling back to the bound port when the config carries none), its protocol and persona, its live hit and scan tallies, and whether it is actually serving, so a port that has drawn no traffic still appears and a configured port whose backend never bound reads as not serving. _internal/portal: TestOverviewSurface_
- **Attackers filter by the service they hit, with a human-versus-bot split**: a service dropdown, and a click on any Exposed services or Ports row, narrows the Sources list to the attackers that touched that protocol, and a summary line reports how many match and their human, bot, scanner, and unclassified split. _internal/portal: TestOverviewSurface, TestDashboardHasSourceFilters_

## Configuration and secrets

- **Config is generated from the persona; the portal binds a fixed loopback port (`8888`)**. _internal/config: TestGenerateFromPersona, TestPortalPortIsFixedLoopback_
- **Writing the default config refuses to overwrite an existing file**. _internal/config: TestWriteDefaultConfigRefusesOverwrite_
- **A listener can record the public port an attacker reaches, distinct from the port the process binds**, so behind an edge that fronts a loopback backend the console reports the real public port, falling back to the bound port when it is unset. _internal/portal: TestOverviewSurface_

## Build wiring

- **The builder turns the config service set into live listeners for every configured protocol**. _cmd/sweetty: TestBuildProtocolWiresEveryConfiguredProtocol_

## Out of scope and limitations

- **No malware detonation or analysis**: payloads and intent are captured, not executed or emulated (VISION non-goal); the safety boundary is the proof.
- **No blocking or filtering**: the sensor observes, it does not act on traffic (VISION non-goal).
- **Bare `curl url | sh` and `python -c` downloads do not land a file**: these vectors log intent and fail; only wget and curl -O/-o land a payload. Deliberate scope.
