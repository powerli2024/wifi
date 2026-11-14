# Independent QA

These checks are separate from the implementation author's unit suite. They do not install the APK, contact a public diagnostic endpoint, disable TLS validation, or verify phone/VPN behavior.

## Core regression and adversarial cases

From the repository root, with JDK 17:

```sh
./gradlew -p qa/core-harness test --rerun-tasks
```

This isolated Gradle project uses the same Kotlin 2.1.20/JUnit 4.13.2 toolchain as the main build and compiles the current real core sources, all author tests, and `qa/src/test/kotlin`. It does not require an Android runtime. Production sources and the shipped APK are not changed. New JUnit and HTML results use the harness `build/` directory; `qa/results` preserves the imported v0.1.0 evidence.

An alternative integrated invocation, with the Android SDK configured, is `./gradlew -I qa/include-tests.init.gradle :core:test --rerun-tasks`. This adds the same QA test sources for that invocation only. The isolated harness avoids interfering with another main-project build.

Coverage includes all five verdicts, 1,248 execution/failure/TLS/status combinations, 72 network-state combinations, malformed/replayed echo JSON, all redacted network identifier positions, numeric IP equivalence and malformed inputs, bounded lists, endpoint authority ambiguity, and 15,000 deterministic fuzz inputs. These are unit tests, not network security proof.

## Controller concurrency simulation

```sh
./gradlew -p qa/controller-harness test --rerun-tasks
```

This separate JVM-only build copies the current `DiagnosticsController.kt` into its generated source directory and compiles it with the real core code plus minimal fake Android APIs. All HTTPS calls are intercepted in-process; only the synthetic `fake.test` host is accepted. The fake DNS responder constructs numeric addresses directly and never resolves a name.

It exercises actual controller code for explicit start, no-auto-probe/demo/clear, request settings and fresh run IDs, status/type/size/UTF-8/nonce failures, cancellation with blocked cleanup, late callbacks, retained single-run ownership, frozen input policy, repeated concurrent starts, DNS timeout, and the real 20-second deadline. A separate export suite verifies immediate frozen serialization, redacted/full isolation, one-shot consumption, cancellation, duplicate/stale tickets, 64 concurrent consumers, process-payload loss, restored request-code reservation, and 16-bit exhaustion without reuse.

This harness does not verify Android's Looper, UI rendering, lifecycle callbacks, TLS stack, socket cancellation, DNS stack, VPN routing, network monitor callbacks, or real transport behavior. Its fabricated environment can cause the controller's report model to say `ANDROID_RUNTIME`; such a harness report is not real Android evidence and is not supplied as a device report. Only test assertions/logs are retained.

In v0.2.0, `RawDnsControllerTest` additionally uses real **host-loopback** UDP sockets while Android APIs remain fake. It checks raw-only operation and cancellation without starting TCP; this does not validate Android/VPN routing. The core `RawDnsTest` suite covers wire parsing, loopback UDP/TCP, cancellation, absolute deadlines, and redaction.

## Imported v0.1.0 evidence

- `logs/independent-core-tests.log`: real Gradle core/adversarial execution.
- `logs/controller-harness-tests.log`: real Gradle fake-platform controller execution.
- `results/`: machine-readable JUnit results, captured after final test runs.
- APK metadata/signature/hash logs record the exact build inspected; preliminary logs are explicitly named preliminary.

`qa/INDEPENDENT-QA-REPORT.md` records that historical version only. Historical v0.2.0 logs/JUnit snapshots are in `verification/v0.2.0`; see `docs/releases/0.2.0/REVIEW.md` for that release only.

## Android device-loopback smoke runner

The dependency-free `DeviceSmokeInstrumentation` lives only in `androidTest`. It creates numeric loopback DNS fixtures on the selected Android device, checks IPv4/A and IPv6/AAAA UDP/TCP, cancellation, runtime slot recovery and redaction, then writes a labelled test report. It never tests a remote resolver, real VPN, other applications or the physical egress.

```sh
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
adb -s <explicit-test-device> install -r app/build/outputs/apk/debug/app-debug.apk
adb -s <explicit-test-device> install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -s <explicit-test-device> shell am instrument -w dev.proxyaudit.android.test/dev.proxyaudit.android.DeviceSmokeInstrumentation
adb -s <explicit-test-device> shell run-as dev.proxyaudit.android cat files/device-smoke-report.json
```

Choose an isolated test device explicitly. The custom runner reports `PASS`/`FAIL`/`SKIP` and `failed`/`skipped` counts; an adb process exit code alone is not a passing test. IPv6 unavailable is a skip, never a successful IPv6 check.

Current verification scope: [status index](../docs/testing/CURRENT-STATUS.md). Physical runner startup required ADB foreground assistance in the recorded session; the eight passed cases do not prove unattended startup. Documentation checks: `python tools/check_docs.py --root .` from the project root.
