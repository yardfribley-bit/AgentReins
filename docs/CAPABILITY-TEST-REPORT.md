# Capability Test Report

Test date: September 9, 2026

## Scope

This report covers the first end-to-end engineering slice of the AgentReins **Trace + Independent Verification + Recovery** roadmap. It distinguishes automated evidence from features that still require integration testing.

## Automated results

| Capability | Test evidence | Result |
| --- | --- | --- |
| Parse modified and untracked Git files | `testPorcelainParserHandlesOrdinaryAndRenamedFiles` | Passed |
| Parse rename records without treating the source path as another record | `testPorcelainParserHandlesOrdinaryAndRenamedFiles` | Passed |
| Preserve unchanged pre-existing work in mutation comparison | `testMutationComparisonIgnoresUnchangedPreExistingWork` | Passed |
| Label changes without a baseline as unknown | `testMutationWithoutBaselineIsUnknown` | Passed |
| Capture repository root, HEAD, file states, and patch | `testGitSnapshotCapturesRepositoryState` | Passed |
| Capture a verifier's real exit code, stdout, and stderr | `testIndependentVerificationRecordsRealExitCodeAndOutput` | Passed |
| Detect Swift, npm/pnpm/yarn, pytest, Go, and Cargo verification commands | `testProjectVerifierDetectsSupportedProjectTypes` | Passed |
| Reject recovery when the baseline already contains user changes | `testRecoveryEligibilityRejectsPreExistingChanges` | Passed |
| Recover modified and deleted tracked files | `testRecoveryRestoresCleanTrackedStateAndRemovesRecordedUntrackedFiles` | Passed |
| Remove newly created and renamed untracked files during recovery | `testRecoveryRestoresCleanTrackedStateAndRemovesRecordedUntrackedFiles` | Passed |
| Return the fixture repository to a clean Git state | `testRecoveryRestoresCleanTrackedStateAndRemovesRecordedUntrackedFiles` | Passed |
| Build and package Intel and Apple Silicon code | GitHub Actions Universal 2 job | Passed |
| Verify the packaged app signature | GitHub Actions `codesign --verify` step | Passed |
| Preserve and explain per-request context growth | `testContextGrowthPreservesEveryModelRequest` | Passed |

Automated test result: **9 tests passed, 0 failed**.

## Implemented behavior

- WorkBuddy lifecycle events create or update a persistent journal keyed by session and turn.
- Git snapshots run outside the UI actor.
- A snapshot records HEAD, porcelain v2, unstaged and staged patches, diff statistics, numeric statistics, and file states.
- Interrupted journals are marked `stuck` after an application restart.
- The outcome card distinguishes captured lifecycle evidence from partial historical evidence.
- Swift, npm/pnpm/yarn, pytest, Go, and Cargo workspaces can run detected build or test commands after an explicit user action.
- Verification stops after the first failing command and records the real outcome.
- Recovery is enabled only when the baseline was clean, HEAD did not change, mutations exist, and the workspace still matches the recorded final snapshot.
- Recovery requires an explicit destructive-action confirmation.
- Each turn preserves provider-reported usage for every model request and explains first-to-last growth, cumulative processing, the largest one-step increase, and reported cache reuse.

## Safety decisions

Recovery deliberately fails closed in these cases:

- The workspace contained changes before the turn.
- No pre-turn baseline exists.
- HEAD changed during the turn.
- The workspace changed after the final snapshot.
- A recorded path resolves outside the repository.
- Git cannot restore tracked files.

This restriction provides a credible recovery path for the clean-baseline Product Hunt fixture without claiming that complex overlapping user and agent edits are already safe to undo.

## Not yet proven

| Capability | Current status | Required test |
| --- | --- | --- |
| True pre-tool baseline timing | Not proven with WorkBuddy polling | Native hook emits a prompt/pre-tool event before the first mutation. |
| Exact attribution when the user and agent edit the same file | Not implemented | Content-level baseline and three-way attribution fixtures. |
| Recovery with pre-existing user work | Intentionally blocked | Transactional snapshot and replay tests across staged, unstaged, untracked, binary, and permission changes. |
| Recovery after the agent creates commits | Intentionally blocked | Commit-aware preview and explicit branch/reset policy. |
| Full build/test execution outside SwiftPM | Detection implemented; execution not certified in CI | Controlled npm, Python, Go, and Cargo fixtures with success, failure, timeout, and missing-tool cases. |
| Verification sandboxing | Not implemented | Process, filesystem, network, timeout, and output-limit tests. |
| Complete WorkBuddy UI workflow | Not yet manually certified | Start a real task, observe the live journal, verify, recover, and compare Git state. |
| Claude Code, Codex, Cursor, or other adapters | Not implemented | Adapter-specific lifecycle fixtures and end-to-end tests. |
| Provider Trust | Not implemented | Real configured-versus-actual destination evidence. |

## Current release decision

**Engineering slice: pass. Public product claim: limited.**

AgentReins may state that it captures persistent Git evidence, independently verifies supported Swift workspaces, and can recover a clean-baseline fixture. It must not yet state that it can safely undo every agent turn or reliably capture a true pre-execution baseline for every WorkBuddy task.

## Next acceptance test

Run one real WorkBuddy task in a clean fixture repository:

1. Confirm that AgentReins creates the journal before the first file mutation.
2. Modify, create, delete, and rename controlled files through WorkBuddy.
3. Confirm that the outcome card lists the correct turn and workspace.
4. Run independent build and tests from AgentReins.
5. Confirm that the agent's own result and the independent result are visually separate.
6. Preview and approve recovery.
7. Confirm that Git status is clean and the fixture tests return to their baseline result.

Only after this manual test passes should the clean-baseline workflow be used in a public demo.
