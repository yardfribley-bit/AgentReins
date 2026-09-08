# Release Process

AgentReins CI builds a Universal 2 application containing both `arm64` and `x86_64` code. Pull requests and pushes to `main` receive an ad-hoc-signed artifact for verification. Version tags create a GitHub Release.

## Required GitHub secrets for trusted distribution

| Secret | Purpose |
| --- | --- |
| `APPLE_CERTIFICATE_P12` | Base64-encoded Developer ID Application certificate and private key. |
| `APPLE_CERTIFICATE_PASSWORD` | Password used when exporting the `.p12`. |
| `APPLE_ID` | Apple ID used by the notarization service. |
| `APPLE_TEAM_ID` | Apple Developer Team ID. |
| `APPLE_APP_PASSWORD` | App-specific password used by `notarytool`. |

Without these secrets, CI can verify an ad-hoc development build, but a public artifact would still trigger macOS trust warnings. Tagged releases therefore fail closed unless both Developer ID signing and notarization credentials are configured. A production release must be signed, notarized, stapled, and tested on a clean Intel Mac and a clean Apple Silicon Mac.

## Create a release

1. Confirm that the `main` workflow passes.
2. Update user-facing release notes and decide the semantic version.
3. Create and push an annotated tag:

   ```bash
   git tag -a v1.1.0 -m "Release AgentReins 1.1.0"
   git push origin v1.1.0
   ```

4. The workflow builds both architectures, signs the app, notarizes it when credentials exist, creates a ZIP archive and SHA-256 checksum, and publishes the GitHub Release.
5. Download the archive while signed out of GitHub and test it on clean Intel and Apple Silicon systems.

## Architecture verification

```bash
lipo -archs AgentReins.app/Contents/MacOS/AgentReins
```

The command must print both `x86_64` and `arm64`.

## Release safety

- Never commit certificates, passwords, API keys, or notarization credentials.
- Protect the GitHub release environment before storing production secrets.
- Do not describe an ad-hoc build as signed for public distribution.
- Do not publish a tag until the application version, release notes, and implemented capabilities agree.
