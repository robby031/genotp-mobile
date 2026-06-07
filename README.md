# genotp-mobile

Mobile bindings for `genotp-go` using `gomobile`.

## Local build

```bash
make init
make build-all build-source-jar package-ios checksums
```

Generated files:

- `genotp.aar`
- `Genotp.xcframework.zip`
- `genotp-sources.jar`
- `SHA256SUMS`

## CI/CD

This repository now has two GitHub Actions workflows:

- `CI`: runs `go test`, `gosec`, and `golangci-lint` on pushes and pull requests.
- `Release Artifacts`: on tag push like `v1.2.3` or manual dispatch, builds:
  - Android: `genotp.aar`
  - iOS: `Genotp.xcframework.zip`
  - Sources: `genotp-sources.jar`
  - Checksums: `SHA256SUMS`

When triggered by a tag, the release workflow also uploads those files to the GitHub Release so `genotp-flutter` can consume a versioned artifact instead of a manually copied local build.
