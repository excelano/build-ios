# build-ios

build-ios archives, signs and uploads Excelano's iOS apps on GitHub's hosted Xcode runner, so a release is built with the Xcode and SDK that App Store Connect requires without a Mac of that generation on hand. `build-release` and `ship-appstore` in `excelano/shipping` dispatch its workflows; nobody runs them by hand in the course of a release.

The `build` workflow checks out an app's repository at a commit, signs every target under the app's bundle id with the runner's own Apple Distribution certificate and the App Store profile for that bundle id, and keeps the exported `.ipa` as the run's artifact. The `upload` workflow takes the `.ipa` attached to an app's GitHub release, validates it with `altool`, and uploads it to App Store Connect.

## What the repository holds

The `DIST_P12` secret is an Apple Distribution identity whose key exists only here, so revoking its certificate in the developer portal cuts the runner off without touching any other machine, and `DIST_P12_PASSWORD` opens it. `ASC_KEY_P8` is an App Store Connect API key of its own, named by the `ASC_KEY_ID` and `ASC_ISSUER_ID` variables, with the App Manager role.

## Profiles

The runner reads profiles and never makes them. An app's profiles have to list the runner's certificate, which `provision-appstore` arranges by putting every Distribution certificate the team holds on each profile it makes. When the `build` workflow stops with no profile for a bundle id, run `provision-appstore` in the app's repository.
