# Gem Release Process

Don't use the `bundle exec rake release` task. It is more convenient,
but it skips the process of signing the version release task.

## Run Tests

```sh
$ bundle exec rake test
```

## Git Push

```sh
$ git push
```

Check for regressions in automated tests covered by the README badges.

## Bump Version Number and edit CHANGELOG.md

```sh
$ vi lib/sirp/version.rb
$ git add lib/sirp/version.rb
$ vi CHANGELOG.md
$ git add CHANGELOG.md
```

## Local Build and Install w/ Signed Gem

The `build` step should ask for PEM passphrase to sign gem. If it does
not ask it means that the signing cert is not present.

Build:

```sh
$ rake build
Enter PEM pass phrase:
sirp x.x.x built to pkg/sirp-x.x.x.gem
```

Install locally w/ Cert:

```sh
$ gem uninstall sirp
$ rbenv rehash
$ gem install pkg/tss-x.x.x.gem -P MediumSecurity
Successfully installed sirp-x.x.x
1 gem installed
```

## Git Commit Version and CHANGELOG Changes, Tag and push to Github

```sh
$ git add lib/tss/version.rb
$ git add CHANGELOG.md
$ git commit -m 'Bump version v2.0.0'
$ git tag -s v2.0.0 -m "v2.0.0" SHA1_OF_COMMIT
```

Verify last commit and last tag are GPG signed:

```
$ git tag -v v2.0.0
...
gpg: Good signature from "Glenn Rempe (Code Signing Key) <glenn@rempe.us>" [ultimate]
...
```

```
$ git log --show-signature
...
gpg: Good signature from "Glenn Rempe (Code Signing Key) <glenn@rempe.us>" [ultimate]
...
```

Push code and tags to GitHub:

```
$ git push
$ git push --tags
```

## Push gem to Rubygems.org

```sh
$ gem push pkg/sirp-2.0.0.gem
```

Verify Gem Push at [https://rubygems.org/gems/sirp](https://rubygems.org/gems/sirp)

## Create a GitHub Release

Specify the tag we just pushed to attach release to. Copy notes from CHANGELOG.md

[https://github.com/grempe/sirp/releases](https://github.com/grempe/sirp/releases)

## Announce Release on Twitter

The normal blah, blah, blah.
