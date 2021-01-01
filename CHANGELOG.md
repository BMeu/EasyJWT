# Changelog

This project follows semantic versioning.

Possible log types:

* `[added]` for new features.
* `[changed]` for changes in existing functionality.
* `[deprecated]` for once-stable features removed in upcoming releases.
* `[removed]` for deprecated features removed in this release.
* `[fixed]` for any bug fixes.
* `[security]` to invite users to upgrade in case of vulnerabilities.

## 0.2.0 (January 1<sup>st</sup>, 2021)
 * `[fixed]` Compatibility with updated dependencies.
 * Lock dependencies.

## 0.1.1 (May 10<sup>th</sup>, 2019)
 * `[fixed]` Fix typing of the `verify()` method for correct type checks in subclasses.
 * Improve API documentation.

## 0.1.0 (May 5<sup>th</sup>, 2019)

 * Initial release of EasyJWT
 * `[added]` Support optional claims.
 * `[added]` Support all registered JWT claims: `aud`, `exp`, `iat`, `iss`, `jti`, `nbf`, and `sub`.
 * `[added]` Allow disabling strict verification of tokens to support arbitrary token issuers.
