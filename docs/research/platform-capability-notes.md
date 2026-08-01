# Platform capability notes

These notes keep provider design tied to documented platform behavior. They
are not a claim that every endpoint has already been implemented.

## GitLab

GitLab's Events API documents missing detail for some merge-request
discussion notes and for bulk push events. A bulk push may expose ref counts
without individual ref or commit attributes, so activity discovery cannot be
the only source used to prove commit coverage.

- [GitLab Events API](https://docs.gitlab.com/api/events/)
- [GitLab Merge Requests API](https://docs.gitlab.com/api/merge_requests/)

## GitHub

GitHub's Issues API can return pull requests because a pull request is also
represented as an issue. Provider normalization must inspect the PR marker and
then use pull-request endpoints for review-specific data. Pull-request commit
lists are paginated and have a documented limit, so the provider must record
when a separate commit listing is required.

- [GitHub Issues REST API](https://docs.github.com/en/rest/issues/issues)
- [GitHub Pull Requests REST API](https://docs.github.com/en/rest/pulls/pulls)
- [GitHub Commits REST API](https://docs.github.com/en/rest/commits/commits)
- [GitHub Events REST API](https://docs.github.com/en/rest/activity/events)

## Gitee

Gitee must be treated as an independent provider rather than a GitHub-shaped
endpoint wrapper. Its public API documentation exposes separate repository
Issue and Pull Request surfaces and page/per-page parameters, but the exact
activity, review, association, and enterprise-host behavior must be captured
in provider fixtures before those capabilities are advertised. The v5 API
surface commonly documents `access_token` as a request parameter, so the
experimental adapter uses a redacted query-token transport rather than
assuming GitHub's Authorization header convention.

Activity/ref remains `unsupported` in the adapter. A provider-shaped endpoint
found in a generated client or a third-party example is not enough to claim
stable semantics for retention, pagination, push payloads, or ref attribution.

- [Gitee Pull Requests API documentation](https://gitee.com/organizations/api-docs/pull_requests)

## Design consequence

The shared contract covers the minimum concepts needed for an evidence-based
report. Native capabilities remain explicit provider metadata. “Not supported”
and “not observed because the endpoint was incomplete” are different coverage
states and must not be collapsed into an empty successful result.
