# Evidence-based Engineering Activity Reporting

This project turns time-bounded activity from Git hosting platforms into
engineering reports whose claims can be checked against source objects. It
records engineering facts and coverage limits; it is not a productivity or
performance scoring system.

## Platform model

**Provider**:
An adapter for one Git hosting platform that exposes its native objects and
observations through the project's shared reporting language. A provider may
have capabilities that another provider does not; it must report those limits
instead of presenting an empty result as proof of no activity.

**Change request**:
A review-and-integration work item such as a GitLab merge request, GitHub pull
request, or Gitee pull request.
_Avoid_: MR as a cross-platform term, PR as a universal term

**Work item**:
A trackable engineering request such as an Issue, issue-like item, or change
request that can provide context for a report fact.

**Activity**:
A platform observation that something happened during a report window. An
activity is not automatically a report claim until it has been normalized and
supported by evidence.

**Resource API**:
An object-oriented platform interface used as the primary source for
repositories, work items, change requests, interactions, commits, and
releases. Resource results define what the report can claim about those
objects.

**Activity API**:
An optional event or activity stream used for candidate discovery, push/ref
attribution, and cross-checking. It cannot by itself prove complete push/ref
coverage.

**Ref change**:
A provider-observed update to a branch, tag, or other ref, distinct from a
commit observed through a resource API. Its association with a change request
must remain explicit and may be unknown or ambiguous.

**Repository allowlist**:
The explicit set of repositories or projects that a report run is authorized
and expected to inspect. An absent repository is outside the report scope, not
evidence that it had no activity.

## Evidence and publication

**Canonical fact**:
A platform-neutral statement about an observed engineering change, work item,
interaction, release, or ref update that the renderer is allowed to present.

**Evidence**:
A stable reference to the source object, API observation, or commit that
supports a canonical fact. A summary without evidence is not publishable.

**Coverage manifest**:
The record of what the run was asked to inspect, what each provider actually
covered, and which limits, failures, or unknown associations remain.

**Publishable report**:
A rendered report produced only after the evidence and coverage checks pass.
An incomplete run may produce diagnostics and an evidence bundle, but not a
successful publication artifact.

**Change association**:
The confidence state connecting a commit or ref change to a change request:
`linked`, `unlinked`, `ambiguous`, or `unknown`. `unlinked` is a bounded result
of the available checks; it is not a judgment about how work was performed.

**Report profile**:
A reader-facing policy for grouping, ordering, wording, redaction, and output
format. It must not decide whether source data is complete or invent evidence.

**Capability state**:
The result for a provider feature: `supported`, `unsupported`, `unavailable`,
or `incomplete`. It describes what the run and provider can establish, not a
quality score for the provider.

**Failure class**:
The operational cause attached to a coverage diagnostic, such as
`permission_denied`, `rate_limited`, `service_error`, `not_found`, or
`malformed_response`. It explains why a capability state was not supported; it
does not replace the capability state.

**Configuration boundary**:
Collection configuration owns the time window, repository/actor allowlists,
provider registry selection, runtime limits, and environment-only credential
references. Report configuration owns profile, language, privacy, and explicit
actor labels. The two domains are independently validated; the compatibility
single-file loader may validate both, but `collect` and `render` consume only
their respective domains.

**Privacy default**:
Actors are anonymous unless an explicit actor-ID-to-label map is supplied.
Tokens, credentials, and auth headers are never part of a public bundle. Source
URLs may remain evidence after auth query/userinfo redaction, while an unsafe
URL or sensitive payload field blocks publication.

**Actor identity**:
The provider-qualified identity used to attribute an observation. Its stable
identity may remain in the evidence bundle while display names are hidden
unless a report configuration explicitly allows them.

**Resource-observed change**:
A commit or repository change found through a resource API. It may be shown as
an observed change, but it is not a push/ref-change claim unless the provider
has corresponding ref evidence.
