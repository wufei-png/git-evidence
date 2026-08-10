# Evidence-based Engineering Activity Reporting

This project turns time-bounded activity from Git hosting platforms into
engineering reports whose claims can be checked against source objects. It
records evidence-backed assertions and coverage limits; it is not a productivity or
performance scoring system.

## Platform model

**Provider**:
An adapter for one Git hosting platform that exposes its native objects and
observations through the project's shared reporting language. A provider may
have capabilities that another provider does not; it must report those limits
instead of presenting an empty result as proof of no activity.

**Provider instance**:
One configured authority for a Provider, with its own credential reference and
collection limits. Repositories refer to it by a stable provider reference;
Provider kind alone does not identify it.
_Avoid_: Provider config, Provider kind config

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

**Assertion**:
A typed, platform-neutral statement about an observed engineering object or
event that a renderer may present. It names its subject and predicate and is
supported by explicit evidence.
_Avoid_: Canonical fact, Fact, summary

**Evidence**:
A stable reference to the source object, API observation, or commit that
supports an assertion. An assertion without evidence is not render-eligible.

**Retrieval**:
The record of one provider response or cache replay from which source objects
were observed. It captures when and how data was obtained; it does not claim
that a requested source was completely covered.
_Avoid_: Coverage observation, evidence

**Evidence bundle**:
The canonical, provenance-preserving audit artifact exchanged between
collection, validation, and rendering. It is sensitive by default even after
credentials are removed and is not itself an anonymous or public artifact.
_Avoid_: Public bundle, anonymous bundle

**Coverage manifest**:
The record of what the run was asked to inspect, what each provider actually
covered, and which limits, failures, or unknown associations remain.

**Disclosed report**:
A rendered report whose visibility has been explicitly approved by its
operator. Render eligibility is a prerequisite, not that approval. Visibility
approval is an external workflow action, not a property of the evidence bundle.

**Render eligibility**:
The validation result that an evidence bundle has sufficient evidence and core
coverage for deterministic rendering. It is not approval to disclose the
bundle or the resulting report to an audience, and successful validation or
rendering never grants that approval.
_Avoid_: Publishable bundle, public-safe bundle

**Agent orchestration adapter**:
An optional client that resolves reporting intent and sequences core commands;
it is not an authority for provider facts, coverage, or disclosure.
_Avoid_: Agent collector, Agent evidence engine

**Work item relation**:
A future, unimplemented evidence-bound statement that a Change request
references or resolves a Work item. An Agent suggestion is only a candidate and
is not a canonical relation; see ADR-0024.
_Avoid_: Inferred Issue link, bare short reference

**Narrative Source Pack**:
A future, unimplemented separate sensitive artifact containing bounded,
digested narrative source material linked to Bundle Assertions and Evidence. It
is not part of the Evidence bundle and does not grant disclosure approval; see
ADR-0025.
_Avoid_: Enriched bundle, Agent context dump

**Collection plan identity**:
A stable digest of the normalized, non-secret collection configuration that
affects scope, source selection, and collection semantics. It groups repeated
executions of the same intent but does not identify an execution or artifact.
_Avoid_: Run ID, invocation ID

**Collection invocation**:
One actual execution of a collection plan, identified independently of its
configuration and output. Repeating the same plan creates a new invocation.
_Avoid_: Run ID, plan ID

**Bundle digest**:
A content digest of one canonical evidence bundle, used to identify the exact
artifact and detect modification. It is neither a plan identity nor an
execution identity.
_Avoid_: Run ID, config hash

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
Provider instance selection, runtime limits, and environment-only credential
references. Report configuration owns profile, language, privacy, and explicit
actor labels. TOML is the sole configuration language; historical shapes are
outside the boundary.

**Privacy default**:
Actors are anonymous unless an explicit actor-ID-to-label map is supplied.
Tokens, credentials, and auth headers are never part of an evidence bundle.
Source URLs may remain evidence after auth query/userinfo redaction, while an
unsafe URL or sensitive payload field blocks render eligibility. The bundle
remains sensitive even when these checks pass.

**Actor identity**:
The provider-qualified identity used to attribute an observation. Its stable
identity may remain in the evidence bundle while display names are hidden
unless a report configuration explicitly allows them.

**Resource-observed change**:
A commit or repository change found through a resource API. It may be shown as
an observed change, but it is not a push/ref-change claim unless the provider
has corresponding ref evidence.

## Boundary language

**Independent domain boundary**:
Git Evidence owns the meanings of repository, provider, capability, coverage,
publication, and privacy as one product context; similarly named terms from
another system are not synonyms.
_Avoid_: Shared domain model, common runtime

**Thin protocol**:
A documentation-level agreement containing only genuinely shared vocabulary or
exchange rules while each context retains its own meaning and ownership.
_Avoid_: Shared implementation, runtime dependency
