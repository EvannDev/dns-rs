# 0015. The API token file is reloaded

- Status: Accepted (amends 0012: token rotation no longer needs a restart)
- Date: 2026-10-17

## Context

ADR 0012 read the API token once at startup, so rotating it needed a
restart. With several replicas, the Helm chart then had two bad options:

- let a rotated Secret reach only pods created later, so replicas would
  accept different tokens;
- roll the pods through an annotation holding a hash of the token. An
  unsalted SHA-256 in the pod spec is readable by anyone allowed to get
  pods and open to offline guessing of weak tokens; a random salt changes
  at every `helm template` and restarts pods at every GitOps sync.

## Decision

- dns-rs reads the token file (`http.api_token_file`, or
  `DNS_RS_API_TOKEN_FILE`) again at each configuration poll (10 s) and on
  `SIGHUP`, and swaps it into the token the API checks per request.
- An invalid or missing file keeps the previous token, logged once and
  never echoing the token.
- `DNS_RS_API_TOKEN`, set in the environment, stays fixed for the
  process lifetime.
- The Helm chart mounts the token Secret (chart-managed or existing) as a
  file; the kubelet updates it when the Secret changes. Nothing derived
  from the token appears in the pod spec.

## Consequences

- A rotation reaches every replica within the kubelet's Secret sync delay
  (about a minute) plus one poll, without restarting pods, for Secrets the
  chart manages and Secrets managed elsewhere alike.
- Disabling the API (removing the token) still needs a restart: a missing
  file keeps the previous token, so a Secret being recreated does not open
  or close the API by accident.
