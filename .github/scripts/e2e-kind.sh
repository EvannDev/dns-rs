#!/usr/bin/env bash
# End-to-end test of the Helm chart in a kind cluster, with an image already
# loaded into it:
#   - `helm test` passes;
#   - dns-rs resolves through its upstream (the cluster's DNS, so nothing
#     leaves the cluster) and blocks a denied name;
#   - a configuration change reaches every replica without a restart.
#
# Usage: e2e-kind.sh <kube context> <image repository:tag>
# The context must be a kind cluster: the script installs and deletes there.
set -euo pipefail
context=$1 image=$2
[[ $context == kind-* ]] || { echo "refusing to run on $context: not a kind cluster" >&2; exit 2; }
namespace=dns-rs-e2e
release=e2e
values=charts/dns-rs/ci/e2e-values.yaml
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

k() { kubectl --context "$context" -n "$namespace" "$@"; }
h() { helm --kube-context "$context" -n "$namespace" "$@"; }

# Asks <server> on <port> for <name> from the client pod; prints the answer.
ask() { k exec client -- dig "@$1" -p "$2" +short +tries=3 +time=2 "$3"; }

# Waits up to <seconds> until <command…> prints <expected>.
eventually() {
  local seconds=$1 expected=$2 got=""
  shift 2
  for _ in $(seq 1 "$seconds"); do
    got=$("$@" 2>/dev/null || true)
    [ "$got" = "$expected" ] && return 0
    sleep 1
  done
  echo "timed out: '$*' printed '$got', expected '$expected'" >&2
  return 1
}

dns_pods() {
  k get pods -l "app.kubernetes.io/name=dns-rs,app.kubernetes.io/instance=$release" \
    -o jsonpath="{.items[*].$1}"
}

echo "== install"
upstream=$(kubectl --context "$context" -n kube-system get service kube-dns -o jsonpath='{.spec.clusterIP}')
h install "$release" charts/dns-rs --create-namespace -f "$values" \
  --set image.repository="${image%:*}" --set image.tag="${image##*:}" \
  --set upstream.server="$upstream:53" --wait --timeout 3m

echo "== helm test"
h test "$release" --logs --timeout 2m

echo "== resolution and blocking through the Service"
k run client --image=registry.k8s.io/e2e-test-images/jessie-dnsutils:1.7 \
  --restart=Never --command -- sleep 3600 >/dev/null
k wait --for=condition=Ready pod/client --timeout=2m >/dev/null
service="$release-dns-rs-dns"
kubernetes_ip=$(kubectl --context "$context" -n default get service kubernetes -o jsonpath='{.spec.clusterIP}')
eventually 10 "$kubernetes_ip" ask "$service" 53 kubernetes.default.svc.cluster.local
eventually 10 0.0.0.0 ask "$service" 53 blocked.e2e.test
echo "resolved through the upstream, blocked by the deny rule"

echo "== hot reload on every replica"
names_before=$(dns_pods metadata.name)
cat >"$work/config.toml" <<'TOML'
[blocking]
mode = "null"
deny = ["blocked.e2e.test", "reloaded.e2e.test"]
TOML
h upgrade "$release" charts/dns-rs --reuse-values --set-file config="$work/config.toml" --wait --timeout 2m
# The kubelet refreshes ConfigMap volumes within about a minute; dns-rs
# polls every 10 s. Each replica is asked directly, on its pod IP and the
# port the chart gives the container.
port=$(dns_pods 'spec.containers[0].ports[?(@.name=="dns-udp")].containerPort' | cut -d' ' -f1)
for ip in $(dns_pods status.podIP); do
  eventually 150 0.0.0.0 ask "$ip" "$port" reloaded.e2e.test
  echo "replica $ip reloaded"
done
[ "$(dns_pods metadata.name)" = "$names_before" ] || { echo "pods were replaced" >&2; exit 1; }
restarts=$(dns_pods 'status.containerStatuses[0].restartCount')
[ "$(echo "$restarts" | tr -d ' 0')" = "" ] || { echo "restarts: $restarts" >&2; exit 1; }
echo "same pods, no restart"

echo "e2e passed"
