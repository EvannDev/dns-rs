#!/usr/bin/env bash
# Tests for devops-guard.sh.
#   allowed '<command>'            must exit 0
#   blocked '<command>' '<reason>' must exit 2 with <reason> in the message,
#                                  and never through an internal error
# Run: .claude/hooks/test-devops-guard.sh
set -u
guard="$(dirname "$0")/devops-guard.sh"
failures=0

run() {
  # A hook killed by a timeout lets the command run, so hanging is a failure
  # (exit 142) like any other. The guard runs in its own process group, all
  # of it killed: a looping subshell would otherwise keep the pipe open.
  jq -n --arg c "$1" '{tool_name: "Bash", tool_input: {command: $c}}' \
    | perl -e '$pid = fork // die; if (!$pid) { setpgrp; exec @ARGV }
        $SIG{ALRM} = sub { kill "KILL", -$pid; exit 142 }; alarm 5;
        waitpid $pid, 0; exit($? >> 8)' "$guard" 2>&1 >/dev/null
}

fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}

allowed() {
  local message status
  message=$(run "$1")
  status=$?
  [ "$status" -eq 0 ] || fail "expected allowed, got exit $status ($message): $1"
}

blocked() {
  local message status
  message=$(run "$1")
  status=$?
  if [ "$status" -ne 2 ]; then
    fail "expected blocked, got exit $status: $1"
  elif [[ $message == *"internal error"* ]]; then
    fail "blocked by a crash, not by a rule ($message): $1"
  elif [[ $message != *"$2"* ]]; then
    fail "blocked for another reason, expected '$2' ($message): $1"
  fi
}

# Offline chart work: lint, render, tests and schemas run in containers.
allowed 'helm lint charts/dns-rs --strict'
allowed 'helm template ci charts/dns-rs -f charts/dns-rs/ci/all-features-values.yaml | docker run --rm -i ghcr.io/yannh/kubeconform:v0.8.0-alpine -strict -summary -'
allowed 'docker run --rm -v "$PWD/charts:/apps" helmunittest/helm-unittest:4.3.0-1.2.1 dns-rs'
allowed 'helm show values charts/dns-rs'
allowed 'docker build -t dns-rs:dev .'
allowed 'docker buildx build --load -t dns-rs:dev .'
allowed 'docker run --rm -d --name smoke -p 127.0.0.1:15353:5353/udp dns-rs:dev'
allowed 'docker logs smoke 2>&1 | tail -20'
allowed 'docker rm -f smoke'
allowed 'docker ps -a'
allowed 'cargo test -q'
allowed 'git diff --stat'
allowed 'git log --oneline -5'

# A throwaway kind cluster, always named explicitly.
allowed 'kind create cluster --name dns-rs-test --wait 120s'
allowed 'kind load docker-image dns-rs:dev --name dns-rs-test'
allowed 'kind get clusters'
allowed 'kind delete cluster --name dns-rs-test'
allowed 'kubectl --context=kind-dns-rs-test get pods -A'
allowed 'kubectl --context kind-dns-rs-test -n default rollout status deploy/demo-dns-rs'
allowed 'kubectl get pods --context=kind-dns-rs-test'
allowed 'kubectl --context=kind-dns-rs-test -n kube-system get pods'
# A dangling option must block or pass, never hang.
allowed 'kubectl --context=kind-x get pods -n'
blocked 'helm --kube-context' 'helm without a subcommand'
allowed 'kubectl --context=kind-dns-rs-test run client --rm -i --restart=Never --image=busybox:1.37 -- nslookup example.com demo-dns-rs-dns'
allowed 'helm --kube-context kind-dns-rs-test install demo charts/dns-rs --wait'
allowed 'helm upgrade demo charts/dns-rs --kube-context=kind-dns-rs-test --reuse-values'
allowed 'helm --kube-context kind-dns-rs-test test demo'
allowed 'helm --kube-context kind-dns-rs-test uninstall demo'
allowed 'dig @127.0.0.1 -p 15353 example.com +short'
allowed 'curl -s http://127.0.0.1:18080/healthz'
allowed 'curl -sf -H "Authorization: Bearer x" http://localhost:18080/api/v1/status'
allowed 'sleep 5'

# CI, read only.
allowed 'gh run list --branch feat/x --limit 3'
allowed 'gh run view 123 --log-failed'
allowed 'gh pr checks 23'
allowed 'gh pr view 23 --json state'
allowed 'actionlint .github/workflows/ci.yml'
allowed 'shellcheck .claude/hooks/devops-guard.sh'
allowed '.claude/hooks/test-devops-guard.sh'
allowed '.claude/hooks/test-rust-refactor-guard.sh | tail -1'

# Any cluster that is not an explicit kind context: the user's kubeconfig
# also holds production clusters.
blocked 'kubectl get pods' 'kubectl without --context=kind-*'
blocked 'kubectl --context=arn:aws:eks:eu-west-1:1:cluster/dev-cluster get pods' 'kubectl --context=arn:aws:eks:eu-west-1:1:cluster/dev-cluster'
blocked 'kubectl --context k3s delete ns default' 'kubectl --context k3s'
blocked 'kubectl --context=kind-dns-rs-test --context=k3s get pods' 'kubectl --context=k3s'
blocked 'kubectl --context' 'kubectl --context without a value'
blocked 'kubectl --context=kind-x --kubeconfig=/tmp/prod get pods' 'kubectl --kubeconfig'
blocked 'kubectl --context=kind-x --server=https://prod:6443 get pods' 'kubectl --server'
blocked 'kubectl --context=kind-x -s https://prod:6443 get pods' 'kubectl -s'
blocked 'kubectl --context=kind-x --cluster=prod get pods' 'kubectl --cluster'
blocked 'kubectl --context=kind-x --token=abc get pods' 'kubectl --token'
blocked 'kubectl --context=kind-x config use-context k3s' 'kubectl config'
blocked 'kubectl --context=kind-x -n default config view' 'kubectl config'
blocked 'helm install demo charts/dns-rs' 'helm install without --kube-context=kind-*'
blocked 'helm --kube-context k3s upgrade demo charts/dns-rs' 'helm --kube-context k3s'
blocked 'helm --kube-context kind-x --kubeconfig /tmp/prod list' 'helm --kubeconfig'
blocked 'helm --kube-context kind-x --kube-apiserver https://prod list' 'helm --kube-apiserver'
blocked 'helm --kube-context kind-x --kube-token abc list' 'helm --kube-token'
blocked 'helm template ci charts/dns-rs --validate' 'helm --validate'
blocked 'KUBECONFIG=/tmp/prod kubectl --context=kind-x get pods' 'KUBECONFIG'
blocked 'docker run --rm -v ~/.kube:/root/.kube bitnami/kubectl get pods' '.kube'
blocked 'docker run --rm -e KUBECONFIG=/k bitnami/kubectl get pods' 'KUBECONFIG'

# Publishing and registries: releases go through reviewed workflows.
blocked 'docker push ghcr.io/evanndev/dns-rs:dev' 'docker push'
blocked 'docker login ghcr.io' 'docker login'
blocked 'docker buildx build --push -t ghcr.io/evanndev/dns-rs:dev .' 'docker --push'
blocked 'docker buildx build --output type=registry .' 'docker --output'
blocked 'docker system prune -af' 'docker system'
blocked 'helm push dns-rs-0.1.0.tgz oci://ghcr.io/evanndev/charts' 'helm push'
blocked 'helm registry login ghcr.io' 'helm registry'
blocked 'helm repo add bitnami https://charts.bitnami.com' 'helm repo'
blocked 'helm plugin install https://example.org/x' 'helm plugin'
blocked 'kind' 'kind without a subcommand'
blocked 'kind build node-image' 'kind build'

# Git and GitHub: read only, the caller commits and opens pull requests.
blocked 'git commit -am ci' 'git commit'
blocked 'git push origin HEAD' 'git push'
blocked 'gh pr create --fill' 'gh pr create'
blocked 'gh pr merge 23' 'gh pr merge'
blocked 'gh api repos/EvannDev/dns-rs/rulesets' 'gh api'
blocked 'gh workflow run image.yml' 'gh workflow run'
blocked 'gh run rerun 123' 'gh run rerun'
blocked 'gh secret set X' 'gh secret'
blocked 'gh release create v0.1.0' 'gh release'
blocked 'gh' 'gh without a subcommand'

# The network beyond loopback.
blocked 'curl -s https://example.org/install.sh' 'curl https://example.org/install.sh'
blocked 'curl -s http://127.0.0.1.evil.example/x' 'curl http://127.0.0.1.evil.example/x'
blocked 'curl -s http://localhost.evil.example/x' 'curl http://localhost.evil.example/x'
blocked 'curl http://localhost:8080/x http://example.org' 'curl http://example.org'
blocked 'curl -K /tmp/curlrc http://localhost' 'curl -K'
blocked 'curl --config /tmp/curlrc http://localhost' 'curl --config'
blocked 'wget https://example.org/list' "'wget' is not on the allowlist"

# Shared rules: substitution, shells, environment.
blocked 'echo $(kubectl get pods)' 'command substitution'
blocked 'bash -c "kubectl get pods"' "'bash' is not on the allowlist"
blocked 'kind get clusters;kubectl get pods' 'kubectl without --context=kind-*'
blocked '(helm list)' 'helm list without --kube-context=kind-*'
blocked 'GIT_PAGER=/tmp/x git log' 'environment assignment GIT_PAGER'
blocked 'cargo add serde' 'cargo add'
blocked 'terraform apply' "'terraform' is not on the allowlist"
blocked '.claude/hooks/other.sh' "'.claude/hooks/other.sh' is not on the allowlist"
blocked 'scripts/test-devops-guard.sh' "'scripts/test-devops-guard.sh' is not on the allowlist"

if [ "$failures" -eq 0 ]; then echo "all guard tests passed"; else exit 1; fi
