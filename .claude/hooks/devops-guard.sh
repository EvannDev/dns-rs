#!/usr/bin/env bash
# PreToolUse hook of the devops agent. Every Bash call must be made of
# allowlisted programs. Clusters are reached only through an explicit kind
# context: the user's kubeconfig also holds production clusters. Nothing is
# published (images, charts, releases) and git and GitHub are read only.
# Exit code 2 blocks the call and shows the reason to the agent.
#
# Tests: .claude/hooks/test-devops-guard.sh
set -u

GUARD_NAME=devops
GUARD_ALLOWED="kubectl and helm on an explicit kind-* context, offline helm, kind, local docker builds and runs, curl and dig on loopback, read-only gh run/pr/workflow, actionlint, shellcheck, cargo build/test/lint, read-only git, the guard tests, and text tools"
# shellcheck source=guard-lib.sh
. "$(dirname "$0")/guard-lib.sh"

# A pointer to another cluster or kubeconfig, even inside a container.
case $command in
  *.kube* | *KUBECONFIG*) block "a reference to .kube or KUBECONFIG" ;;
esac

# Every context flag must name a kind cluster, and at least one must be
# given: without it, kubectl and helm use the user's current context.
# Prints nothing; returns 1 when no context flag is present.
check_context() {
  local tool=$1 flag=$2 found=1
  shift 2
  while [ $# -gt 0 ]; do
    case $1 in
      "$flag")
        [ $# -ge 2 ] || block "$tool $flag without a value"
        [[ $2 == kind-* ]] || block "$tool $flag $2"
        found=0
        shift
        ;;
      "$flag"=*)
        [[ ${1#*=} == kind-* ]] || block "$tool $1"
        found=0
        ;;
    esac
    shift
  done
  return $found
}

# The first word that is neither an option nor an option's value.
subcommand() {
  while [ $# -gt 0 ]; do
    case $1 in
      # A dangling option must not loop: `shift 2` fails without shifting.
      --context | --kube-context | -n | --namespace) if [ $# -ge 2 ]; then shift 2; else shift; fi ;;
      -*) shift ;;
      *)
        echo "$1"
        return
        ;;
    esac
  done
}

check_kubectl() {
  local word
  for word in "$@"; do
    case $word in
      --kubeconfig* | --server* | --cluster* | --token* | --user* | -s) block "kubectl ${word%%=*}" ;;
    esac
  done
  [ "$(subcommand "$@")" != config ] || block "kubectl config"
  check_context kubectl --context "$@" || block "kubectl without --context=kind-*"
}

check_helm() {
  local word sub
  for word in "$@"; do
    case $word in
      --kubeconfig* | --kube-apiserver* | --kube-token* | --kube-as-* | --validate*) block "helm ${word%%=*}" ;;
    esac
  done
  sub=$(subcommand "$@")
  case $sub in
    "") block "helm without a subcommand" ;;
    lint | template | show | version | package | env) check_context helm --kube-context "$@" || true ;;
    install | upgrade | uninstall | test | status | list | get | history | rollback)
      check_context helm --kube-context "$@" || block "helm $sub without --kube-context=kind-*"
      ;;
    *) block "helm $sub" ;;
  esac
}

check_kind() {
  case ${1-} in
    "") block "kind without a subcommand" ;;
    create | delete | load | get | export | version) ;;
    *) block "kind $1" ;;
  esac
}

check_docker() {
  local word
  for word in "$@"; do
    case $word in
      --push* | --output* | -o) block "docker ${word%%=*}" ;;
    esac
  done
  case ${1-} in
    build | run | ps | logs | images | inspect | rm | stop | version) ;;
    buildx) [ "${2-}" = build ] || block "docker buildx ${2-}" ;;
    *) block "docker ${1-}" ;;
  esac
}

# Only loopback URLs, and no config file that could add others.
check_curl() {
  local word
  for word in "$@"; do
    case $word in
      -K | --config*) block "curl $word" ;;
      -*) ;;
      http://127.0.0.1 | http://127.0.0.1[:/]* | http://localhost | http://localhost[:/]*) ;;
      *://* | *.*) block "curl $word" ;;
    esac
  done
}

check_gh() {
  case "${1-} ${2-}" in
    " ") block "gh without a subcommand" ;;
    "run list" | "run view" | "run watch" | "pr view" | "pr checks" | "pr diff" | "pr list" | "workflow list" | "workflow view") ;;
    run\ * | pr\ * | workflow\ *) block "gh $1 $2" ;;
    *) block "gh $1" ;;
  esac
}

check_program() {
  local program=$1
  shift
  case $program in
    kubectl) check_kubectl "$@" ;;
    helm) check_helm "$@" ;;
    kind) check_kind "$@" ;;
    docker) check_docker "$@" ;;
    curl) check_curl "$@" ;;
    gh) check_gh "$@" ;;
    cargo) check_cargo "$@" ;;
    git) check_git "$@" ;;
    dig | actionlint | shellcheck | sleep) ;;
    # The guards' own tests, by exact path.
    .claude/hooks/test-devops-guard.sh | .claude/hooks/test-rust-refactor-guard.sh) ;;
    *) is_text_tool "$program" || block "'$program' is not on the allowlist" ;;
  esac
}

run_guard
