#!/bin/sh
#
# postern gate script: AWS security group.
#
# Opens and closes one ingress rule per admitted source on a single security
# group, so a knock that opens the local nftables gate on the instance also
# opens the perimeter in front of it.
#
# Read examples/gate-scripts/README.md before deploying this. In particular:
# security group changes are eventually consistent, the rule persists if the
# agent dies, and this is meant to run *alongside* the local nftables gate,
# not instead of it.
#
# Contract (internal/gate/script.go):
#
#   $0 open   <service> <source-cidr> <ttl-seconds> <observed|asserted>
#   $0 close  <service> <source-cidr>
#   $0 state  <service>
#   $0 health <service>
#
# Exit 0 on success, 10 to refuse, anything else to fail.
#
# Configuration, by environment. Set these in a root-owned drop-in on
# posternd.service — an EnvironmentFile, or Environment= lines — the same way
# any other agent setting is set:
#
#   POSTERN_SG_ID        required. The security group to edit, sg-0123....
#   POSTERN_SG_PORTS     required. Comma-separated ports, e.g. "22" or "22,443".
#   POSTERN_SG_PROTO     optional, default tcp.
#   POSTERN_AWS_REGION   optional. Passed as --region when set.
#   POSTERN_AWS_CLI      optional, default "aws". The CLI to invoke; overriding
#                        it is how this script is exercised in a test without
#                        an AWS account.
#
# Credentials come from wherever the AWS CLI finds them. On EC2 that should be
# the instance role, which is the point: no long-lived key on the host.

set -eu

EXIT_REFUSED=10

AWS="${POSTERN_AWS_CLI:-aws}"
PROTO="${POSTERN_SG_PROTO:-tcp}"

die() {
	echo "aws-security-group.sh: $1" >&2
	exit "${2:-1}"
}

refuse() {
	echo "aws-security-group.sh: refused: $1" >&2
	exit "$EXIT_REFUSED"
}

require_env() {
	[ -n "${POSTERN_SG_ID:-}" ] || die "POSTERN_SG_ID is not set"
	[ -n "${POSTERN_SG_PORTS:-}" ] || die "POSTERN_SG_PORTS is not set"
}

# aws_cli runs the CLI with the region flag only when one was configured, so
# an instance that gets its region from IMDS is not overridden.
aws_cli() {
	if [ -n "${POSTERN_AWS_REGION:-}" ]; then
		"$AWS" --region "$POSTERN_AWS_REGION" "$@"
	else
		"$AWS" "$@"
	fi
}

# ip_permissions renders the --ip-permissions argument for one port and one
# CIDR. The description carries the service name so a human reading the
# console can tell a postern rule from a hand-made one, and so `state` can
# report only the rules this tool owns.
#
# IPv6 sources go in Ipv6Ranges, not IpRanges: AWS rejects a v6 CIDR in the v4
# field, and a script that guessed would fail every asserted IPv6 grant.
ip_permissions() {
	port="$1"
	cidr="$2"
	service="$3"
	case "$cidr" in
	*:*)
		printf 'IpProtocol=%s,FromPort=%s,ToPort=%s,Ipv6Ranges=[{CidrIpv6=%s,Description=%s}]' \
			"$PROTO" "$port" "$port" "$cidr" "postern:$service"
		;;
	*)
		printf 'IpProtocol=%s,FromPort=%s,ToPort=%s,IpRanges=[{CidrIp=%s,Description=%s}]' \
			"$PROTO" "$port" "$port" "$cidr" "postern:$service"
		;;
	esac
}

# each_port runs a command per configured port. POSTERN_SG_PORTS is
# comma-separated; IFS is restored afterwards so nothing else in the script
# inherits it.
each_port() {
	oldifs="$IFS"
	IFS=,
	# Deliberately unquoted: this is the word split the comma-separated list
	# is for.
	# shellcheck disable=SC2086
	set -- $POSTERN_SG_PORTS
	IFS="$oldifs"
	for port in "$@"; do
		[ -n "$port" ] || continue
		echo "$port"
	done
}

validate_cidr() {
	case "$1" in
	"" | *[!0-9a-fA-F.:/]*)
		refuse "source $1 is not a CIDR this script will pass to the AWS API"
		;;
	*/*) : ;;
	*) refuse "source $1 has no prefix length" ;;
	esac
}

cmd_open() {
	service="$1"
	cidr="$2"
	# $3 is the ttl in seconds, and this script ignores it on purpose: a
	# security group rule has no expiry field, so the deadline is the agent's
	# to keep. See the README's honest caveats.
	validate_cidr "$cidr"
	require_env

	rc=0
	for port in $(each_port); do
		# Already-present rules come back as
		# InvalidPermission.Duplicate, which is success for our purposes: a
		# re-knock from the same source must not fail.
		out="$(aws_cli ec2 authorize-security-group-ingress \
			--group-id "$POSTERN_SG_ID" \
			--ip-permissions "$(ip_permissions "$port" "$cidr" "$service")" 2>&1)" || {
			case "$out" in
			*InvalidPermission.Duplicate*) continue ;;
			*) echo "$out" >&2; rc=1 ;;
			esac
		}
	done
	return "$rc"
}

cmd_close() {
	service="$1"
	cidr="$2"
	validate_cidr "$cidr"
	require_env

	rc=0
	for port in $(each_port); do
		# Revoking a rule that is not there returns
		# InvalidPermission.NotFound. That is the expected outcome of an
		# idempotent close — the agent re-issues one whenever an open may have
		# applied partially — so it is success, not failure.
		out="$(aws_cli ec2 revoke-security-group-ingress \
			--group-id "$POSTERN_SG_ID" \
			--ip-permissions "$(ip_permissions "$port" "$cidr" "$service")" 2>&1)" || {
			case "$out" in
			*InvalidPermission.NotFound*) continue ;;
			*) echo "$out" >&2; rc=1 ;;
			esac
		}
	done
	return "$rc"
}

# cmd_state prints the sources this script owns on the group, in the format
# internal/gate parses. The expiry column is always "-": a security group rule
# carries no remaining lifetime, and the agent fills it in from its own lease
# store.
#
# Only rules whose description is "postern:<service>" are reported, so a
# hand-made rule on the same group is neither claimed nor withdrawn.
cmd_state() {
	service="$1"
	require_env

	echo postern-state-v1
	first_port="$(each_port | head -n 1)"
	aws_cli ec2 describe-security-groups \
		--group-ids "$POSTERN_SG_ID" \
		--query "SecurityGroups[0].IpPermissions[?FromPort==\`$first_port\`].[IpRanges[?Description=='postern:$service'].CidrIp,Ipv6Ranges[?Description=='postern:$service'].CidrIpv6]" \
		--output text |
		tr '\t' '\n' |
		while read -r cidr; do
			case "$cidr" in
			"" | None) continue ;;
			esac
			# Every source postern admits through this script is reported as
			# observed. The distinction only matters to a target that treats
			# ranges differently from single addresses, and a security group
			# does not.
			echo "$cidr observed -"
		done
}

# cmd_health proves the three things an open would need: the configuration is
# present, the CLI exists, and the credentials in scope can actually read the
# group. It reads rather than writes, so running it on a schedule changes
# nothing.
cmd_health() {
	require_env
	command -v "$AWS" >/dev/null 2>&1 || die "the AWS CLI ($AWS) is not on PATH"
	aws_cli ec2 describe-security-groups --group-ids "$POSTERN_SG_ID" >/dev/null
}

[ "$#" -ge 2 ] || die "usage: $0 <open|close|state|health> <service> [args...]"
verb="$1"
service="$2"
shift 2

case "$verb" in
open)
	[ "$#" -ge 2 ] || die "open needs <source> <ttl-seconds> [kind]"
	cmd_open "$service" "$1" "$2"
	;;
close)
	[ "$#" -ge 1 ] || die "close needs <source>"
	cmd_close "$service" "$1"
	;;
state)
	cmd_state "$service"
	;;
health)
	cmd_health
	;;
*)
	die "unknown verb: $verb"
	;;
esac
