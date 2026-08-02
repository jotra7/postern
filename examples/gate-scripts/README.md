# Gate scripts

A `kind: gate` service can hand its admissions to an executable instead of to
the local kernel:

```yaml
services:
  ssh:
    kind: gate
    proto: tcp
    ports: [22]
    default_ttl: 120s
    max_ttl: 300s
  ssh-perimeter:
    kind: gate
    proto: tcp
    ports: [22]
    default_ttl: 120s
    max_ttl: 300s
    listener_expectation: unchecked
    backend: script
    script_path: /etc/postern/gate-scripts/aws-security-group.sh
    script_timeout: 20s
```

Both services name port 22 on purpose. `ssh` is the local nftables gate, and
`ssh-perimeter` is the provider firewall in front of it. Postern enforces one
owner per port *per backend*, so this pairing is expressible and two services
on the same backend and port are still refused.

The agent invokes the script with an argument vector, never a shell:

```
<script> open   <service> <source-cidr> <ttl-seconds> <observed|asserted>
<script> close  <service> <source-cidr>
<script> state  <service>
<script> health <service>
```

`state` prints a version header and one admission per line, with the remaining
lifetime in whole seconds or `-` when the target cannot say:

```
postern-state-v1
203.0.113.5/32 observed -
198.51.100.0/24 asserted 84
```

Exit `0` for success, `10` to refuse the request, anything else to fail. The
agent tells the two apart: a refusal is not retried, a failure leaves the lease
in place so the close is still owed.

The script must be an absolute path, owned by root, and writable by nobody
else. That is checked when the config is loaded, not at the first knock, so a
bad mode stops the agent starting while you still have another way in.

**`close` must be idempotent.** The agent re-issues one whenever an open may
have applied partially, and again from its reaper, and again on shutdown.

---

## `aws-security-group.sh`

Adds and removes one ingress rule per admitted source on a single security
group. It shells out to whatever AWS CLI the host already has — postern ships
no AWS SDK.

Configure it with root-owned environment on `posternd.service`:

```ini
# /etc/systemd/system/posternd.service.d/gate-script.conf
[Service]
Environment=POSTERN_SG_ID=sg-0123456789abcdef0
Environment=POSTERN_SG_PORTS=22
Environment=POSTERN_AWS_REGION=eu-west-1
```

Credentials come from wherever the CLI finds them. On EC2 that should be the
instance role, so no long-lived key sits on the host.

### IAM policy

Three actions, scoped to the one group. `DescribeSecurityGroups` does not take
a resource condition, so it is scoped by group id in a condition-free
statement of its own — narrow it further with a tag condition if your account
supports it.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PosternEditOneGroup",
      "Effect": "Allow",
      "Action": [
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress"
      ],
      "Resource": "arn:aws:ec2:eu-west-1:123456789012:security-group/sg-0123456789abcdef0"
    },
    {
      "Sid": "PosternReadGroups",
      "Effect": "Allow",
      "Action": "ec2:DescribeSecurityGroups",
      "Resource": "*"
    }
  ]
}
```

Nothing else. In particular no `ec2:ModifyInstanceAttribute` and no
`ec2:CreateSecurityGroup`: this script edits one group's rules and does not
need the ability to attach a different one.

### The honest caveats

**Security group changes are not instant.** The API returns before the change
has propagated to every path that enforces it. Expect seconds, occasionally
more, between the knock and the connection actually being permitted. A local
nftables gate opens in the time one netlink batch takes; this does not, and a
runbook that says "knock, then ssh immediately" will produce confusing
timeouts.

**The rule persists if the agent dies.** This is the big one, and it applies to
every script backend, not just this script. nftables gives each element a
kernel-owned timeout, so a knocked-open hole closes on schedule even if the
agent is SIGKILLed. A security group rule has no expiry field. The deadline
lives in the agent's own lease store and a goroutine inside the agent acts on
it, so:

- a clean stop withdraws the rules;
- a crash leaves them, until the agent restarts and its reaper catches up;
- an agent that never comes back leaves them indefinitely.

That is strictly weaker than either of postern's documented fail postures. The
config loader warns about it every time such a service is read, and
`fail_posture: closed` is refused outright on a script-backed service, because
the mechanism that posture rests on — a drop rule loaded from `boot.nft` at
boot with no process involved — has no script equivalent.

**Use this alongside the local nftables gate, not instead of it.** Declare both
services as shown at the top of this file. The kernel then holds the local bolt
with a real timeout on it while the script handles the perimeter, so a crashed
agent leaves a security group rule pointing at a port the kernel has already
shut. Replacing the local gate with this one would trade a kernel-enforced
expiry for an API call and a promise.

**Description tags are load-bearing.** Every rule this script creates is
described `postern:<service>`, and `state` reports only rules carrying that
description. A rule you added by hand on the same group is neither reported nor
withdrawn. Do not edit the descriptions of postern's rules in the console.

### Trying it without an account

The script takes its CLI from `POSTERN_AWS_CLI`, so it can be driven against a
stub:

```sh
POSTERN_AWS_CLI=/tmp/fake-aws POSTERN_SG_ID=sg-test POSTERN_SG_PORTS=22 \
  ./aws-security-group.sh open ssh-perimeter 203.0.113.5/32 120 observed
```

`internal/gate`'s test suite does exactly this, so the example is executed on
every run rather than only read.
