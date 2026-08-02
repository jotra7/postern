package gate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The AWS example is executed here rather than only read, against a stub CLI,
// so it cannot rot into pseudocode. No AWS account, credentials, or aws(1)
// binary are involved: the script takes its CLI from POSTERN_AWS_CLI.
const exampleAWSScript = "../../examples/gate-scripts/aws-security-group.sh"

// fakeAWS writes a stub `aws` that records its argv and answers
// describe-security-groups with two CIDRs in the --output text shape the real
// CLI produces for the example's --query.
func fakeAWS(t *testing.T, logPath string) string {
	t.Helper()

	body := `#!/bin/sh
printf '%s\n' "$*" >> "` + logPath + `"
for arg in "$@"; do
	if [ "$arg" = describe-security-groups ]; then
		printf '203.0.113.5/32\tNone\n'
		printf 'None\t2001:db8::1/128\n'
		exit 0
	fi
done
exit 0
`
	path := filepath.Join(t.TempDir(), "fake-aws")
	//nolint:gosec // G306: a stub the test then executes; it has to be executable
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatalf("write fake aws: %v", err)
	}
	return path
}

// runExample invokes the example through this package's own invoke, so the
// argument vector the script sees is exactly the one a live agent would send.
// env overrides the working defaults, which is how a test drives the
// misconfigured case.
func runExample(t *testing.T, awsPath string, env map[string]string, args ...string) (string, error) {
	t.Helper()

	path, err := filepath.Abs(exampleAWSScript)
	if err != nil {
		t.Fatalf("resolve the example script: %v", err)
	}
	for k, v := range map[string]string{
		"POSTERN_AWS_CLI":  awsPath,
		"POSTERN_SG_ID":    "sg-0123456789abcdef0",
		"POSTERN_SG_PORTS": "22",
	} {
		if override, ok := env[k]; ok {
			v = override
		}
		t.Setenv(k, v)
	}

	svc := scriptService{name: "ssh-perimeter", path: path, timeout: 20 * time.Second}
	res, err := (&Script{}).invoke(t.Context(), svc, args[0], args[1:]...)
	return string(res.stdout), err
}

// open must reach the authorize call with the source in the v4 range field
// and the service name in the description, because `state` later reports only
// the rules carrying that description.
func TestGate_ExampleAWSScript_OpenAuthorizesTheSourceOnTheGroup(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "aws.log")
	aws := fakeAWS(t, logPath)

	if _, err := runExample(t, aws, nil, "open", "ssh-perimeter", "203.0.113.5/32", "120", "observed"); err != nil {
		t.Fatalf("open: %v", err)
	}

	got := strings.Join(invocationLog(t, logPath), "\n")
	for _, want := range []string{
		"ec2 authorize-security-group-ingress",
		"--group-id sg-0123456789abcdef0",
		"IpRanges=[{CidrIp=203.0.113.5/32,Description=postern:ssh-perimeter}]",
		"FromPort=22,ToPort=22",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the authorize call is missing %q:\n%s", want, got)
		}
	}
}

// An IPv6 source has to go in Ipv6Ranges. AWS rejects a v6 CIDR in the v4
// field, so a script that guessed would fail every asserted IPv6 grant.
func TestGate_ExampleAWSScript_OpenUsesTheIPv6RangeFieldForAnIPv6Source(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "aws.log")
	aws := fakeAWS(t, logPath)

	if _, err := runExample(t, aws, nil, "open", "ssh-perimeter", "2001:db8::/64", "120", "asserted"); err != nil {
		t.Fatalf("open: %v", err)
	}

	got := strings.Join(invocationLog(t, logPath), "\n")
	if !strings.Contains(got, "Ipv6Ranges=[{CidrIpv6=2001:db8::/64,Description=postern:ssh-perimeter}]") {
		t.Errorf("the authorize call did not use Ipv6Ranges:\n%s", got)
	}
	if strings.Contains(got, "CidrIp=2001") {
		t.Errorf("an IPv6 source was passed in the IPv4 range field:\n%s", got)
	}
}

func TestGate_ExampleAWSScript_CloseRevokesTheSource(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "aws.log")
	aws := fakeAWS(t, logPath)

	if _, err := runExample(t, aws, nil, "close", "ssh-perimeter", "203.0.113.5/32"); err != nil {
		t.Fatalf("close: %v", err)
	}
	got := strings.Join(invocationLog(t, logPath), "\n")
	if !strings.Contains(got, "ec2 revoke-security-group-ingress") {
		t.Errorf("close did not revoke:\n%s", got)
	}
}

// The example's state output has to satisfy this package's own parser, or the
// worked example would be one nobody could actually deploy.
func TestGate_ExampleAWSScript_StateOutputParses(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "aws.log")
	aws := fakeAWS(t, logPath)

	out, err := runExample(t, aws, nil, "state", "ssh-perimeter")
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	elems, err := parseScriptState([]byte(out))
	if err != nil {
		t.Fatalf("the example's state output does not parse: %v\n---\n%s", err, out)
	}
	if len(elems) != 2 {
		t.Fatalf("elements = %d, want 2:\n%s", len(elems), out)
	}
	if got := elems[0].Source.Prefix.String(); got != "203.0.113.5/32" {
		t.Errorf("element 0 = %q", got)
	}
	if got := elems[1].Source.Prefix.String(); got != "2001:db8::1/128" {
		t.Errorf("element 1 = %q", got)
	}
}

// A source the script will not hand to the AWS API is refused with the
// contract's refusal code, not with a generic failure, so the agent can tell
// "declined" from "went wrong".
func TestGate_ExampleAWSScript_RefusesASourceWithNoPrefixLength(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "aws.log")
	aws := fakeAWS(t, logPath)

	_, err := runExample(t, aws, nil, "open", "ssh-perimeter", "203.0.113.5", "120", "observed")
	if err == nil {
		t.Fatal("open accepted a source with no prefix length")
	}
	if !strings.Contains(err.Error(), "exited 10") {
		t.Errorf("error = %v, want the contract's refusal exit code", err)
	}
}

// Missing configuration is a failure, not a refusal: it is the operator's
// deployment that is wrong, and the agent should keep retrying rather than
// treating the request as declined.
func TestGate_ExampleAWSScript_FailsWhenTheGroupIsNotConfigured(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "aws.log")
	aws := fakeAWS(t, logPath)

	_, err := runExample(t, aws, map[string]string{"POSTERN_SG_ID": ""},
		"open", "ssh-perimeter", "203.0.113.5/32", "120", "observed")
	if err == nil {
		t.Fatal("open succeeded with no security group configured")
	}
	if strings.Contains(err.Error(), "exited 10") {
		t.Errorf("a misconfiguration was reported as a refusal: %v", err)
	}
}
