package assessment

import (
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

func checklist() *assessmentv1.Checklist {
	return &assessmentv1.Checklist{Checks: []*assessmentv1.Check{
		{CheckId: "shadow.permissions", Title: "/etc/shadow is read by root and shadow only", Test: &assessmentv1.Check_File{File: &assessmentv1.FileTest{
			Path: "/etc/shadow", Presence: assessmentv1.Presence_PRESENCE_REQUIRED, Kind: assessmentv1.FileTest_KIND_REGULAR,
			UserId: proto.Uint32(0), Permissions: proto.Uint32(0o640),
		}}},
		{CheckId: "hosts.equiv", Test: &assessmentv1.Check_File{File: &assessmentv1.FileTest{
			Path: "/etc/hosts.equiv", Presence: assessmentv1.Presence_PRESENCE_FORBIDDEN,
		}}},
		{CheckId: "superuser", Test: &assessmentv1.Check_Account{Account: &assessmentv1.AccountTest{
			Rule: assessmentv1.AccountTest_RULE_ONLY_ROOT_HAS_USER_ID_0,
		}}},
		{CheckId: "shadow.members", Test: &assessmentv1.Check_Account{Account: &assessmentv1.AccountTest{
			Rule: assessmentv1.AccountTest_RULE_GROUP_HAS_NO_MEMBERS, Group: "shadow",
		}}},
		{CheckId: "forwarding", Test: &assessmentv1.Check_KernelParameter{KernelParameter: &assessmentv1.KernelParameterTest{
			Name: "net.ipv4.ip_forward", Allowed: []string{"0"},
		}}},
		{CheckId: "vlan.filter", Test: &assessmentv1.Check_KernelParameter{KernelParameter: &assessmentv1.KernelParameterTest{
			Name: "net.ipv4.conf.eth0/100.rp_filter", Presence: assessmentv1.Presence_PRESENCE_REQUIRED, AtLeast: proto.Int64(1),
		}}},
		{CheckId: "cramfs", Test: &assessmentv1.Check_KernelModule{KernelModule: &assessmentv1.KernelModuleTest{
			Name: "cramfs", Loaded: assessmentv1.Presence_PRESENCE_FORBIDDEN, Disabled: true,
		}}},
		{CheckId: "telnetd", Test: &assessmentv1.Check_Package{Package: &assessmentv1.PackageTest{
			Name: "telnetd", Presence: assessmentv1.Presence_PRESENCE_FORBIDDEN,
		}}},
		{CheckId: "rpcbind", Test: &assessmentv1.Check_Service{Service: &assessmentv1.ServiceTest{
			Unit: "rpcbind.socket", Startup: assessmentv1.ServiceTest_STARTUP_MASKED,
		}}},
		{CheckId: "ssh.root-login", Test: &assessmentv1.Check_Directive{Directive: &assessmentv1.DirectiveTest{
			Source: assessmentv1.DirectiveTest_SOURCE_SSHD, Name: "PermitRootLogin", Assumed: "prohibit-password",
			Allowed: []string{"no", "prohibit-password"},
		}}},
		{CheckId: "umask", Test: &assessmentv1.Check_Directive{Directive: &assessmentv1.DirectiveTest{
			Source: assessmentv1.DirectiveTest_SOURCE_LOGIN_DEFS, Name: "UMASK", Assumed: "022", AtLeast: proto.Int64(0o27),
		}}},
	}}
}

func with(index int, change func(*assessmentv1.Check)) *assessmentv1.Checklist {
	held := checklist()
	change(held.Checks[index])
	return held
}

func TestAChecklistOfEveryTestHoldsNoProblem(t *testing.T) {
	if found := ValidateChecklist(checklist()); len(found) > 0 {
		t.Fatalf("a well formed checklist was refused: %v", found)
	}
}

func TestEveryCheckThatBreaksTheContractIsNamed(t *testing.T) {
	file := func(c *assessmentv1.Check) *assessmentv1.FileTest { return c.GetFile() }
	parameter := func(c *assessmentv1.Check) *assessmentv1.KernelParameterTest { return c.GetKernelParameter() }
	directive := func(c *assessmentv1.Check) *assessmentv1.DirectiveTest { return c.GetDirective() }
	for name, one := range map[string]struct {
		checklist *assessmentv1.Checklist
		problem   string
	}{
		"malformed id":           {with(0, func(c *assessmentv1.Check) { c.CheckId = "shadow permissions" }), "checks[0].check_id"},
		"id named twice":         {with(1, func(c *assessmentv1.Check) { c.CheckId = "shadow.permissions" }), "checks[1].check_id"},
		"long title":             {with(0, func(c *assessmentv1.Check) { c.Title = strings.Repeat("t", MaxTitleLength+1) }), "checks[0].title"},
		"control in title":       {with(0, func(c *assessmentv1.Check) { c.Title = "line\nbreak" }), "checks[0].title"},
		"no test":                {with(0, func(c *assessmentv1.Check) { c.Test = nil }), "checks[0].test"},
		"relative path":          {with(0, func(c *assessmentv1.Check) { file(c).Path = "etc/shadow" }), "checks[0].file.path"},
		"path to resolve":        {with(0, func(c *assessmentv1.Check) { file(c).Path = "/etc/../etc/shadow" }), "checks[0].file.path"},
		"trailing separator":     {with(0, func(c *assessmentv1.Check) { file(c).Path = "/etc/" }), "checks[0].file.path"},
		"the root":               {with(0, func(c *assessmentv1.Check) { file(c).Path = "/" }), "checks[0].file.path"},
		"within proc":            {with(0, func(c *assessmentv1.Check) { file(c).Path = "/proc/1/status" }), "checks[0].file.path"},
		"within tmp":             {with(0, func(c *assessmentv1.Check) { file(c).Path = "/tmp" }), "checks[0].file.path"},
		"long path":              {with(0, func(c *assessmentv1.Check) { file(c).Path = "/" + strings.Repeat("p", MaxPathLength) }), "checks[0].file.path"},
		"undeclared kind":        {with(0, func(c *assessmentv1.Check) { file(c).Kind = assessmentv1.FileTest_Kind(9) }), "checks[0].file.kind"},
		"undeclared presence":    {with(0, func(c *assessmentv1.Check) { file(c).Presence = assessmentv1.Presence(9) }), "checks[0].file.presence"},
		"permissions beyond":     {with(0, func(c *assessmentv1.Check) { file(c).Permissions = proto.Uint32(0o10000) }), "checks[0].file.permissions"},
		"forbidden and judged":   {with(1, func(c *assessmentv1.Check) { file(c).UserId = proto.Uint32(0) }), "checks[1].file.judges"},
		"file judging nothing":   {with(1, func(c *assessmentv1.Check) { file(c).Presence = assessmentv1.Presence_PRESENCE_UNSPECIFIED }), "checks[1].file.judges"},
		"unspecified rule":       {with(2, func(c *assessmentv1.Check) { c.GetAccount().Rule = assessmentv1.AccountTest_RULE_UNSPECIFIED }), "checks[2].account.rule"},
		"group without the rule": {with(2, func(c *assessmentv1.Check) { c.GetAccount().Group = "shadow" }), "checks[2].account.group"},
		"rule without a group":   {with(3, func(c *assessmentv1.Check) { c.GetAccount().Group = "" }), "checks[3].account.group"},
		"group with a colon":     {with(3, func(c *assessmentv1.Check) { c.GetAccount().Group = "sha:dow" }), "checks[3].account.group"},
		"parameter path":         {with(4, func(c *assessmentv1.Check) { parameter(c).Name = "net/../../etc" }), "checks[4].kernel_parameter.name"},
		"parameter dot dot":      {with(4, func(c *assessmentv1.Check) { parameter(c).Name = "net..ipv4" }), "checks[4].kernel_parameter.name"},
		"parameter slash only":   {with(4, func(c *assessmentv1.Check) { parameter(c).Name = "net.//.x" }), "checks[4].kernel_parameter.name"},
		"unnormalized value":     {with(4, func(c *assessmentv1.Check) { parameter(c).Allowed = []string{" 0"} }), "checks[4].kernel_parameter.allowed[0]"},
		"value named twice":      {with(4, func(c *assessmentv1.Check) { parameter(c).Allowed = []string{"0", "0"} }), "checks[4].kernel_parameter.allowed[1]"},
		"values and bounds":      {with(4, func(c *assessmentv1.Check) { parameter(c).AtMost = proto.Int64(1) }), "checks[4].kernel_parameter.carries"},
		"bounds crossed":         {with(5, func(c *assessmentv1.Check) { parameter(c).AtMost = proto.Int64(0) }), "checks[5].kernel_parameter.at_least"},
		"forbidden with values":  {with(4, func(c *assessmentv1.Check) { parameter(c).Presence = assessmentv1.Presence_PRESENCE_FORBIDDEN }), "checks[4].kernel_parameter.judges"},
		"parameter judging nothing": {with(4, func(c *assessmentv1.Check) { parameter(c).Allowed = nil }),
			"checks[4].kernel_parameter.judges"},
		"module name":      {with(6, func(c *assessmentv1.Check) { c.GetKernelModule().Name = "cram fs" }), "checks[6].kernel_module.name"},
		"long module name": {with(6, func(c *assessmentv1.Check) { c.GetKernelModule().Name = strings.Repeat("m", MaxModuleLength+1) }), "checks[6].kernel_module.name"},
		"module judging nothing": {with(6, func(c *assessmentv1.Check) {
			c.GetKernelModule().Loaded, c.GetKernelModule().Disabled = assessmentv1.Presence_PRESENCE_UNSPECIFIED, false
		}), "checks[6].kernel_module.judges"},
		"package name":          {with(7, func(c *assessmentv1.Check) { c.GetPackage().Name = "telnetd;rm" }), "checks[7].package.name"},
		"package presence":      {with(7, func(c *assessmentv1.Check) { c.GetPackage().Presence = assessmentv1.Presence_PRESENCE_UNSPECIFIED }), "checks[7].package.presence"},
		"unit without a suffix": {with(8, func(c *assessmentv1.Check) { c.GetService().Unit = "rpcbind" }), "checks[8].service.unit"},
		"template unit":         {with(8, func(c *assessmentv1.Check) { c.GetService().Unit = "getty@.service" }), "checks[8].service.unit"},
		"service judging nothing": {with(8, func(c *assessmentv1.Check) {
			c.GetService().Startup = assessmentv1.ServiceTest_STARTUP_UNSPECIFIED
		}), "checks[8].service.judges"},
		"undeclared startup":     {with(8, func(c *assessmentv1.Check) { c.GetService().Startup = assessmentv1.ServiceTest_Startup(9) }), "checks[8].service.startup"},
		"unspecified source":     {with(9, func(c *assessmentv1.Check) { directive(c).Source = assessmentv1.DirectiveTest_SOURCE_UNSPECIFIED }), "checks[9].directive.source"},
		"directive name":         {with(9, func(c *assessmentv1.Check) { directive(c).Name = "Permit-Root" }), "checks[9].directive.name"},
		"directive judging none": {with(9, func(c *assessmentv1.Check) { directive(c).Allowed = nil }), "checks[9].directive.judges"},
		"too many values": {with(9, func(c *assessmentv1.Check) {
			directive(c).Allowed = nil
			for index := range MaxValues + 1 {
				directive(c).Allowed = append(directive(c).Allowed, fmt.Sprintf("value-%d", index))
			}
		}), "checks[9].directive.allowed names"},
		"assumed not an integer": {with(10, func(c *assessmentv1.Check) { directive(c).Assumed = "never" }), "checks[10].directive.assumed"},
		"assumed unnormalized":   {with(9, func(c *assessmentv1.Check) { directive(c).Assumed = "no  " }), "checks[9].directive.assumed"},
	} {
		t.Run(name, func(t *testing.T) {
			found := ValidateChecklist(one.checklist)
			if len(found) == 0 {
				t.Fatal("the checklist was admitted")
			}
			named := false
			for _, problem := range found {
				named = named || strings.HasPrefix(problem.Error(), one.problem)
			}
			if !named {
				t.Errorf("no problem starts with %s: %v", one.problem, found)
			}
		})
	}
}

func TestAChecklistHoldsBetweenOneAndItsCeilingOfChecks(t *testing.T) {
	if found := ValidateChecklist(&assessmentv1.Checklist{}); len(found) == 0 {
		t.Error("a checklist naming no check was admitted")
	}
	full := &assessmentv1.Checklist{}
	for index := range MaxChecks + 1 {
		full.Checks = append(full.Checks, &assessmentv1.Check{
			CheckId: fmt.Sprintf("check-%d", index),
			Test:    &assessmentv1.Check_Package{Package: &assessmentv1.PackageTest{Name: "telnetd", Presence: assessmentv1.Presence_PRESENCE_FORBIDDEN}},
		})
	}
	if found := ValidateChecklist(full); len(found) != 1 || !strings.Contains(found[0].Error(), "at most") {
		t.Errorf("a checklist of %d checks was not refused over its size alone: %v", MaxChecks+1, found)
	}
	full.Checks = full.Checks[:MaxChecks]
	if found := ValidateChecklist(full); len(found) > 0 {
		t.Errorf("a checklist of %d checks was refused: %v", MaxChecks, found)
	}
}

func TestAValueIsReadAsTheProgramItBelongsToReadsANumber(t *testing.T) {
	sshd, defs := assessmentv1.DirectiveTest_SOURCE_SSHD, assessmentv1.DirectiveTest_SOURCE_LOGIN_DEFS
	for _, one := range []struct {
		source assessmentv1.DirectiveTest_Source
		value  string
		number int64
		read   bool
	}{
		{sshd, "6", 6, true},
		{sshd, "027", 27, true},
		{sshd, "0x10", 0, false},
		{sshd, "six", 0, false},
		{defs, "027", 0o27, true},
		{defs, "0x1F", 31, true},
		{defs, "-1", -1, true},
		{defs, "99999", 99999, true},
		{defs, "0", 0, true},
		{defs, "08", 0, false},
		{defs, "0x", 0, false},
		{defs, "1_000", 0, false},
		{defs, "", 0, false},
	} {
		number, read := Integer(one.source, one.value)
		if read != one.read || number != one.number {
			t.Errorf("%s %q reads as %d (%t), not %d (%t)", one.source, one.value, number, read, one.number, one.read)
		}
	}
}
