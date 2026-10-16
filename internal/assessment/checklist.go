package assessment

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

var (
	parameterPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*(\.[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*)*$`)
	modulePattern    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	packagePattern   = regexp.MustCompile(`^[A-Za-z0-9+._-]+$`)
	unitPattern      = regexp.MustCompile(`^[A-Za-z0-9:_.\\@-]+\.(service|socket|timer|path|mount|automount|swap|target|slice|scope|device)$`)
	directivePattern = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
)

// Every rule the contract states for a checklist, checked whole so a refusal
// names every check that is wrong at once. The platform holds a checklist to
// all of them before it hands a policy on; an agent built against an older
// contract reads a check it cannot follow as unsupported instead, so these
// rules are where a mistake is caught for every agent at once.
func ValidateChecklist(checklist *assessmentv1.Checklist) []error {
	var found []error
	add := func(format string, arguments ...any) { found = append(found, fmt.Errorf(format, arguments...)) }

	checks := checklist.GetChecks()
	switch {
	case len(checks) == 0:
		add("checks name nothing, and a checklist that asks for no checks is left out of the policy instead")
	case len(checks) > MaxChecks:
		add("checks name %d checks, and a checklist holds at most %d", len(checks), MaxChecks)
	}
	seen := make(map[string]int, len(checks))
	for index, check := range checks {
		name := fmt.Sprintf("checks[%d]", index)
		id := check.GetCheckId()
		if !agentidentity.Valid(id) {
			add("%s.check_id is %s, and it follows the pattern of an agent identifier", name, strconv.Quote(Bounded(id)))
		} else if first, twice := seen[id]; twice {
			add("%s.check_id names %s, which checks[%d] already does", name, id, first)
		} else {
			seen[id] = index
		}
		if title := check.GetTitle(); !Readable(title, MaxTitleLength) {
			add("%s.title is not text of at most %d bytes", name, MaxTitleLength)
		}
		for _, problem := range validateTest(check) {
			add("%s.%s", name, problem)
		}
	}
	return found
}

func validateTest(check *assessmentv1.Check) []string {
	switch test := check.GetTest().(type) {
	case *assessmentv1.Check_File:
		return prefixed("file", validateFile(test.File))
	case *assessmentv1.Check_Account:
		return prefixed("account", validateAccount(test.Account))
	case *assessmentv1.Check_KernelParameter:
		return prefixed("kernel_parameter", validateParameter(test.KernelParameter))
	case *assessmentv1.Check_KernelModule:
		return prefixed("kernel_module", validateModule(test.KernelModule))
	case *assessmentv1.Check_Package:
		return prefixed("package", validatePackage(test.Package))
	case *assessmentv1.Check_Service:
		return prefixed("service", validateService(test.Service))
	case *assessmentv1.Check_Directive:
		return prefixed("directive", validateDirective(test.Directive))
	default:
		return []string{"test is not set, and a check carries exactly one"}
	}
}

func validateFile(test *assessmentv1.FileTest) []string {
	var found []string
	written := test.GetPath()
	switch {
	case written == "":
		found = append(found, "path is empty, and it names an absolute path")
	case len(written) > MaxPathLength:
		found = append(found, fmt.Sprintf("path is longer than %d bytes", MaxPathLength))
	case !strings.HasPrefix(written, "/") || path.Clean(written) != written || strings.ContainsRune(written, 0):
		found = append(found, fmt.Sprintf("path is %s, and it is an absolute path with nothing to resolve", strconv.Quote(Bounded(written))))
	case written == "/":
		found = append(found, "path is the root of the filesystem")
	default:
		for _, held := range Unexamined {
			if written == held || strings.HasPrefix(written, held+"/") {
				found = append(found, fmt.Sprintf("path is within %s, which holds what the kernel and running services make up rather than what a host is configured with", held))
			}
		}
	}
	found = append(found, enumerated("presence", int32(test.GetPresence()), assessmentv1.Presence_name)...)
	found = append(found, enumerated("kind", int32(test.GetKind()), assessmentv1.FileTest_Kind_name)...)
	if test.Permissions != nil && test.GetPermissions() > MaxPermissions {
		found = append(found, fmt.Sprintf("permissions is %#o, and permission bits lie within 07777", test.GetPermissions()))
	}
	judged := test.GetKind() != assessmentv1.FileTest_KIND_UNSPECIFIED || test.UserId != nil || test.GroupId != nil || test.Permissions != nil
	switch test.GetPresence() {
	case assessmentv1.Presence_PRESENCE_FORBIDDEN:
		if judged {
			found = append(found, "judges what the path is, and a path that must not be there is judged on that alone")
		}
	case assessmentv1.Presence_PRESENCE_UNSPECIFIED:
		if !judged {
			found = append(found, "judges nothing: it names neither a presence nor anything of what the path is")
		}
	}
	return found
}

func validateAccount(test *assessmentv1.AccountTest) []string {
	found := enumerated("rule", int32(test.GetRule()), assessmentv1.AccountTest_Rule_name)
	if test.GetRule() == assessmentv1.AccountTest_RULE_UNSPECIFIED {
		found = append(found, "rule is unspecified")
	}
	group := test.GetGroup()
	switch {
	case test.GetRule() != assessmentv1.AccountTest_RULE_GROUP_HAS_NO_MEMBERS:
		if group != "" {
			found = append(found, "group is set, and only a rule about the members of a group names one")
		}
	case group == "" || len(group) > MaxGroupLength || strings.IndexFunc(group, func(r rune) bool { return r <= ' ' || r > '~' || r == ':' }) >= 0:
		found = append(found, fmt.Sprintf("group is %s, and it is a name of at most %d printable bytes without white space or ':'", strconv.Quote(Bounded(group)), MaxGroupLength))
	}
	return found
}

func validateParameter(test *assessmentv1.KernelParameterTest) []string {
	var found []string
	if name := test.GetName(); len(name) > MaxParameterLength || !parameterPattern.MatchString(name) {
		found = append(found, fmt.Sprintf("name is %s, and it is a sysctl name of at most %d bytes, such as %q",
			strconv.Quote(Bounded(name)), MaxParameterLength, "net.ipv4.ip_forward"))
	}
	found = append(found, enumerated("presence", int32(test.GetPresence()), assessmentv1.Presence_name)...)
	values := values("allowed", test.GetAllowed(), MaxParameterValueLength)
	found = append(found, values...)
	found = append(found, bounds(test.AtLeast, test.AtMost)...)
	carried := len(test.GetAllowed()) > 0 || test.AtLeast != nil || test.AtMost != nil
	switch {
	case test.GetPresence() == assessmentv1.Presence_PRESENCE_FORBIDDEN:
		if carried {
			found = append(found, "judges the value of a parameter that must not be there")
		}
	case len(test.GetAllowed()) > 0 && (test.AtLeast != nil || test.AtMost != nil):
		found = append(found, "carries both allowed values and bounds, and a check carries one or the other")
	case !carried && test.GetPresence() == assessmentv1.Presence_PRESENCE_UNSPECIFIED:
		found = append(found, "judges nothing: it names neither a presence nor the values the parameter may hold")
	}
	return found
}

func validateModule(test *assessmentv1.KernelModuleTest) []string {
	var found []string
	if name := test.GetName(); len(name) > MaxModuleLength || !modulePattern.MatchString(name) {
		found = append(found, fmt.Sprintf("name is %s, and it is a module name of at most %d letters, digits, '_' and '-'",
			strconv.Quote(Bounded(name)), MaxModuleLength))
	}
	found = append(found, enumerated("loaded", int32(test.GetLoaded()), assessmentv1.Presence_name)...)
	if test.GetLoaded() == assessmentv1.Presence_PRESENCE_UNSPECIFIED && !test.GetDisabled() {
		found = append(found, "judges nothing: it says neither whether the module may be loaded nor that it must be kept out")
	}
	return found
}

func validatePackage(test *assessmentv1.PackageTest) []string {
	var found []string
	if name := test.GetName(); len(name) > MaxPackageLength || !packagePattern.MatchString(name) {
		found = append(found, fmt.Sprintf("name is %s, and it is a package name of at most %d letters, digits, '+', '.', '_' and '-'",
			strconv.Quote(Bounded(name)), MaxPackageLength))
	}
	found = append(found, enumerated("presence", int32(test.GetPresence()), assessmentv1.Presence_name)...)
	if test.GetPresence() == assessmentv1.Presence_PRESENCE_UNSPECIFIED {
		found = append(found, "presence is unspecified, and a package check says whether the package must be installed or must not")
	}
	return found
}

func validateService(test *assessmentv1.ServiceTest) []string {
	var found []string
	unit := test.GetUnit()
	switch {
	case len(unit) > MaxUnitLength || !unitPattern.MatchString(unit):
		found = append(found, fmt.Sprintf("unit is %s, and it is the full name of a unit of at most %d bytes, such as %q",
			strconv.Quote(Bounded(unit)), MaxUnitLength, "ssh.service"))
	case strings.HasSuffix(unit[:strings.LastIndexByte(unit, '.')], "@"):
		found = append(found, fmt.Sprintf("unit is %s, which is a template rather than a unit the host runs", strconv.Quote(unit)))
	}
	found = append(found, enumerated("startup", int32(test.GetStartup()), assessmentv1.ServiceTest_Startup_name)...)
	found = append(found, enumerated("activity", int32(test.GetActivity()), assessmentv1.ServiceTest_Activity_name)...)
	if test.GetStartup() == assessmentv1.ServiceTest_STARTUP_UNSPECIFIED && test.GetActivity() == assessmentv1.ServiceTest_ACTIVITY_UNSPECIFIED {
		found = append(found, "judges nothing: it says neither how the unit starts nor whether it runs")
	}
	return found
}

func validateDirective(test *assessmentv1.DirectiveTest) []string {
	var found []string
	source := test.GetSource()
	found = append(found, enumerated("source", int32(source), assessmentv1.DirectiveTest_Source_name)...)
	if source == assessmentv1.DirectiveTest_SOURCE_UNSPECIFIED {
		found = append(found, "source is unspecified")
	}
	if name := test.GetName(); len(name) > MaxDirectiveLength || !directivePattern.MatchString(name) {
		found = append(found, fmt.Sprintf("name is %s, and it is a directive of at most %d letters, digits and '_'",
			strconv.Quote(Bounded(name)), MaxDirectiveLength))
	}
	found = append(found, values("allowed", test.GetAllowed(), MaxDirectiveValueLength)...)
	found = append(found, bounds(test.AtLeast, test.AtMost)...)
	bounded := test.AtLeast != nil || test.AtMost != nil
	switch {
	case len(test.GetAllowed()) > 0 && bounded:
		found = append(found, "carries both allowed values and bounds, and a check carries one or the other")
	case len(test.GetAllowed()) == 0 && !bounded:
		found = append(found, "judges nothing: it names neither the values the directive may have nor bounds on it")
	}
	if assumed := test.GetAssumed(); assumed != "" {
		switch _, integer := Integer(source, assumed); {
		case !Normalized(assumed, MaxDirectiveValueLength):
			found = append(found, fmt.Sprintf("assumed is not a value of at most %d printable bytes with its words one space apart", MaxDirectiveValueLength))
		case bounded && !integer:
			found = append(found, fmt.Sprintf("assumed is %s, and a check with bounds assumes an integer", strconv.Quote(assumed)))
		}
	}
	return found
}

func enumerated(field string, value int32, names map[int32]string) []string {
	if _, known := names[value]; !known {
		return []string{fmt.Sprintf("%s is %d, which the contract does not declare", field, value)}
	}
	return nil
}

func values(field string, held []string, maximum int) []string {
	var found []string
	if len(held) > MaxValues {
		found = append(found, fmt.Sprintf("%s names %d values, and a check names at most %d", field, len(held), MaxValues))
	}
	for index, value := range held {
		switch {
		case !Normalized(value, maximum):
			found = append(found, fmt.Sprintf("%s[%d] is not a value of at most %d printable bytes with its words one space apart", field, index, maximum))
		case containsFold(held[:index], value):
			found = append(found, fmt.Sprintf("%s[%d] names %s again", field, index, strconv.Quote(value)))
		}
	}
	return found
}

func containsFold(held []string, value string) bool {
	for _, each := range held {
		if strings.EqualFold(each, value) {
			return true
		}
	}
	return false
}

func bounds(least, most *int64) []string {
	if least != nil && most != nil && *least > *most {
		return []string{fmt.Sprintf("at_least is %d and at_most %d, which no value lies between", *least, *most)}
	}
	return nil
}

func prefixed(test string, problems []string) []string {
	for index, problem := range problems {
		problems[index] = test + "." + problem
	}
	return problems
}

// Integer reads a value the way the program the directive belongs to reads a
// number: sshd in decimal, login.defs as C's strtol does with base 0, where a
// leading 0 is octal and 0x hexadecimal. A kernel parameter is read with the
// rules of sshd.
func Integer(source assessmentv1.DirectiveTest_Source, value string) (int64, bool) {
	if source != assessmentv1.DirectiveTest_SOURCE_LOGIN_DEFS {
		parsed, err := strconv.ParseInt(value, 10, 64)
		return parsed, err == nil
	}
	sign, digits := "", value
	if strings.HasPrefix(digits, "-") || strings.HasPrefix(digits, "+") {
		sign, digits = digits[:1], digits[1:]
	}
	base := 10
	switch {
	case len(digits) > 2 && (digits[:2] == "0x" || digits[:2] == "0X"):
		base, digits = 16, digits[2:]
	case len(digits) > 1 && digits[0] == '0':
		base, digits = 8, digits[1:]
	}
	if digits == "" || strings.ContainsAny(digits, "_+-") {
		return 0, false
	}
	parsed, err := strconv.ParseInt(sign+digits, base, 64)
	return parsed, err == nil
}

// Normalized holds a value to what a check compares against: printable bytes,
// with no white space but single spaces between words, which is what a value
// read from a host becomes before it is compared.
func Normalized(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value || strings.Contains(value, "  ") {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r > '~' }) < 0
}

// Readable is text an operator wrote and a person reads back: valid UTF-8 and
// no control characters, within a bound.
func Readable(value string, maximum int) bool {
	return len(value) <= maximum && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

// Bounded is what a refusal may quote of a value it refuses.
func Bounded(value string) string {
	const shown = 96
	if len(value) <= shown {
		return value
	}
	cut := shown
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut] + "…"
}
