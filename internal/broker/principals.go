package broker

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
)

const (
	scramIterations = 4096
	anyHost         = "*"
)

type acl struct {
	resource   kmsg.ACLResourceType
	name       string
	pattern    kmsg.ACLResourcePatternType
	principal  string
	host       string
	operation  kmsg.ACLOperation
	permission kmsg.ACLPermissionType
}

func (a acl) String() string {
	return fmt.Sprintf("%s %s %s on %s %s", a.principal, a.permission, a.operation, a.resource, a.name)
}

func allowed(principal string, permission Permission) acl {
	return acl{
		resource:   permission.Resource,
		name:       permission.Name,
		pattern:    kmsg.ACLResourcePatternTypeLiteral,
		principal:  principal,
		host:       anyHost,
		operation:  permission.Operation,
		permission: kmsg.ACLPermissionTypeAllow,
	}
}

func (s Security) scram() (kadm.ScramMechanism, error) {
	switch s.Mechanism {
	case MechanismScramSHA256:
		return kadm.ScramSha256, nil
	case MechanismScramSHA512:
		return kadm.ScramSha512, nil
	default:
		return 0, fmt.Errorf("the backbone authenticates nobody under %q, so there is no principal to give a component", s.Mechanism)
	}
}

// Every component gets a credential under the mechanism the deployment
// authenticates with and exactly the permissions its grant holds: what a
// component's principal holds beyond its grant is revoked, whoever added it,
// and a principal that is not a component's is never touched.
func (p *Provisioner) ApplyGrants(ctx context.Context, grants []Grant, passwords map[Component]config.Secret) ([]string, error) {
	mechanism, err := p.security.scram()
	if err != nil {
		return nil, err
	}
	if len(grants) == 0 {
		return nil, errors.New("there is no grant to apply")
	}
	upserts := make([]kadm.UpsertSCRAM, 0, len(grants))
	for _, grant := range grants {
		password := passwords[grant.Component]
		if password.Empty() {
			return nil, fmt.Errorf("no password was given for %s", grant.Component)
		}
		upserts = append(upserts, kadm.UpsertSCRAM{
			User:       string(grant.Component),
			Mechanism:  mechanism,
			Iterations: scramIterations,
			Password:   password.Reveal(),
		})
	}

	var changed []string
	altered, err := p.admin.AlterUserSCRAMs(ctx, nil, upserts)
	if err != nil {
		return changed, fmt.Errorf("set the backbone credentials of the components: %w", err)
	}
	for _, result := range altered.Sorted() {
		if result.Err != nil {
			return changed, fmt.Errorf("set the backbone credential of %s: %w", result.User, result.Err)
		}
		changed = append(changed, "set the credential of "+result.User)
	}

	for _, grant := range grants {
		converged, err := p.converge(ctx, grant)
		changed = append(changed, converged...)
		if err != nil {
			return changed, err
		}
	}

	return changed, p.verifyHeld(ctx, grants, passwords)
}

func (p *Provisioner) converge(ctx context.Context, grant Grant) ([]string, error) {
	principal := grant.Component.Principal()
	held, err := p.held(ctx, principal)
	if err != nil {
		return nil, err
	}
	wanted := map[acl]bool{}
	for _, permission := range grant.Permissions() {
		wanted[allowed(principal, permission)] = true
	}

	var missing, extra []acl
	for entry := range wanted {
		if !held[entry] {
			missing = append(missing, entry)
		}
	}
	for entry := range held {
		if !wanted[entry] {
			extra = append(extra, entry)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].String() < missing[j].String() })
	sort.Slice(extra, func(i, j int) bool { return extra[i].String() < extra[j].String() })

	var changed []string
	if len(missing) > 0 {
		if err := p.create(ctx, missing); err != nil {
			return changed, err
		}
		for _, entry := range missing {
			changed = append(changed, "granted "+entry.String())
		}
	}
	if len(extra) > 0 {
		if err := p.revoke(ctx, extra); err != nil {
			return changed, err
		}
		for _, entry := range extra {
			changed = append(changed, "revoked "+entry.String())
		}
	}
	return changed, nil
}

func (p *Provisioner) held(ctx context.Context, principal string) (map[acl]bool, error) {
	request := kmsg.NewPtrDescribeACLsRequest()
	request.ResourceType = kmsg.ACLResourceTypeAny
	request.ResourcePatternType = kmsg.ACLResourcePatternTypeAny
	request.Principal = kmsg.StringPtr(principal)
	request.Operation = kmsg.ACLOperationAny
	request.PermissionType = kmsg.ACLPermissionTypeAny
	response, err := request.RequestWith(ctx, p.client)
	if err != nil {
		return nil, fmt.Errorf("read the ACLs of %s: %w", principal, err)
	}
	if err := kerr.ErrorForCode(response.ErrorCode); err != nil {
		return nil, fmt.Errorf("read the ACLs of %s: %w", principal, err)
	}
	held := map[acl]bool{}
	for _, resource := range response.Resources {
		for _, entry := range resource.ACLs {
			held[acl{
				resource:   resource.ResourceType,
				name:       resource.ResourceName,
				pattern:    resource.ResourcePatternType,
				principal:  entry.Principal,
				host:       entry.Host,
				operation:  entry.Operation,
				permission: entry.PermissionType,
			}] = true
		}
	}
	return held, nil
}

func (p *Provisioner) create(ctx context.Context, entries []acl) error {
	request := kmsg.NewPtrCreateACLsRequest()
	for _, entry := range entries {
		creation := kmsg.NewCreateACLsRequestCreation()
		creation.ResourceType = entry.resource
		creation.ResourceName = entry.name
		creation.ResourcePatternType = entry.pattern
		creation.Principal = entry.principal
		creation.Host = entry.host
		creation.Operation = entry.operation
		creation.PermissionType = entry.permission
		request.Creations = append(request.Creations, creation)
	}
	response, err := request.RequestWith(ctx, p.client)
	if err != nil {
		return fmt.Errorf("grant %s: %w", entries[0].principal, err)
	}
	if len(response.Results) != len(entries) {
		return fmt.Errorf("grant %s: the backbone answered %d of %d permissions", entries[0].principal, len(response.Results), len(entries))
	}
	for i, result := range response.Results {
		if err := kerr.ErrorForCode(result.ErrorCode); err != nil {
			return fmt.Errorf("grant %s: %w", entries[i], err)
		}
	}
	return nil
}

func (p *Provisioner) revoke(ctx context.Context, entries []acl) error {
	request := kmsg.NewPtrDeleteACLsRequest()
	for _, entry := range entries {
		filter := kmsg.NewDeleteACLsRequestFilter()
		filter.ResourceType = entry.resource
		filter.ResourceName = kmsg.StringPtr(entry.name)
		filter.ResourcePatternType = entry.pattern
		filter.Principal = kmsg.StringPtr(entry.principal)
		filter.Host = kmsg.StringPtr(entry.host)
		filter.Operation = entry.operation
		filter.PermissionType = entry.permission
		request.Filters = append(request.Filters, filter)
	}
	response, err := request.RequestWith(ctx, p.client)
	if err != nil {
		return fmt.Errorf("revoke from %s: %w", entries[0].principal, err)
	}
	for i, result := range response.Results {
		if err := kerr.ErrorForCode(result.ErrorCode); err != nil {
			return fmt.Errorf("revoke %s: %w", entries[i], err)
		}
	}
	return nil
}

// A broker that keeps ACLs and enforces none, an ACL granted to every
// principal, or a component made a superuser each give a component more than
// its grant, and none of them is an ACL of the component's own. The migrator
// asks as each component and refuses to finish while one can see a topic,
// read a topic's configuration or describe a group its grant does not name.
func (p *Provisioner) verifyHeld(ctx context.Context, grants []Grant, passwords map[Component]config.Secret) error {
	topics, groups := map[string]bool{}, map[string]bool{}
	for _, grant := range grants {
		groups[grant.Component.Group()] = true
		for _, permission := range grant.Permissions() {
			if permission.Resource == kmsg.ACLResourceTypeTopic {
				topics[permission.Name] = true
			}
		}
	}
	for _, grant := range grants {
		granted := map[string]bool{}
		for _, permission := range grant.Permissions() {
			granted[permission.Name] = true
		}
		var foreignTopics, foreignGroups []string
		for topic := range topics {
			if !granted[topic] {
				foreignTopics = append(foreignTopics, topic)
			}
		}
		for group := range groups {
			if !granted[group] {
				foreignGroups = append(foreignGroups, group)
			}
		}
		sort.Strings(foreignTopics)
		sort.Strings(foreignGroups)
		if err := p.heldTo(ctx, grant.Component, passwords[grant.Component], foreignTopics, foreignGroups); err != nil {
			return err
		}
	}
	return nil
}

func (p *Provisioner) heldTo(ctx context.Context, component Component, password config.Secret, topics, groups []string) error {
	security := p.security
	security.User = string(component)
	security.Password = password
	secured, err := security.options()
	if err != nil {
		return err
	}
	client, err := kgo.NewClient(append([]kgo.Opt{kgo.SeedBrokers(p.brokers...), kgo.ClientID(p.clientID)}, secured...)...)
	if err != nil {
		return fmt.Errorf("reach the backbone as %s: %w", component, err)
	}
	defer client.Close()
	admin := kadm.NewClient(client)
	beyond := func(what, name string) error {
		return fmt.Errorf("the backbone holds %s to less than its grant: it %s %s, which its grant does not name", component, what, name)
	}

	listed, err := admin.ListTopics(ctx)
	if err != nil {
		return fmt.Errorf("list the topics %s sees: %w", component, named(err))
	}
	for _, topic := range topics {
		if detail, seen := listed[topic]; seen && detail.Err == nil {
			return beyond("sees", topic)
		}
	}
	if len(topics) > 0 {
		described, err := admin.DescribeTopicConfigs(ctx, topics...)
		if err != nil && !errors.Is(err, kerr.TopicAuthorizationFailed) {
			return fmt.Errorf("ask the configuration of topics as %s: %w", component, err)
		}
		for _, resource := range described {
			if !errors.Is(resource.Err, kerr.TopicAuthorizationFailed) {
				return beyond("reads the configuration of", resource.Name)
			}
		}
	}
	if len(groups) > 0 {
		described, err := admin.DescribeGroups(ctx, groups...)
		if err != nil && !errors.Is(err, kerr.GroupAuthorizationFailed) {
			return fmt.Errorf("describe groups as %s: %w", component, err)
		}
		for _, group := range described {
			if !errors.Is(group.Err, kerr.GroupAuthorizationFailed) {
				return beyond("describes the group", group.Group)
			}
		}
	}
	return nil
}
