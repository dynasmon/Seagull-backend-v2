package ruleset

// Who publishes and activates the rules an installation starts from. It is not
// a name the access policy can bind, so no caller is ever recorded under it and
// a pointer carrying it is one no person wrote.
const Installation = "the installation"

// Whether the pointer gives way to the rules an installation starts from: it
// does while nothing is active or what is active is the installation's own, and
// never once a person activated something, the starting rules included.
func (c *Catalogue) Yields(starting ID) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	switch {
	case c.active == nil:
		return true
	case ID(c.active.GetRulesetId()) == starting:
		return false
	default:
		return c.active.GetActivatedBy() == Installation
	}
}
