package broker

// What a reader may hold of the topics it reads, asked every time the group
// gives it partitions or takes them away, with how many of each it holds then.
// A refusal stops the reader before it delivers another batch: one that has to
// read its topics alone, and is not alone, would decide what another reader is
// deciding at the same moment.
type Ownership func(held map[string]int32) error

func (c *Consumer) owned(held map[string]int32) {
	if c.ownership == nil {
		return
	}
	if err := c.ownership(held); err != nil {
		_ = c.refuse(err)
	}
}
