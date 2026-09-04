package sigma

import (
	"fmt"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/dynasmon/Seagull-backend-v2/internal/detection"
)

type parser struct {
	read   *reader
	node   *yaml.Node
	part   string
	tokens []string
	at     int
	terms  map[string]detection.Expression
	names  []string
	used   map[string]struct{}
}

func (p *parser) refuse(reason string) error { return p.read.fault(p.node, p.part, reason) }

func (p *parser) peek() string {
	if p.at >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.at]
}

func (p *parser) next() string {
	token := p.peek()
	p.at++
	return token
}

func (p *parser) expression(depth int) (detection.Expression, error) {
	if depth > detection.MaxDepth {
		return nil, p.refuse(fmt.Sprintf("nests deeper than %d, which is deeper than a condition anybody can read", detection.MaxDepth))
	}

	terms, err := p.gather(depth, "or", (*parser).conjunction)
	if err != nil || len(terms) == 1 {
		return first(terms), err
	}
	return detection.Any{Terms: terms}, nil
}

func (p *parser) conjunction(depth int) (detection.Expression, error) {
	terms, err := p.gather(depth, "and", (*parser).factor)
	if err != nil || len(terms) == 1 {
		return first(terms), err
	}
	return detection.All{Terms: terms}, nil
}

func (p *parser) gather(depth int, joiner string, read func(*parser, int) (detection.Expression, error)) ([]detection.Expression, error) {
	term, err := read(p, depth)
	if err != nil {
		return nil, err
	}

	terms := []detection.Expression{term}
	for strings.EqualFold(p.peek(), joiner) {
		p.next()
		term, err = read(p, depth+1)
		if err != nil {
			return nil, err
		}
		terms = append(terms, term)
	}
	return terms, nil
}

func (p *parser) factor(depth int) (detection.Expression, error) {
	if depth > detection.MaxDepth {
		return nil, p.refuse(fmt.Sprintf("nests deeper than %d, which is deeper than a condition anybody can read", detection.MaxDepth))
	}

	switch token := p.peek(); {
	case token == "":
		return nil, p.refuse("ends where it needs a selection")
	case strings.EqualFold(token, "not"):
		p.next()
		term, err := p.factor(depth + 1)
		if err != nil {
			return nil, err
		}
		return detection.Not{Term: term}, nil
	case token == "(":
		p.next()
		term, err := p.expression(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.next() != ")" {
			return nil, p.refuse("opens a bracket it never closes")
		}
		return term, nil
	case p.at+1 < len(p.tokens) && strings.EqualFold(p.tokens[p.at+1], "of"):
		return p.quantified()
	}
	return p.named(p.next())
}

// `1 of them`, `any of selection_*` and `all of them` say how many of a set of
// selections have to hold. Any other number is refused: the rule language joins
// terms with all, any and not, and counting how many of several terms held is
// not something it can say.
func (p *parser) quantified() (detection.Expression, error) {
	quantity := p.next()
	p.next()

	target := p.next()
	if target == "" {
		return nil, p.refuse(fmt.Sprintf("says %q of nothing", quantity))
	}
	matched, err := p.matching(target)
	if err != nil {
		return nil, err
	}

	switch {
	case strings.EqualFold(quantity, "all"):
		if len(matched) == 1 {
			return matched[0], nil
		}
		return detection.All{Terms: matched}, nil
	case quantity == "1" || strings.EqualFold(quantity, "any"):
		if len(matched) == 1 {
			return matched[0], nil
		}
		return detection.Any{Terms: matched}, nil
	}
	return nil, p.refuse(fmt.Sprintf("says %q of %q, and this reads 1, any and all: how many of several terms held is not a question the rule language asks", quantity, target))
}

func (p *parser) matching(target string) ([]detection.Expression, error) {
	if strings.EqualFold(target, "them") {
		matched := make([]detection.Expression, 0, len(p.names))
		for _, name := range p.names {
			p.used[name] = struct{}{}
			matched = append(matched, p.terms[name])
		}
		return matched, nil
	}

	var matched []detection.Expression
	for _, name := range p.names {
		if !globs(target, name) {
			continue
		}
		p.used[name] = struct{}{}
		matched = append(matched, p.terms[name])
	}
	if len(matched) == 0 {
		return nil, p.refuse(fmt.Sprintf("names %q, which matches none of %s", target, strings.Join(p.names, ", ")))
	}
	return matched, nil
}

func (p *parser) named(token string) (detection.Expression, error) {
	term, declared := p.terms[token]
	if !declared {
		return nil, p.refuse(fmt.Sprintf("names %q, which is not one of %s", token, strings.Join(p.names, ", ")))
	}
	p.used[token] = struct{}{}
	return term, nil
}

func first(terms []detection.Expression) detection.Expression {
	if len(terms) == 0 {
		return nil
	}
	return terms[0]
}

func globs(pattern, name string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == name
	}
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]

	for _, part := range parts[1 : len(parts)-1] {
		index := strings.Index(name, part)
		if index < 0 {
			return false
		}
		name = name[index+len(part):]
	}
	return strings.HasSuffix(name, parts[len(parts)-1])
}

func tokensOf(condition string) []string {
	var tokens []string
	var built strings.Builder

	flush := func() {
		if built.Len() > 0 {
			tokens = append(tokens, built.String())
			built.Reset()
		}
	}
	for index := 0; index < len(condition); index++ {
		switch letter := condition[index]; {
		case letter == ' ' || letter == '\t' || letter == '\n' || letter == '\r':
			flush()
		case letter == '(' || letter == ')' || letter == '|' || letter == ',':
			flush()
			tokens = append(tokens, string(letter))
		case letter == '>' || letter == '<' || letter == '=' || letter == '!':
			flush()
			if index+1 < len(condition) && condition[index+1] == '=' {
				tokens = append(tokens, condition[index:index+2])
				index++
				continue
			}
			tokens = append(tokens, string(letter))
		default:
			built.WriteByte(letter)
		}
	}
	flush()
	return tokens
}

// The aggregation Sigma writes after a pipe. Only a count of matching events is
// translated, because that is the one shape the rule language says exactly: a
// distinct count, a sum, an average and a `near` are each a rule this platform
// cannot state, and a threshold read as anything other than what it says is how
// a rule that wanted twenty events fires on one.
func (p *parser) aggregation() (detection.Count, error) {
	var count detection.Count

	if p.next() != "|" {
		return count, p.refuse("does not read as a condition")
	}
	if function := p.next(); !strings.EqualFold(function, "count") {
		return count, p.refuse(fmt.Sprintf("aggregates with %q, and this translates count() alone", function))
	}
	if p.next() != "(" {
		return count, p.refuse("aggregates with a count that opens no bracket")
	}
	if inside := p.next(); inside != ")" {
		return count, p.refuse(fmt.Sprintf("counts distinct %s, and the rule language counts events rather than the values they carried", inside))
	}

	if strings.EqualFold(p.peek(), "by") {
		p.next()
		grouped, err := p.grouped(p.next())
		if err != nil {
			return count, err
		}
		count.GroupBy = grouped
	}

	comparison := p.next()
	threshold, err := strconv.Atoi(p.next())
	if err != nil {
		return count, p.refuse("compares its count against something that is not a whole number")
	}
	switch comparison {
	case ">":
		count.AtLeast = threshold + 1
	case ">=":
		count.AtLeast = threshold
	default:
		return count, p.refuse(fmt.Sprintf("asks for a count %s %d, and a rule here fires when a window holds at least so many: fewer than a threshold is not something a window can answer", comparison, threshold))
	}
	if left := p.peek(); left != "" {
		return count, p.refuse(fmt.Sprintf("carries %q after its aggregation", left))
	}
	return count, nil
}

func (p *parser) grouped(name string) ([]detection.Field, error) {
	held, known := taxonomy[name]
	if !known {
		return nil, p.refuse(fmt.Sprintf("groups its count by %q, which this build does not translate: it reads %s", name, fieldsNamed()))
	}
	if p.peek() == "," {
		p.next()
		return nil, p.refuse(fmt.Sprintf("groups its count by more than one field, and Sigma groups by one: %q is written after it", p.next()))
	}
	return []detection.Field{held.field}, nil
}
