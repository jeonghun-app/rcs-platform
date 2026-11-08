package ifc

// WholePattern is one POSIX extended regular expression matched against a
// whole value as written: anchored at both ends and with regard to case,
// unlike a trigger's Request-URI pattern, which matches anywhere in the
// hostport and ignores case. Otherwise it follows the rules of every pattern
// of this package (see the package doc): the same reading of an ERE, the
// constructs refused, MaxPatternBytes, MaxPatternInstructions and the
// compile cost; and a match is charged as one of a [Set]'s, against
// DefaultMaxWork.
//
// hss matches the user part of a chatbot URI with it against the ERE of the
// wildcarded PSI (TS 23.003 §13.5, ADR 0009 §3). That ERE is written for the
// whole user part and the lower case of internal/chatbot's normal form; read
// as a trigger reads one, it would also select upper-case and longer user
// parts.
type WholePattern struct{ p pattern }

// CompileWholePattern compiles source as a WholePattern. name says what the
// pattern is in an error, which never quotes the pattern.
func CompileWholePattern(name, source string) (*WholePattern, error) {
	b := setBudget{insts: MaxPatternInstructions, cost: MaxSetCompileCost}
	p, err := b.compile(name, source, patternWhole)
	if err != nil {
		return nil, err
	}
	return &WholePattern{p}, nil
}

// Match reports whether the whole of v matches. It fails with a
// [*LimitError] naming MaxWork, rather than answer either way, when the
// match would cost more than DefaultMaxWork.
func (w *WholePattern) Match(v string) (bool, error) {
	in := newInput(nil, Context{}, DefaultMaxWork)
	ok := in.match(w.p, v)
	if in.exhausted {
		return false, &LimitError{Limit: in.limit}
	}
	return ok, nil
}
