package nzbhydra

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
)

// validAPIKey reports whether every byte belongs to the URL-unreserved set.
func validAPIKey(key string) bool {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	return strings.Trim(key, unreserved) == ""
}

// scrub replaces the raw, query-escaped, path-escaped, Go-quoted, and JSON-escaped API key in s with REDACTED, with hex-digit case of percent escapes ignored.
func (c *Client) scrub(s string) string {
	for _, form := range c.keyForms() {
		s = strings.ReplaceAll(s, form, "REDACTED")
	}
	forms := c.percentForms()
	start, end := nextPercentKey(s, 0, forms)
	if start < 0 {
		return s
	}
	var b strings.Builder
	// Why: reserve space up front to avoid repeated growth across matches.
	b.Grow(len(s))
	offset := 0
	for steps := 0; steps < len(s) && start >= 0; steps++ {
		b.WriteString(s[offset:start])
		b.WriteString("REDACTED")
		offset = end
		start, end = nextPercentKey(s, offset, forms)
	}
	b.WriteString(s[offset:])
	return b.String()
}

// scrubBody redacts key forms and hides bodies containing an escaped key.
func (c *Client) scrubBody(text string) string {
	text = c.scrubText(text)
	// Why: retain detection of key forms with the percent sign itself escaped as JSON.
	if c.apiKey != "" && strings.Contains(text, `\`) && c.containsKeyForms(unescapeBody(text)) {
		return "REDACTED"
	}
	return text
}

// scrubText applies inline redaction and hides text if decoding still reveals the key.
func (c *Client) scrubText(text string) string {
	text = c.scrub(text)
	if c.containsCanonicalKey(text) {
		return "REDACTED"
	}
	return text
}

// maxDecodePasses bounds repeated decoding of percent and backslash escapes.
const maxDecodePasses = 4

// containsCanonicalKey reports whether decoding reveals the raw key or reaches the limit while still changing text.
func (c *Client) containsCanonicalKey(text string) bool {
	if c.apiKey == "" {
		return false
	}
	if strings.Contains(text, c.apiKey) {
		return true
	}
	for range maxDecodePasses {
		if !strings.ContainsAny(text, `%\`) {
			return false
		}
		decoded := decodeEscapes(text, true)
		if strings.Contains(decoded, c.apiKey) {
			return true
		}
		if decoded == text {
			return false
		}
		text = decoded
	}
	// Why: changing text at the limit may still conceal the key.
	return true
}

// unescapeBody decodes recognized backslash escapes while preserving all other bytes.
func unescapeBody(text string) string {
	return decodeEscapes(text, false)
}

// decodeEscapes consumes each recognized escape once and copies all other bytes.
func decodeEscapes(text string, decodePercent bool) string {
	var out strings.Builder
	out.Grow(len(text))
	for i := 0; i < len(text); {
		var size int
		switch text[i] {
		case '%':
			if decodePercent {
				size = writePercentEscape(&out, text[i:])
			}
		case '\\':
			size = writeBackslashEscape(&out, text[i:])
		}
		if size == 0 {
			out.WriteByte(text[i])
			size = 1
		}
		i += size
	}
	return out.String()
}

// writePercentEscape writes one percent-encoded byte, returning its length or zero.
func writePercentEscape(out *strings.Builder, text string) int {
	if len(text) < 3 {
		return 0
	}
	value, err := strconv.ParseUint(text[1:3], 16, 8)
	if err != nil {
		return 0
	}
	out.WriteByte(byte(value))
	return 3
}

// writeBackslashEscape writes the decoded escape, returning its byte length or zero.
func writeBackslashEscape(out *strings.Builder, text string) int {
	if len(text) < 2 {
		return 0
	}
	if r, n := bodyUnicodeEscape(text); n != 0 {
		out.WriteRune(r)
		return n
	}
	index := strings.IndexByte(`"\/bfnrt`, text[1])
	if index >= 0 {
		out.WriteByte("\"\\/\b\f\n\r\t"[index])
		return 2
	}
	return 0
}

// bodyUnicodeEscape decodes a Unicode escape and any following surrogate pair.
func bodyUnicodeEscape(text string) (rune, int) {
	high, ok := bodyHex4(text)
	if !ok {
		return 0, 0
	}
	if !utf16.IsSurrogate(high) {
		return high, 6
	}
	if low, ok := bodyHex4(text[6:]); ok {
		if r := utf16.DecodeRune(high, low); r != '\ufffd' {
			return r, 12
		}
	}
	return '\ufffd', 6
}

// bodyHex4 reads one four-digit Unicode escape at the start of text.
func bodyHex4(text string) (rune, bool) {
	if len(text) < 6 || text[0:2] != `\u` {
		return 0, false
	}
	value, err := strconv.ParseUint(text[2:6], 16, 16)
	return rune(value), err == nil
}

// keyForms returns the distinct raw, query-escaped, path-escaped, Go-quoted, and JSON-escaped forms of the API key, or nil when the key is empty; hex-digit case of percent escapes is matched by nextPercentKey.
func (c *Client) keyForms() []string {
	// Why: ReplaceAll with an empty old inserts at every rune and Contains with an empty key matches every string.
	if c.apiKey == "" {
		return nil
	}
	// Why: every escaped spelling of an unreserved key is the literal key.
	if validAPIKey(c.apiKey) {
		return []string{c.apiKey}
	}
	quoted := strconv.Quote(c.apiKey)
	query, path := url.QueryEscape(c.apiKey), url.PathEscape(c.apiKey)
	candidates := []string{c.apiKey, query, path, (&url.URL{Path: c.apiKey}).EscapedPath(), quoted[1 : len(quoted)-1]}
	// Why: encoding/json writes <, >, &, U+2028 and U+2029 as \uXXXX escapes that no other form matches.
	if b, err := json.Marshal(c.apiKey); err == nil {
		encoded := string(b[1 : len(b)-1])
		candidates = append(candidates, encoded)
		if strings.Contains(c.apiKey, "/") {
			candidates = append(candidates, strings.ReplaceAll(encoded, "/", `\/`))
		}
	}
	forms := make([]string, 0, len(candidates))
	for _, form := range candidates {
		if !slices.Contains(forms, form) {
			forms = append(forms, form)
		}
	}
	return forms
}

// percentForms prepares the distinct query, path, and URL-path spellings in matching order.
func (c *Client) percentForms() []percentForm {
	if validAPIKey(c.apiKey) {
		return nil
	}
	candidates := []string{url.QueryEscape(c.apiKey), url.PathEscape(c.apiKey), (&url.URL{Path: c.apiKey}).EscapedPath()}
	forms := make([]percentForm, 0, len(candidates))
	for i, candidate := range candidates {
		if !slices.Contains(candidates[:i], candidate) {
			forms = append(forms, newPercentForm(candidate))
		}
	}
	return forms
}

// nextPercentKey finds the earliest escaped-key span at or after offset, or -1, -1.
func nextPercentKey(text string, offset int, forms []percentForm) (int, int) {
	start, end := -1, -1
	for i := range forms {
		begin, stop := forms[i].findAfter(text, offset)
		if begin >= 0 && (start < 0 || begin < start) {
			start, end = begin, stop
		}
	}
	return start, end
}

type percentForm struct {
	prefix   string
	pattern  string
	fallback []int
	start    int
	end      int
}

// newPercentForm builds a Knuth-Morris-Pratt prefix table for the pattern starting at its first percent escape.
func newPercentForm(form string) percentForm {
	prefix, pattern := "", form
	if i := strings.IndexByte(form, '%'); i >= 0 {
		prefix, pattern = form[:i], form[i:]
	}
	f := percentForm{prefix: prefix, pattern: pattern, fallback: make([]int, len(pattern))}
	for i := 1; i < len(pattern); i++ {
		f.fallback[i] = f.advance(f.fallback[i-1], pattern[i])
	}
	return f
}

// advance extends the current pattern match by one byte or falls back to its longest viable prefix.
func (f *percentForm) advance(matched int, b byte) int {
	for steps := 0; steps < len(f.pattern) && matched > 0 && f.pattern[matched] != b; steps++ {
		matched = f.fallback[matched-1]
	}
	if f.pattern[matched] == b {
		matched++
	}
	return matched
}

// findAfter reuses a pending match or exhausted search across successive replacements.
func (f *percentForm) findAfter(text string, offset int) (int, int) {
	if f.end != 0 && (f.start >= offset || f.start < 0) {
		return f.start, f.end
	}
	// Why: an invalidated match read at most one pattern length beyond the new offset.
	start, end := f.find(text[offset:])
	if start < 0 {
		f.start, f.end = -1, -1
	} else {
		f.start, f.end = offset+start, offset+end
	}
	return f.start, f.end
}

// find returns the first matching span in text, or -1, -1.
func (f *percentForm) find(text string) (int, int) {
	matched := 0
	foldHex := f.pattern[0] == '%'
	for i := len(f.prefix); i < len(text); i++ {
		b := text[i]
		if foldHex {
			b = percentByte(text, i)
		}
		matched = f.advance(matched, b)
		if matched == len(f.pattern) {
			start := i + 1 - matched - len(f.prefix)
			if f.matchesPrefix(text, start) {
				return start, i + 1
			}
			matched = f.fallback[matched-1]
		}
	}
	return -1, -1
}

// matchesPrefix checks the literal prefix without folding, even when it starts inside an earlier escape.
func (f *percentForm) matchesPrefix(text string, start int) bool {
	// Why: compare backwards so a prior percent sign stops a failed check before it can recheck that candidate's prefix.
	for i := len(f.prefix) - 1; i >= 0; i-- {
		if text[start+i] != f.prefix[i] {
			return false
		}
	}
	return true
}

// percentByte folds lowercase hex only in the two positions after a percent sign.
func percentByte(text string, i int) byte {
	b := text[i]
	if b < 'a' || b > 'f' {
		return b
	}
	if (i >= 1 && text[i-1] == '%') || (i >= 2 && text[i-2] == '%') {
		return b - ('a' - 'A')
	}
	return b
}

type redactedError struct {
	msg string
	// Why: no Unwrap method, so callers cannot reach text that holds the key.
	err error
	// Why: As uses the original key even if the client is replaced.
	key string
}

// Error returns the sanitized message.
func (e *redactedError) Error() string { return e.msg }

// Is matches the hidden error without exposing it.
func (e *redactedError) Is(target error) bool {
	return e.walk(target, func(node error) walkAction {
		// Why: visit nested wrappers within this walk's budget.
		if hiddenRedaction(node) != nil {
			return walkDescend
		}
		if m, ok := node.(interface{ Is(error) bool }); ok && m.Is(target) {
			return walkStop
		}
		return walkDescend
	})
}

// Timeout reports whether the underlying error timed out.
func (e *redactedError) Timeout() bool {
	return classifyHiddenError(e, hiddenTimeoutClassifier.Timeout)
}

// Temporary reports whether the hidden error is temporary.
func (e *redactedError) Temporary() bool {
	return classifyHiddenError(e, hiddenTemporaryClassifier.Temporary)
}

// Why: Go 1.26 vet's printf pass panics on inline interface method expressions. Aliases preserve As target types.
type (
	hiddenTimeoutClassifier   = interface{ Timeout() bool }
	hiddenTemporaryClassifier = interface{ Temporary() bool }
)

// classifyHiddenError reports the first applicable classification within the walk budget.
func classifyHiddenError[T any](e *redactedError, classify func(T) bool) bool {
	reported := false
	e.walk(nil, func(node error) walkAction {
		if uerr, ok := node.(*url.Error); ok { //nolint:errorlint // a URL error classifies its immediate cause
			// Why: schedule the cause so nested wrappers and URL errors share the walk budget.
			_, classifies := uerr.Err.(T)
			_, hidden := uerr.Err.(*redactedError) //nolint:errorlint // inspect only the immediate cause
			if classifies || hidden {
				return walkCauseOnly
			}
			return walkStop
		}
		classifier, ok := node.(T)
		if !ok {
			as, ok := node.(interface{ As(any) bool })
			if !ok || !as.As(&classifier) || isNilValue(classifier) {
				return walkDescend
			}
		}
		reported = classify(classifier)
		return walkStop
	})
	return reported
}

type walkAction uint8

const (
	walkDescend walkAction = iota
	walkStop
	walkCauseOnly
)

// walk visits the hidden tree depth-first in errors.Is order, with shared limits on steps and joins.
func (e *redactedError) walk(target error, visit func(error) walkAction) bool {
	if isNilError(e.err) {
		return false
	}
	// Why: a comparable type may contain a dynamically uncomparable value.
	if !reflect.ValueOf(target).Comparable() {
		target = nil
	}
	stack := [][]error{{e.err}}
	for steps, joins := 0, 0; steps < maxWalkSteps && len(stack) > 0; steps++ {
		var node error
		stack, node = popWalkNode(stack)
		joined, isJoin := node.(interface{ Unwrap() []error })
		if isJoin {
			if joins == maxErrNodes {
				return false
			}
			joins++
		}
		switch visitWalkNode(node, target, visit) {
		case walkStop:
			return true
		case walkCauseOnly:
			stack = stack[:0]
		case walkDescend:
		}
		stack = appendWalkChildren(stack, node, joined, maxWalkSteps-steps-1)
	}
	return false
}

// appendWalkChildren schedules children and drops siblings beyond a clipped join.
func appendWalkChildren(stack [][]error, node error, joined interface{ Unwrap() []error }, remaining int) [][]error {
	children, clipped := walkChildren(node, joined, remaining)
	if clipped {
		// Why: pending siblings follow the unread part of this join.
		stack = stack[:0]
	}
	if children != nil {
		stack = append(stack, children)
	}
	return stack
}

// visitWalkNode checks identity before skipping method calls on nested redacted errors.
func visitWalkNode(node, target error, visit func(error) walkAction) walkAction {
	if target != nil && node == target { //nolint:errorlint // compare this node without starting another traversal
		return walkStop
	}
	if _, hidden := node.(*redactedError); hidden { //nolint:errorlint // only this node is tested
		return walkDescend
	}
	return visit(node)
}

// popWalkNode pops the next non-nil node from the top slice of stack.
func popWalkNode(stack [][]error) ([][]error, error) {
	top := stack[len(stack)-1]
	node := top[0]
	if rest := trimNilErrors(top[1:]); rest != nil {
		stack[len(stack)-1] = rest
		return stack, node
	}
	return stack[:len(stack)-1], node
}

// walkChildren returns the available children and reports whether the join was clipped.
func walkChildren(node error, joined interface{ Unwrap() []error }, remaining int) ([]error, bool) {
	if remaining == 0 {
		return nil, false
	}
	if joined != nil {
		children, clipped := boundedJoinChildren(joined, remaining)
		return trimNilErrors(children), clipped
	}
	var child error
	if hidden := hiddenRedaction(node); hidden != nil {
		child = hidden.err
	} else {
		child = errors.Unwrap(node)
	}
	if isNilError(child) {
		return nil, false
	}
	return []error{child}, false
}

// boundedJoinChildren slices a join before any child is read.
func boundedJoinChildren(joined interface{ Unwrap() []error }, remaining int) ([]error, bool) {
	children := joined.Unwrap()
	return children[:min(len(children), remaining)], len(children) > remaining
}

// trimNilErrors returns errs starting at its first non-nil element, or nil when none exists.
func trimNilErrors(errs []error) []error {
	for i, err := range errs {
		if !isNilError(err) {
			return errs[i:]
		}
	}
	return nil
}

// isNilError reports whether err is nil or holds a nil pointer, map, slice, function, channel, or interface.
func isNilError(err error) bool {
	return isNilValue(err)
}

// isNilValue reports whether value is nil or holds a nil pointer, map, slice, function, channel, or interface.
func isNilValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	if slices.Contains([]reflect.Kind{reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice}, v.Kind()) {
		return v.IsNil()
	}
	return false
}

// As sets target to a sanitized copy, with an opaque cause, of the first *url.Error among the first 64 breadth-first queued nodes; deeper URL errors are not found. The structural key scan examines 64 breadth-first nodes, while Is, Timeout, and Temporary visit at most 4096 nodes and 64 joined errors.
func (e *redactedError) As(target any) bool {
	dst, ok := target.(**url.Error)
	if !ok {
		return false
	}
	// Why: bounded breadth-first walk over the hidden tree; errors.As on it would search unbounded.
	queue := []error{e.err}
	for i := 0; i < maxErrNodes && i < len(queue); i++ {
		if uerr, ok := queue[i].(*url.Error); ok && uerr != nil { //nolint:errorlint // first URL error of a bounded walk; errors.As is the unbounded search
			// Why: hand out a scrubbed copy, never the original that holds the key.
			c := Client{apiKey: e.key}
			*dst = &url.Error{Op: c.scrubText(uerr.Op), URL: c.scrubText(redactURL(c.scrub(uerr.URL))), Err: c.hideCause(uerr.Err)}
			return true
		}
		queue = appendWrapped(queue, queue[i])
	}
	return false
}

// Format prints only the sanitized message for every verb and flag.
func (e *redactedError) Format(f fmt.State, verb rune) {
	if _, err := fmt.Fprintf(f, fmt.FormatString(f, verb), e.msg); err != nil {
		// Why: Format has no error return; a failed write leaves nothing more to print.
		return
	}
}

type opaqueURLCause struct{ hidden *redactedError }

// Error returns the sanitized cause message.
func (e *opaqueURLCause) Error() string { return e.hidden.Error() }

// Is matches the hidden cause.
func (e *opaqueURLCause) Is(target error) bool { return e.hidden.Is(target) }

// As recovers a sanitized copy of a hidden URL error.
func (e *opaqueURLCause) As(target any) bool { return e.hidden.As(target) }

// Format prints only the sanitized cause message.
func (e *opaqueURLCause) Format(f fmt.State, verb rune) { e.hidden.Format(f, verb) }

type classifiedURLCause struct{ opaqueURLCause }

// Timeout delegates to the original immediate cause's Timeout method.
func (e *classifiedURLCause) Timeout() bool {
	t, ok := e.hidden.err.(interface{ Timeout() bool })
	return ok && t.Timeout()
}

// Temporary delegates to the original immediate cause's Temporary method.
func (e *classifiedURLCause) Temporary() bool {
	t, ok := e.hidden.err.(interface{ Temporary() bool })
	return ok && t.Temporary()
}

// hiddenRedaction returns the package-owned wrapper behind node, if any.
func hiddenRedaction(node error) *redactedError {
	switch e := node.(type) { //nolint:errorlint // inspect only this node's type
	case *redactedError:
		return e
	case *opaqueURLCause:
		return e.hidden
	case *classifiedURLCause:
		return e.hidden
	default:
		return nil
	}
}

// maxErrNodes bounds the error tree walk in carriesKey and the joined-error budget in walk.
const maxErrNodes = 64

// maxWalkSteps bounds the total nodes visited by walk so cyclic unwrap chains terminate.
const maxWalkSteps = 4096

// redactedTreeMsg is the replacement message when an error tree exceeds maxErrNodes.
const redactedTreeMsg = "error tree too large: details redacted"

// scrubError hides error trees that carry the API key, contain custom formatters, or exceed the traversal limit.
func (c *Client) scrubError(err error) error {
	carry, tooLarge := c.checkErrorTree(err)
	if !carry {
		return err
	}
	if tooLarge {
		return &redactedError{msg: redactedTreeMsg, err: err, key: c.apiKey}
	}
	return &redactedError{msg: c.scrubText(err.Error()), err: err, key: c.apiKey}
}

// hideCause wraps a URL error's immediate cause and preserves its classification results.
func (c *Client) hideCause(err error) error {
	if isNilError(err) {
		return nil
	}
	hidden := &redactedError{msg: redactedTreeMsg, err: err, key: c.apiKey}
	if _, tooLarge := c.checkErrorTree(err); !tooLarge {
		hidden.msg = c.scrubText(err.Error())
	}
	cause := opaqueURLCause{hidden: hidden}
	_, timesOut := err.(interface{ Timeout() bool })
	_, temporary := err.(interface{ Temporary() bool })
	if timesOut || temporary {
		return &classifiedURLCause{opaqueURLCause: cause}
	}
	return &cause
}

// carriesKey reports whether an error tree needs redaction.
func (c *Client) carriesKey(err error) bool {
	carry, _ := c.checkErrorTree(err)
	return carry
}

// checkErrorTree reports whether err needs redaction and whether its Error method is unsafe to call.
func (c *Client) checkErrorTree(err error) (bool, bool) {
	if err == nil {
		return false, false
	}
	queue := []error{err}
	for i := 0; i < maxErrNodes && i < len(queue); i++ {
		if unsafeErrorNode(queue[i], maxErrNodes-len(queue)) {
			// Why: formatting an oversized tree or a typed-nil node can be unsafe.
			return true, true
		}
		queue = appendWrapped(queue, queue[i])
		if len(queue) > maxErrNodes {
			// Why: a tree past the bound is hidden unread; formatting a fan-out root can be exponential.
			return true, true
		}
	}
	for _, node := range queue {
		if c.errorNodeNeedsRedaction(node) {
			return true, false
		}
	}
	return false, false
}

// errorNodeNeedsRedaction checks custom formatting, URL fields, and error text.
func (c *Client) errorNodeNeedsRedaction(node error) bool {
	// Why: custom formatters can print text beyond Error's result.
	if _, formats := node.(fmt.Formatter); formats && hiddenRedaction(node) == nil {
		return true
	}
	if uerr, ok := node.(*url.Error); ok && (c.containsKey(uerr.Op) || c.containsKey(uerr.URL)) { //nolint:errorlint // inspect only this node's fields
		return true
	}
	return c.containsKey(node.Error())
}

// unsafeErrorNode reports whether err or a direct child is typed nil, or the join exceeds the remaining slots.
func unsafeErrorNode(err error, remaining int) bool {
	if isNilError(err) {
		return true
	}
	if w := errors.Unwrap(err); w != nil {
		return isNilError(w)
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return false
	}
	children, clipped := boundedJoinChildren(joined, remaining)
	if clipped {
		return true
	}
	for _, child := range children {
		if child != nil && isNilError(child) {
			return true
		}
	}
	return false
}

// containsKey reports whether s holds the raw key or an encoded form of it.
func (c *Client) containsKey(s string) bool {
	return c.containsKeyForms(s) || c.containsCanonicalKey(s)
}

// containsKeyForms checks the fixed key forms, ignoring the hex case of percent escapes.
func (c *Client) containsKeyForms(s string) bool {
	if slices.ContainsFunc(c.keyForms(), func(form string) bool { return strings.Contains(s, form) }) {
		return true
	}
	start, _ := nextPercentKey(s, 0, c.percentForms())
	return start >= 0
}

// appendWrapped appends non-nil wrapped errors while bounding queue growth.
func appendWrapped(queue []error, err error) []error {
	if len(queue) > maxErrNodes || isNilError(err) {
		// Why: carriesKey already treats this tree as too large; a typed-nil node has no children.
		return queue
	}
	if w := errors.Unwrap(err); !isNilError(w) {
		return append(queue, w)
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return queue
	}
	children, clipped := boundedJoinChildren(joined, maxErrNodes-len(queue))
	for _, child := range children {
		if !isNilError(child) {
			queue = append(queue, child)
		}
	}
	if clipped {
		// Why: retain an overflow slot without reading the next child.
		queue = append(queue, nil)
	}
	return queue
}

// redactError sanitizes URL errors and hides error trees that may expose the API key.
func (c *Client) redactError(err error) error {
	// Why: only the root can be a *url.Error to copy; errors.As would search the whole tree unbounded.
	if uerr, ok := err.(*url.Error); ok && uerr != nil { //nolint:errorlint // root identity wanted; tree search is the defect
		// Why: copy only when sanitizing changed the URL text or hid the cause; an untouched root keeps its identity for errors.Is.
		// Why: a copy never mutates an error value net/http or a custom transport may share.
		cleanOp, cleanURL := c.scrubText(uerr.Op), c.scrubText(redactURL(c.scrub(uerr.URL)))
		if cleanOp != uerr.Op || cleanURL != uerr.URL || (uerr.Err != nil && c.carriesKey(uerr.Err)) {
			err = &url.Error{Op: cleanOp, URL: cleanURL, Err: c.hideCause(uerr.Err)}
		}
	}
	return c.scrubError(err)
}

// redactURL redacts apikey query values or drops the query when parsing fails.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	var q url.Values
	if err == nil {
		q, err = url.ParseQuery(u.RawQuery)
	}
	if err != nil {
		// Why: an unparseable URL or query may still carry the key, so drop the query whole.
		base, _, _ := strings.Cut(raw, "?")
		return base
	}
	if !q.Has("apikey") {
		return raw
	}
	q.Set("apikey", "REDACTED")
	u.RawQuery = q.Encode()
	return u.String()
}
