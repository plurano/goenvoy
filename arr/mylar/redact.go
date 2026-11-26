package mylar

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
)

// validAPIKey reports whether every byte belongs to the URL-unreserved set.
func validAPIKey(key string) bool {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	return strings.Trim(key, unreserved) == ""
}

// scrub replaces the literal API key in s with REDACTED.
func (c *Client) scrub(s string) string {
	if c.apiKey == "" {
		return s
	}
	return strings.ReplaceAll(s, c.apiKey, "REDACTED")
}

// scrubBody applies inline and canonical key redaction to a response body.
func (c *Client) scrubBody(text string) string {
	return c.scrubText(text)
}

// scrubText applies inline redaction and hides text if decoding still reveals the key.
func (c *Client) scrubText(text string) string {
	text = c.scrub(text)
	if c.containsKey(text) {
		return "REDACTED"
	}
	return text
}

// maxDecodePasses bounds the layers of escape decoding.
const maxDecodePasses = 4

// maxDecodeProjections bounds the distinct new texts at each layer.
const maxDecodeProjections = 16

// maxDecodeBytesFactor bounds retained projection storage relative to the input size.
const maxDecodeBytesFactor = 8

// maxSpellingStepsFactor bounds spelling comparisons per input byte, plus one step per key byte.
const maxSpellingStepsFactor = 8

type escapeKinds uint8

const (
	percentEscapes escapeKinds = 1 << iota
	backslashEscapes
)

// containsKey reports whether text contains the key or escape decoding reaches a bound.
func (c *Client) containsKey(text string) bool {
	if c.apiKey == "" {
		return false
	}
	if c.matchesKeySpelling(text) {
		return true
	}
	if !strings.ContainsAny(text, `%\`) {
		return false
	}
	frontier := []string{text}
	seen := map[string]struct{}{text: {}}
	remainingBytes := uint64(len(text)) * maxDecodeBytesFactor
	for pass := 0; pass < maxDecodePasses && len(frontier) != 0; pass++ {
		next, redact := c.decodeLayer(frontier, seen, &remainingBytes)
		if redact {
			return true
		}
		frontier = next
	}
	// Why: a new projection at the depth limit may still conceal the key.
	return len(frontier) != 0
}

// matchesKeySpelling checks literal and single-layer key spellings and reports budget exhaustion as a match.
func (c *Client) matchesKeySpelling(text string) bool {
	key := c.apiKey
	if strings.Contains(text, key) {
		return true
	}
	if !strings.ContainsAny(text, `%\`) {
		return false
	}
	remaining := uint64(len(text))*maxSpellingStepsFactor + uint64(len(key))
	for start := 0; start <= len(text)-len(key); start++ {
		if matchesKeyAt(text[start:], key, &remaining) || remaining == 0 {
			return true
		}
	}
	return false
}

// matchesKeyAt checks whether the key starts at the first byte of text within the shared budget.
func matchesKeyAt(text, key string, remaining *uint64) bool {
	for i := range len(key) {
		if len(text) < len(key)-i || *remaining == 0 {
			return false
		}
		*remaining--
		size := keyByteSpellingLen(text, key[i])
		if size == 0 {
			return false
		}
		text = text[size:]
	}
	return true
}

// keyByteSpellingLen returns the width of the matching spelling, or zero.
func keyByteSpellingLen(text string, want byte) int {
	switch text[0] {
	case '%':
		if len(text) >= 3 && matchesHexByte(text[1:3], want) {
			return 3
		}
	case '\\':
		if len(text) >= 6 && text[:4] == `\u00` && matchesHexByte(text[4:6], want) {
			return 6
		}
	case want:
		return 1
	}
	return 0
}

// matchesHexByte compares a pair of hex digits to a byte without allocating.
func matchesHexByte(text string, want byte) bool {
	const digits = "0123456789abcdef"
	return matchesHexDigit(text[0], digits[want>>4]) && matchesHexDigit(text[1], digits[want&0xf])
}

// matchesHexDigit compares an ASCII hex byte to a lowercase hex digit.
func matchesHexDigit(got, want byte) bool {
	if got >= 'A' && got <= 'F' {
		got += 'a' - 'A'
	}
	return got == want
}

// decodeLayer collects unseen projections and reports a key match or exceeded budget.
func (c *Client) decodeLayer(frontier []string, seen map[string]struct{}, remainingBytes *uint64) ([]string, bool) {
	next := make([]string, 0, maxDecodeProjections)
	for _, text := range frontier {
		for _, kinds := range [...]escapeKinds{percentEscapes, backslashEscapes, percentEscapes | backslashEscapes} {
			decoded := decodeEscapes(text, kinds)
			// Why: the input is already seen, so this also skips unchanged projections.
			if _, visited := seen[decoded]; visited {
				continue
			}
			// Why: the retained string shares the builder grown to the parent length.
			size := uint64(len(text))
			if size > *remainingBytes || len(next) == maxDecodeProjections || c.matchesKeySpelling(decoded) {
				return nil, true
			}
			*remainingBytes -= size
			seen[decoded] = struct{}{}
			next = append(next, decoded)
		}
	}
	return next, false
}

// decodeEscapes consumes each recognized escape once and copies all other bytes.
func decodeEscapes(text string, kinds escapeKinds) string {
	var out strings.Builder
	out.Grow(len(text))
	for i := 0; i < len(text); {
		var size int
		switch text[i] {
		case '%':
			if kinds&percentEscapes != 0 {
				size = writePercentEscape(&out, text[i:])
			}
		case '\\':
			if kinds&backslashEscapes != 0 {
				size = writeBackslashEscape(&out, text[i:])
			}
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
	high, highOK := hexNibble(text[1])
	low, lowOK := hexNibble(text[2])
	if !highOK || !lowOK {
		return 0
	}
	out.WriteByte(high<<4 | low)
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
	var value rune
	for i := 2; i < 6; i++ {
		digit, ok := hexNibble(text[i])
		if !ok {
			return 0, false
		}
		value = value<<4 | rune(digit)
	}
	return value, true
}

// hexNibble returns the value of an ASCII hex digit.
func hexNibble(b byte) (byte, bool) {
	switch {
	case '0' <= b && b <= '9':
		return b - '0', true
	case 'a' <= b && b <= 'f':
		return b - 'a' + 10, true
	case 'A' <= b && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

type redactedError struct {
	msg string
	// Why: no Unwrap method, so callers cannot reach text that holds the key.
	err error
	// Why: As uses the original key even if the client is replaced.
	key    string
	unsafe bool
}

// Error returns the sanitized message.
func (e *redactedError) Error() string { return e.msg }

// RedactionBoundary marks a wrapper so sibling client modules stop at each other's wrappers.
func (*redactedError) RedactionBoundary() {}

// Is matches the hidden error without exposing it.
func (e *redactedError) Is(target error) bool {
	return e.walk(target, func(node error) walkAction {
		// Why: visit nested wrappers within this walk's budget.
		if hiddenRedaction(node) != nil || foreignRedaction(node) {
			return walkDescend
		}
		if m, ok := node.(interface{ Is(error) bool }); ok && m.Is(target) {
			return walkStop
		}
		return walkDescend
	})
}

// Timeout reports whether the underlying error timed out and returns false for unsafe trees.
func (e *redactedError) Timeout() bool {
	return classifyHiddenError(e, hiddenTimeoutClassifier.Timeout)
}

// Temporary reports whether the hidden error is temporary and returns false for unsafe trees.
func (e *redactedError) Temporary() bool {
	return classifyHiddenError(e, hiddenTemporaryClassifier.Temporary)
}

// Why: Go 1.26 vet's printf pass panics on inline interface method expressions. Aliases preserve As target types.
type (
	hiddenTimeoutClassifier   = interface{ Timeout() bool }
	hiddenTemporaryClassifier = interface{ Temporary() bool }
)

// classifyHiddenError snapshots the hidden tree once and reports its first applicable bounded classification.
func classifyHiddenError[T any](e *redactedError, classify func(T) bool) bool {
	if e.unsafe {
		return false
	}
	tree, unsafe := inspectErrorTree(e.err)
	if unsafe {
		return false
	}
	return classifyTree(tree, e.key, classify)
}

type errorTree struct {
	nodes []error
	ends  []int
}

type errorSpan struct {
	tree       *errorTree
	start, end int
}

type errorSlot struct {
	tree  *errorTree
	index int
}

// children returns the range recorded when this slot was inspected.
func (slot errorSlot) children() errorSpan {
	start := 1
	if slot.index > 0 {
		start = slot.tree.ends[slot.index-1]
	}
	return errorSpan{tree: slot.tree, start: start, end: slot.tree.ends[slot.index]}
}

// classifyTree reports the first applicable classification in depth-first errors.Is order.
func classifyTree[T any](tree errorTree, key string, classify func(T) bool) bool {
	if len(tree.nodes) == 0 {
		return false
	}
	// Why: classify the tree that passed inspection.
	stack := []errorSpan{{tree: &tree, end: 1}}
	// Why: inspections and popped slots draw from the same budget.
	for steps := len(tree.nodes); steps < maxWalkSteps && len(stack) > 0; {
		var slot errorSlot
		stack, slot = popErrorSlot(stack)
		steps++
		action, reported := classifyNode(slot, key, classify)
		if action == walkStop {
			return reported
		}
		if action == walkCauseOnly {
			stack = stack[:0]
		}
		children, read, unsafe := classificationChildren(slot, maxWalkSteps-steps)
		if unsafe {
			return false
		}
		steps += read
		if children.start < children.end {
			stack = append(stack, children)
		}
	}
	return false
}

// popErrorSlot advances the top span and returns its first slot.
func popErrorSlot(stack []errorSpan) ([]errorSpan, errorSlot) {
	last := &stack[len(stack)-1]
	slot := errorSlot{tree: last.tree, index: last.start}
	last.start++
	if last.start == last.end {
		return stack[:len(stack)-1], slot
	}
	return stack, slot
}

// classificationChildren returns the child span, inspection cost, and whether traversal must stop.
func classificationChildren(slot errorSlot, remaining int) (errorSpan, int, bool) {
	if wrapper, ok := slot.tree.nodes[slot.index].(*redactedError); ok { //nolint:errorlint // enter only the current package wrapper
		if remaining < maxErrNodes {
			return errorSpan{}, 0, true
		}
		tree, unsafe := inspectErrorTree(wrapper.err)
		return errorSpan{tree: &tree, end: min(1, len(tree.nodes))}, len(tree.nodes), unsafe
	}
	return slot.children(), 0, false
}

// classifyNode returns the traversal action and classification for a single node.
func classifyNode[T any](slot errorSlot, key string, classify func(T) bool) (walkAction, bool) {
	node := slot.tree.nodes[slot.index]
	if blocksHiddenClassification(node, key) || foreignRedaction(node) {
		return walkStop, false
	}
	switch node.(type) { //nolint:errorlint // classify only the current node
	case *redactedError:
		return walkDescend, false
	case *opaqueURLCause:
		return walkStop, false
	case *classifiedURLCause:
		classifier, ok := node.(T)
		return walkStop, ok && classify(classifier)
	}
	if _, ok := node.(T); ok && isStdlibClassifier(node) {
		return classifyStdlibNode(slot, classify)
	}
	return classifyExternalNode(slot, classify)
}

// classifyStdlibNode returns the action for a known stdlib classifier's effective delegate.
func classifyStdlibNode[T any](slot errorSlot, classify func(T) bool) (walkAction, bool) {
	children := slot.children()
	if children.start == children.end {
		return walkStop, false
	}
	node := slot.tree.nodes[slot.index]
	child := errorSlot{tree: slot.tree, index: children.start}
	delegate := classifierDelegate(node, child)
	if errno, ok := delegate.(syscall.Errno); ok { //nolint:errorlint // match the effective delegate used by the stdlib classifier
		return walkStop, classifyErrno(node, errno, slot.tree.nodes[child.index], classify)
	}
	if _, classifies := delegate.(T); classifies {
		return walkCauseOnly, false
	}
	return walkStop, false
}

// classifyErrno classifies an observed Errno and preserves OpError's platform-specific accept rule.
func classifyErrno[T any](node error, errno syscall.Errno, child error, classify func(T) bool) bool {
	var leaf error = errno
	if op, ok := node.(*net.OpError); ok { //nolint:errorlint // preserve only the current OpError's accept behavior
		if _, syscallChild := child.(*os.SyscallError); syscallChild { //nolint:errorlint // preserve the observed delegate shape
			leaf = &os.SyscallError{Err: errno}
		}
		leaf = &net.OpError{Op: op.Op, Err: leaf}
	}
	classifier, ok := leaf.(T)
	return ok && classify(classifier)
}

// classifyExternalNode checks the classification method of an external node.
func classifyExternalNode[T any](slot errorSlot, classify func(T) bool) (walkAction, bool) {
	classifier, ok := slot.tree.nodes[slot.index].(T)
	if !ok {
		// Why: an As hook runs code outside the walked tree.
		return walkDescend, false
	}
	if slot.hasPackageWrapper() {
		return walkStop, false
	}
	return walkStop, classify(classifier)
}

// hasPackageWrapper reports whether the slot's recorded subtree contains a package wrapper.
func (slot errorSlot) hasPackageWrapper() bool {
	queue := [maxErrNodes]int{slot.index}
	count := 1
	for i := 0; i < maxErrNodes && i < count; i++ {
		current := errorSlot{tree: slot.tree, index: queue[i]}
		node := slot.tree.nodes[current.index]
		if hiddenRedaction(node) != nil || foreignRedaction(node) {
			return true
		}
		children := current.children()
		for index := children.start; index < children.end; index++ {
			queue[count] = index
			count++
		}
	}
	return false
}

// isStdlibClassifier reports whether node has a classifier that delegates to an underlying error.
func isStdlibClassifier(node error) bool {
	switch node.(type) { //nolint:errorlint // match the current stdlib wrapper's dynamic type
	case *net.OpError, *os.SyscallError, *fs.PathError, *url.Error:
		return true
	default:
		return false
	}
}

// classifierDelegate returns the recorded error used by a known stdlib classifier.
func classifierDelegate(node error, child errorSlot) error {
	delegate := child.tree.nodes[child.index]
	if _, op := node.(*net.OpError); op { //nolint:errorlint // match only the current stdlib wrapper
		// Why: both OpError classifiers inspect the error inside a SyscallError directly.
		if _, syscallChild := delegate.(*os.SyscallError); syscallChild { //nolint:errorlint // match the observed direct wrapper
			children := child.children()
			if children.start == children.end {
				return nil
			}
			return child.tree.nodes[children.start]
		}
	}
	return delegate
}

// blocksHiddenClassification reports whether a package wrapper is unsafe or belongs to another key.
func blocksHiddenClassification(node error, key string) bool {
	hidden := hiddenRedaction(node)
	return hidden != nil && (hidden.unsafe || hidden.key != key)
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
		if visitWalkNode(node, target, visit) == walkStop {
			return true
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

// visitWalkNode checks identity before applying the visitor.
func visitWalkNode(node, target error, visit func(error) walkAction) walkAction {
	if target != nil && node == target { //nolint:errorlint // compare this node without starting another traversal
		return walkStop
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
	if err == nil {
		return true
	}
	v := reflect.ValueOf(err)
	if slices.Contains([]reflect.Kind{reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice}, v.Kind()) {
		return v.IsNil()
	}
	return false
}

// As sets target to a sanitized copy of the first non-nil *url.Error within 64 breadth-first nodes.
// It suppresses classification if the current tree is unsafe, preserves nil causes, and replaces unsafe causes with a fixed error.
// For a safe immediate cause implementing Timeout or Temporary, the copy reads its tree once and classifies from that read.
// One classification counts popped nodes and every node its inspections read against 4096; entering a same-key wrapper with fewer than 64 left → false.
func (e *redactedError) As(target any) bool {
	dst, ok := target.(**url.Error)
	if !ok {
		return false
	}
	// Why: finish bounded inspection before copying so a later sibling can suppress classification.
	queue := []error{e.err}
	unsafe := e.unsafe
	var firstURL *url.Error
	for i := 0; i < maxErrNodes && i < len(queue); i++ {
		if uerr, isURL := queue[i].(*url.Error); firstURL == nil && isURL && uerr != nil { //nolint:errorlint // select the first URL error of the bounded walk
			firstURL = uerr
		}
		var unsafeNode bool
		queue, unsafeNode = appendWrappedChildren(queue, queue[i])
		unsafe = unsafe || unsafeNode
	}
	if firstURL == nil {
		return false
	}
	c := Client{apiKey: e.key}
	*dst = &url.Error{
		Op: c.scrubText(firstURL.Op), URL: c.scrubText(redactURL(firstURL.URL)),
		Err: c.hideURLCause(firstURL.Err, unsafe),
	}
	return true
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

// RedactionBoundary marks a wrapper so sibling client modules stop at each other's wrappers.
func (*opaqueURLCause) RedactionBoundary() {}

// Is matches the hidden cause.
func (e *opaqueURLCause) Is(target error) bool { return e.hidden.Is(target) }

// As recovers a sanitized copy of a hidden URL error.
func (e *opaqueURLCause) As(target any) bool { return e.hidden.As(target) }

// Format prints only the sanitized cause message.
func (e *opaqueURLCause) Format(f fmt.State, verb rune) { e.hidden.Format(f, verb) }

type classifiedURLCause struct {
	opaqueURLCause
	timeout   bool
	temporary bool
}

// Timeout reports whether the cause timed out when copied.
func (e *classifiedURLCause) Timeout() bool { return e.timeout }

// Temporary reports whether the cause was temporary when copied.
func (e *classifiedURLCause) Temporary() bool { return e.temporary }

// newClassifiedURLCause captures each classifier's result from the same inspected cause and a synthetic URL root.
func newClassifiedURLCause(cause opaqueURLCause, tree errorTree) *classifiedURLCause {
	tree = tree.withURLRoot()
	return &classifiedURLCause{
		opaqueURLCause: cause,
		timeout:        classifyTree(tree, cause.hidden.key, hiddenTimeoutClassifier.Timeout),
		temporary:      classifyTree(tree, cause.hidden.key, hiddenTemporaryClassifier.Temporary),
	}
}

// withURLRoot adds a synthetic URL slot outside the cause's 64-node inspection limit.
func (tree errorTree) withURLRoot() errorTree {
	nodes := make([]error, 1, len(tree.nodes)+1)
	nodes[0] = &url.Error{Err: tree.nodes[0]}
	ends := make([]int, len(tree.ends)+1)
	ends[0] = 2
	for index, end := range tree.ends {
		ends[index+1] = end + 1
	}
	return errorTree{nodes: append(nodes, tree.nodes...), ends: ends}
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

// foreignRedaction reports whether node is a redaction boundary from another module.
func foreignRedaction(node error) bool {
	_, boundary := node.(interface{ RedactionBoundary() })
	return boundary && hiddenRedaction(node) == nil
}

// maxErrNodes bounds the error tree walk in carriesKey and the joined-error budget in walk.
const maxErrNodes = 64

// maxWalkSteps bounds the total nodes visited by identity search or classification.
const maxWalkSteps = 4096

// redactedTreeMsg is the replacement message when an error tree exceeds maxErrNodes.
const redactedTreeMsg = "error tree too large: details redacted"

// scrubError hides error trees that carry the API key, contain custom formatting or As, or exceed the traversal limit.
func (c *Client) scrubError(err error) error {
	carry, unsafe := c.checkErrorTree(err)
	if !carry {
		return err
	}
	hidden := &redactedError{msg: redactedTreeMsg, err: err, key: c.apiKey, unsafe: unsafe}
	if !unsafe {
		hidden.msg = c.scrubText(err.Error())
	}
	return hidden
}

// hideCause keeps nil causes and replaces typed-nil or unsafe causes with a fixed, unclassified error.
// It scrubs safe causes and captures their classifications when applicable.
func (c *Client) hideCause(err error) error {
	return c.hideURLCause(err, false)
}

// hideURLCause sanitizes the cause and uses its single inspection for both classifications when safe.
func (c *Client) hideURLCause(err error, unsafeParent bool) error {
	if err == nil {
		return nil
	}
	tree, unsafe := inspectErrorTree(err)
	hidden := &redactedError{msg: redactedTreeMsg, err: err, key: c.apiKey, unsafe: unsafe || unsafeParent}
	cause := opaqueURLCause{hidden: hidden}
	if unsafe {
		// Why: retain bounded identity matching without exposing a live classifier.
		return &cause
	}
	hidden.msg = c.scrubText(err.Error())
	if hidden.unsafe {
		return &cause
	}
	_, timesOut := err.(hiddenTimeoutClassifier)
	_, temporary := err.(hiddenTemporaryClassifier)
	if timesOut || temporary {
		return newClassifiedURLCause(cause, tree)
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
	tree, unsafe := inspectErrorTree(err)
	if unsafe {
		return true, true
	}
	if slices.ContainsFunc(tree.nodes, c.hasCustomFormattingOrAs) {
		return true, false
	}
	for _, node := range tree.nodes {
		if c.errorNodeNeedsRedaction(node) {
			return true, false
		}
	}
	return false, false
}

// inspectErrorTree records each node's children in one bounded breadth-first read without calling Error or classifiers.
func inspectErrorTree(err error) (errorTree, bool) {
	if err == nil {
		return errorTree{}, false
	}
	tree := errorTree{nodes: []error{err}}
	for i := 0; i < maxErrNodes && i < len(tree.nodes); i++ {
		var unsafe bool
		tree.nodes, unsafe = appendWrappedChildren(tree.nodes, tree.nodes[i])
		if unsafe {
			// Why: formatting an oversized tree or a typed-nil node can be unsafe.
			return errorTree{}, true
		}
		tree.ends = append(tree.ends, len(tree.nodes))
	}
	return tree, false
}

// hasCustomFormattingOrAs reports whether a node outside the current key's wrappers controls formatting or errors.As.
func (c *Client) hasCustomFormattingOrAs(node error) bool {
	if hidden := hiddenRedaction(node); hidden != nil {
		return hidden.key != c.apiKey
	}
	_, formats := node.(fmt.Formatter)
	_, goStrings := node.(fmt.GoStringer)
	_, customAs := node.(interface{ As(any) bool })
	return formats || goStrings || customAs
}

// errorNodeNeedsRedaction checks URL fields, error text, and values visible to Go-syntax formatting.
func (c *Client) errorNodeNeedsRedaction(node error) bool {
	if uerr, ok := node.(*url.Error); ok && (c.containsKey(uerr.Op) || c.containsKey(uerr.URL)) { //nolint:errorlint // inspect only this node's fields
		return true
	}
	return c.containsKey(node.Error()) || c.reflectedErrorNeedsRedaction(reflect.ValueOf(node))
}

// maxReflectedValues bounds the number of values inspected for each error node.
const maxReflectedValues = 1024

// reflectedErrorNeedsRedaction checks visible values without invoking formatting methods.
func (c *Client) reflectedErrorNeedsRedaction(root reflect.Value) bool {
	queue := []reflect.Value{root}
	if root.Kind() == reflect.Pointer && !root.IsNil() {
		queue = append(queue, root.Elem())
	}
	for i := 0; i < len(queue) && i < maxReflectedValues; i++ {
		value := queue[i]
		if i != 0 && hasReflectedFormatter(value) {
			return true
		}
		queue = appendReflectedChildren(queue, value)
		if queue == nil || c.reflectedValueHasKey(value) {
			return true
		}
	}
	return false
}

// hasReflectedFormatter reports whether fmt would call formatting code for this value.
func hasReflectedFormatter(value reflect.Value) bool {
	if !value.CanInterface() || value.Kind() == reflect.Interface {
		// Why: an interface's dynamic value is checked separately when visited.
		return false
	}
	typ := value.Type()
	return typ.Implements(reflect.TypeFor[fmt.Formatter]()) || typ.Implements(reflect.TypeFor[fmt.GoStringer]())
}

// appendReflectedChildren appends visible children, returning nil if they would exceed the bound.
func appendReflectedChildren(queue []reflect.Value, value reflect.Value) []reflect.Value {
	switch value.Kind() {
	case reflect.Struct:
		return appendReflectedValues(queue, value.NumField(), value.Field)
	case reflect.Array, reflect.Slice:
		return appendReflectedValues(queue, value.Len(), value.Index)
	case reflect.Map:
		return appendReflectedMap(queue, value)
	case reflect.Interface:
		if elem := value.Elem(); elem.IsValid() {
			if len(queue) == maxReflectedValues {
				return nil
			}
			return append(queue, elem)
		}
	case reflect.Invalid, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.String,
		reflect.Chan, reflect.Func, reflect.Pointer, reflect.UnsafePointer:
		// Why: scalar values and nested pointers have no children visible to the walk.
	}
	return queue
}

// appendReflectedValues schedules an indexed set of children within the remaining budget.
func appendReflectedValues(queue []reflect.Value, count int, at func(int) reflect.Value) []reflect.Value {
	if count > maxReflectedValues-len(queue) {
		return nil
	}
	for i := range count {
		queue = append(queue, at(i))
	}
	return queue
}

// appendReflectedMap schedules map keys and values within the remaining budget.
func appendReflectedMap(queue []reflect.Value, value reflect.Value) []reflect.Value {
	count := value.Len()
	if count > (maxReflectedValues-len(queue))/2 {
		return nil
	}
	entries := value.MapRange()
	for range count {
		if !entries.Next() {
			break
		}
		queue = append(queue, entries.Key(), entries.Value())
	}
	return queue
}

// reflectedValueHasKey checks scalar values and byte sequences for the key.
func (c *Client) reflectedValueHasKey(value reflect.Value) bool {
	var text string
	switch value.Kind() {
	case reflect.String:
		text = value.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		text = strconv.FormatInt(value.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		text = "0x" + strconv.FormatUint(value.Uint(), 16)
	case reflect.Float32, reflect.Float64:
		text = strconv.FormatFloat(value.Float(), 'g', -1, value.Type().Bits())
	case reflect.Complex64, reflect.Complex128:
		text = strconv.FormatComplex(value.Complex(), 'g', -1, value.Type().Bits())
	case reflect.Bool:
		text = strconv.FormatBool(value.Bool())
	case reflect.Array, reflect.Slice:
		return c.reflectedBytesHaveKey(value)
	case reflect.Invalid, reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer,
		reflect.Struct, reflect.UnsafePointer:
		return false
	}
	return c.containsKey(text)
}

// reflectedBytesHaveKey checks byte sequences as text after their length has been bounded.
func (c *Client) reflectedBytesHaveKey(value reflect.Value) bool {
	if value.Type().Elem().Kind() != reflect.Uint8 {
		return false
	}
	if value.Kind() == reflect.Slice || value.CanAddr() {
		return c.containsKey(string(value.Bytes()))
	}
	bytes := make([]byte, value.Len())
	for i := range bytes {
		bytes[i] = byte(value.Index(i).Uint() & 0xff)
	}
	return c.containsKey(string(bytes))
}

// appendWrappedChildren reads children once, queues non-nil children, and reports typed nils or overflow.
func appendWrappedChildren(queue []error, err error) ([]error, bool) {
	if len(queue) > maxErrNodes || isNilError(err) {
		return queue, true
	}
	remaining := maxErrNodes - len(queue)
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children, clipped := boundedJoinChildren(joined, remaining)
		return appendJoinChildren(queue, children, clipped)
	}
	child := errors.Unwrap(err)
	switch {
	case child == nil:
		return queue, false
	case isNilError(child):
		return queue, true
	case remaining == 0:
		return append(queue, nil), true
	default:
		return append(queue, child), false
	}
}

// appendJoinChildren queues non-nil children and reports typed nils or a clipped join.
func appendJoinChildren(queue, children []error, clipped bool) ([]error, bool) {
	unsafe := clipped
	for _, child := range children {
		switch {
		case child == nil:
		case isNilError(child):
			unsafe = true
		default:
			queue = append(queue, child)
		}
	}
	if clipped {
		// Why: retain an overflow slot without reading the next child.
		queue = append(queue, nil)
	}
	return queue, unsafe
}

// redactError sanitizes URL errors and hides error trees that may expose the API key.
func (c *Client) redactError(err error) error {
	// Why: only the root can be a *url.Error to copy; errors.As would search the whole tree unbounded.
	if uerr, ok := err.(*url.Error); ok && uerr != nil { //nolint:errorlint // root identity wanted; tree search is the defect
		// Why: copy only when sanitizing changed the URL text or hid the cause; an untouched root keeps its identity for errors.Is.
		// Why: a copy never mutates an error value net/http or a custom transport may share.
		cleanOp, cleanURL := c.scrubText(uerr.Op), c.scrubText(redactURL(uerr.URL))
		if cleanOp != uerr.Op || cleanURL != uerr.URL || (uerr.Err != nil && c.carriesKey(uerr.Err)) {
			// Why: the copy's fields are already sanitized, including its package-owned cause formatter.
			return &url.Error{Op: cleanOp, URL: cleanURL, Err: c.hideCause(uerr.Err)}
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
