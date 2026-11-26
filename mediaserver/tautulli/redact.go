package tautulli

import (
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

// maxDecodeBytesFactor bounds retained projection bytes relative to the input size.
const maxDecodeBytesFactor = 8

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

// matchesKeySpelling checks every possible start for literal or single-layer key bytes.
func (c *Client) matchesKeySpelling(text string) bool {
	key := c.apiKey
	if strings.Contains(text, key) {
		return true
	}
	if !strings.ContainsAny(text, `%\`) {
		return false
	}
	for start := 0; start <= len(text)-len(key); start++ {
		if matchesKeyAt(text[start:], key) {
			return true
		}
	}
	return false
}

// matchesKeyAt checks whether the key starts at the first byte of text.
func matchesKeyAt(text, key string) bool {
	for i := range len(key) {
		if len(text) < len(key)-i {
			return false
		}
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
	return text[0]|0x20 == digits[want>>4] && text[1]|0x20 == digits[want&0xf]
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
			size := uint64(len(decoded))
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
		if unsafeURLCause(node) {
			return walkStop
		}
		var action walkAction
		action, reported = classifyNode(node, classify)
		return action
	})
	return reported
}

// unsafeURLCause reports whether a URL error's immediate cause is unsafe to classify.
func unsafeURLCause(node error) bool {
	uerr, ok := node.(*url.Error) //nolint:errorlint // classify only the current URL error
	if !ok {
		return false
	}
	_, unsafe := inspectErrorTree(uerr.Err)
	return unsafe
}

// classifyNode returns the traversal action and classification for a single node.
func classifyNode[T any](node error, classify func(T) bool) (walkAction, bool) {
	if uerr, ok := node.(*url.Error); ok { //nolint:errorlint // a URL error classifies its immediate cause
		// Why: schedule the immediate cause so nested URL errors share the walk budget.
		_, classifies := uerr.Err.(T)
		if classifies {
			return walkCauseOnly, false
		}
		return walkStop, false
	}
	classifier, ok := node.(T)
	if !ok {
		as, hasAs := node.(interface{ As(any) bool })
		if !hasAs || !as.As(&classifier) || isNilValue(classifier) {
			return walkDescend, false
		}
	}
	return walkStop, classify(classifier)
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

// As sets target to a sanitized copy of the first non-nil *url.Error within 64 breadth-first nodes.
// It preserves nil causes and replaces typed-nil or unsafe causes with a fixed, unclassified error.
// If a safe immediate cause implements Timeout or Temporary, the copy captures both classifications
// in one walk of up to 4096 nodes and 64 joined errors.
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
			*dst = &url.Error{Op: c.scrubText(uerr.Op), URL: c.scrubText(redactURL(uerr.URL)), Err: c.hideCause(uerr.Err)}
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

type classifiedURLCause struct {
	opaqueURLCause
	timeout   bool
	temporary bool
}

// Timeout reports whether the cause timed out when copied.
func (e *classifiedURLCause) Timeout() bool { return e.timeout }

// Temporary reports whether the cause was temporary when copied.
func (e *classifiedURLCause) Temporary() bool { return e.temporary }

// newClassifiedURLCause captures both classifications in one URL-aware walk.
func newClassifiedURLCause(cause opaqueURLCause) *classifiedURLCause {
	copyCause := &classifiedURLCause{opaqueURLCause: cause}
	probe := &redactedError{err: &url.Error{Err: cause.hidden.err}}
	timeoutDone, temporaryDone := false, false
	probe.walk(nil, func(node error) walkAction {
		timeoutAction, temporaryAction := walkDescend, walkDescend
		if !timeoutDone {
			timeoutAction, copyCause.timeout = classifyNode(node, hiddenTimeoutClassifier.Timeout)
			timeoutDone = timeoutAction == walkStop
		}
		if !temporaryDone {
			temporaryAction, copyCause.temporary = classifyNode(node, hiddenTemporaryClassifier.Temporary)
			temporaryDone = temporaryAction == walkStop
		}
		switch {
		case timeoutDone && temporaryDone:
			return walkStop
		case timeoutAction == walkCauseOnly || temporaryAction == walkCauseOnly:
			return walkCauseOnly
		default:
			return walkDescend
		}
	})
	return copyCause
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

// scrubError hides error trees that carry the API key, contain custom formatting or As, or exceed the traversal limit.
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

// hideCause keeps nil causes and replaces typed-nil or unsafe causes with a fixed, unclassified error.
// It scrubs safe causes and captures their classifications when applicable.
func (c *Client) hideCause(err error) error {
	if err == nil {
		return nil
	}
	hidden := &redactedError{msg: redactedTreeMsg, err: err, key: c.apiKey}
	cause := opaqueURLCause{hidden: hidden}
	if _, unsafe := inspectErrorTree(err); unsafe {
		// Why: retain bounded identity matching without exposing a live classifier.
		return &cause
	}
	hidden.msg = c.scrubText(err.Error())
	_, timesOut := err.(hiddenTimeoutClassifier)
	_, temporary := err.(hiddenTemporaryClassifier)
	if timesOut || temporary {
		return newClassifiedURLCause(cause)
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
	queue, unsafe := inspectErrorTree(err)
	if unsafe {
		return true, true
	}
	if slices.ContainsFunc(queue, hasCustomFormattingOrAs) {
		return true, false
	}
	for _, node := range queue {
		if c.errorNodeNeedsRedaction(node) {
			return true, false
		}
	}
	return false, false
}

// inspectErrorTree collects nodes in breadth-first order without calling Error or classifiers.
func inspectErrorTree(err error) ([]error, bool) {
	if err == nil {
		return nil, false
	}
	queue := []error{err}
	for i := 0; i < maxErrNodes && i < len(queue); i++ {
		if unsafeErrorNode(queue[i], maxErrNodes-len(queue)) {
			// Why: formatting an oversized tree or a typed-nil node can be unsafe.
			return nil, true
		}
		queue = appendWrapped(queue, queue[i])
		if len(queue) > maxErrNodes {
			// Why: a tree past the bound is hidden unread; formatting a fan-out root can be exponential.
			return nil, true
		}
	}
	return queue, false
}

// hasCustomFormattingOrAs reports whether an external node controls formatting or errors.As.
func hasCustomFormattingOrAs(node error) bool {
	if hiddenRedaction(node) != nil {
		return false
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
		elem := root.Elem()
		if slices.Contains([]reflect.Kind{reflect.Array, reflect.Slice, reflect.Struct, reflect.Map}, elem.Kind()) {
			queue = append(queue, elem)
		}
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
