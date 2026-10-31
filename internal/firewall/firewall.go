// Package firewall parses the bundled IPdeny IPv4 zone and renders the complete
// nftables batch owned by Socks-VPS. It does not execute nft.
package firewall

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

const (
	TableFamily = "ip"
	TableName   = "socks_vps"
	SetName     = "cn_ipv4"
	ChainName   = "input"

	tableComment     = "Socks-VPS managed table"
	OwnershipComment = "Socks-VPS managed CN IPv4 set"
	chainComment     = "Socks-VPS managed input chain"

	// optionsHeaderLength is the IPv4 header length, in 32-bit words, above
	// which a packet carries IP options. CVE-2026-98432 is only reachable
	// through TCP connection requests that carry IPv4 options.
	optionsHeaderLength = 5

	minPort = 1024
	maxPort = 65535
)

var (
	ErrEmptyCIDRs          = errors.New("IPv4 CIDR list is empty")
	ErrTableConflict       = errors.New("nftables table ip socks_vps is not owned by Socks-VPS")
	ErrTableNotPresent     = errors.New("nftables JSON does not contain table ip socks_vps")
	ErrTableUnhealthy      = errors.New("nftables table ip socks_vps does not provide the required listener protection")
	ErrBlockedNotListening = errors.New("every CN-blocked port must also be a listener port")
)

// TableState describes the read-only ownership decision made before rendering.
type TableState uint8

const (
	TableAbsent TableState = iota
	TableOwned
	TableForeign
)

// ParseCIDRs strictly parses one canonical IPv4 network prefix per non-empty
// line, preserving source order.
func ParseCIDRs(reader io.Reader) ([]netip.Prefix, error) {
	if reader == nil {
		return nil, fmt.Errorf("parse IPv4 CIDRs: nil reader")
	}

	scanner := bufio.NewScanner(reader)
	var prefixes []netip.Prefix
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if line == "" {
			continue
		}
		if strings.TrimSpace(line) != line {
			return nil, fmt.Errorf("parse IPv4 CIDR line %d: surrounding whitespace is not allowed", lineNumber)
		}

		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("parse IPv4 CIDR line %d %q: %w", lineNumber, line, err)
		}
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("parse IPv4 CIDR line %d %q: IPv6 is not allowed", lineNumber, line)
		}
		if prefix != prefix.Masked() {
			return nil, fmt.Errorf("parse IPv4 CIDR line %d %q: host bits must be zero", lineNumber, line)
		}
		prefixes = append(prefixes, prefix)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read IPv4 CIDRs: %w", err)
	}
	if len(prefixes) == 0 {
		return nil, ErrEmptyCIDRs
	}
	return prefixes, nil
}

// ClassifyExistingTable verifies the fixed comment on the cn_ipv4 set from
// `nft --json list table ip socks_vps`. The set comment is the ownership
// marker because nftables versions in supported Linux distributions do not
// consistently include table or chain comments in JSON output. The caller
// handles the command's not-found exit as TableAbsent without fabricating JSON.
func ClassifyExistingTable(reader io.Reader) (TableState, error) {
	if reader == nil {
		return TableForeign, fmt.Errorf("classify existing nftables table: nil reader")
	}

	document, err := decodeNftablesDocument(reader)
	if err != nil {
		return TableForeign, err
	}

	tablePresent := false
	ownedSetPresent := false
	for _, raw := range document.Nftables {
		var object struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
			Set *struct {
				Family  string `json:"family"`
				Table   string `json:"table"`
				Name    string `json:"name"`
				Comment string `json:"comment"`
			} `json:"set"`
		}
		if err := json.Unmarshal(raw, &object); err != nil {
			return TableForeign, fmt.Errorf("decode nftables object: %w", err)
		}
		if object.Table != nil &&
			object.Table.Family == TableFamily &&
			object.Table.Name == TableName {
			tablePresent = true
		}
		if object.Set != nil &&
			object.Set.Family == TableFamily &&
			object.Set.Table == TableName &&
			object.Set.Name == SetName &&
			object.Set.Comment == OwnershipComment {
			ownedSetPresent = true
		}
	}

	if !tablePresent {
		return TableForeign, ErrTableNotPresent
	}
	if ownedSetPresent {
		return TableOwned, nil
	}
	return TableForeign, nil
}

type nftablesDocument struct {
	Nftables []json.RawMessage `json:"nftables"`
}

func decodeNftablesDocument(reader io.Reader) (nftablesDocument, error) {
	var document nftablesDocument
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&document); err != nil {
		return nftablesDocument{}, fmt.Errorf("decode nftables JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nftablesDocument{}, fmt.Errorf("decode nftables JSON: multiple JSON values")
		}
		return nftablesDocument{}, fmt.Errorf("decode nftables JSON trailing data: %w", err)
	}
	return document, nil
}

// CheckHealth verifies the minimum live nftables state required for the
// supplied listener ports: every listener port must be covered by the IPv4
// options drop rule (CVE-2026-98432 mitigation), and every CN-blocked port must
// additionally be covered by the CN source drop rule backed by a non-empty
// owned set. Extra set elements, rules, and unrelated objects are allowed.
func CheckHealth(reader io.Reader, listenerPorts, blockedPorts []int) error {
	if reader == nil {
		return fmt.Errorf("check nftables table health: nil reader")
	}
	requiredListeners, err := portSet("check nftables table health", listenerPorts)
	if err != nil {
		return err
	}
	requiredPorts, err := portSet("check nftables table health", blockedPorts)
	if err != nil {
		return err
	}
	if len(requiredListeners) == 0 {
		return fmt.Errorf("%w: no listener port requires protection", ErrTableUnhealthy)
	}
	for port := range requiredPorts {
		if _, listening := requiredListeners[port]; !listening {
			return fmt.Errorf("check nftables table health: %w: %d", ErrBlockedNotListening, port)
		}
	}

	document, err := decodeNftablesDocument(reader)
	if err != nil {
		return err
	}

	tablePresent := false
	ownedSetPresent := false
	setHasElements := false
	correctInputChain := false
	terminatingRuleBeforeCoverage := false
	acceptRuleBeforeCoverage := false
	coveredPorts := make(map[int]struct{}, len(requiredPorts))
	optionsCoveredPorts := make(map[int]struct{}, len(requiredListeners))
	coverageComplete := func() bool {
		return requiredPortsAreCovered(requiredPorts, coveredPorts) &&
			requiredPortsAreCovered(requiredListeners, optionsCoveredPorts)
	}
	for _, raw := range document.Nftables {
		var object struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
			Set *struct {
				Family  string          `json:"family"`
				Table   string          `json:"table"`
				Name    string          `json:"name"`
				Comment string          `json:"comment"`
				Elem    json.RawMessage `json:"elem"`
			} `json:"set"`
			Element *struct {
				Family string          `json:"family"`
				Table  string          `json:"table"`
				Name   string          `json:"name"`
				Elem   json.RawMessage `json:"elem"`
			} `json:"element"`
			Chain *struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Name   string `json:"name"`
				Type   string `json:"type"`
				Hook   string `json:"hook"`
				Prio   *int   `json:"prio"`
				Policy string `json:"policy"`
			} `json:"chain"`
			Rule *struct {
				Family string            `json:"family"`
				Table  string            `json:"table"`
				Chain  string            `json:"chain"`
				Expr   []json.RawMessage `json:"expr"`
			} `json:"rule"`
		}
		if err := json.Unmarshal(raw, &object); err != nil {
			return fmt.Errorf("decode nftables object: %w", err)
		}
		if object.Table != nil &&
			object.Table.Family == TableFamily &&
			object.Table.Name == TableName {
			tablePresent = true
		}
		if object.Set != nil &&
			object.Set.Family == TableFamily &&
			object.Set.Table == TableName &&
			object.Set.Name == SetName {
			if object.Set.Comment == OwnershipComment {
				ownedSetPresent = true
			}
			if nftExpressionIsNonEmpty(object.Set.Elem) {
				setHasElements = true
			}
		}
		if object.Element != nil &&
			object.Element.Family == TableFamily &&
			object.Element.Table == TableName &&
			object.Element.Name == SetName &&
			nftExpressionIsNonEmpty(object.Element.Elem) {
			setHasElements = true
		}
		if object.Chain != nil &&
			object.Chain.Family == TableFamily &&
			object.Chain.Table == TableName &&
			object.Chain.Name == ChainName &&
			object.Chain.Type == "filter" &&
			object.Chain.Hook == "input" &&
			object.Chain.Prio != nil &&
			*object.Chain.Prio == -10 &&
			object.Chain.Policy == "accept" {
			correctInputChain = true
		}
		if object.Rule != nil &&
			object.Rule.Family == TableFamily &&
			object.Rule.Table == TableName &&
			object.Rule.Chain == ChainName {
			for port := range matchingDropRulePorts(object.Rule.Expr) {
				coveredPorts[port] = struct{}{}
			}
			for port := range matchingOptionsDropRulePorts(object.Rule.Expr) {
				optionsCoveredPorts[port] = struct{}{}
			}
			if !coverageComplete() &&
				isUnconditionalTerminatingRule(object.Rule.Expr) {
				terminatingRuleBeforeCoverage = true
			}
			if acceptsUncoveredBlockedTraffic(
				object.Rule.Expr,
				requiredPorts,
				coveredPorts,
			) || acceptsUncoveredBlockedTraffic(
				object.Rule.Expr,
				requiredListeners,
				optionsCoveredPorts,
			) {
				acceptRuleBeforeCoverage = true
			}
		}
	}

	switch {
	case !tablePresent:
		return fmt.Errorf("%w: table is missing", ErrTableUnhealthy)
	case !ownedSetPresent:
		return fmt.Errorf("%w: ownership marker is missing", ErrTableUnhealthy)
	case len(requiredPorts) > 0 && !setHasElements:
		return fmt.Errorf("%w: %s set is empty", ErrTableUnhealthy, SetName)
	case !correctInputChain:
		return fmt.Errorf("%w: input filter base chain is missing or incorrect", ErrTableUnhealthy)
	case terminatingRuleBeforeCoverage:
		return fmt.Errorf(
			"%w: an unconditional terminating rule precedes complete port coverage",
			ErrTableUnhealthy,
		)
	case acceptRuleBeforeCoverage:
		return fmt.Errorf(
			"%w: an accept rule permits required CN traffic before complete port coverage",
			ErrTableUnhealthy,
		)
	}
	for port := range requiredListeners {
		if _, covered := optionsCoveredPorts[port]; !covered {
			return fmt.Errorf(
				"%w: port %d is not covered by the IPv4 options drop rule",
				ErrTableUnhealthy,
				port,
			)
		}
	}
	for port := range requiredPorts {
		if _, covered := coveredPorts[port]; !covered {
			return fmt.Errorf("%w: port %d is not covered by a drop rule", ErrTableUnhealthy, port)
		}
	}
	return nil
}

// portSet validates listener ports and returns them as a set.
func portSet(context string, ports []int) (map[int]struct{}, error) {
	set := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port < minPort || port > maxPort {
			return nil, fmt.Errorf(
				"%s: port must be between %d and %d: %d",
				context,
				minPort,
				maxPort,
				port,
			)
		}
		set[port] = struct{}{}
	}
	return set, nil
}

func requiredPortsAreCovered(required, covered map[int]struct{}) bool {
	for port := range required {
		if _, exists := covered[port]; !exists {
			return false
		}
	}
	return true
}

func nftExpressionIsNonEmpty(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return false
	}
	switch value := value.(type) {
	case nil:
		return false
	case []any:
		return len(value) > 0
	default:
		return true
	}
}

func matchingDropRulePorts(expressions []json.RawMessage) map[int]struct{} {
	var sourceMatches, portMatches int
	var drop bool
	ports := make(map[int]struct{})
	for _, raw := range expressions {
		var statement map[string]json.RawMessage
		if err := json.Unmarshal(raw, &statement); err != nil || len(statement) != 1 {
			return nil
		}
		if _, exists := statement["drop"]; exists {
			drop = true
			continue
		}
		if _, exists := statement["counter"]; exists {
			continue
		}

		matchRaw, exists := statement["match"]
		if !exists {
			return nil
		}
		var match struct {
			Op    string          `json:"op"`
			Left  json.RawMessage `json:"left"`
			Right json.RawMessage `json:"right"`
		}
		if err := json.Unmarshal(matchRaw, &match); err != nil ||
			(match.Op != "==" && match.Op != "in") {
			return nil
		}
		switch {
		case isPayloadExpression(match.Left, "ip", "saddr") &&
			rawJSONString(match.Right) == "@"+SetName:
			sourceMatches++
		case isPayloadExpression(match.Left, "tcp", "dport"):
			portMatches++
			for port := range nftPortValues(match.Right) {
				ports[port] = struct{}{}
			}
		default:
			return nil
		}
	}
	if sourceMatches != 1 || portMatches != 1 || !drop {
		return nil
	}
	return ports
}

// matchingOptionsDropRulePorts returns the destination ports of a rule that
// drops IPv4 TCP packets whose header carries IP options: exactly one
// `ip hdrlength > 5` match, one `tcp dport` match, an optional counter and a
// drop verdict.
func matchingOptionsDropRulePorts(expressions []json.RawMessage) map[int]struct{} {
	var lengthMatches, portMatches int
	var drop bool
	ports := make(map[int]struct{})
	for _, raw := range expressions {
		var statement map[string]json.RawMessage
		if err := json.Unmarshal(raw, &statement); err != nil || len(statement) != 1 {
			return nil
		}
		if _, exists := statement["drop"]; exists {
			drop = true
			continue
		}
		if _, exists := statement["counter"]; exists {
			continue
		}

		matchRaw, exists := statement["match"]
		if !exists {
			return nil
		}
		var match struct {
			Op    string          `json:"op"`
			Left  json.RawMessage `json:"left"`
			Right json.RawMessage `json:"right"`
		}
		if err := json.Unmarshal(matchRaw, &match); err != nil {
			return nil
		}
		switch {
		case isPayloadExpression(match.Left, "ip", "hdrlength"):
			if match.Op != ">" || rawJSONNumber(match.Right) != optionsHeaderLength {
				return nil
			}
			lengthMatches++
		case isPayloadExpression(match.Left, "tcp", "dport"):
			if match.Op != "==" && match.Op != "in" {
				return nil
			}
			portMatches++
			for port := range nftPortValues(match.Right) {
				ports[port] = struct{}{}
			}
		default:
			return nil
		}
	}
	if lengthMatches != 1 || portMatches != 1 || !drop {
		return nil
	}
	return ports
}

func rawJSONNumber(raw json.RawMessage) int {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value json.Number
	if err := decoder.Decode(&value); err != nil {
		return -1
	}
	number, err := strconv.Atoi(value.String())
	if err != nil {
		return -1
	}
	return number
}

func isUnconditionalTerminatingRule(expressions []json.RawMessage) bool {
	terminates := false
	for _, raw := range expressions {
		var statement map[string]json.RawMessage
		if err := json.Unmarshal(raw, &statement); err != nil || len(statement) != 1 {
			return false
		}
		for name := range statement {
			switch name {
			case "counter", "log", "continue":
			case "accept", "drop", "reject", "return", "queue", "jump", "goto":
				terminates = true
			default:
				return false
			}
		}
	}
	return terminates
}

func acceptsUncoveredBlockedTraffic(
	expressions []json.RawMessage,
	requiredPorts map[int]struct{},
	coveredPorts map[int]struct{},
) bool {
	var accept, sourceMatches, portMatches int
	ports := make(map[int]struct{})
	for _, raw := range expressions {
		var statement map[string]json.RawMessage
		if err := json.Unmarshal(raw, &statement); err != nil || len(statement) != 1 {
			return false
		}
		if _, exists := statement["accept"]; exists {
			accept++
			continue
		}
		if _, exists := statement["counter"]; exists {
			continue
		}
		if _, exists := statement["log"]; exists {
			continue
		}

		matchRaw, exists := statement["match"]
		if !exists {
			return false
		}
		var match struct {
			Op    string          `json:"op"`
			Left  json.RawMessage `json:"left"`
			Right json.RawMessage `json:"right"`
		}
		if err := json.Unmarshal(matchRaw, &match); err != nil ||
			(match.Op != "==" && match.Op != "in") {
			return false
		}
		switch {
		case isPayloadExpression(match.Left, "ip", "saddr") &&
			rawJSONString(match.Right) == "@"+SetName:
			sourceMatches++
		case isPayloadExpression(match.Left, "tcp", "dport"):
			portMatches++
			for port := range nftPortValues(match.Right) {
				ports[port] = struct{}{}
			}
		default:
			return false
		}
	}
	if accept != 1 ||
		sourceMatches > 1 ||
		portMatches > 1 ||
		(sourceMatches == 0 && portMatches == 0) {
		return false
	}
	if portMatches == 0 {
		return !requiredPortsAreCovered(requiredPorts, coveredPorts)
	}
	for port := range ports {
		if _, required := requiredPorts[port]; !required {
			continue
		}
		if _, covered := coveredPorts[port]; !covered {
			return true
		}
	}
	return false
}

func isPayloadExpression(raw json.RawMessage, protocol, field string) bool {
	var expression struct {
		Payload *struct {
			Protocol string `json:"protocol"`
			Field    string `json:"field"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &expression); err != nil || expression.Payload == nil {
		return false
	}
	return expression.Payload.Protocol == protocol && expression.Payload.Field == field
}

func rawJSONString(raw json.RawMessage) string {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return value
}

func nftPortValues(raw json.RawMessage) map[int]struct{} {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil
	}
	ports := make(map[int]struct{})
	collectNFTPorts(value, ports)
	return ports
}

func collectNFTPorts(value any, ports map[int]struct{}) {
	switch value := value.(type) {
	case json.Number:
		port, err := strconv.Atoi(value.String())
		if err == nil && port >= minPort && port <= maxPort {
			ports[port] = struct{}{}
		}
	case []any:
		for _, child := range value {
			collectNFTPorts(child, ports)
		}
	case map[string]any:
		if set, exists := value["set"]; exists {
			collectNFTPorts(set, ports)
		}
		if values, exists := value["range"].([]any); exists && len(values) == 2 {
			first, firstOK := nftPortNumber(values[0])
			last, lastOK := nftPortNumber(values[1])
			if firstOK && lastOK && first <= last {
				for port := first; port <= last; port++ {
					ports[port] = struct{}{}
				}
			}
		}
	}
}

func nftPortNumber(value any) (int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	port, err := strconv.Atoi(number.String())
	if err != nil || port < minPort || port > maxPort {
		return 0, false
	}
	return port, true
}

// Render writes one complete nft -f batch for one listener port that also
// blocks CN sources.
func Render(writer io.Writer, port int, prefixes []netip.Prefix, state TableState) error {
	return RenderPorts(writer, []int{port}, []int{port}, prefixes, state)
}

// RenderPorts writes one complete nft -f batch for all listener ports.
// Every listener port gets the IPv4 options drop rule (CVE-2026-98432
// mitigation); the CN-blocked subset additionally gets the CN source drop rule
// backed by the bundled IPdeny prefixes, which are required only in that case.
// TableAbsent creates the table. TableOwned first deletes the owned table and
// then recreates it in the same batch, so nft applies the replacement as one
// transaction. A non-empty port list never modifies a foreign table.
//
// An empty listener port list requests no protection at all. In that state an
// owned table is removed, while absent and foreign tables are left untouched.
func RenderPorts(
	writer io.Writer,
	listenerPorts []int,
	blockedPorts []int,
	prefixes []netip.Prefix,
	state TableState,
) error {
	if len(listenerPorts) == 0 {
		if len(blockedPorts) != 0 {
			return fmt.Errorf("render nftables batch: %w", ErrBlockedNotListening)
		}
		switch state {
		case TableAbsent, TableForeign:
			return nil
		case TableOwned:
			return RenderRemove(writer, state)
		default:
			return fmt.Errorf("render nftables batch: invalid table state %d", state)
		}
	}
	if writer == nil {
		return fmt.Errorf("render nftables batch: nil writer")
	}
	listeners, err := uniquePorts("render nftables batch", listenerPorts)
	if err != nil {
		return err
	}
	blocked, err := uniquePorts("render nftables batch", blockedPorts)
	if err != nil {
		return err
	}
	for port := range blocked {
		if _, exists := listeners[port]; !exists {
			return fmt.Errorf("render nftables batch: %w: %d", ErrBlockedNotListening, port)
		}
	}
	if len(blocked) > 0 {
		if len(prefixes) == 0 {
			return ErrEmptyCIDRs
		}
		for index, prefix := range prefixes {
			if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() {
				return fmt.Errorf("render nftables batch: invalid canonical IPv4 CIDR at index %d: %v", index, prefix)
			}
		}
	}

	switch state {
	case TableAbsent:
	case TableOwned:
		if _, err := fmt.Fprintf(writer, "delete table %s %s\n\n", TableFamily, TableName); err != nil {
			return fmt.Errorf("render nftables replacement: %w", err)
		}
	case TableForeign:
		return ErrTableConflict
	default:
		return fmt.Errorf("render nftables batch: invalid table state %d", state)
	}

	if _, err := fmt.Fprintf(
		writer,
		"create table %s %s { comment %q; }\n\n",
		TableFamily,
		TableName,
		tableComment,
	); err != nil {
		return fmt.Errorf("render nftables table: %w", err)
	}
	if _, err := fmt.Fprintf(writer, "add set %s %s %s {\n", TableFamily, TableName, SetName); err != nil {
		return fmt.Errorf("render nftables set: %w", err)
	}
	if _, err := io.WriteString(writer, "\ttype ipv4_addr;\n\tflags interval;\n"); err != nil {
		return fmt.Errorf("render nftables set type: %w", err)
	}
	if len(blocked) > 0 {
		if _, err := io.WriteString(writer, "\telements = {\n"); err != nil {
			return fmt.Errorf("render nftables set elements: %w", err)
		}
		for index, prefix := range prefixes {
			suffix := ","
			if index == len(prefixes)-1 {
				suffix = ""
			}
			if _, err := fmt.Fprintf(writer, "\t\t%s%s\n", prefix, suffix); err != nil {
				return fmt.Errorf("render nftables set element %d: %w", index, err)
			}
		}
		if _, err := io.WriteString(writer, "\t};\n"); err != nil {
			return fmt.Errorf("render nftables set closing: %w", err)
		}
	}
	if _, err := fmt.Fprintf(writer, "\tcomment %q;\n}\n\n", OwnershipComment); err != nil {
		return fmt.Errorf("render nftables set comment: %w", err)
	}

	if _, err := fmt.Fprintf(
		writer,
		"add chain %s %s %s { type filter hook input priority -10; comment %q; }\n",
		TableFamily,
		TableName,
		ChainName,
		chainComment,
	); err != nil {
		return fmt.Errorf("render nftables chain: %w", err)
	}
	if _, err := fmt.Fprintf(
		writer,
		"add rule %s %s %s ip hdrlength > %d tcp dport ",
		TableFamily,
		TableName,
		ChainName,
		optionsHeaderLength,
	); err != nil {
		return fmt.Errorf("render nftables options drop rule: %w", err)
	}
	if err := writePortList(writer, listenerPorts); err != nil {
		return fmt.Errorf("render nftables options drop rule: %w", err)
	}
	if _, err := io.WriteString(writer, " counter drop\n"); err != nil {
		return fmt.Errorf("render nftables options drop rule closing: %w", err)
	}
	if len(blocked) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(
		writer,
		"add rule %s %s %s ip saddr @%s tcp dport ",
		TableFamily,
		TableName,
		ChainName,
		SetName,
	); err != nil {
		return fmt.Errorf("render nftables drop rule: %w", err)
	}
	if err := writePortList(writer, blockedPorts); err != nil {
		return fmt.Errorf("render nftables drop rule: %w", err)
	}
	if _, err := io.WriteString(writer, " counter drop\n"); err != nil {
		return fmt.Errorf("render nftables drop rule closing: %w", err)
	}
	return nil
}

// uniquePorts validates a port list and rejects duplicates.
func uniquePorts(context string, ports []int) (map[int]struct{}, error) {
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port < minPort || port > maxPort {
			return nil, fmt.Errorf(
				"%s: port must be between %d and %d: %d",
				context,
				minPort,
				maxPort,
				port,
			)
		}
		if _, exists := seen[port]; exists {
			return nil, fmt.Errorf("%s: duplicate port %d", context, port)
		}
		seen[port] = struct{}{}
	}
	return seen, nil
}

func writePortList(writer io.Writer, ports []int) error {
	if len(ports) == 1 {
		_, err := fmt.Fprint(writer, ports[0])
		return err
	}
	if _, err := io.WriteString(writer, "{ "); err != nil {
		return err
	}
	for index, port := range ports {
		if index > 0 {
			if _, err := io.WriteString(writer, ", "); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(writer, port); err != nil {
			return err
		}
	}
	_, err := io.WriteString(writer, " }")
	return err
}

// RenderRemove writes the complete batch for removing the Socks-VPS table.
// Only a table already classified as owned may be deleted. Absent and foreign
// tables are already in the requested state and produce no batch.
func RenderRemove(writer io.Writer, state TableState) error {
	switch state {
	case TableAbsent, TableForeign:
		return nil
	case TableOwned:
		if writer == nil {
			return fmt.Errorf("render nftables removal: nil writer")
		}
		if _, err := fmt.Fprintf(writer, "delete table %s %s\n", TableFamily, TableName); err != nil {
			return fmt.Errorf("render nftables removal: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("render nftables removal: invalid table state %d", state)
	}
}
