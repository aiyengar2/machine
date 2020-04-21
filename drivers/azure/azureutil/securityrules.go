package azureutil

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2019-12-01/network"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/rancher/machine/drivers/azure/logutil"
	"github.com/rancher/machine/drivers/driverutil"
	"github.com/rancher/machine/libmachine/log"
)

const (
	sshPriority      = 100
	sshPolicyName    = "SSHAllowAny"
	dockerPriority   = 300 // NOTE(aiyengar2): must be greater than sshPriority
	dockerPolicyName = "DockerAllowAny"
	basePriority     = 1000 // NOTE(aiyengar2): must be greater than sshPriority and dockerPriority

	// https://docs.microsoft.com/bs-latn-ba/azure/virtual-machines/windows/nsg-quickstart-portal
	minimumSecurityRulePriority = 100
	maximumSecurityRulePriority = 65500
)

// ConfigureSecurityRules attempts to reconcile an already created NSG's rules with the rules requested
// Priorities set for the rules must be unique and cannot interfere with existing rules
func ConfigureSecurityRules(rules *[]network.SecurityRule, sshPort, dockerPort int, extraPorts []string) (*[]network.SecurityRule, error) {
	e := LoadExistingAzureSecurityRules(rules, basePriority)
	// Add ssh to security group
	sshRule := AllowInboundSecurityRule{
		Priority:    sshPriority,
		Name:        sshPolicyName,
		Description: "Allow ssh from public Internet",
		SrcPort:     "*",
		DstPort:     fmt.Sprintf("%d", sshPort),
		Proto:       network.SecurityRuleProtocolTCP,
	}
	if err := e.AttemptToAddInboundSecurityRule(sshRule); err != nil {
		return nil, err
	}

	// Add docker to security group
	dockerRule := AllowInboundSecurityRule{
		Priority:    dockerPriority,
		Name:        dockerPolicyName,
		Description: "Allow docker engine access (TLS-protected)",
		SrcPort:     "*",
		DstPort:     fmt.Sprintf("%d", dockerPort),
		Proto:       network.SecurityRuleProtocolTCP,
	}
	for _, rule := range e.Rules {
		name := to.String(rule.Name)
		if name != sshPolicyName && name != dockerPolicyName {
			err := checkIfDockerConflict(rule, dockerPort)
			if err != nil {
				return nil, err
			}
		}
	}
	if err := e.AttemptToAddInboundSecurityRule(dockerRule); err != nil {
		return nil, err
	}
	log.Debugf("Docker port is configured as %d", dockerRule.DstPort)

	// Add open ports
	var openPorts []OpenPort
	for _, p := range extraPorts {
		openPort, err := ParseOpenPort(p)
		if err != nil {
			return nil, err
		}
		openPorts = append(openPorts, openPort)
	}
	if err := e.SyncOpenPorts(openPorts); err != nil {
		return nil, err
	}

	log.Debugf("Total NSG rules: %d", len(e.Rules))
	rules = &e.Rules
	return rules, nil
}

// ExistingAzureSecurityRules represents all relevant information from an existing rules struct provided
type ExistingAzureSecurityRules struct {
	Rules                        []network.SecurityRule
	ExistingRules                map[string]int32
	CurrentInboundPriorities     map[int32]string
	NextAvailableInboundPriority int32
}

// LoadExistingAzureSecurityRules creates a new ExistingAzureSecurityRules object from the values provided
func LoadExistingAzureSecurityRules(rules *[]network.SecurityRule, nextAvailableInboundPriority int32) ExistingAzureSecurityRules {
	var existingRules []network.SecurityRule
	if rules == nil {
		existingRules = []network.SecurityRule{}
	} else {
		existingRules = *rules
	}
	e := ExistingAzureSecurityRules{
		Rules:                        existingRules,
		ExistingRules:                make(map[string]int32, len(existingRules)),
		CurrentInboundPriorities:     make(map[int32]string, len(existingRules)),
		NextAvailableInboundPriority: nextAvailableInboundPriority,
	}
	for _, rule := range e.Rules {
		priority := to.Int32(rule.Priority)
		name := to.String(rule.Name)
		e.ExistingRules[name] = priority
		if strings.ToLower(fmt.Sprintf("%s", rule.Direction)) == "inbound" {
			e.CurrentInboundPriorities[priority] = name
		}
	}
	return e
}

// AttemptToAddInboundSecurityRule adds an AllowInboundSecurityRule to the ExistingAzureSecurityRules if there are no conflicts
func (e *ExistingAzureSecurityRules) AttemptToAddInboundSecurityRule(a AllowInboundSecurityRule) error {
	priority, err := e.getExistingRulePriority(a.Name)
	if err != nil {
		// Rule does not exist
		if err := e.canSetInboundPriority(a.Priority); err != nil {
			return fmt.Errorf(
				"cannot set inbound rule %s to priority %d: %s",
				a.Name, a.Priority, err)
		}
		e.Rules = append(e.Rules, a.Rule())
		e.CurrentInboundPriorities[a.Priority] = a.Name
		e.ExistingRules[a.Name] = a.Priority
		return nil
	}
	if _, ok := e.CurrentInboundPriorities[priority]; !ok {
		// Existing rule doesn't exist in inbound priorities is an outbound rule
		return fmt.Errorf("cannot create inbound security rule %s; outbound security rule already exists with the same name", a.Name)
	}
	return nil
}

// AttemptToAddOpenPort parses an open port and tries to add it to ExistingAzureSecurityRules
func (e *ExistingAzureSecurityRules) AttemptToAddOpenPort(openPort OpenPort) error {
	log.Debugf("User-requested port to be opened on NSG: %v/%s", openPort.Port, openPort.Proto)
	priority, err := e.findInboundPriority(openPort.Name)
	if err != nil {
		return err
	}
	return e.AttemptToAddInboundSecurityRule(AllowInboundSecurityRule{
		Priority:    priority,
		Name:        openPort.Name,
		Description: "User requested port to be accessible from Internet via docker-machine",
		SrcPort:     "*",
		DstPort:     openPort.Port,
		Proto:       openPort.Proto,
	})
}

// SyncOpenPorts brings the CurrentOpenPorts to match the requestedOpenPorts, adding or removing ports if necessary
func (e *ExistingAzureSecurityRules) SyncOpenPorts(requestedOpenPorts []OpenPort) error {
	// Gather all existing open ports
	openPortsToBeRemoved := make(map[OpenPort]network.SecurityRule, len(e.Rules))
	for _, rule := range e.Rules {
		// NOTE(aiyengar2): This sync assumes that users don't create ports with the machineOpenPortFormat, as those will be detected as
		// custom ports that are to be removed if they aren't provided in the requestedOpenPorts
		if openPort, err := ConvertRuleToOpenPort(rule); err == nil {
			openPortsToBeRemoved[openPort] = rule
		}
	}
	openPortsToBeAdded := []OpenPort{}
	for _, openPort := range requestedOpenPorts {
		if _, ok := openPortsToBeRemoved[openPort]; ok {
			// no need to delete the port
			delete(openPortsToBeRemoved, openPort)
		} else {
			// queue it to be added
			openPortsToBeAdded = append(openPortsToBeAdded, openPort)
		}
	}
	// Remove all unnecessary open ports
	if len(openPortsToBeRemoved) > 0 {
		removed := []OpenPort{}
		for openPort, rule := range openPortsToBeRemoved {
			e.AttemptToRemoveSecurityRule(rule)
			removed = append(removed, openPort)
		}
		log.Info("Removed the following open ports:", removed)
	}
	// Add any necessary open ports
	if len(openPortsToBeAdded) > 0 {
		for _, openPort := range openPortsToBeAdded {
			if err := e.AttemptToAddOpenPort(openPort); err != nil {
				return err
			}
		}
		log.Info("Opened the following ports:", openPortsToBeAdded)
	}
	return nil
}

// AttemptToRemoveSecurityRule removes a rule if it exists in ExistingAzureSecurityRules
func (e *ExistingAzureSecurityRules) AttemptToRemoveSecurityRule(rule network.SecurityRule) {
	for i, elem := range e.Rules {
		if elem == rule {
			delete(e.ExistingRules, to.String(rule.Name))
			delete(e.CurrentInboundPriorities, to.Int32(rule.Priority))
			if len(e.Rules) == 1 {
				e.Rules = []network.SecurityRule{}
			} else {
				// Swap with last rule as order does not matter
				lastElem := len(e.Rules) - 1
				e.Rules[i] = e.Rules[lastElem]
				e.Rules = e.Rules[:lastElem]
			}
			return
		}
	}
}

// FindPriority either returns the priority of an existing inbound rule or finds a new priority for the inbound rule whose name is specified
func (e *ExistingAzureSecurityRules) findInboundPriority(name string) (int32, error) {
	if priority, err := e.getExistingRulePriority(name); err == nil {
		if _, ok := e.CurrentInboundPriorities[priority]; !ok {
			return 0, fmt.Errorf("rule %s is not an inbound rule", name)
		}
		return priority, nil
	}
	for {
		priority := e.NextAvailableInboundPriority
		e.NextAvailableInboundPriority = priority + 1
		if priority >= maximumSecurityRulePriority {
			return 0, fmt.Errorf("too many existing security rules to add rule %s", name)
		}
		if err := e.canSetInboundPriority(priority); err == nil {
			return priority, nil
		}
	}
}

// getExistingRulePriority finds the priority for a given existing rule or returns an error
func (e *ExistingAzureSecurityRules) getExistingRulePriority(name string) (int32, error) {
	if priority, ok := e.ExistingRules[name]; ok {
		return priority, nil
	}
	return 0, fmt.Errorf("security rule %s does not have a priority", name)
}

// canSetInboundPriority returns an error if the requested priority is already set
func (e *ExistingAzureSecurityRules) canSetInboundPriority(priority int32) error {
	if priority < minimumSecurityRulePriority || priority >= maximumSecurityRulePriority {
		return fmt.Errorf("priority %d is out of bounds", priority)
	}
	if n, ok := e.CurrentInboundPriorities[priority]; ok {
		return fmt.Errorf("inbound security rule %s already has priority %v", n, priority)
	}
	return nil
}

func (e *ExistingAzureSecurityRules) toLogField() logutil.Fields {
	return logutil.Fields{
		"rules": securityRulesToLogField(e.Rules),
	}
}

// AllowInboundSecurityRule represents a security rule that allows inbound traffic to be added to a NSG for a node
type AllowInboundSecurityRule struct {
	Priority    int32
	Name        string
	Description string
	SrcPort     string
	DstPort     string
	Proto       network.SecurityRuleProtocol
}

// Rule creates a network.SecurityRule from an AllowInboundSecurityRule
func (a AllowInboundSecurityRule) Rule() network.SecurityRule {
	return network.SecurityRule{
		Name: to.StringPtr(a.Name),
		SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
			Description:              to.StringPtr(a.Description),
			SourceAddressPrefix:      to.StringPtr("*"),
			DestinationAddressPrefix: to.StringPtr("*"),
			SourcePortRange:          to.StringPtr(a.SrcPort),
			DestinationPortRange:     to.StringPtr(a.DstPort),
			Access:                   network.SecurityRuleAccessAllow,
			Direction:                network.SecurityRuleDirectionInbound,
			Protocol:                 a.Proto,
			Priority:                 to.Int32Ptr(a.Priority),
		},
	}
}

// ConvertRuleToAllowInboundSecurityRule converts a rule to an AllowInboundSecurityRule representation
func ConvertRuleToAllowInboundSecurityRule(rule network.SecurityRule) (*AllowInboundSecurityRule, error) {
	if strings.ToLower(fmt.Sprintf("%s %s", rule.Access, rule.Direction)) != "allow inbound" {
		return nil, fmt.Errorf("rule does not represent a security rule that allows inbound requests")
	}
	return &AllowInboundSecurityRule{
		Priority:    to.Int32(rule.SecurityRulePropertiesFormat.Priority),
		Name:        to.String(rule.Name),
		Description: to.String(rule.SecurityRulePropertiesFormat.Description),
		SrcPort:     to.String(rule.SecurityRulePropertiesFormat.SourcePortRange),
		DstPort:     to.String(rule.SecurityRulePropertiesFormat.DestinationPortRange),
		Proto:       rule.SecurityRulePropertiesFormat.Protocol,
	}, nil
}

// OpenPort is a port to be opened within an NSG
type OpenPort struct {
	Name  string
	Port  string
	Proto network.SecurityRuleProtocol
}

const (
	machineOpenPortFormat = "Port%s-%sAllowAny"
	machineOpenPortRegex  = `Port(\d{1,5})-([a-zA-Z]{1,3}|Asterisk)AllowAny`
)

// ParseOpenPort creates an OpenPort based on the string specified within open ports
func ParseOpenPort(p string) (OpenPort, error) {
	port, protocol := driverutil.SplitPortProto(p)
	proto, err := parseSecurityRuleProtocol(protocol)
	if err != nil {
		return OpenPort{}, fmt.Errorf("cannot parse security rule protocol: %v", err)
	}
	name := fmt.Sprintf(machineOpenPortFormat, port, proto)
	name = strings.Replace(name, "*", "Asterisk", -1)
	return OpenPort{
		Name:  name,
		Port:  port,
		Proto: proto,
	}, nil
}

// ConvertRuleToOpenPort either converts a rule to an OpenPort or returns an error if the rule is not an OpenPort
func ConvertRuleToOpenPort(rule network.SecurityRule) (OpenPort, error) {
	re := regexp.MustCompile(machineOpenPortRegex)
	if matches := re.FindStringSubmatch(*rule.Name); len(matches) == 3 {
		port := matches[1]
		proto, err := parseSecurityRuleProtocol(matches[2])
		if err == nil {
			return OpenPort{
				Name:  *rule.Name,
				Port:  port,
				Proto: proto,
			}, nil
		}
	}
	return OpenPort{}, fmt.Errorf("rule is not an open port")
}

func parseSecurityRuleProtocol(proto string) (network.SecurityRuleProtocol, error) {
	switch strings.ToLower(proto) {
	case "tcp":
		return network.SecurityRuleProtocolTCP, nil
	case "udp":
		return network.SecurityRuleProtocolUDP, nil
	case "*":
		return network.SecurityRuleProtocolAsterisk, nil
	default:
		return "", fmt.Errorf("invalid protocol %s", proto)
	}
}

// checkIfDockerConflict does a rudimentary check to see if the rule could potentially conflict with the ability
// for the docker port to be accessible. If the rule does not pass all rudimentary checks, it returns an error.
func checkIfDockerConflict(rule network.SecurityRule, dockerPort int) error {
	f := securityRuleToLogField(rule)
	priority := to.Int32(rule.Priority)
	if priority > dockerPriority {
		return nil
	}
	purpose := strings.ToLower(fmt.Sprintf("%s %s %s", rule.Access, rule.Direction, rule.Protocol))
	if purpose == "deny inbound tcp" || purpose == "deny inbound *" {
		// check if docker port is covered by rule
		for _, pr := range getDestinationPorts(rule) {
			portWithinRange, err := checkIfPortInPortRange(dockerPort, pr)
			if err != nil {
				return fmt.Errorf("%s: %s", err, f)
			}
			if portWithinRange {
				return fmt.Errorf("rule %s set to %s requests to the Docker port %d: %s",
					to.String(rule.Name), purpose, dockerPort, f)
			}
		}
	}
	return nil
}

func checkIfPortInPortRange(port int, portRange string) (bool, error) {
	if portRange == "*" {
		return true, nil
	}
	s := strings.Split(portRange, "-")
	if len(s) == 2 {
		portMin, portMinErr := strconv.Atoi(s[0])
		portMax, portMaxErr := strconv.Atoi(s[1])
		if portMinErr == nil || portMaxErr == nil || portMin < portMax {
			return (port >= portMin) && (port <= portMax), nil
		}
	}
	if len(s) == 1 {
		portVal, err := strconv.Atoi(s[0])
		if err == nil {
			return port == portVal, nil
		}
	}
	return false, fmt.Errorf("invalid port range %s", portRange)
}

// getDestinationPortRanges returns the destination port ranges that a rule is applied on
func getDestinationPorts(rule network.SecurityRule) []string {
	ports := []string{}
	if rule.DestinationPortRange != nil {
		ports = append(ports, *rule.DestinationPortRange)
	}
	if rule.DestinationPortRanges != nil {
		for _, port := range *rule.DestinationPortRanges {
			ports = append(ports, port)
		}
	}
	return ports
}

// securityRulesToLogField is a helper function that gives log fields for security rules after dereferencing pointers
func securityRulesToLogField(rules []network.SecurityRule) []logutil.Fields {
	fields := make([]logutil.Fields, len(rules))
	for i, rule := range rules {
		fields[i] = securityRuleToLogField(rule)
	}
	return fields
}

// securityRuleToLogField is a helper function that gives a log field for a security rule after dereferencing pointers
func securityRuleToLogField(rule network.SecurityRule) logutil.Fields {
	return logutil.Fields{
		"name":        to.String(rule.Name),
		"description": to.String(rule.Description),
		"priority":    to.Int32(rule.Priority),
		"access":      rule.Access,
		"direction":   rule.Direction,
		"protocol":    rule.Protocol,
		"portRanges":  getDestinationPorts(rule),
	}
}
