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

	machineOpenPortFormat = "Port%s-%sAllowAny"
)

var (
	// NOTE(aiyengar2): This regex is used to identify if the given rule was set by Rancher. It parses the
	// machineOpenPortFormat that is used by Rancher to set open ports requested by the user, where the %s values are set to:
	// 1) port: a 1-5 digit number (i.e. \d{1,5})
	// 2) proto: a 3 letter protocol (i.e. [a-zA-Z]{1,3}) or 'Asterisk'.
	machineOpenPortRegex = regexp.MustCompile(`Port(\d{1,5})-([a-zA-Z]{1,3}|Asterisk)AllowAny`)
)

// ConfigureSecurityRules attempts to reconcile an already created NSG's rules with the rules requested
// Priorities set for the rules must be unique and cannot interfere with existing rules
func ConfigureSecurityRules(rules *[]network.SecurityRule, sshPort, dockerPort int, extraPorts []string) (*[]network.SecurityRule, error) {
	if err := addSSHRule(rules, sshPort); err != nil {
		return nil, err
	}
	if err := addDockerRule(rules, dockerPort); err != nil {
		return nil, err
	}
	log.Debugf("Docker port is configured as %d", dockerPort)
	if err := syncOpenPorts(rules, extraPorts); err != nil {
		return nil, err
	}
	log.Debugf("Total NSG rules: %d", len(*rules))
	return rules, nil
}

func addSSHRule(rules *[]network.SecurityRule, sshPort int) error {
	// Check if any existing rule has the same priority as the SSH rule
	for _, rule := range *rules {
		if strings.ToLower(fmt.Sprintf("%s", rule.Direction)) != "inbound" {
			// Ignore outbound rules
			continue
		}
		priority := to.Int32(rule.Priority)
		if priority == sshPriority {
			name := to.String(rule.Name)
			if name == sshPolicyName {
				// SSH rule already exists
				return nil
			}
			return fmt.Errorf("Cannot set SSH rule as priority %d is already taken by rule %s", sshPriority, name)
		}
	}
	// If not, add the rule
	*rules = append(*rules, network.SecurityRule{
		Name: to.StringPtr(sshPolicyName),
		SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
			Description:              to.StringPtr("Allow ssh from public Internet"),
			SourceAddressPrefix:      to.StringPtr("*"),
			DestinationAddressPrefix: to.StringPtr("*"),
			SourcePortRange:          to.StringPtr("*"),
			DestinationPortRange:     to.StringPtr(fmt.Sprintf("%d", sshPort)),
			Access:                   network.SecurityRuleAccessAllow,
			Direction:                network.SecurityRuleDirectionInbound,
			Protocol:                 network.SecurityRuleProtocolTCP,
			Priority:                 to.Int32Ptr(sshPriority),
		},
	})
	return nil
}

func addDockerRule(rules *[]network.SecurityRule, dockerPort int) error {
	// Check if any existing rule has the same priority as the Docker rule or check any conflicts
	for _, rule := range *rules {
		if strings.ToLower(fmt.Sprintf("%s", rule.Direction)) != "inbound" {
			// Ignore outbound rules
			continue
		}
		priority := to.Int32(rule.Priority)
		if priority == dockerPriority {
			name := to.String(rule.Name)
			if name == dockerPolicyName {
				// Docker rule already exists
				return nil
			}
			return fmt.Errorf("Cannot set Docker rule as priority %d is already taken by rule %s", dockerPriority, name)
		}
		if priority < dockerPriority {
			// If the priority is less than the docker priority, we should check if there's a conflict
			err := checkIfDockerConflict(rule, dockerPort)
			if err != nil {
				return err
			}
		}
	}
	// If not, add the rule
	*rules = append(*rules, network.SecurityRule{
		Name: to.StringPtr(dockerPolicyName),
		SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
			Description:              to.StringPtr("Allow docker engine access (TLS-protected)"),
			SourceAddressPrefix:      to.StringPtr("*"),
			DestinationAddressPrefix: to.StringPtr("*"),
			SourcePortRange:          to.StringPtr("*"),
			DestinationPortRange:     to.StringPtr(fmt.Sprintf("%d", dockerPort)),
			Access:                   network.SecurityRuleAccessAllow,
			Direction:                network.SecurityRuleDirectionInbound,
			Protocol:                 network.SecurityRuleProtocolTCP,
			Priority:                 to.Int32Ptr(dockerPriority),
		},
	})
	return nil
}

func syncOpenPorts(rules *[]network.SecurityRule, openPorts []string) error {
	openPortsToBeDeleted := make(map[string]network.SecurityRule)
	takenPriorities := make(map[int32]bool)
	// Add all rules for deletion by default
	for _, rule := range *rules {
		takenPriorities[to.Int32(rule.Priority)] = true
		if isOpenPort(rule) {
			openPortsToBeDeleted[to.String(rule.Name)] = rule
		}
	}
	// Remove from deletion if it exists or add to queue if it does not exist
	openPortsToBeAdded := make(map[string]network.SecurityRule)
	for _, p := range openPorts {
		op := parseOpenPort(p)
		if op == nil {
			return fmt.Errorf("unable to parse open port %s", p)
		}
		if _, ok := openPortsToBeDeleted[op.name]; ok {
			// Remove port from list of open ports to be deleted
			delete(openPortsToBeDeleted, op.name)
			continue
		}
		openPortsToBeAdded[op.name] = network.SecurityRule{
			Name: to.StringPtr(op.name),
			SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
				Description:              to.StringPtr("User requested port to be accessible from Internet via docker-machine"),
				SourceAddressPrefix:      to.StringPtr("*"),
				DestinationAddressPrefix: to.StringPtr("*"),
				SourcePortRange:          to.StringPtr("*"),
				DestinationPortRange:     to.StringPtr(op.port),
				Access:                   network.SecurityRuleAccessAllow,
				Direction:                network.SecurityRuleDirectionInbound,
				Protocol:                 op.proto,
			},
		}
	}
	// Log open ports to be deleted and added
	if len(openPortsToBeDeleted) > 0 || len(openPortsToBeAdded) > 0 {
		removedPorts := make([]string, len(openPortsToBeDeleted))
		addedPorts := make([]string, len(openPortsToBeAdded))
		i := 0
		for op := range openPortsToBeDeleted {
			removedPorts[i] = op
			i++
		}
		i = 0
		for op := range openPortsToBeAdded {
			addedPorts[i] = op
			i++
		}
		log.Info("Updating security rule configuration", logutil.Fields{
			"openPortsRemoved": removedPorts,
			"openPortsAdded":   addedPorts,
		})
	}
	// Remove all unnecessary open ports and release the priorities
	for _, rule := range openPortsToBeDeleted {
		delete(takenPriorities, to.Int32(rule.Priority))
		removeSecurityRule(rules, rule)
	}
	// Add any necessary open ports
	priority := int32(1000)
	for _, rule := range openPortsToBeAdded {
		// Find a priority that can be given to this rule
		_, taken := takenPriorities[priority]
		for taken {
			priority++
			_, taken = takenPriorities[priority]
		}
		rule.Priority = to.Int32Ptr(priority)
		priority++
		*rules = append(*rules, rule)
	}
	return nil
}

// checkIfDockerConflict does a rudimentary check to see if the rule could potentially conflict with the ability
// for the docker port to be accessible. If the rule does not pass all rudimentary checks, it returns an error.
func checkIfDockerConflict(rule network.SecurityRule, dockerPort int) error {
	purpose := strings.ToLower(fmt.Sprintf("%s %s %s", rule.Access, rule.Direction, rule.Protocol))
	if purpose == "deny inbound tcp" || purpose == "deny inbound *" {
		// check if docker port is covered by rule
		dstPorts := getDestinationPorts(rule)
		f := logutil.Fields{
			"name":        to.String(rule.Name),
			"description": to.String(rule.Description),
			"priority":    to.Int32(rule.Priority),
			"access":      rule.Access,
			"direction":   rule.Direction,
			"protocol":    rule.Protocol,
			"portRanges":  dstPorts,
		}
		for _, pr := range dstPorts {
			if checkIfPortInPortRange(dockerPort, pr) {
				return fmt.Errorf("rule %s set to %s requests to the Docker port %d: %s",
					to.String(rule.Name), purpose, dockerPort, f)
			}
		}
	}
	return nil
}

// checkIfPortInPortRange returns true if the port is within the portRange specified. If the port
// range provided is improperly formatted, it returns false
func checkIfPortInPortRange(port int, portRange string) bool {
	if portRange == "*" {
		return true
	}
	s := strings.Split(portRange, "-")
	if len(s) == 2 {
		// Port range represents is a range i.e. "2000-3000"
		portMin, portMinErr := strconv.Atoi(s[0])
		portMax, portMaxErr := strconv.Atoi(s[1])
		if portMinErr == nil && portMaxErr == nil && portMin < portMax {
			return (port >= portMin) && (port <= portMax)
		}
	}
	if len(s) == 1 {
		// Port range represents a single port i.e. "2376"
		portVal, err := strconv.Atoi(s[0])
		if err == nil {
			return port == portVal
		}
	}
	return false
}

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

func removeSecurityRule(rules *[]network.SecurityRule, rule network.SecurityRule) {
	for i, elem := range *rules {
		if elem != rule {
			continue
		}
		if len(*rules) == 1 {
			*rules = []network.SecurityRule{}
		}
		// Swap with last element and shorten slice
		r := *rules
		r[i] = r[len(r)-1]
		r = r[:len(r)-1]
		*rules = r
	}
}

type openPort struct {
	name  string
	port  string
	proto network.SecurityRuleProtocol
}

func isOpenPort(rule network.SecurityRule) bool {
	return machineOpenPortRegex.MatchString(to.String(rule.Name))
}

func parseOpenPort(p string) *openPort {
	var op openPort
	var protocol string
	op.port, protocol = driverutil.SplitPortProto(p)
	switch strings.ToLower(protocol) {
	case "tcp":
		op.proto = network.SecurityRuleProtocolTCP
	case "udp":
		op.proto = network.SecurityRuleProtocolUDP
	case "*":
		op.proto = network.SecurityRuleProtocolAsterisk
	default:
		return nil
	}
	name := fmt.Sprintf(machineOpenPortFormat, op.port, op.proto)
	op.name = strings.Replace(name, "*", "Asterisk", -1)
	return &op
}
