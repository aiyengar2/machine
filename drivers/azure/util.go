package azure

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/rancher/machine/drivers/azure/azureutil"
	"github.com/rancher/machine/drivers/azure/logutil"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/ssh"
	"github.com/rancher/machine/libmachine/state"
)

var (
	supportedEnvironments = []string{
		azure.PublicCloud.Name,
		azure.USGovernmentCloud.Name,
		azure.ChinaCloud.Name,
		azure.GermanCloud.Name,
	}
)

// requiredOptionError forms an error from the error indicating the option has
// to be provided with a value for this driver.
type requiredOptionError string

func (r requiredOptionError) Error() string {
	return fmt.Sprintf("%s driver requires the %q option.", driverName, string(r))
}

// newAzureClient creates an AzureClient helper from the Driver context and
// initiates authentication if required.
func (d *Driver) newAzureClient(ctx context.Context) (*azureutil.AzureClient, error) {
	env, err := azure.EnvironmentFromName(d.Environment)
	if err != nil {
		supportedValues := strings.Join(supportedEnvironments, ", ")
		return nil, fmt.Errorf("Invalid Azure environment: %q, supported values: %s", d.Environment, supportedValues)
	}

	var (
		authorizer *autorest.BearerAuthorizer
	)
	if d.ClientID != "" && d.ClientSecret != "" { // use client credentials auth
		log.Debug("Using Azure client credentials.")
		authorizer, err = azureutil.AuthenticateClientCredentials(ctx, env, d.SubscriptionID, d.ClientID, d.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("Failed to authenticate using client credentials: %+v", err)
		}
	} else { // use browser-based device auth
		log.Debug("Using Azure device flow authentication.")
		authorizer, err = azureutil.AuthenticateDeviceFlow(ctx, env, d.SubscriptionID)
		if err != nil {
			return nil, fmt.Errorf("Error creating Azure client: %v", err)
		}
	}
	return azureutil.New(env, d.SubscriptionID, authorizer), nil
}

// generateSSHKey creates a ssh key pair locally and saves the public key file
// contents in OpenSSH format to the DeploymentContext.
func (d *Driver) generateSSHKey(deploymentCtx *azureutil.DeploymentContext) error {
	privPath := d.GetSSHKeyPath()
	pubPath := privPath + ".pub"

	log.Debug("Creating SSH key...", logutil.Fields{
		"pub":  pubPath,
		"priv": privPath,
	})

	if err := ssh.GenerateSSHKey(privPath); err != nil {
		return err
	}
	log.Debug("SSH key pair generated.")

	publicKey, err := ioutil.ReadFile(pubPath)
	deploymentCtx.SSHPublicKey = string(publicKey)
	return err
}

func (d *Driver) naming() azureutil.ResourceNaming {
	return azureutil.ResourceNaming(d.BaseDriver.MachineName)
}

// ipAddress returns machine’s private or public IP address according to the
// configuration. If no IP address is found it returns empty string.
func (d *Driver) ipAddress(ctx context.Context) (ip string, err error) {
	c, err := d.newAzureClient(ctx)
	if err != nil {
		return "", err
	}

	var ipType string
	if d.UsePrivateIP || d.NoPublicIP {
		ipType = "Private"
		ip, err = c.GetPrivateIPAddress(ctx, d.ResourceGroup, d.naming().NIC())
	} else {
		ipType = "Public"
		ip, err = c.GetPublicIPAddress(ctx, d.ResourceGroup,
			d.naming().IP(),
			d.DNSLabel != "")
	}

	log.Debugf("Retrieving %s IP address...", ipType)
	if err != nil {
		return "", fmt.Errorf("Error querying %s IP: %v", ipType, err)
	}
	if ip == "" {
		log.Debugf("%s IP address is not yet allocated.", ipType)
	}
	return ip, nil
}

// resolveNSGReference extracts the NetworkSecurityGroupID from nsg
func (d *Driver) resolveNSGReference(nsg string) (azure.Resource, error) {
	if strings.Contains(nsg, "/") {
		// ARM resource identifier provided
		nsgResource, err := azure.ParseResourceID(nsg)
		if err != nil {
			return nsgResource, fmt.Errorf("unable to parse resource ID of network security group: %s", nsg)
		}
		return nsgResource, nil
	}
	var name string
	if len(nsg) == 0 {
		// Legacy case
		name = d.naming().NSG()
	} else {
		name = nsg
	}
	return azure.Resource{
		SubscriptionID: d.SubscriptionID,
		ResourceGroup:  d.ResourceGroup,
		Provider:       "Microsoft.Network",
		ResourceType:   "networkSecurityGroups",
		ResourceName:   name,
	}, nil
}

func machineStateForVMPowerState(ps azureutil.VMPowerState) state.State {
	m := map[azureutil.VMPowerState]state.State{
		azureutil.Running:      state.Running,
		azureutil.Starting:     state.Starting,
		azureutil.Stopping:     state.Stopping,
		azureutil.Stopped:      state.Stopped,
		azureutil.Deallocating: state.Stopping,
		azureutil.Deallocated:  state.Stopped,
		azureutil.Unknown:      state.None,
	}

	if v, ok := m[ps]; ok {
		return v
	}
	log.Warnf("Azure PowerState %q does not map to a docker-machine state.", ps)
	return state.None
}

// parseVirtualNetwork parses Virtual Network input format "[resourcegroup:]name"
// into Resource Group (uses provided one if omitted) and Virtual Network Name
func parseVirtualNetwork(name string, defaultRG string) (string, string) {
	l := strings.SplitN(name, ":", 2)
	if len(l) == 2 {
		return l[0], l[1]
	}
	return defaultRG, name
}
