package azureutil

import (
	"time"
)

var (
	// defaults
	defaultAzureListTimeout   = time.Second * 10
	defaultAzureCreateTimeout = time.Minute * 5

	// Authentication Workflow
	validateAuthorizerTimeout = time.Second * 5
	findTenantIDTimeout       = time.Second * 5

	// Clients
	defaultClientPollingDelay = time.Second * 5

	// Azure API Requests
	createResourceGroupsTimeout = defaultAzureCreateTimeout

	powerStatePollingInterval = time.Second * 5
	waitStartTimeout          = time.Minute * 10
	waitPowerOffTimeout       = time.Minute * 5
)
