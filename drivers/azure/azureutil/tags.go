package azureutil

import (
	"fmt"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/rancher/machine/drivers/azure/logutil"
)

const (
	taggedByMachineSuffix = "tagged-by-machine-do-not-remove"

	// This key indicates that the resource specified is managed by rancher
	managedByRancherKey = "managed-by-rancher"
)

// RancherMachineTags indicates whether a tag should be set or unset for a resource
// by either calling SetTags (where true values will be set) or UnsetTags (where true
// values will be unset) on an existing set of tags
type RancherMachineTags struct {
	ManagedByRancher bool
}

// GetMachineTags extracts RancherMachineTags from a given set of tags
func GetMachineTags(tags map[string]*string) RancherMachineTags {
	keyExists := func(key string) bool {
		val, ok := tags[getTag(key)]
		return ok && to.String(val) == "true"
	}
	return RancherMachineTags{
		ManagedByRancher: keyExists(managedByRancherKey),
	}
}

// CreateTags creates a new set of tags for an Azure object
func (r RancherMachineTags) CreateTags() map[string]*string {
	return r.SetTags(map[string]*string{})
}

// SetTags adds the tags requested to an existing set of tags from Azure
func (r RancherMachineTags) SetTags(tags map[string]*string) map[string]*string {
	if r.ManagedByRancher {
		tags[getTag(managedByRancherKey)] = to.StringPtr("true")
	}
	return tags
}

// UnsetTags removes the tags requested from an existing set of tags from Azure
func (r RancherMachineTags) UnsetTags(tags map[string]*string) map[string]*string {
	if r.ManagedByRancher {
		delete(tags, getTag(managedByRancherKey))
	}
	return tags
}

func (r RancherMachineTags) toLogField() logutil.Fields {
	return logutil.Fields{
		"managedByRancher": r.ManagedByRancher,
	}
}

func getTag(tag string) string {
	return fmt.Sprintf("%s-%s", tag, taggedByMachineSuffix)
}
