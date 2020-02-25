package azureutil

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/drivers/azure/logutil"
)

var (
	// See https://docs.microsoft.com/en-us/dotnet/api/microsoft.azure.management.batch.models.imagereference.id?view=azure-dotnet#Microsoft_Azure_Management_Batch_Models_ImageReference_Id
	customImageFormat = "subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/images/%s"
	galleryImageFormat = "subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/galleries/%s/images/%s/versions/%s"

	// Regex: https://docs.microsoft.com/bs-latn-ba/rest/api/securitycenter/locations/get
	subscriptionRegex = regexp.MustCompile(`subscriptions/[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}`)
	// Regex: https://docs.microsoft.com/en-us/rest/api/resources/resources/listbyresourcegroup
	resourceGroupRegex = regexp.MustCompile(`resourceGroups/[-\w\._\(\)]+`)
	// The name must begin with a letter or number, end with a letter, number or underscore, and may contain only letters, numbers, underscores, periods, or hyphens
	imageRegex = regexp.MustCompile(`images/[A-Za-z][A-Za-z0-9-_]{1,61}[A-Za-z0-9_]`)
	// Shared image gallery name shouldn't contain hyphens, may contain letters, numbers and allow underscores and periods in the middle.
	galleryRegex = regexp.MustCompile(`galleries/[A-Za-z0-9][A-Za-z0-9_.]{1,61}[A-Za-z0-9]`)
	// Allowed characters for image version are numbers and periods. Numbers must be within the range of a 32-bit integer. Format: MajorVersion.MinorVersion.Patch
	versionRegex = regexp.MustCompile(`versions/[0-9][0-9.]{1,62}[0-9]`)
)

type customImage struct{ subscriptionId, resourceGroup, galleryName, imageName, versionId string }

// Parses a custom image based on https://docs.microsoft.com/en-us/dotnet/api/microsoft.azure.management.batch.models.imagereference.id?view=azure-dotnet#Microsoft_Azure_Management_Batch_Models_ImageReference_Id
func parseCustomImageReference(image string) (*customImage, error) {
	// NOTE(aiyengar2): the custom image ID provided must adhere to the ARM resource identifier format as we
	// do not have information about the resourceGroup that contains the requested custom image.
	// customImageFormat = "/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/images/%s"
	parsedSubscription := subscriptionRegex.FindString(image)
	parsedResourceGroup := resourceGroupRegex.FindString(image)
	parsedImage := imageRegex.FindString(image)
	if len(parsedSubscription) != 0 && len(parsedResourceGroup) != 0 && len(parsedImage) != 0 {
		if l := strings.Split(strings.Trim(image, "/"), "/"); len(l) == 8 {
			return &customImage{
				subscriptionId: parsedSubscription,
				resourceGroup:  parsedResourceGroup,
				imageName:      parsedImage, 
			}, nil
		} else if len(l) == 12 {
			parsedGallery := galleryRegex.FindString(image)
			parsedVersion := versionRegex.FindString(image)
			if len(parsedGallery) != 0 && len(parsedVersion) != 0 {
				return &customImage{
					subscriptionId: parsedSubscription,
					resourceGroup:  parsedResourceGroup,
					galleryName:    parsedGallery,
					imageName:      parsedImage, 
					versionId:      parsedVersion,
				}, nil
			}
		}
	}
	log.Info(
		"NOTE: if you intended to provide a custom image name, we require the ARM resource identifier for that custom image. See " +
		"https://docs.microsoft.com/en-us/dotnet/api/microsoft.azure.management.batch.models.imagereference.id?view=azure-dotnet#Microsoft_Azure_Management_Batch_Models_ImageReference_Id " + 
		"for more information on how to supply a custom image's ARM resource identifier.")
	return nil, fmt.Errorf("image name %q not a valid format", image)
}

func (c customImage) isGalleryImage() bool {
	return len(c.galleryName) == 0
}

func (c customImage) toCustomImageReferenceId() string {
	if c.isGalleryImage() {
		return fmt.Sprintf(galleryImageFormat, c.subscriptionId, c.resourceGroup, c.galleryName, c.imageName, c.versionId)
	} else {
		return fmt.Sprintf(customImageFormat, c.subscriptionId, c.resourceGroup, c.imageName)
	}
}

func (c customImage) toLogField() logutil.Fields {
	if c.isGalleryImage() {
		return logutil.Fields{
			"subscriptionId": c.subscriptionId,
			"resourceGroup":  c.resourceGroup,
			"galleryName":    c.galleryName,
			"imageName":      c.imageName, 
			"versionId":      c.versionId,
		}
	}
	return logutil.Fields{
		"subscriptionId": c.subscriptionId,
		"resourceGroup":  c.resourceGroup,
		"imageName":      c.imageName, 
	}
}