package detectors

import "ai-surface-platform/internal/detection"

// RegisterAll registers every built-in detector into r. catalog seeds the
// technology-vulnerability detector (pass nil, or
// NewEmptyVulnerabilityCatalog(), for the default empty catalog —
// phase8.md §41: this project ships no hardcoded CVE data).
func RegisterAll(r *detection.Registry, catalog *VulnerabilityCatalog) error {
	all := []detection.Detector{
		hstsDetector{},
		cspDetector{},
		xContentTypeOptionsDetector{},
		referrerPolicyDetector{},
		permissionsPolicyDetector{},
		cookieDetector{},
		corsDetector{},
		certificateExpirationDetector{},
		obsoleteProtocolDetector{},
		informationDisclosureDetector{},
		exposedServiceDetector{},
		sensitiveEndpointDetector{},
		backupFileDetector{},
		gitExposureDetector{},
		envFileExposureDetector{},
		securityTxtDetector{},
		errorDisclosureDetector{},
		directoryListingDetector{},
		exposedAPIDocDetector{},
		graphQLInventoryDetector{},
		httpMethodExposureDetector{},
		authSurfaceDetector{},
		NewTechnologyVulnerabilityDetector(catalog),
	}
	for _, d := range all {
		if err := r.Register(d); err != nil {
			return err
		}
	}
	return nil
}
