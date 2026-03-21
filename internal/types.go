package app

// Fields sourced from: https://github.com/sigstore/fulcio/blob/v1.8.5/pkg/certificate/extensions.go#L60
type BuildInfo struct {
	// Reference to specific build instructions that are responsible for signing.
	BuildSignerURI string `json:"BuildSignerURI,omitempty"`

	// Immutable reference to the specific version of the build instructions that is responsible for signing.
	BuildSignerDigest string `json:"BuildSignerDigest,omitempty"`

	// Specifies whether the build took place in platform-hosted cloud infrastructure or customer/self-hosted infrastructure.
	RunnerEnvironment string `json:"RunnerEnvironment,omitempty"`

	// Source repository URL that the build was based on.
	SourceRepositoryURI string `json:"SourceRepositoryURI,omitempty"`

	// Immutable reference to a specific version of the source code that the build was based upon.
	SourceRepositoryDigest string `json:"SourceRepositoryDigest,omitempty"`

	// Source Repository Ref that the build run was based upon.
	SourceRepositoryRef string `json:"SourceRepositoryRef,omitempty"`

	// Immutable identifier for the source repository the workflow was based upon.
	SourceRepositoryIdentifier string `json:"SourceRepositoryIdentifier,omitempty"`

	// Source repository owner URL of the owner of the source repository that the build was based on.
	SourceRepositoryOwnerURI string `json:"SourceRepositoryOwnerURI,omitempty"`

	// Immutable identifier for the owner of the source repository that the workflow was based upon.
	SourceRepositoryOwnerIdentifier string `json:"SourceRepositoryOwnerIdentifier,omitempty"`

	// Build Config URL to the top-level/initiating build instructions.
	BuildConfigURI string `json:"BuildConfigURI,omitempty"`

	// Immutable reference to the specific version of the top-level/initiating build instructions.
	BuildConfigDigest string `json:"BuildConfigDigest,omitempty"`

	// Event or action that initiated the build.
	BuildTrigger string `json:"BuildTrigger,omitempty"`

	// Run Invocation URL to uniquely identify the build execution.
	RunInvocationURI string `json:"RunInvocationURI,omitempty"`

	// Source repository visibility at the time of the build.
	SourceRepositoryVisibility string `json:"SourceRepositoryVisibility,omitempty"`

	// Deployment target for a workflow or job.
	DeploymentEnvironment string `json:"DeploymentEnvironment,omitempty"`
}

type AttestationReport struct {
	Evidence []*AttestationEvidence `json:"evidence"`
	Data     *AttestationReportData `json:"data"`
}

type AttestationEvidence struct {
	Kind string `json:"kind"`
	Blob []byte `json:"blob"`
	Data any    `json:"data,omitempty"`
}

type AttestationReportData struct {
	RequestID    string            `json:"request_id"`
	Nonce        string            `json:"nonce,omitempty"`
	BuildInfo    *BuildInfo        `json:"build_info"`
	TLS          *TLSReportData    `json:"tls"`
	Endorsements []string          `json:"endorsements"`
	UserData     map[string]any    `json:"user_data,omitempty"`
	SecureBoot   *bool             `json:"secure_boot,omitempty"`
	TPMPCRs      map[string]string `json:"tpm_pcrs,omitempty"`
}

type TLSReportData struct {
	Client  *TLSCertificateData `json:"client,omitempty"`
	Public  *TLSCertificateData `json:"public,omitempty"`
	Private *TLSCertificateData `json:"private,omitempty"`
}

type TLSCertificateData struct {
	CertificateFingerprint string `json:"certificate"`
	PublicKeyFingerprint   string `json:"public_key,omitempty"`
}
