package sandbox

import "slices"

func inferenceManifestProtocol(backend, protocol string) bool {
	return (backend == "firecracker-linux" || backend == "firecracker-osv") &&
		(protocol == "osv-sandbox-artifacts/v7" || backend == "firecracker-linux" && protocol == "osv-sandbox-artifacts/v8")
}

func signedRemoteInferenceFeature(backend string, manifest *SignedArtifactManifest) bool {
	return manifest != nil && inferenceManifestProtocol(backend, manifest.Protocol) &&
		manifest.Backend == backend && manifest.GuestInference.validate(backend) == nil && slices.Contains(manifest.AgentFeatures, "remote-infer-v1") &&
		slices.Contains(manifest.AgentFeatures, "vsock-proxy-v1")
}

func (m *Manager) hasRemoteInferenceFeature() bool {
	return signedRemoteInferenceFeature(m.config.Backend, m.manifest)
}

func (m *Manager) hasLinuxProxyFeature() bool {
	return m.config.Backend == "firecracker-linux" && m.manifest != nil &&
		(m.manifest.Protocol == "osv-sandbox-artifacts/v3" || m.manifest.Protocol == "osv-sandbox-artifacts/v4" || m.manifest.Protocol == "osv-sandbox-artifacts/v5" || m.manifest.Protocol == "osv-sandbox-artifacts/v6" || m.manifest.Protocol == "osv-sandbox-artifacts/v7" || m.manifest.Protocol == "osv-sandbox-artifacts/v8") && slices.Contains(m.manifest.AgentFeatures, "vsock-proxy-v1")
}

func (m *Manager) hasGuestProxyFeature() bool {
	return m.hasLinuxProxyFeature() || m.config.Backend == "firecracker-osv" && m.hasRemoteInferenceFeature()
}

func (m *Manager) hasLinuxWatchFeature() bool {
	return m.config.Backend == "firecracker-linux" && m.manifest != nil &&
		(m.manifest.Protocol == "osv-sandbox-artifacts/v4" || m.manifest.Protocol == "osv-sandbox-artifacts/v5" || m.manifest.Protocol == "osv-sandbox-artifacts/v6" || m.manifest.Protocol == "osv-sandbox-artifacts/v7" || m.manifest.Protocol == "osv-sandbox-artifacts/v8") && slices.Contains(m.manifest.AgentFeatures, "workspace-watch-v1")
}

func (m *Manager) hasOSvAgentFeature(feature string) bool {
	return m.config.Backend == "firecracker-osv" && m.manifest != nil &&
		slices.Contains(m.manifest.AgentFeatures, feature)
}

func (m *Manager) hasOSvInputFeature() bool {
	return m.hasOSvAgentFeature("input-files-v1") && m.hasOSvAgentFeature("pristine-v1") &&
		(m.manifest.Protocol == "osv-sandbox-artifacts/v2" || m.manifest.Protocol == "osv-sandbox-artifacts/v7")
}

// CapabilityReport describes supported API behavior, not current host health.
// The manager is authoritative for the backend and authenticated template.
type CapabilityReport struct {
	RemoteInferencePolicy    *InferenceCapabilities `json:"remote_inference_policy,omitempty"`
	PortForwardPolicy        *PortPolicy            `json:"port_forward_policy,omitempty"`
	CodeRuntime              *SignedCodeRuntime     `json:"code_runtime,omitempty"`
	CodeLanguages            []string               `json:"code_languages,omitempty"`
	TemplateID               string                 `json:"template_id,omitempty"`
	NetworkFetchPolicy       *EgressPolicy          `json:"network_fetch_policy,omitempty"`
	Protocol                 string                 `json:"protocol"`
	Backend                  string                 `json:"backend"`
	Workload                 string                 `json:"workload"`
	Stage                    string                 `json:"stage"`
	GuestResultProtocol      string                 `json:"guest_result_protocol"`
	ArtifactAuthenticated    bool                   `json:"artifact_authenticated"`
	ArtifactManifestProtocol string                 `json:"artifact_manifest_protocol,omitempty"`
	ArtifactManifestSHA256   string                 `json:"artifact_manifest_sha256,omitempty"`
	AllowedEntrypoints       []string               `json:"allowed_entrypoints"`
	Methods                  []string               `json:"methods"`
	Features                 CapabilityFeatures     `json:"features"`
	Limits                   CapabilityLimits       `json:"limits"`
}

type CapabilityFeatures struct {
	SessionArtifacts        bool `json:"session_artifacts"`
	RemoteInference         bool `json:"remote_inference,omitempty"`
	InferenceBilling        bool `json:"inference_billing,omitempty"`
	PortPreview             bool `json:"port_preview,omitempty"`
	CodeContexts            bool `json:"code_contexts"`
	NetworkFetch            bool `json:"network_fetch"`
	SessionListing          bool `json:"session_listing"`
	SessionTimeoutUpdate    bool `json:"session_timeout_update"`
	InteractiveStdin        bool `json:"interactive_stdin"`
	OneShotJob              bool `json:"one_shot_job"`
	Argv                    bool `json:"argv"`
	Stdout                  bool `json:"stdout"`
	Stderr                  bool `json:"stderr"`
	ExitCode                bool `json:"exit_code"`
	Timeout                 bool `json:"timeout"`
	Cancellation            bool `json:"cancellation"`
	InputFiles              bool `json:"input_files"`
	Stdin                   bool `json:"stdin"`
	Environment             bool `json:"environment"`
	WorkingDirectory        bool `json:"working_directory"`
	StreamingOutput         bool `json:"streaming_output"`
	PersistentWorkspace     bool `json:"persistent_workspace"`
	Sessions                bool `json:"sessions"`
	BackgroundCommands      bool `json:"background_commands"`
	SessionEnvironment      bool `json:"session_environment"`
	SessionWorkingDirectory bool `json:"session_working_directory"`
	SessionFiles            bool `json:"session_files"`
	FileWatch               bool `json:"file_watch"`
	RecursiveFileWatch      bool `json:"recursive_file_watch"`
	FileWatchEntry          bool `json:"file_watch_entry"`
	NetworkEgress           bool `json:"network_egress"`
	PauseResume             bool `json:"pause_resume"`
	Snapshots               bool `json:"snapshots"`
	PortForward             bool `json:"port_forward"`
	WarmPool                bool `json:"warm_pool"`
}

type CapabilityLimits struct {
	SessionArtifactCount     int `json:"session_artifact_count,omitempty"`
	SessionArtifactMaxBytes  int `json:"session_artifact_max_bytes,omitempty"`
	SessionArtifactReadBytes int `json:"session_artifact_read_bytes,omitempty"`
	SessionArtifactEntries   int `json:"session_artifact_entries,omitempty"`
	SessionArtifactDepth     int `json:"session_artifact_depth,omitempty"`
	SessionArtifactPathBytes int `json:"session_artifact_path_bytes,omitempty"`
	PreviewGrants            int `json:"preview_grants,omitempty"`
	PreviewGrantIDs          int `json:"preview_grant_ids,omitempty"`
	PreviewTTLMS             int `json:"preview_ttl_ms,omitempty"`
	PreviewRequests          int `json:"preview_requests,omitempty"`
	PreviewRequestBytes      int `json:"preview_request_bytes,omitempty"`
	PortConnections          int `json:"port_connections,omitempty"`
	PortConnectionIDs        int `json:"port_connection_ids,omitempty"`
	PortFrameBytes           int `json:"port_frame_bytes,omitempty"`
	PortMaxBytes             int `json:"port_max_bytes,omitempty"`
	PortTimeoutMS            int `json:"port_timeout_ms,omitempty"`
	PortTenantConnections    int `json:"port_tenant_connections,omitempty"`
	CodeContexts             int `json:"code_contexts,omitempty"`
	CodeExecutionIDs         int `json:"code_execution_ids,omitempty"`
	CodeSourceBytes          int `json:"code_source_bytes,omitempty"`
	CodeOutputBytes          int `json:"code_output_bytes,omitempty"`
	CodeEventPage            int `json:"code_event_page,omitempty"`
	FileWatchActive          int `json:"file_watch_active,omitempty"`
	FileWatchHistory         int `json:"file_watch_history,omitempty"`
	FileWatchEvents          int `json:"file_watch_events,omitempty"`
	FileWatchBytes           int `json:"file_watch_bytes,omitempty"`
	FileWatchPage            int `json:"file_watch_page,omitempty"`
	FileWatchDirectories     int `json:"file_watch_directories,omitempty"`
	SessionMaxLifetimeMS     int `json:"session_max_lifetime_ms,omitempty"`
	SessionListPageMax       int `json:"session_list_page_max,omitempty"`
	CommandInputChunkBytes   int `json:"command_input_chunk_bytes,omitempty"`
	CommandInputTotalBytes   int `json:"command_input_total_bytes,omitempty"`
	CommandInputRequests     int `json:"command_input_requests,omitempty"`
	MaxConcurrent            int `json:"max_concurrent"`
	MaxArguments             int `json:"max_arguments"`
	MaxArgumentBytes         int `json:"max_argument_bytes"`
	MaxEnvEntries            int `json:"max_env_entries,omitempty"`
	MaxEnvBytes              int `json:"max_env_bytes,omitempty"`
	MaxStdinBytes            int `json:"max_stdin_bytes,omitempty"`
	MaxInputFiles            int `json:"max_input_files"`
	MaxInputBytes            int `json:"max_input_bytes"`
	MaxOutputBytes           int `json:"max_output_bytes"`
	MaxTimeoutMS             int `json:"max_timeout_ms"`
	MinMemoryMiB             int `json:"min_memory_mib"`
	MaxMemoryMiB             int `json:"max_memory_mib"`
	MaxVCPUs                 int `json:"max_vcpus"`
	SessionMaxTTLMS          int `json:"session_max_ttl_ms"`
	SessionFileMaxBytes      int `json:"session_file_max_bytes"`
	CommandHistory           int `json:"command_history"`
	CommandOutputEvents      int `json:"command_output_events"`
	CommandOutputBytes       int `json:"command_output_bytes"`
}

func (m *Manager) Capabilities() (CapabilityReport, error) {
	config := m.config
	workload := "legacy-diagnostic-guest"
	features := CapabilityFeatures{OneShotJob: true, Argv: true, Stdout: true,
		Stderr: true, ExitCode: true, Timeout: true, Cancellation: true}
	features.RemoteInference = m.hasRemoteInferenceFeature() && config.EgressSocket != ""
	limits := CapabilityLimits{MaxConcurrent: config.Limits.MaxConcurrent,
		MaxArguments: 64, MaxOutputBytes: config.Limits.MaxOutputByte,
		MaxTimeoutMS: config.Limits.MaxTimeoutMS, MinMemoryMiB: config.Limits.MinMemoryMiB,
		MaxMemoryMiB: config.Limits.MaxMemoryMiB, MaxVCPUs: config.Limits.MaxVCPUs}
	switch config.Backend {
	case "firecracker-linux":
		features.NetworkEgress = m.hasLinuxProxyFeature() && config.EgressSocket != ""
		workload = "linux-process"
		features.InputFiles = true
		features.Environment, features.Stdin, features.WorkingDirectory = true, true, true
		limits.MaxEnvEntries, limits.MaxEnvBytes, limits.MaxStdinBytes = 32, 8192, linuxJobStdinMaxBytes
		limits.MaxArgumentBytes = 32 * 1024
		limits.MaxInputFiles, limits.MaxInputBytes = 64, 512*1024
	case "firecracker-osv":
		features.NetworkEgress = m.hasGuestProxyFeature() && config.EgressSocket != ""
		workload = "osv-native-module"
		limits.MaxArgumentBytes = 32 * 1024
		if m.hasOSvInputFeature() {
			features.InputFiles = true
			limits.MaxInputFiles, limits.MaxInputBytes = 64, 512*1024
		}
		if m.hasOSvAgentFeature("environment") {
			features.Environment = true
			limits.MaxEnvEntries, limits.MaxEnvBytes = osvJobEnvMaxCount, osvJobEnvMaxBytes
		}
		if m.hasOSvAgentFeature("stdin") {
			features.Stdin = true
			limits.MaxStdinBytes = osvJobStdinMaxBytes
		}
	}
	resultProtocol := "osv-agent/v1"
	if provider, ok := m.backend.(resultProtocolBackend); ok {
		_, resultProtocol = provider.ResultProtocol()
	}
	if m.pool != nil {
		features.WarmPool = true
		_, resultProtocol = m.pool.backend.ResultProtocol()
	}
	stage := "diagnostic"
	if config.Production {
		stage = "production"
	}
	report := CapabilityReport{
		Protocol: "osv-sandbox-capabilities/v1", Backend: config.Backend,
		Workload: workload, Stage: stage, GuestResultProtocol: resultProtocol,
		AllowedEntrypoints: append([]string{}, config.AllowedEntrypoints...),
		Methods:            []string{"GET /v1/capabilities", "GET /v1/doctor", "POST /v1/jobs"},
		Features:           features, Limits: limits,
	}
	if m.catalog != nil {
		report.TemplateID = m.config.defaultTemplateID()
	}
	if m.manifest != nil {
		report.Methods = append(report.Methods, "GET /v2/templates")
		report.ArtifactAuthenticated = true
		report.ArtifactManifestProtocol = m.manifest.Protocol
		report.ArtifactManifestSHA256 = m.manifest.digestSHA256
		if validSHA256Hex(m.manifest.digestSHA256) {
			report.Methods = append(report.Methods, "POST /v2/jobs")
			if config.Backend == "firecracker-linux" {
				if _, ok := m.backend.(FirecrackerLinuxBackend); ok {
					report.Features.Sessions = true
					report.Features.SessionListing = true
					report.Features.SessionTimeoutUpdate = true
					report.Limits.SessionMaxLifetimeMS = sessionLifetimeMS(config)
					report.Limits.SessionListPageMax = 100
					report.Features.PersistentWorkspace = true
					report.Features.SessionFiles = true
					if m.hasLinuxArtifactFeature() && m.backend.(FirecrackerLinuxBackend).WorkspaceArtifacts {
						report.Features.SessionArtifacts = true
						report.Limits.SessionArtifactCount, report.Limits.SessionArtifactMaxBytes = sessionArtifactLimit, sessionArtifactBytes
						report.Limits.SessionArtifactReadBytes, report.Limits.SessionArtifactEntries = sessionArtifactReadBytes, sessionArtifactEntries
						report.Limits.SessionArtifactDepth, report.Limits.SessionArtifactPathBytes = sessionArtifactDepth, sessionArtifactPathBytes
						report.Methods = append(report.Methods, "POST /v2/sessions/{id}/artifacts", "POST /v2/sessions/{id}/artifacts/{artifact}/read", "DELETE /v2/sessions/{id}/artifacts/{artifact}")
					}
					if m.hasLinuxPortFeature() && m.backend.(FirecrackerLinuxBackend).PortForward {
						report.Features.PortForward = true
						report.Limits.PortConnections, report.Limits.PortConnectionIDs = sessionPortActiveLimit, sessionPortHistoryLimit
						report.Limits.PortFrameBytes, report.Limits.PortMaxBytes, report.Limits.PortTimeoutMS = portDataLimit, portByteLimit, portDurationLimitMS
						report.Methods = append(report.Methods, "POST /v2/sessions/{id}/ports/{port}/connections/{connection}", "GET /v2/sessions/{id}/ports/{port}/connections/{connection}", "DELETE /v2/sessions/{id}/ports/{port}/connections/{connection}")
					}
					if m.hasLinuxCodeFeature() && m.backend.(FirecrackerLinuxBackend).CodeContexts {
						report.Features.CodeContexts = true
						report.CodeRuntime = m.manifest.CodeRuntime.clone()
						for _, language := range []string{"python", "javascript", "typescript"} {
							if slices.Contains(config.AllowedEntrypoints, codeEntrypoint(language)) {
								report.CodeLanguages = append(report.CodeLanguages, language)
							}
						}
						report.Limits.CodeContexts, report.Limits.CodeExecutionIDs = 4, 256
						report.Limits.CodeSourceBytes, report.Limits.CodeOutputBytes, report.Limits.CodeEventPage = codeSourceLimit, codeOutputLimit, 64
						report.Methods = append(report.Methods, "POST /v2/sessions/{id}/contexts", "POST /v2/sessions/{id}/contexts/default", "GET /v2/sessions/{id}/contexts", "GET /v2/sessions/{id}/contexts/{context}", "POST /v2/sessions/{id}/contexts/{context}/restart", "DELETE /v2/sessions/{id}/contexts/{context}", "POST /v2/sessions/{id}/code-executions", "GET /v2/sessions/{id}/code-executions/{execution}", "DELETE /v2/sessions/{id}/code-executions/{execution}")
					}
					if m.hasLinuxWatchFeature() && m.backend.(FirecrackerLinuxBackend).FileWatch {
						report.Features.FileWatch, report.Features.RecursiveFileWatch, report.Features.FileWatchEntry = true, true, true
						report.Limits.FileWatchActive, report.Limits.FileWatchHistory = sessionWatchActiveLimit, sessionWatchHistoryLimit
						report.Limits.FileWatchEvents, report.Limits.FileWatchBytes = sessionWatchEventLimit, sessionWatchByteLimit
						report.Limits.FileWatchPage, report.Limits.FileWatchDirectories = sessionWatchPageLimit, sessionWatchDirectoryLimit
						report.Methods = append(report.Methods, "POST /v2/sessions/{id}/watches", "GET /v2/sessions/{id}/watches", "GET /v2/sessions/{id}/watches/{watch}", "DELETE /v2/sessions/{id}/watches/{watch}")
					}
					report.Features.StreamingOutput = true
					report.Features.BackgroundCommands = true
					report.Features.InteractiveStdin = true
					report.Limits.CommandInputChunkBytes = commandInputChunkLimit
					report.Limits.CommandInputTotalBytes = commandInputByteLimit
					report.Limits.CommandInputRequests = commandInputRequestLimit
					report.Features.SessionEnvironment = true
					report.Features.SessionWorkingDirectory = true
					report.Limits.CommandHistory = commandHistoryLimit
					report.Limits.CommandOutputEvents = 256
					report.Limits.CommandOutputBytes = min(m.backend.(FirecrackerLinuxBackend).guestOutputLimit(), commandOutputLimit)
					report.Limits.SessionMaxTTLMS = min(sessionMaxTTLMS, sessionLifetimeMS(config))
					report.Limits.SessionFileMaxBytes = sessionFileLimit
					report.Methods = append(report.Methods,
						"POST /v2/sessions", "GET /v2/sessions", "POST /v2/sessions/{id}/timeout", "GET /v2/sessions/{id}", "GET /v2/sessions/{id}/capabilities",
						"POST /v2/sessions/{id}/commands", "POST /v2/sessions/{id}/files",
						"DELETE /v2/sessions/{id}",
						"POST /v2/sessions/{id}/commands/start", "GET /v2/sessions/{id}/commands",
						"GET /v2/sessions/{id}/commands/{command}", "DELETE /v2/sessions/{id}/commands/{command}",
						"GET /v2/sessions/{id}/commands/{command}/events",
						"POST /v2/sessions/{id}/commands/{command}/stdin",
						"GET /v2/sessions/{id}/commands/{command}/stdin/{sequence}")
				}
			}
		}
	}
	return report, nil
}

func (r *CapabilityReport) restrictEntrypoints(tenant *tenantRuntime) {
	if tenant == nil || tenant.inference == nil {
		disableRemoteInference(r)
	}
	r.restrictPorts(tenant)
	if tenant != nil && r.Features.CodeContexts {
		languages := []string{}
		for _, language := range r.CodeLanguages {
			if tenant.allowsEntrypoint(codeEntrypoint(language)) {
				languages = append(languages, language)
			}
		}
		r.CodeLanguages = languages
	}
	if tenant == nil {
		r.AllowedEntrypoints = []string{}
		return
	}
	allowed := make(map[string]struct{}, len(tenant.policy.AllowedEntrypoints))
	for _, entrypoint := range tenant.policy.AllowedEntrypoints {
		if entrypoint == "*" {
			return
		}
		allowed[entrypoint] = struct{}{}
	}
	filtered := make([]string, 0, len(r.AllowedEntrypoints))
	for _, entrypoint := range r.AllowedEntrypoints {
		if _, ok := allowed[entrypoint]; ok {
			filtered = append(filtered, entrypoint)
		}
	}
	r.AllowedEntrypoints = filtered
}
