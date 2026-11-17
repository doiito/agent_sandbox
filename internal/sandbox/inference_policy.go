package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// InferenceUnits is an integer microcredit amount. JSON strings preserve exact
// balances for clients whose native JSON number type has only 53 integer bits.
type InferenceUnits uint64

func (u InferenceUnits) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(u), 10))
}
func (u *InferenceUnits) UnmarshalJSON(data []byte) error {
	var text string
	if json.Unmarshal(data, &text) != nil || len(text) == 0 || len(text) > 20 || len(text) > 1 && text[0] == '0' {
		return errors.New("inference units must be a canonical decimal string")
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return errors.New("inference units must be a canonical decimal string")
		}
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return errors.New("inference units overflow")
	}
	*u = InferenceUnits(value)
	return nil
}

type InferencePrice struct {
	RequestUnits    InferenceUnits `json:"request_units"`
	InputByteUnits  InferenceUnits `json:"input_byte_units"`
	OutputByteUnits InferenceUnits `json:"output_byte_units"`
}

func (p InferencePrice) cost(input, output uint64) (InferenceUnits, error) {
	total := uint64(p.RequestUnits)
	for _, pair := range [][2]uint64{{input, uint64(p.InputByteUnits)}, {output, uint64(p.OutputByteUnits)}} {
		if pair[0] != 0 && pair[1] > (math.MaxUint64-total)/pair[0] {
			return 0, errors.New("inference price overflow")
		}
		total += pair[0] * pair[1]
	}
	return InferenceUnits(total), nil
}

type InferenceCredential struct {
	File   string `json:"file"`
	Header string `json:"header"`
	Prefix string `json:"prefix,omitempty"`
}
type InferenceEndpoint struct {
	Name       string               `json:"name"`
	URL        string               `json:"url"`
	Credential *InferenceCredential `json:"credential,omitempty"`
	Price      InferencePrice       `json:"price"`
}
type InferencePolicy struct {
	Endpoints      []InferenceEndpoint `json:"endpoints"`
	MaxInvocations int                 `json:"max_invocations,omitempty"`
	BudgetUnits    *InferenceUnits     `json:"budget_units,omitempty"`
}

var inferenceEndpointName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

type inferenceRules struct {
	policy    InferencePolicy
	endpoints map[string]InferenceEndpoint
	request   int
	response  int
	timeoutMS int
}

func compileInferencePolicy(input InferencePolicy, network *egressRules) (*inferenceRules, error) {
	if network == nil {
		return nil, errors.New("inference requires explicit egress policy")
	}
	if input.MaxInvocations == 0 {
		input.MaxInvocations = 128
	}
	if len(input.Endpoints) < 1 || len(input.Endpoints) > 32 || input.MaxInvocations < 1 || input.MaxInvocations > 256 {
		return nil, errors.New("invalid inference policy bounds")
	}
	rules := &inferenceRules{policy: input, endpoints: make(map[string]InferenceEndpoint), request: network.policy.MaxRequestBytes,
		response: network.policy.MaxResponseBytes, timeoutMS: network.policy.TimeoutMS}
	rules.policy.Endpoints = make([]InferenceEndpoint, 0, len(input.Endpoints))
	if input.BudgetUnits != nil {
		value := *input.BudgetUnits
		rules.policy.BudgetUnits = &value
	}
	for _, endpoint := range input.Endpoints {
		if !inferenceEndpointName.MatchString(endpoint.Name) {
			return nil, errors.New("invalid inference endpoint name")
		}
		if _, exists := rules.endpoints[endpoint.Name]; exists {
			return nil, errors.New("duplicate inference endpoint name")
		}
		u, origin, err := egressURL(endpoint.URL)
		if err != nil || u.RawQuery != "" || u.ForceQuery || !network.origins[origin] {
			return nil, errors.New("inference endpoint requires an authorized fixed egress URL")
		}
		if u.Path == "" {
			u.Path = "/"
		}
		endpoint.URL = u.String()
		if _, err := endpoint.Price.cost(uint64(rules.request), uint64(rules.response)); err != nil {
			return nil, err
		}
		if endpoint.Credential != nil {
			credential := *endpoint.Credential
			if !filepath.IsAbs(credential.File) || filepath.Clean(credential.File) != credential.File ||
				!validHeaderName(credential.Header) || egressHeaderBlocked(credential.Header) || len(credential.Prefix) > 128 ||
				strings.HasPrefix(strings.ToLower(credential.Header), "x-osv-") {
				return nil, errors.New("invalid inference credential configuration")
			}
			credential.Header = http.CanonicalHeaderKey(credential.Header)
			switch credential.Header {
			case "Content-Type", "Content-Encoding", "Accept", "Cookie", "Set-Cookie", "Origin", "Referer", "Idempotency-Key", "X-Idempotency-Key":
				return nil, errors.New("inference credential header is reserved")
			}
			for _, c := range credential.Prefix {
				if c < 32 || c > 126 {
					return nil, errors.New("invalid inference credential prefix")
				}
			}
			endpoint.Credential = &credential
		}
		rules.endpoints[endpoint.Name] = endpoint
		rules.policy.Endpoints = append(rules.policy.Endpoints, endpoint)
	}
	return rules, nil
}

type inferencePermit struct {
	endpoint       string
	price          InferencePrice
	maxInvocations int
	budget         *InferenceUnits
	maxRequest     uint64
	maxResponse    uint64
}

func (r *inferenceRules) permit(endpoint string) (inferencePermit, error) {
	entry, exists := r.endpoints[endpoint]
	if !exists {
		return inferencePermit{}, errors.New("inference endpoint denied")
	}
	return inferencePermit{endpoint: endpoint, price: entry.Price, maxInvocations: r.policy.MaxInvocations,
		budget: r.policy.BudgetUnits, maxRequest: uint64(r.request), maxResponse: uint64(r.response)}, nil
}

// Persisted records also enforce ownership, field and numeric invariants.
func decodeInferenceJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("trailing inference JSON")
	}
	return nil
}
