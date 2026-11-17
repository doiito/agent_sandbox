package sandbox

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func inferenceTestRules(t *testing.T) *inferenceRules {
	t.Helper()
	network, err := compileEgressPolicy(EgressPolicy{AllowedOrigins: []string{"https://models.test"}, MaxRequestBytes: 32, MaxResponseBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	budget := InferenceUnits(300)
	rules, err := compileInferencePolicy(InferencePolicy{Endpoints: []InferenceEndpoint{{Name: "local-model", URL: "https://models.test/invoke",
		Price: InferencePrice{RequestUnits: 5, InputByteUnits: 2, OutputByteUnits: 3}}}, MaxInvocations: 4, BudgetUnits: &budget}, network)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func TestInferenceUnitsAreExactCanonicalDecimalStrings(t *testing.T) {
	for _, text := range []string{`"0"`, `"9007199254740993"`, `"18446744073709551615"`} {
		var value InferenceUnits
		if err := json.Unmarshal([]byte(text), &value); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(value)
		if err != nil || string(encoded) != text {
			t.Fatal("loss of exact units", text)
		}
	}
	for _, text := range []string{`0`, `null`, `""`, `"00"`, `"+1"`, `"-1"`, `"1.0"`, `"1e3"`, `" 1"`, `"18446744073709551616"`} {
		var value InferenceUnits
		if json.Unmarshal([]byte(text), &value) == nil {
			t.Fatal("ambiguous units accepted", text)
		}
	}
}

func TestInferencePriceOverflowAndZeroRates(t *testing.T) {
	for _, price := range []InferencePrice{{RequestUnits: math.MaxUint64, InputByteUnits: 1}, {InputByteUnits: math.MaxUint64}, {OutputByteUnits: math.MaxUint64}} {
		if _, err := price.cost(2, 2); err == nil {
			t.Fatal("price wrapped")
		}
	}
	if value, err := (InferencePrice{}).cost(math.MaxUint64, math.MaxUint64); err != nil || value != 0 {
		t.Fatal("free metering rejected")
	}
	if value, err := (InferencePrice{RequestUnits: math.MaxUint64}).cost(0, 0); err != nil || value != math.MaxUint64 {
		t.Fatal("exact maximum lost")
	}
}

func TestInferencePolicyRequiresExistingEgressAndCopiesInput(t *testing.T) {
	rules := inferenceTestRules(t)
	if rules.policy.Endpoints[0].URL != "https://models.test:443/invoke" {
		t.Fatal("noncanonical endpoint")
	}
	if _, err := rules.permit("other"); err == nil {
		t.Fatal("unknown model permitted")
	}
	if _, err := compileInferencePolicy(rules.policy, nil); err == nil {
		t.Fatal("inference bypassed egress")
	}
	network, _ := compileEgressPolicy(EgressPolicy{AllowedOrigins: []string{"https://models.test"}})
	input := rules.policy
	credential := InferenceCredential{File: "/managed/model.token", Header: "authorization", Prefix: "Bearer "}
	input.Endpoints[0].Credential = &credential
	copy, err := compileInferencePolicy(input, network)
	if err != nil {
		t.Fatal(err)
	}
	input.Endpoints[0].Name = "mutated"
	credential.Prefix = "changed"
	*input.BudgetUnits = 1
	if copy.policy.Endpoints[0].Name != "local-model" || copy.policy.Endpoints[0].Credential.Prefix != "Bearer " || *copy.policy.BudgetUnits != 300 {
		t.Fatal("mutable input changed compiled inference policy")
	}
}

func TestInferencePolicyRejectsUnboundEndpointsAndCredentials(t *testing.T) {
	network, _ := compileEgressPolicy(EgressPolicy{AllowedOrigins: []string{"https://models.test"}})
	for _, url := range []string{"https://elsewhere.test/invoke", "https://user:secret@models.test/invoke", "https://models.test/invoke?key=secret", "https://models.test/invoke#secret", "file:///tmp/model"} {
		_, err := compileInferencePolicy(InferencePolicy{Endpoints: []InferenceEndpoint{{Name: "model", URL: url}}}, network)
		if err == nil {
			t.Fatal("unbound endpoint accepted", url)
		}
	}
	for _, name := range []string{"", "../model", strings.Repeat("x", 33), "Upper", "a b"} {
		_, err := compileInferencePolicy(InferencePolicy{Endpoints: []InferenceEndpoint{{Name: name, URL: "https://models.test/"}}}, network)
		if err == nil {
			t.Fatal("invalid alias accepted")
		}
	}
	for _, credential := range []InferenceCredential{{File: "relative", Header: "Authorization"}, {File: "/managed/../secret", Header: "Authorization"},
		{File: "/managed/key", Header: "Host"}, {File: "/managed/key", Header: "Cookie"}, {File: "/managed/key", Header: "Content-Type"},
		{File: "/managed/key", Header: "Content-Encoding"}, {File: "/managed/key", Header: "Idempotency-Key"}, {File: "/managed/key", Header: "X-Idempotency-Key"},
		{File: "/managed/key", Header: "X-OSV-Tenant"}, {File: "/managed/key", Header: "X-Api-Key", Prefix: "bad\r\n"}} {
		_, err := compileInferencePolicy(InferencePolicy{Endpoints: []InferenceEndpoint{{Name: "model", URL: "https://models.test/", Credential: &credential}}}, network)
		if err == nil {
			t.Fatal("unsafe credential configuration accepted")
		}
	}
	endpoint := InferenceEndpoint{Name: "model", URL: "https://models.test/"}
	if _, err := compileInferencePolicy(InferencePolicy{Endpoints: []InferenceEndpoint{endpoint, endpoint}}, network); err == nil {
		t.Fatal("duplicate alias accepted")
	}
}
