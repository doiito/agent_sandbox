package sandbox

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// LoadConfig performs strict decoding so production launcher and unprivileged
// API processes interpret exactly the same policy document.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Config{}, fmt.Errorf("decode %s: expected exactly one JSON object", path)
	}
	config.ApplyDefaults()
	return config, config.Validate()
}
