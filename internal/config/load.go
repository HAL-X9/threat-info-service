package config

import "fmt"

// Load reads the YAML file at path, overlays secrets from the environment and
// validates the result. On success the returned value is safe to use.
//
// getenv is supplied by the caller so that Load never touches process state.
func Load(path string, getenv func(string) string) (*Config, error) {
	cfg, err := readAndDecodeYAML(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load app configuration from YAML: %w", err)
	}

	cfg.Database.DSN = getenv(EnvDatabaseDSN)
	cfg.APIToken = getenv(EnvAPIToken)

	if err = Validate(cfg); err != nil {
		return nil, fmt.Errorf("failed to validate app configuration: %w", err)
	}

	return cfg, nil
}

func ResolvePath(flagValue string, getenv func(string) string) string {
	if flagValue != "" {
		return flagValue
	}

	if v := getenv(EnvConfigPath); v != "" {
		return v
	}

	return DefaultConfigPath
}
