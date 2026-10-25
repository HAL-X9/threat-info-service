package config

const (
	// EnvConfigPath names the environment variable holding the path to the YAML config file.
	EnvConfigPath = "THREAT_INFO_CONFIG_PATH"
	// EnvDatabaseDSN names the environment variable holding the database DSN.
	EnvDatabaseDSN = "THREAT_INFO_DATABASE_DSN"
	// EnvAPIToken names the environment variable holding the token that authorizes writes.
	EnvAPIToken = "THREAT_INFO_API_TOKEN"
	// DefaultConfigPath is used when neither the -config flag nor EnvConfigPath is set.
	DefaultConfigPath = "configs/config.yaml"
)
