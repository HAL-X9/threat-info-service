package config

const (
	// EnvConfigPath names the environment variable holding the path to the YAML config file.
	EnvConfigPath = "THREAT_INFO_CONFIG_PATH"
	// EnvDatabaseDSN names the environment variable holding the database DSN.
	EnvDatabaseDSN = "THREAT_INFO_DATABASE_DSN"
	// EnvAPIToken names the environment variable holding the token that authorizes writes.
	EnvAPIToken = "THREAT_INFO_API_TOKEN"
	// EnvTLSCertFile and EnvTLSKeyFile name the variables that override the TLS files of the YAML file.
	EnvTLSCertFile = "THREAT_INFO_TLS_CERT_FILE"
	EnvTLSKeyFile  = "THREAT_INFO_TLS_KEY_FILE"
	// DefaultConfigPath is used when neither the -config flag nor EnvConfigPath is set.
	DefaultConfigPath = "configs/config.yaml"
)
