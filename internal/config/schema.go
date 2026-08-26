package config

import (
	_ "embed"
)

//go:embed schema/keg.schema.json
var repoSchemaJSON []byte

//go:embed schema/config.schema.json
var userSchemaJSON []byte

// RepoSchemaJSON returns the raw JSON Schema bytes for .keg.yaml repository configuration.
func RepoSchemaJSON() []byte {
	return repoSchemaJSON
}

// UserSchemaJSON returns the raw JSON Schema bytes for config.yaml user configuration.
func UserSchemaJSON() []byte {
	return userSchemaJSON
}
