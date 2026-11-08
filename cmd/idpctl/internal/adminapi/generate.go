// Package adminapi holds the admin API types and HTTP client generated from
// contract/openapi/admin.json, the only contract between idpctl and the admin
// Worker. Nothing in adminapi.gen.go is edited by hand; regenerate it with
// go generate and let TestGeneratedCodeMatchesSpec catch drift.
package adminapi

//go:generate oapi-codegen -config oapi-codegen.yaml ../../../../contract/openapi/admin.json
