/*
 * This file is part of GADS.
 *
 * Copyright (c) 2022-2025 Nikola Shabanov
 *
 * This source code is licensed under the GNU Affero General Public License v3.0.
 * You may obtain a copy of the license at https://www.gnu.org/licenses/agpl-3.0.html
 */

package models

// OIDCConfig holds the configuration for OpenID Connect (Keycloak) integration
type OIDCConfig struct {
	Enabled      bool   `json:"enabled" bson:"enabled"`
	IssuerURL    string `json:"issuer_url" bson:"issuer_url"`       // e.g. https://sso.example.dev/realms/SSO
	ClientID     string `json:"client_id" bson:"client_id"`         // OIDC client ID
	ClientSecret string `json:"client_secret" bson:"client_secret"` // OIDC client secret
	RedirectURI  string `json:"redirect_uri" bson:"redirect_uri"`   // e.g. http://hub:10000/auth/sso/callback
	AdminGroup   string `json:"admin_group" bson:"admin_group"`     // Keycloak group name for admin role
	GroupsClaim  string `json:"groups_claim" bson:"groups_claim"`   // JWT claim containing groups, default "groups"
}
