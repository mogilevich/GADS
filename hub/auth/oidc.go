/*
 * This file is part of GADS.
 *
 * Copyright (c) 2022-2025 Nikola Shabanov
 *
 * This source code is licensed under the GNU Affero General Public License v3.0.
 * You may obtain a copy of the license at https://www.gnu.org/licenses/agpl-3.0.html
 */

package auth

import (
	"GADS/common/models"
	"context"
	"fmt"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	oidcProvider    *oidc.Provider
	oauth2Conf      *oauth2.Config
	oidcVerifier    *oidc.IDTokenVerifier
	oidcConf        *models.OIDCConfig
	oidcMu          sync.RWMutex
	oidcInitialized bool
)

// OIDCClaims represents the claims extracted from a Keycloak ID token
type OIDCClaims struct {
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
}

// InitOIDC initializes the OIDC provider and OAuth2 configuration
func InitOIDC(config models.OIDCConfig) error {
	oidcMu.Lock()
	defer oidcMu.Unlock()

	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	oauthConfig := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	oidcProvider = provider
	oauth2Conf = oauthConfig
	oidcVerifier = verifier
	oidcConf = &config
	oidcInitialized = true

	return nil
}

// IsOIDCEnabled returns whether OIDC authentication is configured and available
func IsOIDCEnabled() bool {
	oidcMu.RLock()
	defer oidcMu.RUnlock()
	return oidcInitialized
}

// GetOAuth2Config returns the OAuth2 configuration for the authorization code flow
func GetOAuth2Config() *oauth2.Config {
	oidcMu.RLock()
	defer oidcMu.RUnlock()
	return oauth2Conf
}

// GetOIDCConfig returns the current OIDC configuration
func GetOIDCConfig() *models.OIDCConfig {
	oidcMu.RLock()
	defer oidcMu.RUnlock()
	return oidcConf
}

// VerifyIDToken verifies a raw ID token string and returns the parsed token
func VerifyIDToken(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	oidcMu.RLock()
	verifier := oidcVerifier
	oidcMu.RUnlock()

	if verifier == nil {
		return nil, fmt.Errorf("OIDC verifier is not initialized")
	}

	return verifier.Verify(ctx, rawIDToken)
}

// ExtractUserFromIDToken extracts username and role from a verified ID token
func ExtractUserFromIDToken(idToken *oidc.IDToken) (username string, role string, groups []string, err error) {
	var claims OIDCClaims

	// Use the groups claim from config, default to "groups"
	groupsClaim := "groups"
	if oidcConf != nil && oidcConf.GroupsClaim != "" {
		groupsClaim = oidcConf.GroupsClaim
	}

	// Parse claims into a generic map first to handle dynamic groups claim
	var rawClaims map[string]interface{}
	if err := idToken.Claims(&rawClaims); err != nil {
		return "", "", nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Extract standard claims
	if err := idToken.Claims(&claims); err != nil {
		return "", "", nil, fmt.Errorf("failed to parse standard claims: %w", err)
	}

	// Extract groups from the configured claim
	if groupsRaw, ok := rawClaims[groupsClaim]; ok {
		if groupsList, ok := groupsRaw.([]interface{}); ok {
			for _, g := range groupsList {
				if gs, ok := g.(string); ok {
					claims.Groups = append(claims.Groups, gs)
				}
			}
		}
	}

	// Determine username: prefer preferred_username, fallback to email
	username = claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		return "", "", nil, fmt.Errorf("no username found in ID token claims")
	}

	// Determine role based on group membership
	role = "user"
	if oidcConf != nil && oidcConf.AdminGroup != "" {
		for _, g := range claims.Groups {
			if g == oidcConf.AdminGroup {
				role = "admin"
				break
			}
		}
	}

	return username, role, claims.Groups, nil
}
