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
	"GADS/common/db"
	"GADS/common/models"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// SSOLoginHandler initiates the OIDC authorization code flow
// @Summary      SSO Login
// @Description  Redirects the user to the Keycloak login page
// @Tags         Authentication
// @Success      302  "Redirect to Keycloak"
// @Failure      404  {object}  models.ErrorResponse
// @Router       /auth/sso/login [get]
func SSOLoginHandler(c *gin.Context) {
	if !IsOIDCEnabled() {
		c.JSON(http.StatusNotFound, gin.H{"error": "SSO is not configured"})
		return
	}

	state, err := generateRandomState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}

	// Store state in an HTTP-only cookie for CSRF protection (5 min TTL)
	c.SetCookie("oidc_state", state, 300, "/", "", false, true)

	url := GetOAuth2Config().AuthCodeURL(state)
	c.Redirect(http.StatusFound, url)
}

// SSOCallbackHandler handles the OIDC callback after Keycloak authentication
// @Summary      SSO Callback
// @Description  Handles the OIDC callback, provisions user, and redirects to the UI
// @Tags         Authentication
// @Param        code   query  string  true  "Authorization code"
// @Param        state  query  string  true  "State parameter"
// @Success      200    "HTML page that sets localStorage and redirects"
// @Failure      400    {string}  string  "Invalid state"
// @Failure      401    {string}  string  "Token verification failed"
// @Failure      500    {string}  string  "Internal error"
// @Router       /auth/sso/callback [get]
func SSOCallbackHandler(c *gin.Context) {
	if !IsOIDCEnabled() {
		c.JSON(http.StatusNotFound, gin.H{"error": "SSO is not configured"})
		return
	}

	// Validate state parameter against cookie
	state := c.Query("state")
	cookieState, err := c.Cookie("oidc_state")
	if err != nil || state == "" || state != cookieState {
		c.String(http.StatusBadRequest, "Invalid state parameter")
		return
	}

	// Clear the state cookie
	c.SetCookie("oidc_state", "", -1, "/", "", false, true)

	// Handle error responses from Keycloak
	if errParam := c.Query("error"); errParam != "" {
		errDesc := c.Query("error_description")
		c.String(http.StatusUnauthorized, "Authentication failed: %s - %s", errParam, errDesc)
		return
	}

	// Exchange authorization code for tokens
	code := c.Query("code")
	if code == "" {
		c.String(http.StatusBadRequest, "Missing authorization code")
		return
	}

	oauth2Token, err := GetOAuth2Config().Exchange(c.Request.Context(), code)
	if err != nil {
		c.String(http.StatusInternalServerError, "Token exchange failed: %v", err)
		return
	}

	// Extract and verify ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		c.String(http.StatusInternalServerError, "No ID token in response")
		return
	}

	idToken, err := VerifyIDToken(c.Request.Context(), rawIDToken)
	if err != nil {
		c.String(http.StatusUnauthorized, "ID token verification failed: %v", err)
		return
	}

	// Extract user info from ID token
	username, role, _, err := ExtractUserFromIDToken(idToken)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to extract user info: %v", err)
		return
	}

	// JIT user provisioning
	err = provisionSSOUser(username, role)
	if err != nil {
		c.String(http.StatusInternalServerError, "User provisioning failed: %v", err)
		return
	}

	// Generate GADS JWT (same as local login)
	scopes := []string{"user"}
	if role == "admin" {
		scopes = append(scopes, "admin")
	}

	defaultTenant, err := db.GlobalMongoStore.GetOrCreateDefaultTenant()
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to get default tenant")
		return
	}

	origin := GetOriginFromRequest(c)
	token, err := GenerateJWT(username, role, defaultTenant, scopes, time.Hour, origin)
	if err != nil {
		c.String(http.StatusInternalServerError, "Token generation failed")
		return
	}

	// Serve HTML page that sets localStorage and redirects to the UI
	serveCallbackHTML(c, token, username, role)
}

// provisionSSOUser creates or updates a user in MongoDB based on SSO login
func provisionSSOUser(username, role string) error {
	existingUser, err := db.GlobalMongoStore.GetUser(username)
	if err == nil && existingUser.Username != "" {
		// User exists — update role only for SSO-provisioned users (password starts with __SSO__)
		if strings.HasPrefix(existingUser.Password, "__SSO__") && existingUser.Role != role {
			existingUser.Role = role
			existingUser.ID = "" // Clear _id so omitempty excludes it from $set (MongoDB _id is immutable)
			return db.GlobalMongoStore.AddOrUpdateUser(existingUser)
		}
		return nil
	}

	// Create new SSO user with a random password they can't use for local login
	randomPassword, err := generateRandomKey(32)
	if err != nil {
		return fmt.Errorf("failed to generate random password: %w", err)
	}

	defaultWorkspace, err := db.GlobalMongoStore.GetDefaultWorkspace()
	if err != nil {
		return fmt.Errorf("failed to get default workspace: %w", err)
	}

	newUser := models.User{
		Username:     username,
		Password:     "__SSO__" + randomPassword,
		Role:         role,
		WorkspaceIDs: []string{defaultWorkspace.ID},
	}

	return db.GlobalMongoStore.AddOrUpdateUser(newUser)
}

// serveCallbackHTML renders an HTML page that stores auth data in localStorage and redirects
func serveCallbackHTML(c *gin.Context, token, username, role string) {
	// Use template.JSEscapeString to prevent XSS
	safeToken := template.JSEscapeString(token)
	safeUsername := template.JSEscapeString(username)
	safeRole := template.JSEscapeString(role)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>SSO Login</title></head>
<body>
<p>Logging in...</p>
<script>
try {
  localStorage.setItem('accessToken', '%s');
  localStorage.setItem('username', '%s');
  localStorage.setItem('userRole', '%s');
  window.location.replace('/');
} catch (e) {
  document.body.innerHTML = '<p>Login failed: ' + e.message + '</p><p><a href="/">Go to home</a></p>';
}
</script>
<noscript>
<p>JavaScript is required. <a href="/">Click here</a> to continue.</p>
</noscript>
</body>
</html>`, safeToken, safeUsername, safeRole)

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

// generateRandomState generates a cryptographically secure random state string
func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// generateRandomKey is defined in secretcache.go and reused here for SSO password generation
