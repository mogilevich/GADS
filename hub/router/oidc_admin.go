/*
 * This file is part of GADS.
 *
 * Copyright (c) 2022-2025 Nikola Shabanov
 *
 * This source code is licensed under the GNU Affero General Public License v3.0.
 * You may obtain a copy of the license at https://www.gnu.org/licenses/agpl-3.0.html
 */

package router

import (
	"GADS/common/db"
	"GADS/common/models"
	"GADS/hub/auth"
	"GADS/hub/config"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetOIDCConfigHandler godoc
// @Summary      Get OIDC configuration
// @Description  Returns the current OIDC/SSO configuration (client_secret is masked)
// @Tags         Admin - OIDC
// @Produce      json
// @Success      200  {object}  models.OIDCConfig
// @Failure      500  {object}  models.ErrorResponse
// @Security     BearerAuth
// @Router       /admin/oidc-config [get]
func GetOIDCConfigHandler(c *gin.Context) {
	oidcConfig, err := db.GlobalMongoStore.GetOIDCConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get OIDC configuration"})
		return
	}

	// Mask the client secret for display
	if oidcConfig.ClientSecret != "" {
		oidcConfig.ClientSecret = "***"
	}

	c.JSON(http.StatusOK, oidcConfig)
}

// UpdateOIDCConfigHandler godoc
// @Summary      Update OIDC configuration
// @Description  Updates the OIDC/SSO configuration and reinitializes the provider
// @Tags         Admin - OIDC
// @Accept       json
// @Produce      json
// @Param        config  body      models.OIDCConfig  true  "OIDC Configuration"
// @Success      200     {object}  models.SuccessResponse
// @Failure      400     {object}  models.ErrorResponse
// @Failure      500     {object}  models.ErrorResponse
// @Security     BearerAuth
// @Router       /admin/oidc-config [post]
func UpdateOIDCConfigHandler(c *gin.Context) {
	var newConfig models.OIDCConfig
	if err := c.ShouldBindJSON(&newConfig); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// If client_secret is masked, preserve the existing one
	if newConfig.ClientSecret == "***" {
		existingConfig, err := db.GlobalMongoStore.GetOIDCConfig()
		if err == nil {
			newConfig.ClientSecret = existingConfig.ClientSecret
		}
	}

	// Set default groups claim if empty
	if newConfig.GroupsClaim == "" {
		newConfig.GroupsClaim = "groups"
	}

	// Save to MongoDB
	err := db.GlobalMongoStore.UpdateOIDCConfig(newConfig)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save OIDC configuration"})
		return
	}

	// Reinitialize OIDC provider if enabled
	if newConfig.Enabled {
		err = auth.InitOIDC(newConfig)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Configuration saved but OIDC initialization failed: " + err.Error()})
			return
		}
		config.GlobalHubConfig.OIDCEnabled = true
	} else {
		config.GlobalHubConfig.OIDCEnabled = false
	}

	c.JSON(http.StatusOK, gin.H{"message": "OIDC configuration updated successfully"})
}

// GetSSOStatusHandler godoc
// @Summary      Get SSO status
// @Description  Returns whether SSO/OIDC is enabled and the login URL
// @Tags         Authentication
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Router       /auth/sso/status [get]
func GetSSOStatusHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"sso_enabled": auth.IsOIDCEnabled(),
		"login_url":   "/auth/sso/login",
	})
}
