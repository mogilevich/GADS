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
	"GADS/hub/auth"
	"GADS/hub/config"
	"bytes"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func HandleRequests(uiFiles fs.FS) *gin.Engine {
	// Create the router and allow all origins
	// Allow particular headers as well
	r := gin.Default()

	// Add Swagger route
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	ginConfig := cors.DefaultConfig()
	ginConfig.AllowAllOrigins = true
	ginConfig.AllowHeaders = []string{"Authorization", "Content-Type"}
	r.Use(cors.New(ginConfig))

	// Handle UI serving only if we have UI files embedded
	if uiFiles != nil {
		uiFS, err := fs.Sub(uiFiles, "hub-ui/build")
		if err != nil {
			log.Fatalf("Failed to get UI files filesystem: %v", err)
		}

		r.Use(func(c *gin.Context) {
			path := c.Request.URL.Path

			// Skip UI serving for swagger routes
			if strings.HasPrefix(path, "/swagger/") {
				return
			}

			// For root path, serve index.html with SSO button injection if needed
			if path == "/" {
				serveIndexHTML(c, uiFS)
				return
			}

			_, err := uiFS.Open(strings.TrimPrefix(path, "/"))
			if err != nil {
				return
			}

			fileServer := http.FileServer(http.FS(uiFS))
			fileServer.ServeHTTP(c.Writer, c.Request)
			c.Abort()
		})

		r.NoRoute(func(c *gin.Context) {
			serveIndexHTML(c, uiFS)
		})
	}

	authGroup := r.Group("/")
	// Unauthenticated endpoints
	authGroup.POST("/authenticate", auth.LoginHandler)
	authGroup.GET("/available-devices", AvailableDevicesSSE)
	authGroup.GET("/reports/screenshots/:build_id/:session_id/:filename", GetScreenshot)
	authGroup.GET("/admin/provider/:nickname/info", ProviderInfoSSE)
	authGroup.GET("/devices/control/:udid/in-use", DeviceInUseWS)
	authGroup.POST("/provider-update", ProviderUpdate)
	// OAuth2 endpoints (unauthenticated)
	authGroup.POST("/oauth/token", OAuth2TokenEndpoint)
	// SSO/OIDC endpoints (unauthenticated)
	authGroup.GET("/auth/sso/login", auth.SSOLoginHandler)
	authGroup.GET("/auth/sso/callback", auth.SSOCallbackHandler)
	authGroup.GET("/auth/sso/status", GetSSOStatusHandler)
	// Enable authentication on the endpoints below
	if config.GlobalHubConfig.AuthEnabled {
		authGroup.Use(auth.AuthMiddleware())
	}
	authGroup.GET("/user-info", auth.GetUserInfoHandler)
	authGroup.GET("/appium-logs", GetAppiumLogs)
	authGroup.GET("/health", HealthCheck)
	authGroup.POST("/logout", auth.LogoutHandler)
	authGroup.Any("/device/:udid/*path", DeviceProxyHandler)
	authGroup.Any("/provider/:name/*path", ProviderProxyHandler)
	authGroup.GET("/admin/providers", GetProviders)
	authGroup.POST("/admin/providers/add", AddProvider)
	authGroup.POST("/admin/providers/update", UpdateProvider)
	authGroup.DELETE("/admin/providers/:nickname", DeleteProvider)
	authGroup.GET("/admin/providers/logs", GetProviderLogs)
	authGroup.POST("/admin/device", AddDevice)
	authGroup.PUT("/admin/device", UpdateDevice)
	authGroup.DELETE("/admin/device/:udid", DeleteDevice)
	authGroup.POST("/admin/device/:udid/release", ReleaseUsedDevice)
	authGroup.GET("/admin/devices", GetDevices)
	authGroup.POST("/admin/user", AddUser)
	authGroup.GET("/admin/users", GetUsers)
	authGroup.GET("/admin/files", GetFiles)
	authGroup.POST("/admin/download-github-file", DownloadResourceFromGithubRepo)
	authGroup.POST("/admin/upload-file", UploadFile)
	authGroup.PUT("/admin/user", UpdateUser)
	authGroup.DELETE("/admin/user/:nickname", DeleteUser)
	authGroup.GET("/admin/global-settings", GetGlobalStreamSettings)
	authGroup.POST("/admin/global-settings", UpdateGlobalStreamSettings)
	authGroup.GET("/admin/minio-config", GetMinioConfig)
	authGroup.POST("/admin/minio-config", UpdateMinioConfig)
	authGroup.GET("/admin/turn-config", GetTURNConfig)
	authGroup.POST("/admin/turn-config", UpdateTURNConfig)
	authGroup.GET("/ice-config", GetICEConfig)
	authGroup.GET("/admin/system-status", GetSystemStatus)
	authGroup.POST("/admin/workspaces", CreateWorkspace)
	authGroup.PUT("/admin/workspaces", UpdateWorkspace)
	authGroup.DELETE("/admin/workspaces/:id", DeleteWorkspace)
	authGroup.GET("/admin/workspaces", GetWorkspaces)
	authGroup.GET("/workspaces", GetUserWorkspaces)
	// OIDC configuration endpoints
	authGroup.GET("/admin/oidc-config", GetOIDCConfigHandler)
	authGroup.POST("/admin/oidc-config", UpdateOIDCConfigHandler)
	// Secret Keys endpoints
	authGroup.GET("/admin/secret-keys", GetSecretKeys)
	authGroup.POST("/admin/secret-keys", AddSecretKey)
	authGroup.PUT("/admin/secret-keys/:id", UpdateSecretKey)
	authGroup.DELETE("/admin/secret-keys/:id", DisableSecretKey)
	// Secret Keys Audit History endpoints
	authGroup.GET("/admin/secret-keys/history", GetSecretKeyHistory)
	authGroup.GET("/admin/secret-keys/history/:id", GetSecretKeyHistoryByID)
	// Client Credentials endpoints
	authGroup.POST("/client-credentials", CreateClientCredential)
	authGroup.GET("/client-credentials", ListClientCredentials)
	authGroup.GET("/client-credentials/:id", GetClientCredential)
	authGroup.PUT("/client-credentials/:id", UpdateClientCredential)
	authGroup.DELETE("/client-credentials/:id", RevokeClientCredential)
	// Custom Actions endpoints
	authGroup.GET("/custom-actions", GetCustomActions)
	authGroup.POST("/custom-actions", CreateCustomAction)
	authGroup.PUT("/custom-actions/:id", UpdateCustomAction)
	authGroup.DELETE("/custom-actions/:id", DeleteCustomAction)
	authGroup.GET("/custom-actions/favorites", GetUserFavorites)
	authGroup.POST("/custom-actions/favorites/:id", AddUserFavorite)
	authGroup.DELETE("/custom-actions/favorites/:id", RemoveUserFavorite)
	// Appium reports endpoints
	reportsGroup := authGroup.Group("/reports")
	reportsGroup.GET("/builds", GetBuildReports)
	reportsGroup.GET("/builds/:build_id/sessions", GetBuildSessions)
	reportsGroup.GET("/sessions/:session_id/logs", GetSessionLogs)

	appiumGroup := r.Group("/grid")
	appiumGroup.Use(AppiumGridMiddleware())
	appiumGroup.Any("/*path")

	return r
}

// serveIndexHTML reads index.html from the UI filesystem, injects SSO button if OIDC is enabled, and serves it
func serveIndexHTML(c *gin.Context, uiFS fs.FS) {
	indexFile, err := uiFS.Open("index.html")
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer indexFile.Close()

	htmlBytes, err := io.ReadAll(indexFile)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if auth.IsOIDCEnabled() {
		htmlBytes = injectSSOButton(htmlBytes)
	}

	c.Data(http.StatusOK, "text/html; charset=utf-8", htmlBytes)
	c.Abort()
}

// injectSSOButton injects a small script into index.html that adds an SSO login button
// to the login page. The button only appears when the user is not authenticated.
func injectSSOButton(html []byte) []byte {
	ssoScript := []byte(`<script>
(function() {
  // Only show SSO button if user is not logged in
  if (localStorage.getItem('accessToken')) return;

  // Wait for the page to render, then inject the SSO button
  var attempts = 0;
  var interval = setInterval(function() {
    attempts++;
    if (attempts > 50) { clearInterval(interval); return; }

    // Look for any form or login-related container
    var form = document.querySelector('form');
    var root = document.getElementById('root');
    if (!form && (!root || !root.innerHTML)) return;

    clearInterval(interval);

    // Create SSO button container
    var container = document.createElement('div');
    container.id = 'sso-login-container';
    container.style.cssText = 'text-align:center;margin-top:16px;';

    var divider = document.createElement('div');
    divider.style.cssText = 'color:#888;font-size:13px;margin-bottom:10px;font-family:sans-serif;';
    divider.textContent = '— or —';

    var btn = document.createElement('a');
    btn.href = '/auth/sso/login';
    btn.textContent = 'Login with SSO';
    btn.style.cssText = 'display:inline-block;padding:10px 28px;background:#1976d2;color:#fff;' +
      'border-radius:6px;text-decoration:none;font-family:sans-serif;font-size:14px;font-weight:500;' +
      'box-shadow:0 2px 8px rgba(0,0,0,0.15);transition:background 0.2s;';
    btn.onmouseover = function() { btn.style.background='#1565c0'; };
    btn.onmouseout = function() { btn.style.background='#1976d2'; };

    container.appendChild(divider);
    container.appendChild(btn);

    // Insert right after the login form instead of at the bottom of the page
    if (form) {
      form.parentNode.insertBefore(container, form.nextSibling);
    } else {
      document.body.appendChild(container);
    }

    // Remove SSO button if user becomes authenticated (SPA navigation)
    var observer = new MutationObserver(function() {
      if (localStorage.getItem('accessToken')) {
        var el = document.getElementById('sso-login-container');
        if (el) el.remove();
        observer.disconnect();
      }
    });
    observer.observe(root, { childList: true, subtree: true });
  }, 100);
})();
</script>`)

	return bytes.Replace(html, []byte("</body>"), append(ssoScript, []byte("</body>")...), 1)
}
