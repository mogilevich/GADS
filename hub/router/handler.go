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
	"fmt"
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
	var uiFS fs.FS
	if uiFiles != nil {
		subFS, err := fs.Sub(uiFiles, "hub-ui/build")
		if err != nil {
			log.Fatalf("Failed to get UI files filesystem: %v", err)
		}
		uiFS = subFS

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
	}

	r.NoRoute(func(c *gin.Context) {
		// Unmatched /grid/* paths must get a W3C error response, not the UI fallback page
		if strings.HasPrefix(c.Request.URL.Path, "/grid/") {
			writeW3CError(c, w3cUnknownCommand(fmt.Sprintf("Unknown grid endpoint `%s`", c.Request.URL.Path)))
			return
		}

		if uiFS == nil {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		serveIndexHTML(c, uiFS)
	})

	authGroup := r.Group("/")
	// Unauthenticated endpoints
	authGroup.POST("/authenticate", auth.LoginHandler)
	authGroup.GET("/available-devices", AvailableDevicesSSE)
	authGroup.GET("/admin/provider/:nickname/info", ProviderInfoSSE)
	authGroup.GET("/devices/control/:udid/in-use", DeviceInUseWS)
	authGroup.POST("/devices/control/:udid/lock", LockDevice)
	authGroup.POST("/devices/control/:udid/unlock", UnlockDevice)
	authGroup.POST("/devices/control/:udid/release", ReleaseDevice)
	authGroup.POST("/provider-update", ProviderUpdate)
	// OAuth2 endpoints (unauthenticated)
	authGroup.POST("/oauth/token", OAuth2TokenEndpoint)
	// SSO endpoints (unauthenticated)
	authGroup.GET("/auth/sso/login", auth.SSOLoginHandler)
	authGroup.GET("/auth/sso/callback", auth.SSOCallbackHandler)
	authGroup.GET("/auth/sso/status", auth.SSOStatusHandler)
	// Enable authentication on the endpoints below
	if config.GlobalHubConfig.AuthEnabled {
		authGroup.Use(auth.AuthMiddleware())
	}
	authGroup.GET("/user-info", auth.GetUserInfoHandler)
	authGroup.GET("/appium-logs", GetAppiumLogs)
	authGroup.GET("/automation-sessions", GetAutomationSessions)
	authGroup.GET("/health", HealthCheck)
	authGroup.POST("/logout", auth.LogoutHandler)
	authGroup.POST("/change-password", auth.ChangePasswordHandler)
	authGroup.GET("/devices/control/:udid/adb-tunnel", ADBTunnelHandler)
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
	authGroup.GET("/admin/devices", GetDevices)
	authGroup.POST("/admin/user", AddUser)
	authGroup.GET("/admin/users", GetUsers)
	authGroup.GET("/admin/files", GetFiles)
	authGroup.POST("/admin/files/webdriveragent", UploadWebDriverAgentFile)
	authGroup.POST("/admin/files/webdriveragent/sign", SignAndUploadWebDriverAgentFile)
	authGroup.POST("/admin/files/broadcast", UploadBroadcastFile)
	authGroup.POST("/admin/files/broadcast/sign", SignAndUploadBroadcastFile)
	authGroup.POST("/admin/files/supervision", UploadSupervisionProfile)
	authGroup.POST("/admin/files/csr", GenerateCSR)
	authGroup.DELETE("/admin/files/:id", DeleteFile)
	// Uploaded device apps (available to all authenticated users, installed via device control)
	authGroup.GET("/apps", GetApps)
	authGroup.POST("/apps", UploadApp)
	authGroup.DELETE("/apps/:id", DeleteApp)
	authGroup.PUT("/admin/user", UpdateUser)
	authGroup.DELETE("/admin/user/:nickname", DeleteUser)
	authGroup.DELETE("/admin/user/:nickname/sessions", DeleteUserSessions)
	authGroup.GET("/admin/global-settings", GetGlobalStreamSettings)
	authGroup.POST("/admin/global-settings", UpdateGlobalStreamSettings)
	authGroup.GET("/admin/minio-config", GetMinioConfig)
	authGroup.POST("/admin/minio-config", UpdateMinioConfig)
	authGroup.GET("/admin/oidc-config", GetOIDCConfig)
	authGroup.POST("/admin/oidc-config", UpdateOIDCConfig)
	authGroup.GET("/admin/turn-config", GetTURNConfig)
	authGroup.POST("/admin/turn-config", UpdateTURNConfig)
	authGroup.GET("/ice-config", GetICEConfig)
	authGroup.GET("/admin/system-status", GetSystemStatus)
	authGroup.POST("/admin/workspaces", CreateWorkspace)
	authGroup.PUT("/admin/workspaces", UpdateWorkspace)
	authGroup.DELETE("/admin/workspaces/:id", DeleteWorkspace)
	authGroup.GET("/admin/workspaces", GetWorkspaces)
	authGroup.GET("/workspaces", GetUserWorkspaces)
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

	registerGridRoutes(r.Group("/grid"))

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
		htmlBytes = injectCopyTokenButton(htmlBytes)
	}

	c.Data(http.StatusOK, "text/html; charset=utf-8", htmlBytes)
	c.Abort()
}

// injectSSOButton injects a small script into index.html that adds an SSO login button
// to the login page. The button only appears when the user is not authenticated.
func injectSSOButton(html []byte) []byte {
	ssoScript := []byte(`<script>
(function() {
  // Keep the SSO button next to the login form while the user is signed out. The UI
  // can sign out without reloading the page (a 401 after a hub restart or an idle
  // session), so the button follows the page instead of being placed once on load.
  function render() {
    var el = document.getElementById('sso-login-container');
    var form = document.querySelector('form');
    if (localStorage.getItem('accessToken') || !form) {
      if (el) el.remove();
      return;
    }
    if (el) return;

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
    form.parentNode.insertBefore(container, form.nextSibling);
  }

  // The device list re-renders constantly, so handle at most one batch of changes per frame
  var scheduled = false;
  new MutationObserver(function() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(function() { scheduled = false; render(); });
  }).observe(document.body, { childList: true, subtree: true });
  render();
})();
</script>`)

	return bytes.Replace(html, []byte("</body>"), append(ssoScript, []byte("</body>")...), 1)
}

// injectCopyTokenButton injects a floating button for ADB tunnel CLI.
// On device control pages (/devices/control/<udid>) it copies the full pre-filled
// adb-tunnel command. On other pages it copies just the access token.
func injectCopyTokenButton(html []byte) []byte {
	script := []byte(`<script>
(function() {
  var btnStyle = 'position:fixed;bottom:16px;right:16px;z-index:9999;padding:8px 14px;' +
    'background:#2e7d32;color:#fff;border:none;border-radius:6px;cursor:pointer;' +
    'font-family:sans-serif;font-size:13px;font-weight:500;box-shadow:0 2px 8px rgba(0,0,0,0.2);' +
    'transition:background 0.2s,transform 0.1s;';

  function copyToClipboard(text, btn, label) {
    navigator.clipboard.writeText(text).then(function() {
      btn.textContent = '\u2705 Copied!';
      btn.style.transform = 'scale(1.05)';
      setTimeout(function() { btn.textContent = label; btn.style.transform = 'scale(1)'; }, 1500);
    }).catch(function() {
      var ta = document.createElement('textarea');
      ta.value = text; ta.style.cssText = 'position:fixed;left:-9999px';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy');
      document.body.removeChild(ta);
      btn.textContent = '\u2705 Copied!';
      setTimeout(function() { btn.textContent = label; }, 1500);
    });
  }

  function getUdidFromUrl() {
    var m = window.location.pathname.match(/\/devices\/control\/([^/]+)/);
    return m ? m[1] : null;
  }

  function renderButton() {
    var old = document.getElementById('gads-adb-btn');
    if (old) old.remove();

    var token = localStorage.getItem('accessToken');
    if (!token) return;

    var udid = getUdidFromUrl();
    var btn = document.createElement('button');
    btn.id = 'gads-adb-btn';
    btn.style.cssText = btnStyle;
    btn.onmouseover = function() { btn.style.background='#1b5e20'; };
    btn.onmouseout = function() { btn.style.background='#2e7d32'; };

    if (udid) {
      var label = '\u{1F4CB} adb-tunnel';
      btn.textContent = label;
      btn.title = 'Copy full adb-tunnel command to clipboard';
      btn.onclick = function() {
        var cmd = 'GADS adb-tunnel --hub=' + window.location.origin +
          ' --udid=' + udid + ' --token=' + localStorage.getItem('accessToken');
        copyToClipboard(cmd, btn, label);
      };
    } else {
      var label = '\u{1F4CB} ADB Token';
      btn.textContent = label;
      btn.title = 'Copy access token for adb-tunnel CLI';
      btn.onclick = function() {
        copyToClipboard(localStorage.getItem('accessToken'), btn, label);
      };
    }

    document.body.appendChild(btn);
  }

  // Re-render on SPA navigation and on sign-in / sign-out, which can both happen
  // without a page reload
  var renderedFor;
  function sync() {
    var state = localStorage.getItem('accessToken') ? window.location.pathname : null;
    if (state === renderedFor && (state === null || document.getElementById('gads-adb-btn'))) return;
    renderedFor = state;
    renderButton();
  }

  var scheduled = false;
  new MutationObserver(function() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(function() { scheduled = false; sync(); });
  }).observe(document.body, { childList: true, subtree: true });
  sync();
})();
</script>`)

	return bytes.Replace(html, []byte("</body>"), append(script, []byte("</body>")...), 1)
}
