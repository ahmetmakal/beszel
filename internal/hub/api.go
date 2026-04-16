package hub

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/blang/semver"
	"github.com/google/uuid"
	"github.com/henrygd/beszel"
	"github.com/henrygd/beszel/internal/alerts"
	"github.com/henrygd/beszel/internal/entities/packages"
	"github.com/henrygd/beszel/internal/ghupdate"
	"github.com/henrygd/beszel/internal/hub/config"
	"github.com/henrygd/beszel/internal/hub/systems"
	"github.com/henrygd/beszel/internal/hub/utils"
	"github.com/henrygd/beszel/internal/osv"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

// UpdateInfo holds information about the latest update check
type UpdateInfo struct {
	lastCheck time.Time
	Version   string `json:"v"`
	Url       string `json:"url"`
}

var containerIDPattern = regexp.MustCompile(`^[a-fA-F0-9]{12,64}$`)

// Middleware to allow only admin role users
var requireAdminRole = customAuthMiddleware(func(e *core.RequestEvent) bool {
	return e.Auth.GetString("role") == "admin"
})

// Middleware to exclude readonly users
var excludeReadOnlyRole = customAuthMiddleware(func(e *core.RequestEvent) bool {
	return e.Auth.GetString("role") != "readonly"
})

// customAuthMiddleware handles boilerplate for custom authentication middlewares. fn should
// return true if the request is allowed, false otherwise. e.Auth is guaranteed to be non-nil.
func customAuthMiddleware(fn func(*core.RequestEvent) bool) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		if e.Auth == nil {
			return e.UnauthorizedError("The request requires valid record authorization token.", nil)
		}
		if !fn(e) {
			return e.ForbiddenError("The authorized record is not allowed to perform this action.", nil)
		}
		return e.Next()
	}
}

// registerMiddlewares registers custom middlewares
func (h *Hub) registerMiddlewares(se *core.ServeEvent) {
	// authorizes request with user matching the provided email
	authorizeRequestWithEmail := func(e *core.RequestEvent, email string) (err error) {
		if e.Auth != nil || email == "" {
			return e.Next()
		}
		isAuthRefresh := e.Request.URL.Path == "/api/collections/users/auth-refresh" && e.Request.Method == http.MethodPost
		e.Auth, err = e.App.FindAuthRecordByEmail("users", email)
		if err != nil || !isAuthRefresh {
			return e.Next()
		}
		// auth refresh endpoint, make sure token is set in header
		token, _ := e.Auth.NewAuthToken()
		e.Request.Header.Set("Authorization", token)
		return e.Next()
	}
	// authenticate with trusted header
	if autoLogin, _ := utils.GetEnv("AUTO_LOGIN"); autoLogin != "" {
		se.Router.BindFunc(func(e *core.RequestEvent) error {
			return authorizeRequestWithEmail(e, autoLogin)
		})
	}
	// authenticate with trusted header
	if trustedHeader, _ := utils.GetEnv("TRUSTED_AUTH_HEADER"); trustedHeader != "" {
		se.Router.BindFunc(func(e *core.RequestEvent) error {
			return authorizeRequestWithEmail(e, e.Request.Header.Get(trustedHeader))
		})
	}
}

// registerApiRoutes registers custom API routes
func (h *Hub) registerApiRoutes(se *core.ServeEvent) error {
	// auth protected routes
	apiAuth := se.Router.Group("/api/beszel")
	apiAuth.Bind(apis.RequireAuth())
	// auth optional routes
	apiNoAuth := se.Router.Group("/api/beszel")

	// create first user endpoint only needed if no users exist
	if totalUsers, _ := se.App.CountRecords("users"); totalUsers == 0 {
		apiNoAuth.POST("/create-user", h.um.CreateFirstUser)
	}
	// check if first time setup on login page
	apiNoAuth.GET("/first-run", func(e *core.RequestEvent) error {
		total, err := e.App.CountRecords("users")
		return e.JSON(http.StatusOK, map[string]bool{"firstRun": err == nil && total == 0})
	})
	// get public key and version
	apiAuth.GET("/info", h.getInfo)
	apiAuth.GET("/getkey", h.getInfo) // deprecated - keep for compatibility w/ integrations
	// check for updates
	if optIn, _ := utils.GetEnv("CHECK_UPDATES"); optIn == "true" {
		var updateInfo UpdateInfo
		apiAuth.GET("/update", updateInfo.getUpdate)
	}
	// send test notification
	apiAuth.POST("/test-notification", h.SendTestNotification)
	// heartbeat status and test
	apiAuth.GET("/heartbeat-status", h.getHeartbeatStatus).BindFunc(requireAdminRole)
	apiAuth.POST("/test-heartbeat", h.testHeartbeat).BindFunc(requireAdminRole)
	// get config.yml content
	apiAuth.GET("/config-yaml", config.GetYamlConfig).BindFunc(requireAdminRole)
	// handle agent websocket connection
	apiNoAuth.GET("/agent-connect", h.handleAgentConnect)
	// get or create universal tokens
	apiAuth.GET("/universal-token", h.getUniversalToken).BindFunc(excludeReadOnlyRole)
	// update / delete user alerts
	apiAuth.POST("/user-alerts", alerts.UpsertUserAlerts)
	apiAuth.DELETE("/user-alerts", alerts.DeleteUserAlerts)
	// refresh SMART devices for a system
	apiAuth.POST("/smart/refresh", h.refreshSmartData).BindFunc(excludeReadOnlyRole)
	// get systemd service details
	apiAuth.GET("/systemd/info", h.getSystemdInfo)
	// get package info for all systemd services of a system
	apiAuth.GET("/systemd/packages", h.getSystemdPackages)
	// trigger vulnerability rescan for a system
	apiAuth.POST("/vulnerabilities/scan", h.triggerVulnScan).BindFunc(excludeReadOnlyRole)
	// /containers routes
	if enabled, _ := utils.GetEnv("CONTAINER_DETAILS"); enabled != "false" {
		// get container logs
		apiAuth.GET("/containers/logs", h.getContainerLogs)
		// get container info
		apiAuth.GET("/containers/info", h.getContainerInfo)
	}
	return nil
}

// getInfo returns data needed by authenticated users, such as the public key and current version
func (h *Hub) getInfo(e *core.RequestEvent) error {
	type infoResponse struct {
		Key         string `json:"key"`
		Version     string `json:"v"`
		CheckUpdate bool   `json:"cu"`
	}
	info := infoResponse{
		Key:     h.pubKey,
		Version: beszel.Version,
	}
	if optIn, _ := utils.GetEnv("CHECK_UPDATES"); optIn == "true" {
		info.CheckUpdate = true
	}
	return e.JSON(http.StatusOK, info)
}

// getUpdate checks for the latest release on GitHub and returns update info if a newer version is available
func (info *UpdateInfo) getUpdate(e *core.RequestEvent) error {
	if time.Since(info.lastCheck) < 6*time.Hour {
		return e.JSON(http.StatusOK, info)
	}
	info.lastCheck = time.Now()
	latestRelease, err := ghupdate.FetchLatestRelease(context.Background(), http.DefaultClient, "")
	if err != nil {
		return err
	}
	currentVersion, err := semver.Parse(strings.TrimPrefix(beszel.Version, "v"))
	if err != nil {
		return err
	}
	latestVersion, err := semver.Parse(strings.TrimPrefix(latestRelease.Tag, "v"))
	if err != nil {
		return err
	}
	if latestVersion.GT(currentVersion) {
		info.Version = strings.TrimPrefix(latestRelease.Tag, "v")
		info.Url = latestRelease.Url
	}
	return e.JSON(http.StatusOK, info)
}

// GetUniversalToken handles the universal token API endpoint (create, read, delete)
func (h *Hub) getUniversalToken(e *core.RequestEvent) error {
	if e.Auth.IsSuperuser() {
		return e.ForbiddenError("Superusers cannot use universal tokens", nil)
	}

	tokenMap := universalTokenMap.GetMap()
	userID := e.Auth.Id
	query := e.Request.URL.Query()
	token := query.Get("token")
	enable := query.Get("enable")
	permanent := query.Get("permanent")

	// helper for deleting any existing permanent token record for this user
	deletePermanent := func() error {
		rec, err := h.FindFirstRecordByFilter("universal_tokens", "user = {:user}", dbx.Params{"user": userID})
		if err != nil {
			return nil // no record
		}
		return h.Delete(rec)
	}

	// helper for upserting a permanent token record for this user
	upsertPermanent := func(token string) error {
		rec, err := h.FindFirstRecordByFilter("universal_tokens", "user = {:user}", dbx.Params{"user": userID})
		if err == nil {
			rec.Set("token", token)
			return h.Save(rec)
		}

		col, err := h.FindCachedCollectionByNameOrId("universal_tokens")
		if err != nil {
			return err
		}
		newRec := core.NewRecord(col)
		newRec.Set("user", userID)
		newRec.Set("token", token)
		return h.Save(newRec)
	}

	// Disable universal tokens (both ephemeral and permanent)
	if enable == "0" {
		tokenMap.RemovebyValue(userID)
		_ = deletePermanent()
		return e.JSON(http.StatusOK, map[string]any{"token": token, "active": false, "permanent": false})
	}

	// Enable universal token (ephemeral or permanent)
	if enable == "1" {
		if token == "" {
			token = uuid.New().String()
		}

		if permanent == "1" {
			// make token permanent (persist across restarts)
			tokenMap.RemovebyValue(userID)
			if err := upsertPermanent(token); err != nil {
				return err
			}
			return e.JSON(http.StatusOK, map[string]any{"token": token, "active": true, "permanent": true})
		}

		// default: ephemeral mode (1 hour)
		_ = deletePermanent()
		tokenMap.Set(token, userID, time.Hour)
		return e.JSON(http.StatusOK, map[string]any{"token": token, "active": true, "permanent": false})
	}

	// Read current state
	// Prefer permanent token if it exists.
	if rec, err := h.FindFirstRecordByFilter("universal_tokens", "user = {:user}", dbx.Params{"user": userID}); err == nil {
		dbToken := rec.GetString("token")
		// If no token was provided, or the caller is asking about their permanent token, return it.
		if token == "" || token == dbToken {
			return e.JSON(http.StatusOK, map[string]any{"token": dbToken, "active": true, "permanent": true})
		}
		// Token doesn't match their permanent token (avoid leaking other info)
		return e.JSON(http.StatusOK, map[string]any{"token": token, "active": false, "permanent": false})
	}

	// No permanent token; fall back to ephemeral token map.
	if token == "" {
		// return existing token if it exists
		if token, _, ok := tokenMap.GetByValue(userID); ok {
			return e.JSON(http.StatusOK, map[string]any{"token": token, "active": true, "permanent": false})
		}
		// if no token is provided, generate a new one
		token = uuid.New().String()
	}

	// Token is considered active only if it belongs to the current user.
	activeUser, ok := tokenMap.GetOk(token)
	active := ok && activeUser == userID
	response := map[string]any{"token": token, "active": active, "permanent": false}
	return e.JSON(http.StatusOK, response)
}

// getHeartbeatStatus returns current heartbeat configuration and whether it's enabled
func (h *Hub) getHeartbeatStatus(e *core.RequestEvent) error {
	if h.hb == nil {
		return e.JSON(http.StatusOK, map[string]any{
			"enabled": false,
			"msg":     "Set HEARTBEAT_URL to enable outbound heartbeat monitoring",
		})
	}
	cfg := h.hb.GetConfig()
	return e.JSON(http.StatusOK, map[string]any{
		"enabled":  true,
		"url":      cfg.URL,
		"interval": cfg.Interval,
		"method":   cfg.Method,
	})
}

// testHeartbeat triggers a single heartbeat ping and returns the result
func (h *Hub) testHeartbeat(e *core.RequestEvent) error {
	if h.hb == nil {
		return e.JSON(http.StatusOK, map[string]any{
			"err": "Heartbeat not configured. Set HEARTBEAT_URL environment variable.",
		})
	}
	if err := h.hb.Send(); err != nil {
		return e.JSON(http.StatusOK, map[string]any{"err": err.Error()})
	}
	return e.JSON(http.StatusOK, map[string]any{"err": false})
}

// containerRequestHandler handles both container logs and info requests
func (h *Hub) containerRequestHandler(e *core.RequestEvent, fetchFunc func(*systems.System, string) (string, error), responseKey string) error {
	systemID := e.Request.URL.Query().Get("system")
	containerID := e.Request.URL.Query().Get("container")

	if systemID == "" || containerID == "" || !containerIDPattern.MatchString(containerID) {
		return e.BadRequestError("Invalid system or container parameter", nil)
	}

	system, err := h.sm.GetSystem(systemID)
	if err != nil || !system.HasUser(e.App, e.Auth) {
		return e.NotFoundError("", nil)
	}

	data, err := fetchFunc(system, containerID)
	if err != nil {
		return e.InternalServerError("", err)
	}

	return e.JSON(http.StatusOK, map[string]string{responseKey: data})
}

// getContainerLogs handles GET /api/beszel/containers/logs requests
func (h *Hub) getContainerLogs(e *core.RequestEvent) error {
	return h.containerRequestHandler(e, func(system *systems.System, containerID string) (string, error) {
		return system.FetchContainerLogsFromAgent(containerID)
	}, "logs")
}

func (h *Hub) getContainerInfo(e *core.RequestEvent) error {
	return h.containerRequestHandler(e, func(system *systems.System, containerID string) (string, error) {
		return system.FetchContainerInfoFromAgent(containerID)
	}, "info")
}

// getSystemdInfo handles GET /api/beszel/systemd/info requests
func (h *Hub) getSystemdInfo(e *core.RequestEvent) error {
	query := e.Request.URL.Query()
	systemID := query.Get("system")
	serviceName := query.Get("service")

	if systemID == "" || serviceName == "" {
		return e.BadRequestError("Invalid system or service parameter", nil)
	}
	sys, err := h.sm.GetSystem(systemID)
	if err != nil || !sys.HasUser(e.App, e.Auth) {
		return e.NotFoundError("", nil)
	}
	// verify service exists before fetching details
	_, err = e.App.FindFirstRecordByFilter("systemd_services", "system = {:system} && name = {:name}", dbx.Params{
		"system": systemID,
		"name":   serviceName,
	})
	if err != nil {
		return e.NotFoundError("", err)
	}
	details, err := sys.FetchSystemdInfoFromAgent(serviceName)
	if err != nil {
		return e.InternalServerError("", err)
	}

	// Fetch package info for this service
	pkgInfo := h.getServicePackageInfo(e.App, systemID, serviceName)

	result := map[string]any{
		"details": details,
		"pkg":     pkgInfo,
	}

	// Fetch vulnerability info for this service
	if vulnData, err := osv.GetVulnData(e.App, systemID); err == nil && vulnData != nil {
		result["vulnScannedAt"] = vulnData.ScannedAt
		if svcVuln, ok := vulnData.Services[serviceName]; ok {
			result["vuln"] = svcVuln
		}
	}

	e.Response.Header().Set("Cache-Control", "public, max-age=60")
	return e.JSON(http.StatusOK, result)
}

// getServicePackageInfo looks up package info for a single service.
func (h *Hub) getServicePackageInfo(app core.App, systemID, serviceName string) *packages.PackageInfo {
	var row struct {
		PackagesRaw string `db:"packages"`
	}
	err := app.DB().
		Select("packages").
		From("system_details").
		Where(dbx.HashExp{"id": systemID}).
		One(&row)
	if err != nil || row.PackagesRaw == "" {
		return nil
	}

	var pkgs []*packages.PackageInfo
	if err := json.Unmarshal([]byte(row.PackagesRaw), &pkgs); err != nil {
		return nil
	}
	for _, p := range pkgs {
		if p.Service == serviceName {
			return p
		}
	}
	return nil
}

// getSystemdPackages handles GET /api/beszel/systemd/packages requests.
// Returns a map of service name → {pkgName, version} and vulnerability scan data.
func (h *Hub) getSystemdPackages(e *core.RequestEvent) error {
	systemID := e.Request.URL.Query().Get("system")
	if systemID == "" {
		return e.BadRequestError("Invalid system parameter", nil)
	}
	sys, err := h.sm.GetSystem(systemID)
	if err != nil || !sys.HasUser(e.App, e.Auth) {
		return e.NotFoundError("", nil)
	}

	var row struct {
		PackagesRaw string `db:"packages"`
		VulnsRaw    string `db:"vulns"`
	}
	if err := e.App.DB().
		Select("packages", "vulns").
		From("system_details").
		Where(dbx.HashExp{"id": systemID}).
		One(&row); err != nil {
		return e.JSON(http.StatusOK, map[string]any{"services": map[string]any{}})
	}

	var pkgs []*packages.PackageInfo
	if row.PackagesRaw != "" {
		_ = json.Unmarshal([]byte(row.PackagesRaw), &pkgs)
	}

	type svcPkgInfo struct {
		PkgName string `json:"pkgName"`
		Version string `json:"version"`
	}
	services := make(map[string]svcPkgInfo, len(pkgs))
	for _, p := range pkgs {
		services[p.Service] = svcPkgInfo{PkgName: p.Package, Version: p.Version}
	}

	result := map[string]any{"services": services}

	if row.VulnsRaw != "" {
		var vulnData osv.VulnScanData
		if err := json.Unmarshal([]byte(row.VulnsRaw), &vulnData); err == nil {
			result["vulns"] = vulnData
		}
	}

	e.Response.Header().Set("Cache-Control", "public, max-age=120")
	return e.JSON(http.StatusOK, result)
}

// triggerVulnScan handles POST /api/beszel/vulnerabilities/scan requests.
// Runs an OSV vulnerability scan for a single system (or all systems if no system param).
func (h *Hub) triggerVulnScan(e *core.RequestEvent) error {
	systemID := e.Request.URL.Query().Get("system")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		var err error
		if systemID != "" {
			err = h.vulnScanner.ScanSystem(ctx, systemID)
		} else {
			err = h.vulnScanner.ScanAllSystems(ctx)
		}
		if err != nil {
			h.Logger().Error("Manual vulnerability scan failed", "err", err)
			return
		}
		h.HandleVulnerabilityAlerts()
	}()
	return e.JSON(http.StatusOK, map[string]string{"status": "started"})
}

// refreshSmartData handles POST /api/beszel/smart/refresh requests
// Fetches fresh SMART data from the agent and updates the collection
func (h *Hub) refreshSmartData(e *core.RequestEvent) error {
	systemID := e.Request.URL.Query().Get("system")
	if systemID == "" {
		return e.BadRequestError("Invalid system parameter", nil)
	}

	system, err := h.sm.GetSystem(systemID)
	if err != nil || !system.HasUser(e.App, e.Auth) {
		return e.NotFoundError("", nil)
	}

	if err := system.FetchAndSaveSmartDevices(); err != nil {
		return e.InternalServerError("", err)
	}

	return e.JSON(http.StatusOK, map[string]string{"status": "ok"})
}
