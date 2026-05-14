package admin

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"muvon/internal/db"
)

var rewritePatternValid = regexp.MustCompile(`^$|^[^\x00-\x1f]*$`)

func routeError(err error) string {
	s := err.Error()
	if strings.Contains(s, "duplicate") || strings.Contains(s, "unique") {
		return "A route with this path prefix already exists on this host"
	}
	if strings.Contains(s, "foreign key") || strings.Contains(s, "violates") {
		return "Referenced host or component does not exist"
	}
	return "Failed to save route"
}

func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	hostID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid host id"})
		return
	}

	routes, err := s.db.ListRoutesByHost(r.Context(), hostID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if routes == nil {
		routes = []db.Route{}
	}
	writeJSON(w, http.StatusOK, routes)
}

func (s *Server) handleCreateRoute(w http.ResponseWriter, r *http.Request) {
	hostID, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid host id"})
		return
	}

	var req db.Route
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.HostID = hostID

	if req.RouteType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "route_type is required"})
		return
	}
	if req.RouteType == "proxy" && req.ManagedComponentID == nil && (req.BackendURL == nil || *req.BackendURL == "") && len(req.BackendURLs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "backend_url, backend_urls, or managed_component_id is required for proxy routes"})
		return
	}
	if req.RouteType == "static" && (req.StaticRoot == nil || *req.StaticRoot == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "static_root is required for static routes"})
		return
	}
	if req.RouteType == "redirect" && (req.RedirectURL == nil || *req.RedirectURL == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "redirect_url is required for redirect routes"})
		return
	}
	if req.PathPrefix == "" {
		req.PathPrefix = "/"
	}
	if !strings.HasPrefix(req.PathPrefix, "/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path prefix must start with /"})
		return
	}
	if req.RewritePattern != nil && *req.RewritePattern != "" {
		if _, err := regexp.Compile(*req.RewritePattern); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rewrite_pattern is not a valid regular expression: " + err.Error()})
			return
		}
	}
	req.IsActive = true

	route, err := s.db.CreateRoute(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": routeError(err)})
		return
	}

	s.auditLog(r, "route.create", "route", strconv.Itoa(route.ID), map[string]any{"path_prefix": route.PathPrefix, "host_id": route.HostID})
	if err := s.triggerReload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "route created but config reload failed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, route)
}

func (s *Server) handleGetRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	route, err := s.db.GetRoute(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "route not found"})
		return
	}
	writeJSON(w, http.StatusOK, route)
}

func (s *Server) handleUpdateRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	var req db.Route
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.ID = id

	// Mevcut route'u al, eksik alanları doldur
	existing, err := s.db.GetRoute(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "route not found"})
		return
	}

	if req.HostID == 0 {
		req.HostID = existing.HostID
	}
	if req.PathPrefix == "" {
		req.PathPrefix = existing.PathPrefix
	}
	if !strings.HasPrefix(req.PathPrefix, "/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path prefix must start with /"})
		return
	}
	if req.RouteType == "" {
		req.RouteType = existing.RouteType
	}
	if req.RewritePattern != nil && *req.RewritePattern != "" {
		if _, err := regexp.Compile(*req.RewritePattern); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rewrite_pattern is not a valid regular expression: " + err.Error()})
			return
		}
	}

	route, err := s.db.UpdateRoute(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": routeError(err)})
		return
	}

	s.auditLog(r, "route.update", "route", strconv.Itoa(id), map[string]any{"path_prefix": route.PathPrefix})
	if err := s.triggerReload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "route updated but config reload failed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, route)
}

func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}

	if err := s.db.DeleteRoute(r.Context(), id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "route not found"})
		return
	}

	s.auditLog(r, "route.delete", "route", strconv.Itoa(id), nil)
	if err := s.triggerReload(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "route deleted but config reload failed: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
