package admin

import (
	"encoding/json"
	"net/http"
	"strconv"

	"muvon/internal/db"
)

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
	if req.RouteType == "proxy" && (req.BackendURL == nil || *req.BackendURL == "") && len(req.BackendURLs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "backend_url or backend_urls is required for proxy routes"})
		return
	}
	if req.PathPrefix == "" {
		req.PathPrefix = "/"
	}
	req.IsActive = true
	// log_enabled: UI her zaman gönderir; JSON decode doğrudan req.LogEnabled'ı doldurur.

	route, err := s.db.CreateRoute(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
	if req.RouteType == "" {
		req.RouteType = existing.RouteType
	}

	route, err := s.db.UpdateRoute(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
