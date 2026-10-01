package handler

import (
	"encoding/json"
	"net/http"

	"go_tutorial/internal/model"
	"go_tutorial/internal/service"
)

// SecurityHandler handles HTTP requests for website security audits.
type SecurityHandler struct {
	securityService *service.SecurityService
}

// NewSecurityHandler creates a new SecurityHandler instance.
func NewSecurityHandler(securityService *service.SecurityService) *SecurityHandler {
	return &SecurityHandler{securityService: securityService}
}

// RegisterRoutes registers security analysis endpoints.
func (h *SecurityHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/security/analyze", h.HandleAnalyze)
}

// HandleAnalyze handles the POST /api/v1/security/analyze request.
func (h *SecurityHandler) HandleAnalyze(w http.ResponseWriter, r *http.Request) {
	var req model.SecurityAnalysisRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "Invalid JSON body: 'url' field is required")
		return
	}

	if req.URL == "" {
		Error(w, http.StatusBadRequest, "The 'url' field cannot be empty")
		return
	}

	result, err := h.securityService.Analyze(req.URL)
	if err != nil {
		Error(w, http.StatusBadGateway, err.Error())
		return
	}

	JSON(w, http.StatusOK, result)
}
