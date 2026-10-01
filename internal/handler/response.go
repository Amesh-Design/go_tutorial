package handler

import (
	"encoding/json"
	"net/http"
)

// StandardResponse wraps API responses in a consistent JSON structure.
type StandardResponse struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

// JSON writes a JSON response with status code.
func JSON(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(StandardResponse{
		Success: true,
		Data:    data,
	})
}

// Error writes a standardized error JSON response.
func Error(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(StandardResponse{
		Success: false,
		Error:   message,
	})
}
