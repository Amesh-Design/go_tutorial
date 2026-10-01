package handler

import (
	"encoding/json"
	"errors"
	"go_tutorial/internal/model"
	"go_tutorial/internal/repository"
	"go_tutorial/internal/service"
	"net/http"
)

// UserHandler manages incoming HTTP requests related to user registration and user data.
type UserHandler struct {
	userService *service.UserService
}

// NewUserHandler constructs a new UserHandler.
func NewUserHandler(userService *service.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

// RegisterRoutes registers user endpoints onto the provided http.ServeMux.
func (h *UserHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/register", h.HandleRegister)
	mux.HandleFunc("POST /api/v1/auth/login", h.HandleLogin)
	mux.HandleFunc("GET /api/v1/users", h.HandleListUsers)
}

// HandleLogin handles the POST /api/v1/auth/login request.
func (h *UserHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest

	// Parse JSON body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "Invalid JSON body: please check your request payload")
		return
	}

	// Call service layer to authenticate
	loginResponse, err := h.userService.Login(req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			Error(w, http.StatusUnauthorized, err.Error())
			return
		}
		Error(w, http.StatusBadRequest, err.Error())
		return
	}

	// Return 200 OK with login confirmation and user profile
	JSON(w, http.StatusOK, loginResponse)
}


// HandleRegister handles the POST /api/v1/auth/register request.
func (h *UserHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var req model.RegisterRequest

	// Parse JSON body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "Invalid JSON body: please check your request payload")
		return
	}

	// Call service layer
	userResponse, err := h.userService.Register(req)
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrUserAlreadyExists):
			Error(w, http.StatusConflict, err.Error())
		default:
			Error(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	// Return 201 Created with safe user data
	JSON(w, http.StatusCreated, userResponse)
}

// HandleListUsers handles the GET /api/v1/users request.
func (h *UserHandler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.userService.GetAllUsers()
	if err != nil {
		Error(w, http.StatusInternalServerError, "Failed to retrieve users")
		return
	}

	JSON(w, http.StatusOK, users)
}
