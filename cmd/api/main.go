package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"go_tutorial/internal/config"
	"go_tutorial/internal/handler"
	"go_tutorial/internal/repository"
	"go_tutorial/internal/service"
)

func main() {
	// 0. Load Configuration (.env file and environment variables)
	cfg := config.Load()
	log.Printf("Loaded environment: %s", cfg.AppEnv)

	// 1. Initialize Repository (Neon PostgreSQL or In-Memory fallback)
	var userRepo repository.UserRepository

	if cfg.DatabaseURL != "" {
		log.Printf("Connecting to Neon PostgreSQL: %s", maskDatabaseURL(cfg.DatabaseURL))
		db, err := sql.Open("pgx", cfg.DatabaseURL)
		if err != nil {
			log.Fatalf("Database connection configuration error: %v", err)
		}
		defer db.Close()

		// Configure pool
		db.SetMaxOpenConns(20)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(5 * time.Minute)

		if err := db.Ping(); err != nil {
			log.Fatalf("❌ Failed to connect to Neon DB: %v", err)
		}
		log.Println("✅ Successfully connected to Neon PostgreSQL!")

		pgRepo, err := repository.NewPostgresUserRepository(db)
		if err != nil {
			log.Fatalf("❌ Failed to verify 'users' table in Neon: %v", err)
		}
		userRepo = pgRepo
	} else {
		log.Println("⚠️  No DB_URL found. Using in-memory repository.")
		userRepo = repository.NewMemoryUserRepository()
	}

	// 2. Business Logic Layer (Services)
	userService := service.NewUserService(userRepo)
	securityService := service.NewSecurityService()

	// 3. Delivery Layer (HTTP Handlers)
	userHandler := handler.NewUserHandler(userService)
	securityHandler := handler.NewSecurityHandler(securityService)

	// 4. Setup HTTP Router & Register Routes
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		handler.JSON(w, http.StatusOK, map[string]string{
			"status": "healthy",
			"env":    cfg.AppEnv,
			"time":   time.Now().UTC().Format(time.RFC3339),
		})
	})

	// User auth endpoints
	userHandler.RegisterRoutes(mux)

	// Security analysis endpoints
	securityHandler.RegisterRoutes(mux)

	// 5. Configure HTTP Server
	port := ":" + cfg.Port
	server := &http.Server{
		Addr:         port,
		Handler:      loggingMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	fmt.Println("==================================================")
	fmt.Printf("🚀 Go Backend & Security Analysis API running at http://localhost%s\n", port)
	fmt.Println("Endpoints available:")
	fmt.Printf("  GET  http://localhost%s/api/health\n", port)
	fmt.Printf("  POST http://localhost%s/api/v1/auth/register\n", port)
	fmt.Printf("  POST http://localhost%s/api/v1/auth/login\n", port)
	fmt.Printf("  GET  http://localhost%s/api/v1/users\n", port)
	fmt.Printf("  POST http://localhost%s/api/v1/security/analyze\n", port)
	fmt.Println("==================================================")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

// loggingMiddleware logs incoming HTTP requests with latency.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[%s] %s (%v)", r.Method, r.URL.Path, time.Since(start))
	})
}

// maskDatabaseURL hides passwords in database connection strings for safe logging.
func maskDatabaseURL(rawURL string) string {
	if len(rawURL) > 20 {
		return rawURL[:12] + "****" + rawURL[len(rawURL)-8:]
	}
	return "****"
}

