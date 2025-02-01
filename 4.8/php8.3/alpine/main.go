package main

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/didip/tollbooth"
	"github.com/didip/tollbooth/limiter"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// Session manager
var sessionManager = scs.New()

// Load environment variables
func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using system environment variables.")
	}
}

// Secure HTTP headers middleware
func secureHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// Rate limiting middleware (5 requests per minute per IP)
func rateLimitMiddleware(next http.Handler) http.Handler {
	lim := tollbooth.NewLimiter(5, &limiter.ExpirableOptions{DefaultExpirationTTL: time.Minute})
	return tollbooth.LimitFuncHandler(lim, next.ServeHTTP)
}

// Authentication middleware
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := sessionManager.GetString(r.Context(), "userID")
		if userID == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Login handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.Form.Get("username")
		password := r.Form.Get("password")

		// Load credentials from environment variables
		expectedUser := os.Getenv("ADMIN_USERNAME")
		expectedPasswordHash := os.Getenv("ADMIN_PASSWORD_HASH") // Pre-hashed password

		// Secure constant-time username comparison
		if subtle.ConstantTimeCompare([]byte(username), []byte(expectedUser)) != 1 {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Compare bcrypt hashed password
		err := bcrypt.CompareHashAndPassword([]byte(expectedPasswordHash), []byte(password))
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Set session
		sessionManager.Put(r.Context(), "userID", username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	fmt.Fprint(w, `<form method="POST">
		<input type="text" name="username" placeholder="Username">
		<input type="password" name="password" placeholder="Password">
		<button type="submit">Login</button>
	</form>`)
}

// Logout handler
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	sessionManager.Remove(r.Context(), "userID")
	http.Redirect(w, r, "/login", http.StatusFound)
}

// Reverse proxy to forward authenticated requests to Admirer
func proxyHandler() http.Handler {
	target, _ := url.Parse("http://localhost:8080") // Admirer instance
	proxy := httputil.NewSingleHostReverseProxy(target)
	return proxy
}

func main() {
	// Load environment variables
	loadEnv()

	// Check if required env variables are set
	if os.Getenv("ADMIN_USERNAME") == "" || os.Getenv("ADMIN_PASSWORD_HASH") == "" {
		log.Fatal("Missing environment variables: ADMIN_USERNAME and ADMIN_PASSWORD_HASH")
	}

	// Configure session security
	sessionManager.Lifetime = 30 * time.Minute
	sessionManager.Cookie.HttpOnly = true
	sessionManager.Cookie.Secure = true

	// Define routes
	mux := http.NewServeMux()
	mux.Handle("/login", http.HandlerFunc(loginHandler))
	mux.Handle("/logout", http.HandlerFunc(logoutHandler))
	mux.Handle("/", authMiddleware(proxyHandler()))

	// Apply security middleware
	handler := rateLimitMiddleware(secureHeadersMiddleware(sessionManager.LoadAndSave(mux)))

	log.Println("Secure proxy running on :80")
	log.Fatal(http.ListenAndServe(":80", handler))
}
