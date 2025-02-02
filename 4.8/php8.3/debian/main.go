package main

import (
	"bufio"
	"crypto/subtle"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/didip/tollbooth"
	"github.com/didip/tollbooth/limiter"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// Session manager
// Session storage in memory
var (
	sessionStore = make(map[string]time.Time)
	sessionMutex sync.Mutex
)

// Session lifetime
const sessionDuration = 30 * time.Minute

// Start session cleanup routine
func startSessionCleanup() {
	ticker := time.NewTicker(sessionDuration)
	go func() {
		for range ticker.C {
			sessionMutex.Lock()
			now := time.Now()
			for user, expiry := range sessionStore {
				if now.After(expiry) {
					delete(sessionStore, user)
					log.Println("🗑️ Cleaned expired session for user:", user)
				}
			}
			sessionMutex.Unlock()
		}
	}()
}

// Load environment variables
func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using system environment variables.")
	}
}

// Generate a bcrypt password hash
func generateBcryptHash() {
	reader := bufio.NewReader(os.Stdin)

	// Prompt for password
	fmt.Print("Enter password: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	fmt.Print("Confirm password: ")
	passwordConfirm, _ := reader.ReadString('\n')
	passwordConfirm = strings.TrimSpace(passwordConfirm)

	// Check if passwords match
	if password != passwordConfirm {
		fmt.Println("Error: Passwords do not match!")
		os.Exit(1)
	}

	// Generate bcrypt hash
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Error generating bcrypt hash:", err)
		os.Exit(1)
	}

	// Print the generated hash
	fmt.Println("Generated bcrypt hash:", string(hash))
	os.Exit(0) // Exit after generating the password hash
}

// Secure HTTP headers middleware
func secureHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Content-Type-Options", "nosniff")
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
		username := os.Getenv("ADMIN_USERNAME")

		sessionMutex.Lock()
		expiry, exists := sessionStore[username]
		sessionMutex.Unlock()

		// Debug logs
		log.Println("🔍 Checking session for user:", username)
		log.Println("🔍 Session exists:", exists, "| Expiry:", expiry)

		if !exists || time.Now().After(expiry) {
			log.Println("🚨 User session expired or not found, redirecting to login")
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})

}

// Login handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		username := r.Form.Get("username")
		password := r.Form.Get("password")

		// Load credentials from environment variables
		expectedUser := os.Getenv("ADMIN_USERNAME")
		expectedPasswordHash := os.Getenv("ADMIN_PASSWORD_HASH")

		// Secure constant-time username comparison
		if subtle.ConstantTimeCompare([]byte(username), []byte(expectedUser)) != 1 {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Compare bcrypt hashed password
		err = bcrypt.CompareHashAndPassword([]byte(expectedPasswordHash), []byte(password))
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Store user in memory with expiration
		sessionMutex.Lock()
		sessionStore[username] = time.Now().Add(sessionDuration)
		sessionMutex.Unlock()
		log.Println("✅ User logged in:", username)

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	nonce := "random-nonce-value"

	tmpl, err := template.New("login").Parse(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login</title>
            <style nonce="` + nonce + `">
                body {
                    font-family: Arial, sans-serif;
                    height: 100vh;
                    margin: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    background: url('https://raw.githubusercontent.com/KiTechSoftware/gcr-admirer/refs/heads/main/space.png') no-repeat center center fixed;
                    background-size: cover;
                }
                .login-card {
                    background: rgba(0, 0, 0, 0.3);
                    backdrop-filter: blur(10px);
                    border-radius: 15px;
                    padding: 50px;
                    box-shadow: 0 0 30px rgba(255, 255, 255, 0.4);
                    text-align: center;
                }
                .login-card input {
                    width: 100%;
                    margin: 10px -10px;
                    padding: 10px;
                    border: none;
                    border-radius: 0;
                    background: none;
					border-bottom: 1px solid rgba(255, 255, 255, 0.6);
                    color: white;
                }
				.login-card input::placeholder { 
					color: #ddd;
					font-size: 1.2em;
				}
                .login-card button {
					width: 100%;
                    padding: 15px 0;
                    border: none;
                    border-radius: 5px;
                    background: #333;
                    color: #fff;
                    cursor: pointer;
                }
                .login-card button:hover {
                    background: #555;
                }
            </style>
        </head>
        <body>
            <div class="login-card">
                <form method="POST">
                    <input type="text" name="username" placeholder="Username">
                    <input type="password" name="password" placeholder="Password">
                    <button type="submit">Login</button>
                </form>
            </div>
        </body>
        </html>
    `)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'nonce-"+nonce+"'; img-src 'self' https://raw.githubusercontent.com")
	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, nil)
}

// Logout handler
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	sessionMutex.Lock()
	delete(sessionStore, username)
	sessionMutex.Unlock()

	log.Println("🔴 User logged out:", username)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// Reverse proxy to forward authenticated requests to Adminer
func proxyHandler() http.Handler {
	target, _ := url.Parse("http://localhost:" + os.Getenv("ADMIRER_PORT")) // Adminer instance
	proxy := httputil.NewSingleHostReverseProxy(target)

	return proxy
}

func main() {
	// Define a flag for generating bcrypt hash
	genPass := flag.Bool("g", false, "Generate bcrypt password hash")
	flag.Parse()

	// If -g is passed, generate bcrypt hash
	if *genPass {
		generateBcryptHash()
	}

	// Load environment variables
	loadEnv()

	// Check if required env variables are set
	if os.Getenv("ADMIN_USERNAME") == "" || os.Getenv("ADMIN_PASSWORD_HASH") == "" {
		log.Fatal("Missing environment variables: ADMIN_USERNAME and ADMIN_PASSWORD_HASH")
	}

	// Start session cleanup
	startSessionCleanup()

	mux := http.NewServeMux()
	mux.Handle("/login", http.HandlerFunc(loginHandler))
	mux.Handle("/logout", http.HandlerFunc(logoutHandler))
	mux.Handle("/", authMiddleware(proxyHandler()))

	// Start proxy
	log.Println("Secure proxy running on :" + os.Getenv("PROXY_PORT"))
	log.Fatal(
		http.ListenAndServe(
			":"+os.Getenv("PROXY_PORT"),
			rateLimitMiddleware(secureHeadersMiddleware(mux)),
		),
	)
}
