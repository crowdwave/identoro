package main

import (
    "context"
    "crypto/rand"
    "database/sql"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "html/template"
    "log"
    "net/http"
    "os"
    "os/signal"
    "regexp"
    "strconv"
    "sync"
    "syscall"
    "time"

    "github.com/google/uuid"
    "github.com/gorilla/csrf"
    "github.com/gorilla/sessions"
    "github.com/jackc/pgx/v4/pgxpool"
    "github.com/joho/godotenv"
    _ "github.com/mattn/go-sqlite3" // SQLite driver
    "github.com/unrolled/secure"
    "golang.org/x/crypto/bcrypt"
    "gopkg.in/gomail.v2"
)

var (
    db                     Database
    store                  *sessions.CookieStore
    tmpl                   = template.Must(template.ParseGlob("templates/*.html"))
    config                 *Config
    version                = "1.0.0"
    dbAvailable            = false
    loginMaxPerHour        = 15
    loginLock              sync.Mutex
    loginAttemptsByAccount = make(map[string]int)
    currentEpochHour       int64
)

type Config struct {
    DbType            string
    ConnStr           string
    SecretKey         string
    EmailSender       string
    EmailPassword     string
    SmtpHost          string
    SmtpPort          int
    WebServerAddress  string
    EmailReplyTo      string
    RecaptchaSiteKey  string
    RecaptchaSecretKey string
}

type User struct {
    UserID            string
    Username          string
    Password          string
    Email             string
    ResetToken        sql.NullString
    Verified          bool
    VerificationToken sql.NullString
}

type Database interface {
    Open() error
    CreateUser(username, password, email, verificationToken string) error
    GetUserByUsername(username string) (User, error)
    UpdateUserVerification(token string) error
    UpdateUserResetToken(email, resetToken string) error
    UpdateUserPassword(token, hashedPassword string) error
    TestConnection() error
}

type PostgresDB struct {
    connStr string
    pool    *pgxpool.Pool
}

func (db *PostgresDB) Open() error {
    var err error
    for i := 0; i < 5; i++ { // Retry up to 5 times
        db.pool, err = pgxpool.Connect(context.Background(), db.connStr)
        if err == nil {
            return nil
        }
        log.Printf("Failed to connect to PostgreSQL, attempt %d: %v", i+1, err)
        time.Sleep(time.Duration(i) * time.Second) // Exponential backoff
    }
    return err
}

func (db *PostgresDB) CreateUser(username, password, email, verificationToken string) error {
    if !dbAvailable {
        return fmt.Errorf("database not available")
    }
    userID := uuid.New().String()
    query := `INSERT INTO identoro_users (user_id, username, password, email, verification_token) VALUES ($1, $2, $3, $4, $5)`
    _, err := db.pool.Exec(context.Background(), query, userID, username, password, email, verificationToken)
    return err
}

func (db *PostgresDB) GetUserByUsername(username string) (User, error) {
    var user User
    if !dbAvailable {
        return user, fmt.Errorf("database not available")
    }
    query := `SELECT user_id, username, password, email, reset_token, verified, verification_token FROM identoro_users WHERE username = $1`
    row := db.pool.QueryRow(context.Background(), query, username)
    err := row.Scan(&user.UserID, &user.Username, &user.Password, &user.Email, &user.ResetToken, &user.Verified, &user.VerificationToken)
    return user, err
}

func (db *PostgresDB) UpdateUserVerification(token string) error {
    if !dbAvailable {
        return fmt.Errorf("database not available")
    }
    query := `UPDATE identoro_users SET verified = TRUE, verification_token = NULL WHERE verification_token = $1`
    _, err := db.pool.Exec(context.Background(), query, token)
    return err
}

func (db *PostgresDB) UpdateUserResetToken(email, resetToken string) error {
    if !dbAvailable {
        return fmt.Errorf("database not available")
    }
    query := `UPDATE identoro_users SET reset_token = $1 WHERE email = $2`
    _, err := db.pool.Exec(context.Background(), query, resetToken, email)
    return err
}

func (db *PostgresDB) UpdateUserPassword(token, hashedPassword string) error {
    if !dbAvailable {
        return fmt.Errorf("database not available")
    }
    query := `UPDATE identoro_users SET password = $1, reset_token = NULL WHERE reset_token = $2`
    _, err := db.pool.Exec(context.Background(), query, hashedPassword, token)
    return err
}

func (db *PostgresDB) TestConnection() error {
    var result int
    return db.pool.QueryRow(context.Background(), "SELECT 1").Scan(&result)
}

type SQLiteDB struct {
    connStr string
    db      *sql.DB
}

func (db *SQLiteDB) Open() error {
    var err error
    db.db, err = sql.Open("sqlite3", db.connStr)
    return err
}

func (db *SQLiteDB) CreateUser(username, password, email, verificationToken string) error {
    userID := uuid.New().String()
    query := `INSERT INTO identoro_users (user_id, username, password, email, verification_token) VALUES (?, ?, ?, ?, ?)`
    _, err := db.db.Exec(query, userID, username, password, email, verificationToken)
    return err
}

func (db *SQLiteDB) GetUserByUsername(username string) (User, error) {
    var user User
    query := `SELECT user_id, username, password, email, reset_token, verified, verification_token FROM identoro_users WHERE username = ?`
    row := db.db.QueryRow(query, username)
    err := row.Scan(&user.UserID, &user.Username, &user.Password, &user.Email, &user.ResetToken, &user.Verified, &user.VerificationToken)
    return user, err
}

func (db *SQLiteDB) UpdateUserVerification(token string) error {
    query := `UPDATE identoro_users SET verified = 1, verification_token = NULL WHERE verification_token = ?`
    _, err := db.db.Exec(query, token)
    return err
}

func (db *SQLiteDB) UpdateUserResetToken(email, resetToken string) error {
    query := `UPDATE identoro_users SET reset_token = ? WHERE email = ?`
    _, err := db.db.Exec(query, resetToken, email)
    return err
}

func (db *SQLiteDB) UpdateUserPassword(token, hashedPassword string) error {
    query := `UPDATE identoro_users SET password = ?, reset_token = NULL WHERE reset_token = ?`
    _, err := db.db.Exec(query, hashedPassword, token)
    return err
}

func (db *SQLiteDB) TestConnection() error {
    return db.db.Ping()
}

func loadConfig() (*Config, error) {
    err := godotenv.Load()
    if err != nil {
        return nil, fmt.Errorf("error loading .env file: %v", err)
    }

    smtpPort, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
    if err != nil {
        return nil, fmt.Errorf("invalid SMTP_PORT value in .env file")
    }

    config := &Config{
        DbType:            os.Getenv("DB_TYPE"),
        ConnStr:           os.Getenv("DATABASE_URL"),
        SecretKey:         os.Getenv("SECRET_KEY"),
        EmailSender:       os.Getenv("EMAIL_SENDER"),
        EmailPassword:     os.Getenv("EMAIL_PASSWORD"),
        SmtpHost:          os.Getenv("SMTP_HOST"),
        SmtpPort:          smtpPort,
        WebServerAddress:  os.Getenv("WEB_SERVER_ADDRESS"),
        EmailReplyTo:      os.Getenv("EMAIL_REPLY_TO"),
        RecaptchaSiteKey:  os.Getenv("RECAPTCHA_SITE_KEY"),
        RecaptchaSecretKey: os.Getenv("RECAPTCHA_SECRET_KEY"),
    }

    return config, nil
}

func printConfig(config *Config) {
    fmt.Println("Server Version:", version)
    fmt.Println("Configuration:")
    fmt.Printf("  DB_TYPE: %s\n", config.DbType)
    fmt.Printf("  DATABASE_URL: %s\n", config.ConnStr)
    fmt.Printf("  SECRET_KEY: %s\n", maskString(config.SecretKey))
    fmt.Printf("  EMAIL_SENDER: %s\n", config.EmailSender)
    fmt.Printf("  EMAIL_PASSWORD: %s\n", maskString(config.EmailPassword))
    fmt.Printf("  SMTP_HOST: %s\n", config.SmtpHost)
    fmt.Printf("  SMTP_PORT: %d\n", config.SmtpPort)
    fmt.Printf("  WEB_SERVER_ADDRESS: %s\n", config.WebServerAddress)
    fmt.Printf("  EMAIL_REPLY_TO: %s\n", config.EmailReplyTo)
    fmt.Printf("  RECAPTCHA_SITE_KEY: %s\n", config.RecaptchaSiteKey)
    fmt.Printf("  RECAPTCHA_SECRET_KEY: %s\n", maskString(config.RecaptchaSecretKey))

    if config.DbType == "postgres" {
        fmt.Println("\nExample SQL for creating an updatable view for PostgreSQL:")
        fmt.Println(`CREATE VIEW identoro_users AS
                      SELECT user_id, user_name AS username, passwd AS password, mail AS email, reset_token, is_verified AS verified, verification_token
                      FROM actual_users_table;

                      CREATE RULE insert_identoro_users AS
                      ON INSERT TO identoro_users
                      DO INSTEAD
                      INSERT INTO actual_users_table (user_name, passwd, mail, verification_token)
                      VALUES (NEW.username, NEW.password, NEW.email, NEW.verification_token);

                      CREATE RULE update_identoro_users AS
                      ON UPDATE TO identoro_users
                      DO INSTEAD
                      UPDATE actual_users_table
                      SET user_name = NEW.username,
                          passwd = NEW.password,
                          mail = NEW.email,
                          reset_token = NEW.reset_token,
                          is_verified = NEW.verified,
                          verification_token = NEW.verification_token
                      WHERE user_id = NEW.user_id;`)
    }
}

func maskString(s string) string {
    if len(s) <= 4 {
        return "****"
    }
    return s[:2] + "****" + s[len(s)-2:]
}

func jsonResponse(w http.ResponseWriter, statusCode int, message string, data interface{}) {
    response := map[string]interface{}{
        "status":  statusCode,
        "message": message,
        "data":    data,
    }
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    json.NewEncoder(w).Encode(response)
}

func errorResponse(w http.ResponseWriter, statusCode int, message string) {
    w.WriteHeader(statusCode)
    w.Write([]byte(message))
    log.Printf("Error: %s, StatusCode: %d", message, statusCode)
}

func main() {
    var err error
    config, err = loadConfig()
    if err != nil {
        log.Fatal(err)
    }

    switch config.DbType {
    case "postgres":
        db = &PostgresDB{connStr: config.ConnStr}
    case "sqlite":
        db = &SQLiteDB{connStr: config.ConnStr}
    default:
        log.Fatal("Unsupported database type")
    }

    // Retry connecting to the database in a separate goroutine
    go func() {
        for {
            err := db.Open()
            if err == nil {
                log.Println("Connected to the database")
                dbAvailable = true
                return
            }
            log.Printf("Database connection failed: %v. Retrying in %d seconds...", err, 1)
            dbAvailable = false
            time.Sleep(1 * time.Second)
        }
    }()

    store = sessions.NewCookieStore([]byte(config.SecretKey))
    store.Options = &sessions.Options{
        Path:     "/",
        MaxAge:   3600 * 8, // 8 hours
        HttpOnly: true,
        Secure:   true, // Ensure the cookie is sent over HTTPS
    }

    csrfMiddleware := csrf.Protect([]byte(config.SecretKey))

    http.Handle("/", logRequest(csrfMiddleware(http.HandlerFunc(homeHandler))))
    http.Handle("/signup", logRequest(csrfMiddleware(http.HandlerFunc(signupHandler))))
    http.Handle("/signin", logRequest(csrfMiddleware(http.HandlerFunc(signinHandler))))
    http.Handle("/signout", logRequest(csrfMiddleware(http.HandlerFunc(signoutHandler))))
    http.Handle("/forgot", logRequest(csrfMiddleware(http.HandlerFunc(forgotHandler))))
    http.Handle("/reset", logRequest(csrfMiddleware(http.HandlerFunc(resetHandler))))
    http.Handle("/verify", logRequest(csrfMiddleware(http.HandlerFunc(verifyHandler))))

    // Secure middleware
    secureMiddleware := secure.New(secure.Options{
        ContentTypeNosniff:  true,
        XSSProtection:       "1; mode=block",
        XFrameOptions:       "DENY",
        ContentSecurityPolicy: "default-src 'self'",
    })

    finalHandler := secureMiddleware.Handler(http.DefaultServeMux)

    // Signal handling for graceful shutdown
    stop := make(chan os.Signal, 1)
    signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-stop
        log.Println("Shutting down server...")
        if config.DbType == "postgres" && dbAvailable {
            pgDb := db.(*PostgresDB)
            pgDb.pool.Close()
        } else if config.DbType == "sqlite" {
            sqlDb := db.(*SQLiteDB)
            sqlDb.db.Close()
        }
        os.Exit(0)
    }()

    printConfig(config)

    log.Println("Server started at :8080")
    log.Fatal(http.ListenAndServe(":8080", finalHandler))
}

func logRequest(handler http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ip := r.RemoteAddr
        if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
            ip = forwarded
        }

        log.Printf("%s - %s - %s %s\n", time.Now().Format(time.RFC3339), ip, r.Method, r.URL.Path)
        handler.ServeHTTP(w, r)
    })
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    if !dbAvailable {
        jsonResponse(w, http.StatusServiceUnavailable, "Database not available", nil)
        return
    }
    session, _ := store.Get(r, "session")
    username, ok := session.Values["username"].(string)
    tmpl.ExecuteTemplate(w, "home.html", map[string]interface{}{
        "Username": username,
        "SignedIn": ok,
        "Endpoints": []string{
            "/signup",
            "/signin",
            "/signout",
            "/forgot",
            "/reset",
            "/verify",
        },
    })
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
    if !dbAvailable {
        jsonResponse(w, http.StatusServiceUnavailable, "Database not available", nil)
        return
    }
    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        email := r.FormValue("email")
        password := r.FormValue("password")
        recaptchaResponse := r.FormValue("g-recaptcha-response")

        if !isValidUsername(username) || !isValidEmail(email) || !isValidPassword(password) {
            if r.Header.Get("Content-Type") == "application/json") {
                jsonResponse(w, http.StatusBadRequest, "Invalid input", nil)
            } else {
                errorResponse(w, http.StatusBadRequest, "Invalid input")
            }
            return
        }

        if (!verifyRecaptcha(recaptchaResponse)) {
            if r.Header.Get("Content-Type") == "application/json") {
                jsonResponse(w, http.StatusBadRequest, "Invalid reCAPTCHA", nil)
            } else {
                errorResponse(w, http.StatusBadRequest, "Invalid reCAPTCHA")
            }
            return
        }

        hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        verificationToken := generateToken()
        err := db.CreateUser(username, string(hashedPassword), email, verificationToken)
        if err != nil {
            if r.Header.Get("Content-Type") == "application/json") {
                jsonResponse(w, http.StatusBadRequest, "Username or email already exists", nil)
            } else {
                errorResponse(w, http.StatusBadRequest, "Username or email already exists")
            }
            return
        }

        verificationURL := fmt.Sprintf("%s/verify?token=%s", config.WebServerAddress, verificationToken)
        emailBody := fmt.Sprintf("Please click the following link to verify your account: %s", verificationURL)
        sendEmail(email, "Verify your account", emailBody)

        if r.Header.Get("Content-Type") == "application/json") {
            jsonResponse(w, http.StatusSeeOther, "Signup successful, please verify your email", nil)
        } else {
            http.Redirect(w, r, "/signin", http.StatusSeeOther)
        }
    } else {
        tmpl.ExecuteTemplate(w, "signup.html", map[string]interface{}{
            "RecaptchaSiteKey": config.RecaptchaSiteKey,
        })
    }
}

func signinHandler(w http.ResponseWriter, r *http.Request) {
    if !dbAvailable {
        jsonResponse(w, http.StatusServiceUnavailable, "Database not available", nil)
        return
    }
    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")

        if !isValidUsername(username) || !isValidPassword(password) {
            if r.Header.Get("Content-Type") == "application/json") {
                jsonResponse(w, http.StatusBadRequest, "Invalid input", nil)
            } else {
                errorResponse(w, http.StatusBadRequest, "Invalid input")
            }
            return
        }

        // Rate limiting by account (username)
        epochHour := time.Now().Unix() / 3600
        loginLock.Lock()
        if currentEpochHour != epochHour {
            loginAttemptsByAccount = make(map[string]int)
            currentEpochHour = epochHour
        }
        attempts := loginAttemptsByAccount[username]
        if attempts >= loginMaxPerHour {
            loginLock.Unlock()
            if r.Header.Get("Content-Type") == "application/json") {
                jsonResponse(w, http.StatusTooManyRequests, "Too many login attempts", nil)
            } else {
                errorResponse(w, http.StatusTooManyRequests, "Too many login attempts")
            }
            return
        }
        loginAttemptsByAccount[username]++
        loginLock.Unlock()

        user, err := db.GetUserByUsername(username)
        if err != nil {
            if r.Header.Get("Content-Type") == "application/json") {
                jsonResponse(w, http.StatusUnauthorized, "Invalid credentials", nil)
            } else {
                errorResponse(w, http.StatusUnauthorized, "Invalid credentials")
            }
            return
        }

        if !user.Verified {
            if r.Header.Get("Content-Type") == "application/json") {
                jsonResponse(w, http.StatusUnauthorized, "Account not verified", nil)
            } else {
                errorResponse(w, http.StatusUnauthorized, "Account not verified")
            }
            return
        }

        if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
            if r.Header.Get("Content-Type") == "application/json") {
                jsonResponse(w, http.StatusUnauthorized, "Invalid credentials", nil)
            } else {
                errorResponse(w, http.StatusUnauthorized, "Invalid credentials")
            }
            return
        }

        session, _ := store.Get(r, "session")
        session.Values["username"] = username
        session.Save(r, w)

        if r.Header.Get("Content-Type") == "application/json") {
            jsonResponse(w, http.StatusSeeOther, "Signin successful", nil)
        } else {
            http.Redirect(w, r, "/", http.StatusSeeOther)
        }
    } else {
        tmpl.ExecuteTemplate(w, "signin.html", nil)
    }
}

func signoutHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")
    delete(session.Values, "username")
    session.Save(r, w)
    if r.Header.Get("Content-Type") == "application/json") {
        jsonResponse(w, http.StatusOK, "Signout successful", nil)
    } else {
        http.Redirect(w, r, "/", http.StatusSeeOther)
    }
}

func forgotHandler(w http.ResponseWriter, r *http.Request) {
    if !dbAvailable {
        jsonResponse(w, http.StatusServiceUnavailable, "Database not available", nil)
        return
    }
    if r.Method == http.MethodPost {
        email := r.FormValue("email")

        if !isValidEmail(email) {
            if r.Header.Get("Content-Type") == "application/json") {
                jsonResponse(w, http.StatusBadRequest, "Invalid email", nil)
            } else {
                errorResponse(w, http.StatusBadRequest, "Invalid email")
            }
            return
        }

        resetToken := generateToken()
        err := db.UpdateUserResetToken(email, resetToken)
        if err != nil {
            if r.Header.Get("Content-Type") == "application/json") {
                jsonResponse(w, http.StatusBadRequest, "Invalid email", nil)
            } else {
                errorResponse(w, http.StatusBadRequest, "Invalid email")
            }
            return
        }

        resetURL := fmt.Sprintf("%s/reset?token=%s", config.WebServerAddress, resetToken)
        emailBody := fmt.Sprintf("Click the link to reset your password: %s", resetURL)
        sendEmail(email, "Reset your password", emailBody)

        if r.Header.Get("Content-Type") == "application/json") {
            jsonResponse(w, http.StatusSeeOther, "Password reset email sent", nil)
        } else {
            http.Redirect(w, r, "/signin", http.StatusSeeOther)
        }
    } else {
        tmpl.ExecuteTemplate(w, "forgot.html", nil)
    }
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
    if !dbAvailable {
        jsonResponse(w, http.StatusServiceUnavailable, "Database not available", nil)
        return
    }
    if r.Method == http.MethodPost {
        token := r.FormValue("token")
        newPassword := r.FormValue("new_password")

        if !isValidPassword(newPassword) {
            if r.Header.Get("Content-Type") == "application/json") {
                jsonResponse(w, http.StatusBadRequest, "Invalid input", nil)
            } else {
                errorResponse(w, http.StatusBadRequest, "Invalid input")
            }
            return
        }

        hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
        err := db.UpdateUserPassword(token, string(hashedPassword))
        if err != nil {
            if r.Header.Get("Content-Type") == "application/json") {
                jsonResponse(w, http.StatusBadRequest, "Invalid token", nil)
            } else {
                errorResponse(w, http.StatusBadRequest, "Invalid token")
            }
            return
        }

        if r.Header.Get("Content-Type") == "application/json") {
            jsonResponse(w, http.StatusSeeOther, "Password reset successful", nil)
        } else {
            http.Redirect(w, r, "/signin", http.StatusSeeOther)
        }
    } else {
        tmpl.ExecuteTemplate(w, "reset.html", nil)
    }
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
    if !dbAvailable {
        jsonResponse(w, http.StatusServiceUnavailable, "Database not available", nil)
        return
    }
    token := r.URL.Query().Get("token")
    err := db.UpdateUserVerification(token)
    if err != nil {
        if r.Header.Get("Content-Type") == "application/json") {
            jsonResponse(w, http.StatusBadRequest, "Invalid token", nil)
        } else {
            errorResponse(w, http.StatusBadRequest, "Invalid token")
        }
        return
    }

    if r.Header.Get("Content-Type") == "application/json") {
        jsonResponse(w, http.StatusSeeOther, "Account verified", nil)
    } else {
        http.Redirect(w, r, "/signin", http.StatusSeeOther)
    }
}

func generateToken() string {
    token := make([]byte, 16)
    rand.Read(token)
    return hex.EncodeToString(token)
}

func sendEmail(to, subject, body string) {
    m := gomail.NewMessage()
    m.SetHeader("From", config.EmailSender)
    m.SetHeader("To", to)
    m.SetHeader("Subject", subject)
    m.SetHeader("Reply-To", config.EmailReplyTo)
    m.SetBody("text/plain", body)

    d := gomail.NewDialer(config.SmtpHost, config.SmtpPort, config.EmailSender, config.EmailPassword)

    if err := d.DialAndSend(m); err != nil {
        log.Fatal(err)
    }
}

func isValidUsername(username string) bool {
    re := regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)
    return re.MatchString(username)
}

func isValidEmail(email string) bool {
    re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
    return re.MatchString(email)
}

func isValidPassword(password string) bool {
    return len(password) >= 6
}
