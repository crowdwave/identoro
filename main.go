package main

import (
    "context"
    "database/sql"
    "encoding/json"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "net/url"
    "os"
    "os/signal"
    "os/user"
    "path/filepath"
    "regexp"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/dgrijalva/jwt-go"
    "github.com/google/uuid"
    "github.com/golang-jwt/jwt"
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
    config                 *Config
    version                = "1.0.0"
    dbAvailable            = false
    loginMaxPerHour        = 15
    loginLock              sync.Mutex
    loginAttemptsByAccount = make(map[string]int)
    currentEpochHour       int64
    userNameOrID           string
    groupNameOrID          string
    hashKey                []byte
    mySigningKey           []byte
)

type Config struct {
    DbType                 string
    ConnStr                string
    SecretKey              string
    EmailSender            string
    EmailPassword          string
    SmtpHost               string
    SmtpPort               int
    WebServerAddress       string
    EmailReplyTo           string
    RecaptchaSiteKey       string
    RecaptchaSecretKey     string
    User                   string
    Group                  string
    HashKey                string
    RequireFirstAndLastName bool
    UseJWTAuth             bool
    JWTSecret              string
    JWTExpirationHours     int
}

type User struct {
    UserID              string
    Username            string
    Password            string
    Email               string
    Firstname           string
    Lastname            string
    Verified            bool
    SigninCount         int
    UnsuccessfulSignins int
    CreatedAt           time.Time
}

type Database interface {
    Open() error
    CreateUser(username, password, email, firstname, lastname string) error
    GetUserByUsername(username string) (User, error)
    GetUserByID(userID string) (User, error)
    UpdateUserVerification(email string) error
    UpdateUserPasswordByEmail(email, hashedPassword string) error
    IncrementSigninCount(userID string) error
    IncrementUnsuccessfulSignins(username string) error
    ResetUnsuccessfulSignins(username string) error
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

func (db *PostgresDB) CreateUser(username, password, email, firstname, lastname string) error {
    if !dbAvailable {
        return fmt.Errorf("database not available")
    }
    userID := uuid.New().String()
    query := `INSERT INTO identoro_users (user_id, username, password, email, firstname, lastname, verified, signin_count, unsuccessful_signins, created_at) VALUES ($1, $2, $3, $4, $5, $6, FALSE, 0, 0, CURRENT_TIMESTAMP)`
    _, err := db.pool.Exec(context.Background(), query, userID, username, password, email, firstname, lastname)
    return err
}

func (db *PostgresDB) GetUserByUsername(username string) (User, error) {
    var user User
    if !dbAvailable {
        return user, fmt.Errorf("database not available")
    }
    query := `SELECT user_id, username, password, email, firstname, lastname, verified, signin_count, unsuccessful_signins, created_at FROM identoro_users WHERE username = $1`
    row := db.pool.QueryRow(context.Background(), query, username)
    err := row.Scan(&user.UserID, &user.Username, &user.Password, &user.Email, &user.Firstname, &user.Lastname, &user.Verified, &user.SigninCount, &user.UnsuccessfulSignins, &user.CreatedAt)
    return user, err
}

func (db *PostgresDB) GetUserByID(userID string) (User, error) {
    var user User
    if !dbAvailable {
        return user, fmt.Errorf("database not available")
    }
    query := `SELECT user_id, username, password, email, firstname, lastname, verified, signin_count, unsuccessful_signins, created_at FROM identoro_users WHERE user_id = $1`
    row := db.pool.QueryRow(context.Background(), query, userID)
    err := row.Scan(&user.UserID, &user.Username, &user.Password, &user.Email, &user.Firstname, &user.Lastname, &user.Verified, &user.SigninCount, &user.UnsuccessfulSignins, &user.CreatedAt)
    return user, err
}

func (db *PostgresDB) UpdateUserVerification(email string) error {
    if !dbAvailable {
        return fmt.Errorf("database not available")
    }
    query := `UPDATE identoro_users SET verified = TRUE WHERE email = $1`
    _, err := db.pool.Exec(context.Background(), query, email)
    return err
}

func (db *PostgresDB) UpdateUserPasswordByEmail(email, hashedPassword string) error {
    if !dbAvailable {
        return fmt.Errorf("database not available")
    }
    query := `UPDATE identoro_users SET password = $1 WHERE email = $2`
    _, err := db.pool.Exec(context.Background(), query, hashedPassword, email)
    return err
}

func (db *PostgresDB) IncrementSigninCount(userID string) error {
    query := `UPDATE identoro_users SET signin_count = signin_count + 1 WHERE user_id = $1`
    _, err := db.pool.Exec(context.Background(), query, userID)
    return err
}

func (db *PostgresDB) IncrementUnsuccessfulSignins(username string) error {
    query := `UPDATE identoro_users SET unsuccessful_signins = unsuccessful_signins + 1 WHERE username = $1`
    _, err := db.pool.Exec(context.Background(), query, username)
    return err
}

func (db *PostgresDB) ResetUnsuccessfulSignins(username string) error {
    query := `UPDATE identoro_users SET unsuccessful_signins = 0 WHERE username = $1`
    _, err := db.pool.Exec(context.Background(), query, username)
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

func (db *SQLiteDB) CreateUser(username, password, email, firstname, lastname string) error {
    userID := uuid.New().String()
    query := `INSERT INTO identoro_users (user_id, username, password, email, firstname, lastname, verified, signin_count, unsuccessful_signins, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, CURRENT_TIMESTAMP)`
    _, err := db.db.Exec(query, userID, username, password, email, firstname, lastname)
    return err
}

func (db *SQLiteDB) GetUserByUsername(username string) (User, error) {
    var user User
    query := `SELECT user_id, username, password, email, firstname, lastname, verified, signin_count, unsuccessful_signins, created_at FROM identoro_users WHERE username = ?`
    row := db.db.QueryRow(query, username)
    err := row.Scan(&user.UserID, &user.Username, &user.Password, &user.Email, &user.Firstname, &user.Lastname, &user.Verified, &user.SigninCount, &user.UnsuccessfulSignins, &user.CreatedAt)
    return user, err
}

func (db *SQLiteDB) GetUserByID(userID string) (User, error) {
    var user User
    query := `SELECT user_id, username, password, email, firstname, lastname, verified, signin_count, unsuccessful_signins, created_at FROM identoro_users WHERE user_id = ?`
    row := db.db.QueryRow(query, userID)
    err := row.Scan(&user.UserID, &user.Username, &user.Password, &user.Email, &user.Firstname, &user.Lastname, &user.Verified, &user.SigninCount, &user.UnsuccessfulSignins, &user.CreatedAt)
    return user, err
}

func (db *SQLiteDB) UpdateUserVerification(email string) error {
    query := `UPDATE identoro_users SET verified = 1 WHERE email = ?`
    _, err := db.db.Exec(query, email)
    return err
}

func (db *SQLiteDB) UpdateUserPasswordByEmail(email, hashedPassword string) error {
    query := `UPDATE identoro_users SET password = ? WHERE email = ?`
    _, err := db.db.Exec(query, hashedPassword, email)
    return err
}

func (db *SQLiteDB) IncrementSigninCount(userID string) error {
    query := `UPDATE identoro_users SET signin_count = signin_count + 1 WHERE user_id = ?`
    _, err := db.db.Exec(query, userID)
    return err
}

func (db *SQLiteDB) IncrementUnsuccessfulSignins(username string) error {
    query := `UPDATE identoro_users SET unsuccessful_signins = unsuccessful_signins + 1 WHERE username = ?`
    _, err := db.db.Exec(query, username)
    return err
}

func (db *SQLiteDB) ResetUnsuccessfulSignins(username string) error {
    query := `UPDATE identoro_users SET unsuccessful_signins = 0 WHERE username = ?`
    _, err := db.db.Exec(query, username)
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

    jwtExpirationHours, err := strconv.Atoi(os.Getenv("JWT_EXPIRATION_HOURS"))
    if err != nil {
        return nil, fmt.Errorf("invalid JWT_EXPIRATION_HOURS value in .env file")
    }

    config := &Config{
        DbType:                 os.Getenv("DB_TYPE"),
        ConnStr:                os.Getenv("DATABASE_URL"),
        SecretKey:              os.Getenv("SECRET_KEY"),
        EmailSender:            os.Getenv("EMAIL_SENDER"),
        EmailPassword:          os.Getenv("EMAIL_PASSWORD"),
        SmtpHost:               os.Getenv("SMTP_HOST"),
        SmtpPort:               smtpPort,
        WebServerAddress:       os.Getenv("WEB_SERVER_ADDRESS"),
        EmailReplyTo:           os.Getenv("EMAIL_REPLY_TO"),
        RecaptchaSiteKey:       os.Getenv("RECAPTCHA_SITE_KEY"),
        RecaptchaSecretKey:     os.Getenv("RECAPTCHA_SECRET_KEY"),
        User:                   os.Getenv("USER"),
        Group:                  os.Getenv("GROUP"),
        HashKey:                os.Getenv("HASH_KEY"),
        RequireFirstAndLastName: os.Getenv("REQUIRE_FIRST_AND_LAST_NAME") == "true",
        UseJWTAuth:             os.Getenv("USE_JWT_AUTH") == "true",
        JWTSecret:              os.Getenv("JWT_SECRET"),
        JWTExpirationHours:     jwtExpirationHours,
    }

    // Validate environment variables
    if config.DbType != "postgres" && config.DbType != "sqlite" {
        return nil, fmt.Errorf("DB_TYPE must be either 'postgres' or 'sqlite'")
    }
    if !isValidURL(config.WebServerAddress) {
        return nil, fmt.Errorf("invalid WEB_SERVER_ADDRESS value in .env file")
    }
    if !isValidEmail(config.EmailSender) {
        return nil, fmt.Errorf("invalid EMAIL_SENDER value in .env file")
    }
    if !isValidEmail(config.EmailReplyTo) {
        return nil, fmt.Errorf("invalid EMAIL_REPLY_TO value in .env file")
    }

    return config, nil
}

func loadHashKey() ([]byte, error) {
    key := os.Getenv("HASH_KEY")
    if key == "" {
        return nil, fmt.Errorf("HASH_KEY not set in environment variables")
    }
    return []byte(key), nil
}

func generateJWT(user User) (string, error) {
    claims := jwt.MapClaims{
        "user_id": user.UserID,
        "exp":     time.Now().Add(time.Hour * time.Duration(config.JWTExpirationHours)).Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(config.JWTSecret))
}

func printConfig(config *Config) {
    fmt.Println("Server Version:", version)
    fmt.Println("Configuration:")
    fmt.Printf("  DB_TYPE: %s\n", config.DbType)
    fmt.Printf("  DATABASE_URL: %s\n", maskString(config.ConnStr))
    fmt.Printf("  SECRET_KEY: %s\n", maskString(config.SecretKey))
    fmt.Printf("  EMAIL_SENDER: %s\n", config.EmailSender)
    fmt.Printf("  EMAIL_PASSWORD: %s\n", maskString(config.EmailPassword))
    fmt.Printf("  SMTP_HOST: %s\n", config.SmtpHost)
    fmt.Printf("  SMTP_PORT: %d\n", config.SmtpPort)
    fmt.Printf("  WEB_SERVER_ADDRESS: %s\n", config.WebServerAddress)
    fmt.Printf("  EMAIL_REPLY_TO: %s\n", config.EmailReplyTo)
    fmt.Printf("  RECAPTCHA_SITE_KEY: %s\n", config.RecaptchaSiteKey)
    fmt.Printf("  RECAPTCHA_SECRET_KEY: %s\n", maskString(config.RecaptchaSecretKey))
    fmt.Printf("  USER: %s\n", config.User)
    fmt.Printf("  GROUP: %s\n", config.Group)
    fmt.Printf("  HASH_KEY: %s\n", maskString(config.HashKey))
    fmt.Printf("  REQUIRE_FIRST_AND_LAST_NAME: %t\n", config.RequireFirstAndLastName)
    fmt.Printf("  USE_JWT_AUTH: %t\n", config.UseJWTAuth)
    fmt.Printf("  JWT_SECRET: %s\n", maskString(config.JWTSecret))
    fmt.Printf("  JWT_EXPIRATION_HOURS: %d\n", config.JWTExpirationHours)

    if config.DbType == "postgres" {
        fmt.Println("\nExample SQL for creating an updatable view for PostgreSQL:")
        fmt.Println(`CREATE VIEW identoro_users AS
                      SELECT user_id, user_name AS username, passwd AS password, mail AS email, first_name AS firstname, last_name AS lastname, is_verified AS verified, signin_count, unsuccessful_signins, created_at
                      FROM actual_users_table;

                      CREATE RULE insert_identoro_users AS
                      ON INSERT TO identoro_users
                      DO INSTEAD
                      INSERT INTO actual_users_table (user_name, passwd, mail, first_name, last_name, is_verified, signin_count, unsuccessful_signins, created_at)
                      VALUES (NEW.username, NEW.password, NEW.email, NEW.firstname, NEW.lastname, NEW.verified, NEW.signin_count, NEW.unsuccessful_signins, NEW.created_at);

                      CREATE RULE update_identoro_users AS
                      ON UPDATE TO identoro_users
                      DO INSTEAD
                      UPDATE actual_users_table
                      SET user_name = NEW.username,
                          passwd = NEW.password,
                          mail = NEW.email,
                          first_name = NEW.firstname,
                          last_name = NEW.lastname,
                          is_verified = NEW.verified,
                          signin_count = NEW.signin_count,
                          unsuccessful_signins = NEW.unsuccessful_signins,
                          created_at = NEW.created_at
                      WHERE user_id = NEW.user_id;`)

        fmt.Println("\nIf you do not already have a users table, you can use the following SQL to create it:")
        fmt.Println(`CREATE TABLE identoro_users (
                      user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                      user_name VARCHAR(50) NOT NULL,
                      passwd VARCHAR(100) NOT NULL,
                      mail VARCHAR(100) NOT NULL,
                      first_name VARCHAR(50),
                      last_name VARCHAR(50),
                      is_verified BOOLEAN NOT NULL DEFAULT FALSE,
                      signin_count INTEGER NOT NULL DEFAULT 0,
                      unsuccessful_signins INTEGER NOT NULL DEFAULT 0,
                      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                  );`)
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

func displayHelp() {
    fmt.Println("Usage: go run main.go [--help]")
    fmt.Println()
    fmt.Println("Environment Variables:")
    fmt.Println("  DB_TYPE: The type of database to use (e.g., postgres, sqlite).")
    fmt.Println("  DATABASE_URL: The connection string for the database.")
    fmt.Println("  SECRET_KEY: The secret key for session management.")
    fmt.Println("  EMAIL_SENDER: The email address to send emails from.")
    fmt.Println("  EMAIL_PASSWORD: The password for the email sender.")
    fmt.Println("  SMTP_HOST: The SMTP host for sending emails.")
    fmt.Println("  SMTP_PORT: The SMTP port for sending emails.")
    fmt.Println("  WEB_SERVER_ADDRESS: The address where the web server will be hosted.")
    fmt.Println("  EMAIL_REPLY_TO: The reply-to email address for outgoing emails.")
    fmt.Println("  RECAPTCHA_SITE_KEY: The site key for reCAPTCHA.")
    fmt.Println("  RECAPTCHA_SECRET_KEY: The secret key for reCAPTCHA.")
    fmt.Println("  USER: The user name or ID for dropping privileges.")
    fmt.Println("  GROUP: The group name or ID for dropping privileges.")
    fmt.Println("  HASH_KEY: The secret hash key for generating secure tokens.")
    fmt.Println("  REQUIRE_FIRST_AND_LAST_NAME: Whether firstname and lastname are required (true/false).")
    fmt.Println("  USE_JWT_AUTH: Whether to use JWT authentication (true/false).")
    fmt.Println("  JWT_SECRET: The secret key for signing JWTs.")
    fmt.Println("  JWT_EXPIRATION_HOURS: The expiration time for JWTs in hours.")
    fmt.Println()
    fmt.Println("Example of creating a suitable hash key using Linux CLI commands:")
    fmt.Println("  dd if=/dev/urandom bs=32 count=1 | base64")
    fmt.Println()
    os.Exit(0)
}

func main() {
    help := flag.Bool("help", false, "Display help information")
    flag.Parse()

    if *help {
        displayHelp()
    }

    var err error
    config, err = loadConfig()
    if err != nil {
        log.Fatal(err)
    }

    hashKey, err = loadHashKey()
    if err != nil {
        log.Fatal(err)
    }

    userNameOrID = config.User
    groupNameOrID = config.Group

    jailSelf()

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

    csrfMiddleware := csrf.Protect(hashKey)

    http.Handle("/", logRequest(csrfMiddleware(http.HandlerFunc(homeHandler))))
    http.Handle("/signup", logRequest(csrfMiddleware(http.HandlerFunc(signupHandler))))
    http.Handle("/signin", logRequest(csrfMiddleware(http.HandlerFunc(signinHandler))))
    http.Handle("/signout", logRequest(csrfMiddleware(http.HandlerFunc(signoutHandler))))
    http.Handle("/forgot", logRequest(csrfMiddleware(http.HandlerFunc(forgotHandler))))
    http.Handle("/reset", logRequest(csrfMiddleware(http.HandlerFunc(resetHandler))))
    http.Handle("/verify", logRequest(csrfMiddleware(http.HandlerFunc(verifyHandler))))
    http.Handle("/me", logRequest(csrfMiddleware(http.HandlerFunc(meHandler))))

    // Secure middleware
    secureMiddleware := secure.New(secure.Options{
        ContentTypeNosniff:  true,
        BrowserXssFilter:    true,
        FrameDeny:           true,
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
    response := map[string]interface{}{
        "Username": username,
        "SignedIn": ok,
        "Endpoints": []string{
            "/signup",
            "/signin",
            "/signout",
            "/forgot",
            "/reset",
            "/verify",
            "/me",
        },
    }
    jsonResponse(w, http.StatusOK, "Home", response)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
    if !dbAvailable {
        jsonResponse(w, http.StatusServiceUnavailable, "Database not available", nil)
        return
    }
    switch r.Method {
    case http.MethodPost:
        username := r.FormValue("username")
        email := r.FormValue("email")
        password := r.FormValue("password")
        firstname := r.FormValue("firstname")
        lastname := r.FormValue("lastname")
        recaptchaResponse := r.FormValue("g-recaptcha-response")

        if !isValidUsername(username) || !isValidEmail(email) || !isValidPassword(password) {
            jsonResponse(w, http.StatusBadRequest, "Invalid input", nil)
            return
        }

        if config.RequireFirstAndLastName && (firstname == "" || lastname == "") {
            jsonResponse(w, http.StatusBadRequest, "Firstname and lastname are required", nil)
            return
        }

        if !verifyRecaptcha(recaptchaResponse) {
            jsonResponse(w, http.StatusBadRequest, "Invalid reCAPTCHA", nil)
            return
        }

        hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        err := db.CreateUser(username, string(hashedPassword), email, firstname, lastname)
        if err != nil {
            jsonResponse(w, http.StatusBadRequest, "Username or email already exists", nil)
            return
        }

        user, err := db.GetUserByUsername(username)
        if err != nil {
            jsonResponse(w, http.StatusInternalServerError, "Could not retrieve user", nil)
            return
        }

        token, err := generateVerificationToken(user.UserID)
        if err != nil {
            jsonResponse(w, http.StatusInternalServerError, "Could not generate verification token", nil)
            return
        }

        err = sendVerificationEmail(email, token)
        if err != nil {
            jsonResponse(w, http.StatusInternalServerError, "Could not send verification email", nil)
            return
        }

        jsonResponse(w, http.StatusSeeOther, "Signup successful, please verify your email", nil)
    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

func signinHandler(w http.ResponseWriter, r *http.Request) {
    if !dbAvailable {
        jsonResponse(w, http.StatusServiceUnavailable, "Database not available", nil)
        return
    }
    switch r.Method {
    case http.MethodPost:
        time.Sleep(2 * time.Second)

        username := r.FormValue("username")
        password := r.FormValue("password")

        if !isValidUsername(username) || !isValidPassword(password) {
            jsonResponse(w, http.StatusBadRequest, "Invalid input", nil)
            return
        }

        epochHour := time.Now().Unix() / 3600
        loginLock.Lock()
        if currentEpochHour != epochHour {
            loginAttemptsByAccount = make(map[string]int)
            currentEpochHour = epochHour
        }
        attempts := loginAttemptsByAccount[username]
        if attempts >= loginMaxPerHour {
            loginLock.Unlock()
            jsonResponse(w, http.StatusTooManyRequests, "Too many login attempts", nil)
            return
        }
        loginAttemptsByAccount[username]++
        loginLock.Unlock()

        user, err := db.GetUserByUsername(username)
        if err != nil {
            db.IncrementUnsuccessfulSignins(username)
            jsonResponse(w, http.StatusUnauthorized, "Invalid credentials", nil)
            return
        }

        if !user.Verified {
            jsonResponse(w, http.StatusUnauthorized, "Account not verified", nil)
            return
        }

        if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
            db.IncrementUnsuccessfulSignins(username)
            jsonResponse(w, http.StatusUnauthorized, "Invalid credentials", nil)
            return
        }

        db.ResetUnsuccessfulSignins(username)
        err = db.IncrementSigninCount(user.UserID)
        if err != nil {
            log.Printf("Failed to increment signin count: %v", err)
        }

        if config.UseJWTAuth {
            token, err := generateJWT(user)
            if err != nil {
                http.Error(w, "Could not generate token", http.StatusInternalServerError)
                return
            }
            jsonResponse(w, http.StatusOK, "Signin successful", map[string]string{"token": token})
        } else {
            session, _ := store.Get(r, "session")
            session.Values["username"] = username
            session.Save(r, w)
            jsonResponse(w, http.StatusSeeOther, "Signin successful", nil)
        }
    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

func signoutHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")
    delete(session.Values, "username")
    session.Save(r, w)
    jsonResponse(w, http.StatusOK, "Signout successful", nil)
}

func forgotHandler(w http.ResponseWriter, r *http.Request) {
    if !dbAvailable {
        jsonResponse(w, http.StatusServiceUnavailable, "Database not available", nil)
        return
    }
    switch r.Method {
    case http.MethodPost:
        email := r.FormValue("email")

        if !isValidEmail(email) {
            jsonResponse(w, http.StatusBadRequest, "Invalid email", nil)
            return
        }

        token, err := generateResetToken(email)
        if err != nil {
            jsonResponse(w, http.StatusInternalServerError, "Could not generate token", nil)
            return
        }

        resetURL := fmt.Sprintf("%s/reset?token=%s", config.WebServerAddress, token)
        emailBody := fmt.Sprintf("Click the link to reset your password: %s", resetURL)
        sendEmail(email, "Reset your password", emailBody)

        jsonResponse(w, http.StatusSeeOther, "Password reset email sent", nil)
    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
    if !dbAvailable {
        jsonResponse(w, http.StatusServiceUnavailable, "Database not available", nil)
        return
    }
    switch r.Method {
    case http.MethodPost:
        token := r.FormValue("token")
        newPassword := r.FormValue("new_password")

        if !isValidPassword(newPassword) {
            jsonResponse(w, http.StatusBadRequest, "Invalid input", nil)
            return
        }

        email, err := validateResetToken(token)
        if err != nil {
            jsonResponse(w, http.StatusUnauthorized, "Invalid token", nil)
            return
        }

        hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
        err = db.UpdateUserPasswordByEmail(email, string(hashedPassword))
        if err != nil {
            jsonResponse(w, http.StatusBadRequest, "Could not update password", nil)
            return
        }

        jsonResponse(w, http.StatusSeeOther, "Password reset successful", nil)
    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
    if !dbAvailable {
        jsonResponse(w, http.StatusServiceUnavailable, "Database not available", nil)
        return
    }
    switch r.Method {
    case http.MethodGet:
        token := r.URL.Query().Get("token")
        userID, err := validateVerificationToken(token)
        if err != nil {
            jsonResponse(w, http.StatusBadRequest, "Invalid token", nil)
            return
        }

        user, err := db.GetUserByID(userID)
        if err != nil {
            jsonResponse(w, http.StatusInternalServerError, "Could not retrieve user", nil)
            return
        }

        err = db.UpdateUserVerification(user.Email)
        if err != nil {
            jsonResponse(w, http.StatusBadRequest, "Verification failed", nil)
            return
        }

        jsonResponse(w, http.StatusSeeOther, "Account verified", nil)
    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

func generateVerificationToken(userID string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user_id": userID,
        "exp":     time.Now().Add(15 * time.Minute).Unix(),
    })
    return token.SignedString([]byte(config.JWTSecret))
}

func validateVerificationToken(tokenString string) (string, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(config.JWTSecret), nil
    })
    if err != nil {
        return "", err
    }
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        return claims["user_id"].(string), nil
    }
    return "", fmt.Errorf("invalid token")
}

func generateResetToken(email string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "email": email,
        "exp":   time.Now().Add(15 * time.Minute).Unix(),
    })
    return token.SignedString([]byte(config.JWTSecret))
}

func validateResetToken(tokenString string) (string, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(config.JWTSecret), nil
    })
    if err != nil {
        return "", err
    }
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        return claims["email"].(string), nil
    }
    return "", fmt.Errorf("invalid token")
}

func sendEmail(to, subject, body string) error {
    m := gomail.NewMessage()
    m.SetHeader("From", config.EmailSender)
    m.SetHeader("To", to)
    m.SetHeader("Subject", subject)
    m.SetHeader("Reply-To", config.EmailReplyTo)
    m.SetBody("text/plain", body)

    d := gomail.NewDialer(config.SmtpHost, config.SmtpPort, config.EmailSender, config.EmailPassword)

    return d.DialAndSend(m)
}

func sendVerificationEmail(to, token string) error {
    verificationURL := fmt.Sprintf("%s/verify?token=%s", config.WebServerAddress, token)
    emailBody := fmt.Sprintf("Please click the following link to verify your account: %s", verificationURL)
    return sendEmail(to, "Verify your account", emailBody)
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

func isValidURL(url string) bool {
    re := regexp.MustCompile(`^https?://[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+$`)
    return re.MatchString(url)
}

func verifyRecaptcha(response string) bool {
    recaptchaURL := "https://www.google.com/recaptcha/api/siteverify"
    form := url.Values{}
    form.Add("secret", config.RecaptchaSecretKey)
    form.Add("response", response)

    resp, err := http.PostForm(recaptchaURL, form)
    if err != nil {
        log.Printf("Failed to verify reCAPTCHA: %v", err)
        return false
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Printf("Failed to read reCAPTCHA response body: %v", err)
        return false
    }

    var result map[string]interface{}
    if err := json.Unmarshal(body, &result); err != nil {
        log.Printf("Failed to unmarshal reCAPTCHA response: %v", err)
        return false
    }

    success, ok := result["success"].(bool)
    return ok && success
}

func isStaticallyLinked() bool {
    f, err := os.Open("/proc/self/exe")
    if err != nil {
        log.Fatalf("Failed to open /proc/self/exe: %v", err)
    }
    defer f.Close()

    buf := make([]byte, 1024)
    _, err = f.Read(buf)
    if err != nil {
        log.Fatalf("Failed to read /proc/self/exe: %v", err)
    }

    dynamicLinkers := []string{
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/ld-linux.so.2",
    }
    for _, linker := range dynamicLinkers {
        if len(buf) >= len(linker) && string(buf[:len(linker)]) == linker {
            return false
        }
    }
    return true
}

func jailSelf() {
    log.Println("Running on Linux")
    if runtime.GOOS != "linux" {
        log.Println("Skipping jailSelf: not running on Linux")
        return
    }

    if !isStaticallyLinked() {
        log.Fatal("This program must be statically compiled!")
    }

    if os.Geteuid() != 0 {
        log.Fatal("This program must be run as root!")
    }

    if userNameOrID == "" || groupNameOrID == "" {
        log.Fatal("User and group must be provided!")
    }

    var uid, gid int
    var err error

    if userID, err := strconv.Atoi(userNameOrID); err == nil {
        uid = userID
    } else {
        usr, err := user.Lookup(userNameOrID)
        if err != nil {
            log.Fatalf("Failed to lookup user: %v", err)
        }
        uid, err = strconv.Atoi(usr.Uid)
        if err != nil {
            log.Fatalf("Failed to convert user ID: %v", err)
        }
    }

    if groupID, err := strconv.Atoi(groupNameOrID); err == nil {
        gid = groupID
    } else {
        grp, err := user.LookupGroup(groupNameOrID)
        if err != nil {
            log.Fatalf("Failed to lookup group: %v", err)
        }
        gid, err = strconv.Atoi(grp.Gid)
        if err != nil {
            log.Fatalf("Failed to convert group ID: %v", err)
        }
    }

    tempDir := os.TempDir()
    jailPath := filepath.Join(tempDir, "identorochroot")

    if _, err := os.Stat(jailPath); err == nil {
        if err = os.RemoveAll(jailPath); err != nil {
            log.Fatalf("Failed to remove existing directory: %v", err)
        }
    }

    if err = os.Mkdir(jailPath, 0755); err != nil {
        log.Fatalf("Failed to create directory: %v", err)
    }

    if err = os.Chdir(jailPath); err != nil {
        log.Fatalf("Failed to change directory: %v", err)
    }

    if err = syscall.Chroot("."); err != nil {
        log.Fatalf("Failed to chroot: %v", err)
    }

    if err = syscall.Setgid(gid); err != nil {
        log.Fatalf("Failed to set group ID: %v", err)
    }

    if err = syscall.Setuid(uid); err != nil {
        log.Fatalf("Failed to set user ID: %v", err)
    }

    log.Printf("Dropped privileges to user: %s and group: %s", userNameOrID, groupNameOrID)
}

func meHandler(w http.ResponseWriter, r *http.Request) {
    if !dbAvailable {
        jsonResponse(w, http.StatusServiceUnavailable, "Database not available", nil)
        return
    }
    if config.UseJWTAuth {
        tokenString := r.Header.Get("Authorization")
        if tokenString == "" {
            jsonResponse(w, http.StatusUnauthorized, "Authorization header is required", nil)
            return
        }

        tokenString = strings.TrimPrefix(tokenString, "Bearer ")
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }
            return []byte(config.JWTSecret), nil
        })

        if err != nil || !token.Valid {
            jsonResponse(w, http.StatusUnauthorized, "Invalid token", nil)
            return
        }

        if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
            userID := claims["user_id"].(string)
            user, err := db.GetUserByID(userID)
            if err != nil {
                jsonResponse(w, http.StatusInternalServerError, "Could not retrieve user", nil)
                return
            }
            jsonResponse(w, http.StatusOK, "User info", user)
        } else {
            jsonResponse(w, http.StatusUnauthorized, "Invalid token claims", nil)
        }
    } else {
        session, _ := store.Get(r, "session")
        username, ok := session.Values["username"].(string)
        if !ok {
            jsonResponse(w, http.StatusUnauthorized, "Not signed in", nil)
            return
        }
        user, err := db.GetUserByUsername(username)
        if err != nil {
            jsonResponse(w, http.StatusInternalServerError, "Could not retrieve user", nil)
            return
        }
        jsonResponse(w, http.StatusOK, "User info", user)
    }
}
