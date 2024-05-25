import (
    "crypto/rand"
    "database/sql"
    "encoding/hex"
    "flag"
    "fmt"
    "log"
    "net"
    "net/http"
    "os"
    "regexp"
    "strconv"
    "time"

    "github.com/gorilla/csrf"
    "github.com/gorilla/sessions"
    "github.com/gomail/gomail"
    "github.com/joho/godotenv"
    _ "github.com/mattn/go-sqlite3"
    "golang.org/x/crypto/bcrypt"
    "html/template"
    "io/ioutil"
    "encoding/json"
)

var (
    db                *sql.DB
    store             *sessions.CookieStore
    tmpl              = template.Must(template.ParseGlob("templates/*.html"))
    config            *Config
)

type Config struct {
    SecretKey         string
    EmailSender       string
    EmailPassword     string
    SmtpHost          string
    SmtpPort          int
    DbName            string
    WebServerAddress  string
    EmailReplyTo      string
    RecaptchaSiteKey  string
    RecaptchaSecretKey string
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
        SecretKey:         os.Getenv("SECRET_KEY"),
        EmailSender:       os.Getenv("EMAIL_SENDER"),
        EmailPassword:     os.Getenv("EMAIL_PASSWORD"),
        SmtpHost:          os.Getenv("SMTP_HOST"),
        SmtpPort:          smtpPort,
        DbName:            os.Getenv("DB_NAME"),
        WebServerAddress:  os.Getenv("WEB_SERVER_ADDRESS"),
        EmailReplyTo:      os.Getenv("EMAIL_REPLY_TO"),
        RecaptchaSiteKey:  os.Getenv("RECAPTCHA_SITE_KEY"),
        RecaptchaSecretKey: os.Getenv("RECAPTCHA_SECRET_KEY"),
    }

    return config, nil
}

func main() {
    var err error
    config, err = loadConfig()
    if err != nil {
        log.Fatal(err)
    }

    store = sessions.NewCookieStore([]byte(config.SecretKey))
    store.Options = &sessions.Options{
        Path:     "/",
        MaxAge:   3600 * 8, // 8 hours
        HttpOnly: true,
        Secure:   true, // Ensure the cookie is sent over HTTPS
    }

    createDB := flag.Bool("create-db", false, "Create the database")
    flag.Parse()

    if *createDB {
        if flag.NFlag() != 1 {
            log.Fatal("No other flags should be provided when using -create-db")
        }
        createDatabase(config.DbName)
        return
    }

    db, err = sql.Open("sqlite3", config.DbName)
    if err != nil {
        log.Fatal(err)
    }

    csrfMiddleware := csrf.Protect([]byte(config.SecretKey))

    http.Handle("/", logRequest(csrfMiddleware(http.HandlerFunc(homeHandler))))
    http.Handle("/signup", logRequest(csrfMiddleware(http.HandlerFunc(signupHandler))))
    http.Handle("/signin", logRequest(csrfMiddleware(http.HandlerFunc(signinHandler))))
    http.Handle("/signout", logRequest(csrfMiddleware(http.HandlerFunc(signoutHandler))))
    http.Handle("/forgot", logRequest(csrfMiddleware(http.HandlerFunc(forgotHandler))))
    http.Handle("/reset", logRequest(csrfMiddleware(http.HandlerFunc(resetHandler))))
    http.Handle("/verify", logRequest(csrfMiddleware(http.HandlerFunc(verifyHandler))))

    log.Println("Server started at :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func createDatabase(dbName string) {
    if _, err := os.Stat(dbName); err == nil {
        fmt.Printf("Database %s already exists. Overwrite? (y/n): ", dbName)
        var response string
        fmt.Scanln(&response)
        if response != "y" {
            fmt.Println("Aborted.")
            return
        }
        os.Remove(dbName)
    }

    db, err := sql.Open("sqlite3", dbName)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    schema := `
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        reset_token TEXT,
        verified BOOLEAN NOT NULL DEFAULT FALSE,
        verification_token TEXT
    );
    `
    _, err = db.Exec(schema)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Database created successfully.")
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

func errorResponse(w http.ResponseWriter, statusCode int, message string) {
    w.WriteHeader(statusCode)
    w.Write([]byte(message))
    log.Printf("Error: %s, StatusCode: %d", message, statusCode)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")
    tmpl.ExecuteTemplate(w, "home.html", map[string]interface{}{
        "Username": session.Values["username"],
        "RecaptchaSiteKey": config.RecaptchaSiteKey,
    })
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        email := r.FormValue("email")
        password := r.FormValue("password")
        recaptchaResponse := r.FormValue("g-recaptcha-response")

        if !isValidUsername(username) || !isValidEmail(email) || !isValidPassword(password) {
            errorResponse(w, http.StatusBadRequest, "Invalid input")
            return
        }

        if !verifyRecaptcha(recaptchaResponse) {
            errorResponse(w, http.StatusBadRequest, "Invalid reCAPTCHA")
            return
        }

        hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        verificationToken := generateToken()
        _, err := db.Exec("INSERT INTO users (username, password, email, verification_token) VALUES (?, ?, ?, ?)", username, hashedPassword, email, verificationToken)
        if err != nil {
            errorResponse(w, http.StatusBadRequest, "Username or email already exists")
            return
        }

        verificationURL := fmt.Sprintf("%s/verify?token=%s", config.WebServerAddress, verificationToken)
        emailBody := fmt.Sprintf("Please click the following link to verify your account: %s", verificationURL)
        sendEmail(email, "Verify your account", emailBody)

        http.Redirect(w, r, "/signin", http.StatusSeeOther)
    } else {
        tmpl.ExecuteTemplate(w, "signup.html", map[string]interface{}{
            "RecaptchaSiteKey": config.RecaptchaSiteKey,
        })
    }
}

func verifyRecaptcha(response string) bool {
    secret := config.RecaptchaSecretKey
    req, err := http.NewRequest("POST", "https://www.google.com/recaptcha/api/siteverify", nil)
    if err != nil {
        log.Println("Failed to create reCAPTCHA request:", err)
        return false
    }

    q := req.URL.Query()
    q.Add("secret", secret)
    q.Add("response", response)
    req.URL.RawQuery = q.Encode()

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Println("Failed to verify reCAPTCHA:", err)
        return false
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Println("Failed to read reCAPTCHA response body:", err)
        return false
    }

    var recaptchaResponse struct {
        Success bool `json:"success"`
    }
    if err := json.Unmarshal(body, &recaptchaResponse); err != nil {
        log.Println("Failed to unmarshal reCAPTCHA response:", err)
        return false
    }

    return recaptchaResponse.Success
}

func signinHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")

        if !isValidUsername(username) || !isValidPassword(password) {
            errorResponse(w, http.StatusBadRequest, "Invalid input")
            return
        }

        var hashedPassword string
        var verified bool
        err := db.QueryRow("SELECT password, verified FROM users WHERE username = ?", username).Scan(&hashedPassword, &verified)
        if err != nil {
            errorResponse(w, http.StatusUnauthorized, "Invalid credentials")
            return
        }

        if !verified {
            errorResponse(w, http.StatusUnauthorized, "Account not verified")
            return
        }

        if bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) != nil {
            errorResponse(w, http.StatusUnauthorized, "Invalid credentials")
            return
        }

        session, _ := store.Get(r, "session")
        session.Values["username"] = username
        session.Save(r, w)

        http.Redirect(w, r, "/", http.StatusSeeOther)
    } else {
        tmpl.ExecuteTemplate(w, "signin.html", nil)
    }
}

func signoutHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")
    delete(session.Values, "username")
    session.Save(r, w)
    http.Redirect(w, r, "/", http.StatusSeeOther)
}

func forgotHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        email := r.FormValue("email")

        if !isValidEmail(email) {
            errorResponse(w, http.StatusBadRequest, "Invalid email")
            return
        }

        resetToken := generateToken()
        _, err := db.Exec("UPDATE users SET reset_token = ? WHERE email = ?", resetToken, email)
        if err != nil {
            errorResponse(w, http.StatusBadRequest, "Invalid email")
            return
        }

        resetURL := fmt.Sprintf("%s/reset?token=%s", config.WebServerAddress, resetToken)
        emailBody := fmt.Sprintf("Click the link to reset your password: %s", resetURL)
        sendEmail(email, "Reset your password", emailBody)

        http.Redirect(w, r, "/signin", http.StatusSeeOther)
    } else {
        tmpl.ExecuteTemplate(w, "forgot.html", nil)
    }
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        token := r.FormValue("token")
        newPassword := r.FormValue("new_password")

        if !isValidPassword(newPassword) {
            errorResponse(w, http.StatusBadRequest, "Invalid input")
            return
        }

        hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
        _, err := db.Exec("UPDATE users SET password = ?, reset_token = NULL WHERE reset_token = ?", hashedPassword, token)
        if err != nil {
            errorResponse(w, http.StatusBadRequest, "Invalid token")
            return
        }

        http.Redirect(w, r, "/signin", http.StatusSeeOther)
    } else {
        tmpl.ExecuteTemplate(w, "reset.html", nil)
    }
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")
    result, err := db.Exec("UPDATE users SET verified = 1, verification_token = NULL WHERE verification_token = ?", token)
    if err != nil {
        errorResponse(w, http.StatusBadRequest, "Invalid token")
        return
    }

    rowsAffected, err := result.RowsAffected()
    if err != nil || rowsAffected == 0 {
        errorResponse(w, http.StatusBadRequest, "Invalid token")
        return
    }

    http.Redirect(w, r, "/signin", http.StatusSeeOther)
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
