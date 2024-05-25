package main

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

    "github.com/gorilla/sessions"
    "github.com/gomail/gomail"
    "github.com/joho/godotenv"
    _ "github.com/mattn/go-sqlite3"
    "golang.org/x/crypto/bcrypt"
    "html/template"
)

var (
    db                *sql.DB
    store             *sessions.CookieStore
    tmpl              = template.Must(template.ParseGlob("templates/*.html"))
    emailSender       string
    emailPassword     string
    smtpHost          string
    smtpPort          int
    dbName            string
    webServerAddress  string
    emailReplyTo      string
)

func init() {
    err := godotenv.Load()
    if err != nil {
        log.Fatal("Error loading .env file")
    }

    dbName = os.Getenv("DB_NAME")
    if dbName == "" {
        log.Fatal("DB_NAME is not set in .env file")
    }

    secretKey := os.Getenv("SECRET_KEY")
    if secretKey == "" {
        log.Fatal("SECRET_KEY is not set in .env file")
    }

    emailSender = os.Getenv("EMAIL_SENDER")
    if emailSender == "" {
        log.Fatal("EMAIL_SENDER is not set in .env file")
    }

    emailPassword = os.Getenv("EMAIL_PASSWORD")
    if emailPassword == "" {
        log.Fatal("EMAIL_PASSWORD is not set in .env file")
    }

    smtpHost = os.Getenv("SMTP_HOST")
    if smtpHost == "" {
        log.Fatal("SMTP_HOST is not set in .env file")
    }

    smtpPortStr := os.Getenv("SMTP_PORT")
    if smtpPortStr == "" {
        log.Fatal("SMTP_PORT is not set in .env file")
    }

    smtpPort, err = strconv.Atoi(smtpPortStr)
    if err != nil {
        log.Fatal("Invalid SMTP_PORT value in .env file")
    }

    webServerAddress = os.Getenv("WEB_SERVER_ADDRESS")
    if webServerAddress == "" {
        log.Fatal("WEB_SERVER_ADDRESS is not set in .env file")
    }

    emailReplyTo = os.Getenv("EMAIL_REPLY_TO")
    if emailReplyTo == "" {
        log.Fatal("EMAIL_REPLY_TO is not set in .env file")
    }

    store = sessions.NewCookieStore([]byte(secretKey))
}

func main() {
    createDB := flag.Bool("create-db", false, "Create the database")
    flag.Parse()

    if *createDB {
        if flag.NFlag() != 1 {
            log.Fatal("No other flags should be provided when using -create-db")
        }
        createDatabase()
        return
    }

    var err error
    db, err = sql.Open("sqlite3", dbName)
    if err != nil {
        log.Fatal(err)
    }

    http.Handle("/", logRequest(http.HandlerFunc(homeHandler)))
    http.Handle("/signup", logRequest(http.HandlerFunc(signupHandler)))
    http.Handle("/signin", logRequest(http.HandlerFunc(signinHandler)))
    http.Handle("/signout", logRequest(http.HandlerFunc(signoutHandler)))
    http.Handle("/forgot", logRequest(http.HandlerFunc(forgotHandler)))
    http.Handle("/reset", logRequest(http.HandlerFunc(resetHandler)))
    http.Handle("/verify", logRequest(http.HandlerFunc(verifyHandler)))

    log.Println("Server started at :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func createDatabase() {
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
        ip, _, err := net.SplitHostPort(r.RemoteAddr)
        if err != nil {
            ip = r.RemoteAddr
        }
        log.Printf("%s - %s - %s %s\n", time.Now().Format(time.RFC3339), ip, r.Method, r.URL.Path)
        handler.ServeHTTP(w, r)
    })
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")
    tmpl.ExecuteTemplate(w, "home.html", session.Values["username"])
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        email := r.FormValue("email")
        password := r.FormValue("password")

        if !isValidUsername(username) || !isValidEmail(email) || !isValidPassword(password) {
            http.Error(w, "Invalid input", http.StatusBadRequest)
            return
        }

        hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
        verificationToken := generateToken()
        _, err := db.Exec("INSERT INTO users (username, password, email, verification_token) VALUES (?, ?, ?, ?)", username, hashedPassword, email, verificationToken)
        if err != nil {
            http.Error(w, "Username or email already exists", http.StatusBadRequest)
            return
        }

        verificationURL := fmt.Sprintf("%s/verify?token=%s", webServerAddress, verificationToken)
        emailBody := fmt.Sprintf("Please click the following link to verify your account: %s", verificationURL)
        sendEmail(email, "Verify your account", emailBody)

        http.Redirect(w, r, "/signin", http.StatusSeeOther)
    } else {
        tmpl.ExecuteTemplate(w, "signup.html", nil)
    }
}

func signinHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")

        if !isValidUsername(username) || !isValidPassword(password) {
            http.Error(w, "Invalid input", http.StatusBadRequest)
            return
        }

        var hashedPassword string
        var verified bool
        err := db.QueryRow("SELECT password, verified FROM users WHERE username = ?", username).Scan(&hashedPassword, &verified)
        if err != nil {
            http.Error(w, "Invalid credentials", http.StatusUnauthorized)
            return
        }

        if !verified {
            http.Error(w, "Account not verified", http.StatusUnauthorized)
            return
        }

        if bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) != nil {
            http.Error(w, "Invalid credentials", http.StatusUnauthorized)
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
            http.Error(w, "Invalid email", http.StatusBadRequest)
            return
        }

        resetToken := generateToken()
        _, err := db.Exec("UPDATE users SET reset_token = ? WHERE email = ?", resetToken, email)
        if err != nil {
            http.Error(w, "Invalid email", http.StatusBadRequest)
            return
        }

        resetURL := fmt.Sprintf("%s/reset?token=%s", webServerAddress, resetToken)
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
            http.Error(w, "Invalid input", http.StatusBadRequest)
            return
        }

        hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
        _, err := db.Exec("UPDATE users SET password = ?, reset_token = NULL WHERE reset_token = ?", hashedPassword, token)
        if err != nil {
            http.Error(w, "Invalid token", http.StatusBadRequest)
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
        http.Error(w, "Invalid token", http.StatusBadRequest)
        return
    }

    rowsAffected, err := result.RowsAffected()
    if err != nil || rowsAffected == 0 {
        http.Error(w, "Invalid token", http.StatusBadRequest)
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
    m.SetHeader("From", emailSender)
    m.SetHeader("To", to)
    m.SetHeader("Subject", subject)
    m.SetHeader("Reply-To", emailReplyTo)
    m.SetBody("text/plain", body)

    d := gomail.NewDialer(smtpHost, smtpPort, emailSender, emailPassword)

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
