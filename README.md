Here is a `README.md` file for the program:

```markdown
# Go Web Server with Rate Limiting and CSRF Protection

This is a Go web server that supports user signup, signin, password reset, and account verification functionalities. It uses PostgreSQL (via `pgx` driver) or SQLite for data storage and includes rate limiting for login attempts per account.

## Features

- User Signup
- User Signin
- Password Reset
- Account Verification
- CSRF Protection
- Rate Limiting (15 login attempts per account per hour)
- Configurable via Environment Variables
- Graceful Shutdown on SIGINT or SIGTERM

## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/your-repo/go-web-server.git
    cd go-web-server
    ```

2. **Install dependencies:**

    ```bash
    go mod tidy
    ```

3. **Create a `.env` file:**

    ```bash
    cp .env.example .env
    ```

4. **Update the `.env` file with your configuration:**

    ```
    DB_TYPE=postgres
    DATABASE_URL=your_database_url
    SECRET_KEY=your_secret_key
    EMAIL_SENDER=your_email_sender
    EMAIL_PASSWORD=your_email_password
    SMTP_HOST=your_smtp_host
    SMTP_PORT=your_smtp_port
    WEB_SERVER_ADDRESS=http://localhost:8080
    EMAIL_REPLY_TO=your_reply_to_email
    RECAPTCHA_SITE_KEY=your_recaptcha_site_key
    RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
    ```

## Usage

1. **Run the server:**

    ```bash
    go run main.go
    ```

2. **Access the server:**

    Open your browser and go to `http://localhost:8080`

## API Endpoints

- `/signup` - User signup
- `/signin` - User signin
- `/signout` - User signout
- `/forgot` - Password reset request
- `/reset` - Password reset
- `/verify` - Account verification

## Configuration

The server can be configured using the following environment variables:

- `DB_TYPE` - Type of database (`postgres` or `sqlite`)
- `DATABASE_URL` - Connection string for the database
- `SECRET_KEY` - Secret key for session cookies and CSRF protection
- `EMAIL_SENDER` - Email address used for sending emails
- `EMAIL_PASSWORD` - Password for the email sender
- `SMTP_HOST` - SMTP server host
- `SMTP_PORT` - SMTP server port
- `WEB_SERVER_ADDRESS` - Address of the web server
- `EMAIL_REPLY_TO` - Reply-to email address
- `RECAPTCHA_SITE_KEY` - Site key for Google reCAPTCHA
- `RECAPTCHA_SECRET_KEY` - Secret key for Google reCAPTCHA

## Rate Limiting

The server implements rate limiting to prevent abuse of the login functionality. Each account (username) is limited to 15 login attempts per hour. If the limit is exceeded, a "Too Many Requests" response is returned.

## Graceful Shutdown

The server handles `SIGINT` and `SIGTERM` signals for graceful shutdown, ensuring that the database connection is properly closed before the server exits.

## Example SQL for PostgreSQL Updatable View

If you are using PostgreSQL, you might need an updatable view for compatibility with existing tables. Here is an example SQL script:

```sql
CREATE VIEW user_view AS
SELECT id, user_name AS username, passwd AS password, mail AS email, reset_token, is_verified AS verified, verification_token
FROM old_users_table;

CREATE RULE update_user_view AS
ON UPDATE TO user_view
DO INSTEAD
UPDATE old_users_table
SET user_name = NEW.username,
    passwd = NEW.password,
    mail = NEW.email,
    reset_token = NEW.reset_token,
    is_verified = NEW.verified,
    verification_token = NEW.verification_token
WHERE id = NEW.id;
```

## License

This project is licensed under the MIT License.
```

You can customize the repository URL, email addresses, and any other details specific to your project. This `README.md` provides an overview of the features, installation instructions, usage, configuration options, rate limiting, graceful shutdown, and an example SQL script for PostgreSQL.
