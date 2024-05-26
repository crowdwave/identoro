# Identoro User Signup Server for SQLite or PostgreSQL

This is a Go web server that supports user signup, signin, password reset, and account verification functionalities. It uses PostgreSQL (via `pgx` driver) or SQLite for data storage and includes rate limiting for login attempts per account.

## Features

- User Signup
- User Signin
- Password Reset (using time-expiring signed strings)
- Account Verification
- CSRF Protection
- Rate Limiting (15 login attempts per account per hour)
- Configurable via Environment Variables
- Graceful Shutdown on SIGINT or SIGTERM

## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/crowdwave/identoro.git
    cd identoro
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
    USER=your_user_name_or_id
    GROUP=your_group_name_or_id
    HASH_KEY=your_hash_key
    ```

## Environment Variables

- `DB_TYPE`: The type of database to use. Set to either `postgres` for PostgreSQL or `sqlite` for SQLite.
- `DATABASE_URL`: The connection string for the database. For PostgreSQL, it typically looks like `postgres://user:password@hostname:port/dbname`. For SQLite, it is the path to the database file.
- `SECRET_KEY`: A secret key used for session cookies and CSRF protection. It should be a strong, random string.
- `EMAIL_SENDER`: The email address that will be used to send emails (e.g., noreply@example.com).
- `EMAIL_PASSWORD`: The password for the email sender account.
- `SMTP_HOST`: The SMTP server host used to send emails.
- `SMTP_PORT`: The SMTP server port (e.g., 587 for TLS, 465 for SSL).
- `WEB_SERVER_ADDRESS`: The address where the web server will be hosted (e.g., http://localhost:8080).
- `EMAIL_REPLY_TO`: The reply-to email address for outgoing emails.
- `RECAPTCHA_SITE_KEY`: The site key for Google reCAPTCHA used to verify human users.
- `RECAPTCHA_SECRET_KEY`: The secret key for Google reCAPTCHA used to verify human users.
- `USER`: The user name or ID to drop privileges to after the server has started. This is used for security purposes.
- `GROUP`: The group name or ID to drop privileges to after the server has started. This is used for security purposes.
- `HASH_KEY`: A secret key used for generating secure tokens. It should be a strong, random string. You can generate one using the following command:

    ```sh
    dd if=/dev/urandom bs=32 count=1 | base64
    ```

## To compile it yourself

A binary is provided for 64 bit AMD64 linux but you can compile it yourself for other platforms.

Clone the repository:

```sh
git clone https://github.com/crowdwave/identoro.git
cd identoro
```

Build the server:

```sh
go mod tidy
CGO_ENABLED=0 go build -o identoro main.go
```

## Usage

### Why must identoro be started with sudo?

On Linux (not other platforms), this server must be started with sudo or as root. This is because when the server starts, it puts itself in a chroot jail which means it cannot see files outside its working directory. This is why you are required to provide `--user` and `--group` on the command line so that the server can change its user and group to a non-root user after it has started. This is a security feature to prevent the server from being able to access the entire file system.

1. **Run the server:**

    ```bash
    sudo ./identoro
    ```

2. **Access the server:**

    Open your browser and go to `http://localhost:8080`

## API Endpoints

### `/signup` - User Signup

- **Method**: POST
- **Expected Data**:
    ```json
    {
        "username": "string",
        "email": "string",
        "password": "string",
        "g-recaptcha-response": "string"
    }
    ```
- **HTML Output**: Renders the signup page.
- **JSON Output**: 
    - Success: `{"status": 303, "message": "Signup successful, please verify your email"}`
    - Error: `{"status": 400, "message": "Invalid input"}` or other relevant error messages.

### `/signin` - User Signin

- **Method**: POST
- **Expected Data**:
    ```json
    {
        "username": "string",
        "password": "string"
    }
    ```
- **HTML Output**: Renders the signin page.
- **JSON Output**:
    - Success: `{"status": 303, "message": "Signin successful"}`
    - Error: `{"status": 400, "message": "Invalid input"}` or other relevant error messages.

### `/signout` - User Signout

- **Method**: GET
- **HTML Output**: Redirects to the home page.
- **JSON Output**: `{"status": 200, "message": "Signout successful"}`

### `/forgot` - Password Reset Request

- **Method**: POST
- **Expected Data**:
    ```json
    {
        "email": "string"
    }
    ```
- **HTML Output**: Renders the forgot password page.
- **JSON Output**:
    - Success: `{"status": 303, "message": "Password reset email sent"}`
    - Error: `{"status": 400, "message": "Invalid email"}` or other relevant error messages.

### `/reset` - Password Reset

- **Method**: POST
- **Expected Data**:
    ```json
    {
        "token": "string",
        "new_password": "string"
    }
    ```
- **HTML Output**: Renders the reset password page.
- **JSON Output**:
    - Success: `{"status": 303, "message": "Password reset successful"}`
    - Error: `{"status": 400, "message": "Invalid token"}` or other relevant error messages.

### `/verify` - Account Verification

- **Method**: GET
- **Expected Data**:
    ```json
    {
        "token": "string"
    }
    ```
- **HTML Output**: Redirects to the signin page.
- **JSON Output**:
    - Success: `{"status": 303, "message": "Account verified"}`
    - Error: `{"status": 400, "message": "Invalid token"}` or other relevant error messages.

## Rate Limiting

The server implements rate limiting to prevent abuse of the login functionality. Each account (username) is limited to 15 login attempts per hour. If the limit is exceeded, a "Too Many Requests" response is returned.

## Graceful Shutdown

The server handles `SIGINT` and `SIGTERM` signals

 for graceful shutdown, ensuring that the database connection is properly closed before the server exits.

## Integration with PostgreSQL 

### If you are using Postgres and already have a users table.

Identoro works with your existing Postgres users table via Postgres views which map our SQL queries to your table and field names. You need to create the necessary views on your Postgres server, ensuring the required fields are present and have matching column data types.

The view names must be exactly as shown below and all fields must be present - your job is to put in the name of your users table and the names of the fields in your users table.

### Example:

Assuming your actual `users` table (`actual_users_table`) has the following schema:

```sql
CREATE TABLE actual_users_table (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_name VARCHAR(50) NOT NULL,
    passwd VARCHAR(100) NOT NULL,
    mail VARCHAR(100) NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    verification_token VARCHAR(50)
);
```

Your view should ensure that the columns have the same data types:

```sql
CREATE VIEW identoro_users AS
SELECT 
    user_id, 
    user_name AS username, 
    passwd AS password, 
    mail AS email, 
    is_verified AS verified, 
    verification_token 
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
SET 
    user_name = NEW.username,
    passwd = NEW.password,
    mail = NEW.email,
    is_verified = NEW.verified,
    verification_token = NEW.verification_token
WHERE user_id = NEW.user_id;

```

### Key Points to Ensure

- **Matching Data Types**: Ensure that the data types of the columns in the view match the data types of the columns in the underlying table. This is critical for insert, update, and select operations to work correctly.
- **Constraints and Defaults**: Any constraints (like `NOT NULL`, `DEFAULT`, etc.) or default values should also be considered to ensure data integrity.
- **Indexes**: Indexes on the underlying table can help optimize the performance of queries on the view.

### If you are using Postgres and do not already have a users table

If you do not have an existing users table, you can use the following SQL to create the needed users table (in this context you do not need the views):

```sql
-- Create the users table
CREATE TABLE identoro_users (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_name VARCHAR(50) NOT NULL,
    passwd VARCHAR(100) NOT NULL,
    mail VARCHAR(100) NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    verification_token VARCHAR(50)
);
```

By ensuring data type consistency and respecting constraints, your views will correctly map the columns and provide seamless integration with the Identoro server's queries.


To turn this into a Create React App (CRA) project with TypeScript, follow these steps:

1. **Install Create React App with TypeScript:**

```bash
npx create-react-app identoro-client --template typescript
cd identoro-client
```

2. **Replace the content of `src/App.tsx` with the provided code in ui_react.tsx:**



3. **Install additional dependencies:**

```bash
npm install react-router-dom @types/react-router-dom
```

4. **Start the development server:**

```bash
npm start
```

### Explanation:
- We have created individual components for each page: `Signup`, `Signin`, `Signout`, `ForgotPassword`, `ResetPassword`, `VerifyAccount`, and `Home`.
- The main `App` component uses `useState` to manage authentication state and `useEffect` to check authentication status on load.
- `localStorage` is used to store the `userId` when a user signs in and to remove it when they sign out.
- Routes are defined for each component using `react-router-dom`.


## License

This project is licensed under the MIT License.

---

This documentation now fully explains each environment variable and provides detailed information about generating and using the `HASH_KEY`.
