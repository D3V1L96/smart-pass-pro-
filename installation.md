Here's a professional **INSTALLATION.md** suitable for a GitHub repository. It is written from a developer's perspective and covers local setup, configuration, database, and production deployment.

# Installation Guide

Welcome to **SmartPass Pro**.

This guide explains how to install, configure, and run SmartPass Pro on your local development environment. Follow each step carefully to ensure a successful setup.

---

# System Requirements

| Component             | Requirement                                         |
| --------------------- | --------------------------------------------------- |
| Operating System      | Windows 10/11, Linux, or macOS                      |
| Node.js               | v18.x or later (LTS Recommended)                    |
| npm                   | v9.x or later                                       |
| PostgreSQL            | v14+ (or Neon PostgreSQL)                           |
| Git                   | Latest Version                                      |
| Modern Browser        | Chrome, Edge, Firefox                               |
| VS Code (Recommended) | Latest Version                                      |
| Internet Connection   | Required for Google OAuth and Resend Email Services |

---

# Technology Stack

| Layer          | Technology                 |
| -------------- | -------------------------- |
| Frontend       | HTML5, CSS3, JavaScript    |
| Backend        | Node.js, Express.js        |
| Database       | PostgreSQL (Neon)          |
| Real-Time      | Socket.IO                  |
| Authentication | JWT + Google OAuth         |
| Email Service  | Resend                     |
| Security       | Helmet, Rate Limiting, Joi |

---

# Project Structure

```text
SmartPass-Pro/
│
├── frontend/
│
├── backend/
│
├── package.json
│
├── README.md
│
├── INSTALLATION.md
│
└── .env
```

---

# Step 1 — Clone the Repository

```bash
git clone https://github.com/USERNAME/SmartPass-Pro.git
```

Replace `USERNAME` with your GitHub username.

Navigate into the project directory:

```bash
cd SmartPass-Pro
```

---

# Step 2 — Install Dependencies

Install all required Node.js packages.

```bash
npm install
```

If the frontend and backend are separated:

Backend:

```bash
cd backend
npm install
```

Frontend:

```bash
cd ../frontend
npm install
```

---

# Step 3 — Configure Environment Variables

Create a `.env` file inside the backend directory.

Example:

```env
# Server
PORT=3000
NODE_ENV=development

# JWT
JWT_SECRET=your_jwt_secret
JWT_REFRESH_SECRET=your_refresh_secret
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# PostgreSQL
DATABASE_URL=postgresql://username:password@host/database

# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# Resend
RESEND_API_KEY=your_resend_api_key

# Frontend
CLIENT_URL=http://localhost:5500
```

**Never commit your `.env` file to GitHub.**

---

# Step 4 — Configure PostgreSQL Database

Create a PostgreSQL database.

Example:

```sql
CREATE DATABASE smartpass_pro;
```

Run the database schema and migration files to create the required tables.

Example tables include:

* users
* roles
* gate_passes
* sessions
* refresh_tokens
* otp_logs
* audit_logs
* notifications

After updating your `.env`, verify that the backend connects successfully to the database.

---

# Step 5 — Start the Backend Server

Navigate to the backend directory.

```bash
cd backend
```

Run:

```bash
node server.js
```

or, if using Nodemon:

```bash
npm run dev
```

You should see output similar to:

```text
Server running on port 3000
Connected to PostgreSQL
Socket.IO initialized
```

---

# Step 6 — Launch the Frontend

If using static HTML:

Open `index.html` using Live Server in Visual Studio Code.

Or start the frontend development server if one is configured:

```bash
npm start
```

Open your browser:

```
http://localhost:5500
```

or the configured frontend URL.

---

# Step 7 — Verify the Installation

Confirm the following:

* Backend server starts without errors.
* Database connection is established.
* Login page loads successfully.
* User registration and authentication work correctly.
* JWT authentication is functioning.
* Google OAuth login works (if configured).
* Socket.IO establishes a real-time connection.
* Email and OTP delivery works.
* QR code generation functions correctly.
* All role-based dashboards are accessible according to permissions.

---

# Running the Application

Start the backend:

```bash
cd backend
npm run dev
```

Start the frontend:

```bash
cd frontend
npm start
```

Open the application in your browser.

---

# Production Deployment

Before deploying SmartPass Pro:

* Set `NODE_ENV=production`.
* Use HTTPS with a valid SSL certificate.
* Store secrets securely using environment variables.
* Enable secure cookies.
* Configure CORS for production domains only.
* Use a production PostgreSQL (Neon) instance.
* Configure Google OAuth production redirect URIs.
* Configure the Resend production API key.
* Enable application monitoring and logging.
* Schedule regular database backups.

---

# Recommended VS Code Extensions

* ESLint
* Prettier
* DotENV
* PostgreSQL
* REST Client
* GitLens
* Error Lens

---

# Common Installation Issues

| Issue                        | Solution                                                       |
| ---------------------------- | -------------------------------------------------------------- |
| Cannot connect to PostgreSQL | Verify `DATABASE_URL` and database availability.               |
| JWT authentication fails     | Ensure JWT secrets are correctly configured.                   |
| Google login fails           | Verify OAuth credentials and authorized redirect URIs.         |
| Emails are not sent          | Confirm the Resend API key and sender domain configuration.    |
| Socket.IO not connecting     | Check CORS settings and server availability.                   |
| QR verification fails        | Ensure pass approval and QR generation completed successfully. |

---

# Updating Dependencies

To install the latest compatible package versions:

```bash
npm update
```

To install a new package:

```bash
npm install <package-name>
```

---

# Security Recommendations

* Never expose secrets in source code.
* Never commit `.env` files.
* Use HTTPS in production.
* Rotate JWT secrets periodically.
* Regularly update dependencies.
* Restrict database access to trusted hosts.
* Monitor audit logs for suspicious activity.
* Enable rate limiting and secure HTTP headers.

---

# Installation Complete

If every step has been completed successfully, SmartPass Pro is ready for development or deployment.

For additional information about the project architecture, workflow, and features, refer to the `README.md`.
