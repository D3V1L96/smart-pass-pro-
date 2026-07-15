| Method | Endpoint           | Description   |
| ------ | ------------------ | ------------- |
| POST   | /api/auth/register | Register User |
| POST   | /api/auth/login    | Login         |
| POST   | /api/auth/google   | Google OAuth  |
| POST   | /api/auth/logout   | Logout        |
| POST   | /api/auth/refresh  | Refresh Token |
==============================================
| Method | Endpoint         |
| ------ | ---------------- |
| POST   | /api/pass/create |
| GET    | /api/pass/all    |
| GET    | /api/pass/:id    |
| PUT    | /api/pass/update |
| DELETE | /api/pass/delete |
============================
| Method | Endpoint         |
| ------ | ---------------- |
| GET    | /api/admin/users |
| PUT    | /api/admin/user  |
| DELETE | /api/admin/user  |
| GET    | /api/admin/audit |
============================
| Security Control     | Description                        |
| -------------------- | ---------------------------------- |
| JWT Authentication   | Secure access tokens               |
| Refresh Tokens       | Long-lived session management      |
| Google OAuth         | Trusted third-party authentication |
| bcrypt               | Password hashing                   |
| Helmet               | Secure HTTP headers                |
| Rate Limiting        | Prevent brute-force attacks        |
| RBAC                 | Role-based permissions             |
| Joi Validation       | Request validation                 |
| SQL Parameterization | Prevent SQL Injection              |
| CORS Protection      | Cross-origin access control        |
| Secure Cookies       | Token protection                   |
| Audit Logs           | Complete activity tracking         |
| OTP Verification     | Additional verification layer      |
| QR Validation        | Prevent duplicate pass usage       |
============================================================
| Role          | Permissions                                          |
| ------------- | ---------------------------------------------------- |
| Student       | Create and track personal pass requests              |
| Teacher       | Create and manage student requests                   |
| Principal     | Review, approve, or reject requests                  |
| Guard         | Verify QR codes and validate gate passes             |
| Administrator | Manage users, roles, system settings, and audit logs |
=======================================================================
