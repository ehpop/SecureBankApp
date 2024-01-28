# SecureBankApp

(Hopefully) secure bank application.
![Logged In](images/logged-in.png)

## Requirements

You just need Docker!

## To run with docker

```shell
docker compose up --build
```

---

### Features

- **User Authentication:**
  - User can register to create an account.
  - ![Register](images/register.png)
  - Random password combinations during log in enhance security.
  - ![Login Username](images/log-in-username.png)
  - ![Login Combination](images/log-in-combination.png)
  - User can change password.
  - ![Change Password](images/change-password.png)

- **Log in Attempts:**
  - User can see his login attempts.
  - ![Failed Login Attempts](images/show-login-attempts.png)

- **Money Transactions:**
  - Secure money transfer functionality.
  - ![Transfer](images/make-transaction.png)
  - View transaction history.
  - ![History](images/show-transactions.png)

- **Document Management:**
  - Upload and manage encrypted documents securely.
  - ![Upload](images/file-upload.png)
  - ![Upload](images/manage-files.png)
  - Access and delete documents with proper authentication.
  - ![Access Document](images/access-document.png)
  - ![Delete Document](images/delete-document.png)

- **Password Recovery:**
  - Password recovery process with email verification.
  - ![Password Recovery 1](images/password-recovery-1.png)
  - Set a new password after password recovery.
  - ![Password Recovery 2](images/password-recovery-2.png)

- **Security Measures:**
  - CSRF protection with Flask-WTF.
  - Login attempts tracking and security timeouts.
  - Password strength checks and secure password storage.

- **HTTPS and SSL Protocol**
  - HTTPS protocol with SSL certificate.
  - SSL certificate generated with OpenSSL.
  - ![Certificate](images/cert.png)

- **Responsive design**
  - App can be accessed from mobile devices.
  - ![Responsive](images/mobile-main.png)
  - ![Responsive](images/mobile-login.png)
---

### Project Structure

- **config:** Contains configuration files, including server settings and timeouts.
- **models:** Database models for users, credentials, transactions, login attempts, credit cards, documents, and
  password recovery codes.
- **forms:** Web forms for user input validation, including login, registration, transfer, document management, password
  recovery, and password change.
- **views_helper:** Helper functions for password-related operations and user authentication.
- **helpers:** Additional helper functions, including password strength checking.

---

### Technologies

- **Flask:** Web framework for Python.
- **Flask-WTF:** Form validation and CSRF protection.
- **Bootstrap:** Front-end framework.
- **Jinja2:** Template engine for Python.
- **SQLAlchemy:** ORM for Python.
- **PostgreSQL:** Database.
- **bcrypt:** Password hashing.
- **PyCryptodome:** Encryption and decryption.