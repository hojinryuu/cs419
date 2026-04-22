# Secure Document Sharing System (CS 419)


A security-first web application built with Python/Flask that focuses on encrypted document storage, Role-Based Access Control (RBAC), and defense-in-depth authentication.


## Features
- **Identity:** Brute-force protection with account lockout logic.
- **Access Control:** RBAC enforcing Admin, User, and Guest roles.
- **Data Protection:** Fernet (AES-128) encryption at rest and TLS 1.3 in transit.
- **Audit Logging:** Persistent security event tracking in `security.log`.


## Prerequisites
- Python 3.10 or higher
- `pip` (Python package installer)


## Installation & Setup


1. **Clone the repository:**
  ```bash
      git clone <your-repo-url>
      cd <project-folder>
   ```
2. **Install dependencies:**


   pip install -r requirements.txt


3. **Configure Environment Variables:**
   Create a .env file in the root directory
   ``` plaintext
   SECRET_KEY=generate_a_random_string_here <br>
   ENCRYPTION_KEY=generate_a_fernet_key_here
   ```




4. **Running the Application*:**


This application is configured to run exclusively over HTTPS. The required cert.pem and key.pem files are included in the repository for grading convenience.


Run the server:
```
python app.py
```
The application will be available at:


https://127.0.0.1:5000


Default Credentials (for Grading) <br>
Role    Username    Password<br>
Admin   admin   AdminPass123!<br>
User    user    UserPass123!<br>
Guest   guest   GuestPass123!

To generate PEM files, use the following command
```
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```
5. **Project Structure**


   app.py: Main application logic and routing.


   config.py: Security configuration and env loading.


   data/: JSON files for users/sessions and encrypted uploads.


   logs/: Security audit logs.


   docs/: Security Design Document and Pentest Report


   presentation/: Presentation


   templates/: frontend for relevant pages


   static/: styling for said frontend pages
