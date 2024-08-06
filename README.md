# 🏦 Hamada Bank System

## 📑 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Security Measures](#security-measures)
- [Screenshots](#screenshots)
- [Installation](#installation)
  - [Using Docker](#using-docker)
  - [Using Virtual Environment](#using-virtual-environment)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Contributing](#contributing)
- [License](#license)

---

## 🌟 Overview

Hamada Bank System is a robust and secure banking application built with Flask. It provides a comprehensive set of features for both users and administrators, ensuring secure transactions and efficient account management.


https://github.com/user-attachments/assets/6a12117d-d5c6-4e40-8cea-22822fb40ea0


---
## 🚀 Features

- 👤 User Authentication and Authorization
- 💰 Account Management (Savings, Current, Islamic)
- 💸 Deposit and Withdrawal Transactions
- 💳 Loan Application and Management
- 📊 Transaction History and Account Statement
- 👑 Admin Dashboard for User Management
- 📱 Responsive Web Design for Mobile and Desktop

---

## 🔒 Security Measures

- 🔐 Password Hashing using Werkzeug Security
- 🚫 Rate Limiting to Prevent Brute Force Attacks
- 🔑 JWT (JSON Web Tokens) for Secure Authentication
- 🛡️ CSRF Protection
- 🧹 Input Sanitization to Prevent XSS Attacks
- 🔍 Detailed Logging for Audit Trails
- 🔒 Account Lockout After Multiple Failed Login Attempts
- 🔐 Secure Session Management
- 📜 Transaction Integrity Checks

---

## 📸 Screenshots

### HOME PAGE
![image](https://github.com/user-attachments/assets/acc6200d-bb8f-4364-a1f1-bc1113e0f2c1)

### LOGIN PAGE 
![image](https://github.com/user-attachments/assets/f3705284-b41a-4139-bda8-97cf023bc895)

### ADMIN DASHBOARD
![image](https://github.com/user-attachments/assets/4702813b-317b-4073-883c-289f5be71a3d)

![image](https://github.com/user-attachments/assets/144042a7-8901-4d31-9500-40f76aa65bc5)

### USER PROFILE PAGE
![image](https://github.com/user-attachments/assets/04e9d6cd-7c16-4248-acc9-af5e061fd239)

### REGISTER PAGE
![image](https://github.com/user-attachments/assets/4e27437e-7be0-4b83-aa19-16773c31bd3a)

### USER DASHBOARD
![image](https://github.com/user-attachments/assets/ebe2f82b-df16-4422-8c90-eb67364b090c)

### DEPOSIT PAGE
![image](https://github.com/user-attachments/assets/4967f965-9ed9-410f-819a-1d7a15cbd316)

### WITHDRAW PAGE
![image](https://github.com/user-attachments/assets/8a21105e-fbfd-4440-9a1c-717669a78304)

### LOAN PAGE
![image](https://github.com/user-attachments/assets/b0b6f4ec-6490-4112-9831-ac5e0980fe88)

### TRANSACTION 
![image](https://github.com/user-attachments/assets/cd35cfb5-af74-45a1-a1d4-1ce4b9d80b2b)

### ADMIN CREATE A USER ACCOUNT
![image](https://github.com/user-attachments/assets/0438f2e3-9231-468d-8ce8-7c293a8062bd)

![image](https://github.com/user-attachments/assets/885a8376-cd8f-41f7-b6a0-591b5bd794de)

### 404 PAGE
![image](https://github.com/user-attachments/assets/8119d80b-152e-4c9c-a287-c460b05b766d)

### 500 PAGE
![image](https://github.com/user-attachments/assets/8d2badb3-7998-45ac-9fb4-416972421048)

### RATE LIMIT PAGE
![image](https://github.com/user-attachments/assets/b7c41958-12a4-46a1-bab7-baf29c9e287c)


---


## 🛠️ Installation

### Using Docker

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/hamada-bank-system.git
   cd hamada-bank-system
   ```

2. Build and run the Docker containers:
   ```
   docker-compose up --build
   ```

3. Access the application at `http://localhost:5000`

### Using Virtual Environment

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/hamada-bank-system.git
   cd hamada-bank-system
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   ```
   export FLASK_APP=app.py
   export FLASK_ENV=development
   export SECRET_KEY=your_secret_key
   export JWT_SECRET_KEY=your_jwt_secret_key
   ```

5. Initialize the database:
   ```
   flask db upgrade
   ```

6. Run the application:
   ```
   flask run
   ```

7. Access the application at `http://localhost:5000`

---

## 🖥️ Usage

1. Register a new account or log in with existing credentials.
2. Navigate through the dashboard to perform various banking operations.
3. Admins can access the admin dashboard for user management and system monitoring.

## 🔗 API Endpoints

- `/api/balance`: Get user's current balance
- `/api/admin/logs`: Retrieve system logs (Admin only)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
