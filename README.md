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

## 🌟 Overview

Hamada Bank System is a robust and secure banking application built with Flask. It provides a comprehensive set of features for both users and administrators, ensuring secure transactions and efficient account management.

## 🚀 Features

- 👤 User Authentication and Authorization
- 💰 Account Management (Savings, Current, Islamic)
- 💸 Deposit and Withdrawal Transactions
- 💳 Loan Application and Management
- 📊 Transaction History and Account Statement
- 👑 Admin Dashboard for User Management
- 📱 Responsive Web Design for Mobile and Desktop

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

## 📸 Screenshots

[Insert screenshots of your application here]

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