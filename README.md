# CodeClass — Student Coding Portal

A full-stack starter website for a school coding lab.

## Features

- Student sign-up and login
- Secure password hashing with bcrypt
- JWT authentication
- Student dashboard
- HTML, CSS, JavaScript and Python project editor
- Save and edit projects
- HTML/CSS/JavaScript live preview
- Python code storage (safe by default; not executed)
- Learning Center for HTML, CSS, JavaScript and Python
- Student learning notes
- Admin dashboard
- Admin can see students and all saved project code
- SQLite database
- Responsive mobile/tablet/desktop UI

## Run locally

1. Install Node.js 18+.
2. Open this folder in a terminal.
3. Run:

   npm install
   npm start

4. Open http://localhost:3000

Default admin:
- Email: admin@school.local
- Password: Admin@12345

For production, set:
- JWT_SECRET
- ADMIN_EMAIL
- ADMIN_PASSWORD

Example:

JWT_SECRET="a-long-random-secret" ADMIN_EMAIL="admin@your-school.com" ADMIN_PASSWORD="Use-a-strong-password" npm start

## Important security note

Do NOT execute arbitrary student Python code directly on the same server process. If Python execution is required, use an isolated sandbox/container with CPU, memory, time, filesystem and network restrictions.
