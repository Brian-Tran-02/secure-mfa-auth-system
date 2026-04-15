Run instructions

Instalations required
Node.js
PostgreSQL


Database setup (we used pgadmin to manage and test our database)
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  mfa_enabled BOOLEAN DEFAULT FALSE,
  totp_secret TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


.env file
DB_USER=postgres
DB_HOST=localhost
DB_NAME=mfa_auth_db
DB_PASSWORD=your_password
DB_PORT=5432
PORT=5000



Initialization
cd server
npm install
npm run dev


Frontend
Run index.html in prefered browser
