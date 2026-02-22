# 🔐 Flask Authentication & User Management

Complete authentication & user management API with a live interactive demo UI.

## 1 click Deploy

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/qVtbsw?referralCode=-Xd4K_&utm_medium=integration&utm_source=template&utm_campaign=generic)

## Quick Start

```bash
pip install -r requirements.txt
python app.py
# Open http://localhost:8080
```

## Environment Variables

| Var | Default | Description |
|-----|---------|-------------|
| `SECRET_KEY` | `change-me-in-production` | JWT signing key |
| `DATABASE_URL` | `sqlite:///users.db` | DB connection (auto-set by Railway Postgres) |
| `JWT_EXPIRY_HOURS` | `24` | Token lifetime |
| `PORT` | `5000` | Server port (auto-set by Railway) |

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/register` | No | Register (`username`, `email`, `password`) |
| POST | `/api/auth/login` | No | Login (`username`/`email` + `password`) |
| POST | `/api/auth/logout` | No | Logout (clears cookie) |
| GET | `/api/auth/me` | Yes | Current user profile |
| PUT | `/api/users/me` | Yes | Update profile (`display_name`, `email`, `bio`) |
| PUT | `/api/users/me/password` | Yes | Change password |
| DELETE | `/api/users/me` | Yes | Delete account |
| GET | `/api/users/{username}` | No | Public profile |
| GET | `/api/admin/users` | Admin | List users (`?q=`, `?page=`) |
| PUT | `/api/admin/users/{id}` | Admin | Toggle `is_active`/`is_admin` |
| DELETE | `/api/admin/users/{id}` | Admin | Delete user |
| GET | `/api/health` | No | Health check |

**Auth:** Send `Authorization: Bearer <token>` header or use the auto-set `token` cookie.

**First registered user = admin.**
