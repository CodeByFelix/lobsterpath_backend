# 🦞 Lobster Path — AI Security Operations Center (Backend)

> **The Control Plane for securing AI Agent traffic in production.**

Lobster Path is a FastAPI-based backend that acts as the **Control Plane** for an AI Security Operations Center (AI-SOC). It intercepts, inspects, and governs all LLM traffic flowing between your AI Agents and their providers — providing real-time observability, security policy enforcement, and automated threat alerting.

It works in tandem with [**Lobster Trap**](https://github.com/user/lobstertrap) (the Go-based Data Plane) to form a complete AI security gateway.

---
**Frontend Codebase: https:** https://github.com/CodeByFelix/lobsterpath_frontend
**Lobster Trap Codebase:** https://github.com/CodeByFelix/lobstertrap

## ✨ Key Features

### 🔐 Authentication & Access Control
- JWT-based authentication with secure token management
- Email verification via OTP (SMTP integration)
- Per-endpoint rate limiting (login, signup, OTP)
- Device and session tracking (IP, OS, browser)

### 🛡️ AI Gateway (Reverse Proxy)
- **SDK-Agnostic Routing** — Accepts traffic on `/chat/completions`, `/v1/chat/completions`, and `/openai/v1/chat/completions` to normalize path inconsistencies across SDKs like LangChain, OpenAI, and others
- **Dynamic Backend Selection** — Each API Key maps to a specific LLM provider backend (OpenAI, Groq, Together AI, Mistral, DeepSeek, Perplexity, OpenRouter)
- **Token Swap** — Transparently replaces the user's SOC API Key with the real provider API Key before forwarding
- **Security Policy Injection** — Dynamically assembles and injects security policies into every request via Lobster Trap headers

### 📊 Real-Time Observability
- Full audit logging of every LLM request/response (prompts, tokens, models, verdicts)
- Ingress and egress metadata capture from Lobster Trap's Deep Packet Inspection (DPI)
- Correlation ID tracing for end-to-end request tracking

### 🚨 Automated Security Alerting
- Email-based security alerts triggered on `DENY` and `HUMAN_REVIEW` verdicts
- Configurable alert thresholds and cooldown windows per project
- Background task processing for non-blocking alert delivery

### 📋 Security Policy Management
- Curated rule bank with 12+ ingress rules and 2+ egress rules
- Per-project policy configuration (enable/disable individual rules)
- Rules cover: prompt injection, PII detection, credential leaks, malware requests, phishing, data exfiltration, obfuscation, and more

### 📝 AI-Powered Security Reports
- On-demand comprehensive security audit reports generated via LLM
- Dynamic model selection per provider
- Reports delivered via email with full threat analysis

### 🔒 Production Security
- Environment-aware API documentation (hidden in production, visible in development)
- Security headers middleware (HSTS, X-Frame-Options, XSS Protection, Content-Type-Options)
- Global exception handler with safe error responses
- CORS configuration with allowlist support

---

## 🏗️ Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌───────────────┐     ┌──────────────┐
│   AI Agent /    │────▶│  Lobster Path    │────▶│  Lobster Trap │────▶│ LLM Provider │
│   LangChain     │     │  (Control Plane) │     │  (Data Plane) │     │ (OpenAI/Groq)│
│                 │◀────│  FastAPI + Py    │◀────│  Go Proxy     │◀────│              │
└─────────────────┘     └──────────────────┘     └───────────────┘     └──────────────┘
                              │
                              ▼
                        ┌──────────┐
                        │ Postgres │
                        │    DB    │
                        └──────────┘
```

**Request Flow:**
1. AI Agent sends an OpenAI-compatible request to Lobster Path
2. Lobster Path authenticates the API Key, assembles a security policy, and swaps tokens
3. The request is forwarded to Lobster Trap for Deep Packet Inspection
4. Lobster Trap evaluates the policy, logs the verdict, and forwards to the real LLM provider
5. The response flows back through the same chain with egress inspection
6. Audit events are recorded and security alerts are triggered if necessary

---

## 📁 Project Structure

```
lobsterpath_backend/
├── main.py                    # FastAPI application entry point
├── alembic.ini                # Alembic database migration config
├── requirements.txt           # Python dependencies
├── .env.example               # Environment variable template
│
├── migration/                 # Alembic migration scripts
│
└── src/
    ├── __init__.py            # Package initialization
    ├── database.py            # Async PostgreSQL connection (asyncpg)
    ├── model.py               # SQLModel ORM models (User, Project, APIKey, Policy, AuditEvent)
    ├── schema.py              # Pydantic request/response schemas
    ├── settings.py            # Environment configuration (pydantic-settings)
    ├── middleware.py           # Rate limiting, request logging, security headers
    ├── rule_bank.py           # Security rule definitions & provider/model registry
    ├── utils.py               # Auth utilities (JWT, password hashing, policy assembly)
    ├── loggings.py            # Logging configuration
    │
    ├── email/                 # HTML email templates (OTP, alerts, reports)
    │
    └── routers/
        ├── auth_router.py     # Authentication endpoints (signup, login, OTP, sessions)
        ├── project_router.py  # Project & API Key CRUD, policy management, reports
        ├── gateway_router.py  # AI Gateway proxy (the main traffic interception point)
        ├── webhook_router.py  # Lobster Trap webhook receiver
        ├── rule_router.py     # Rule bank & provider/model listing endpoints
        └── utils.py           # Background tasks (report generation, alert emails)
```

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.12+**
- **PostgreSQL** (with asyncpg driver)
- **Lobster Trap** binary running on port `8080` (the Data Plane)

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/lobsterpath-backend.git
cd lobsterpath-backend
```

### 2. Set Up Virtual Environment
```bash
python -m venv myenv
source myenv/bin/activate        # Linux/macOS
# myenv\Scripts\activate         # Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
```bash
cp .env.example .env
```

Edit `.env` with your actual values:

```env
# --- Database (PostgreSQL) ---
DB_HOST=your-database-host
DB_PORT=5432
DB_DATABASE=postgres
DB_USER=your-db-user
DB_PASSWORD=your-db-password

# --- JWT Authentication ---
SECRET_KEY=your-jwt-secret-key
ALGORITHM=HS256

# --- Email (SMTP) ---
MAIL_USERNAME=your-smtp-username
MAIL_PASSWORD=your-smtp-password
MAIL_FROM=your-email@example.com
MAIL_PORT=2525
MAIL_SERVER=your-smtp-server

# --- CORS ---
CORS_ORIGINS=http://localhost:5173,http://localhost:3000

# --- Lobster Trap Data Plane ---
LOBSTERTRAP_BASE_URL=http://localhost:8080

# --- Environment (development/production) ---
ENVIRONMENT=development
```

### 5. Run Database Migrations
```bash
alembic upgrade head
```

### 6. Start the Server
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`. In development mode, interactive docs are at `http://localhost:8000/docs`.

---

## 🔌 API Endpoints

### Authentication (`/auth`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/register` | Create a new user account |
| `POST` | `/auth/login` | Authenticate and receive JWT tokens |
| `POST` | `/auth/request-otp` | Request email verification OTP |
| `POST` | `/auth/verify-otp` | Verify email with OTP |
| `GET` | `/auth/user-detail` | Get current user profile |
| `GET` | `/auth/sessions` | List active sessions |
| `DELETE` | `/auth/sessions/{id}` | Revoke a specific session |

### Projects (`/projects`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/projects/` | Create a new project |
| `GET` | `/projects/` | List all user projects |
| `GET` | `/projects/{id}` | Get project details |
| `DELETE` | `/projects/{id}` | Delete a project and all related data |
| `POST` | `/projects/{id}/toggle` | Activate/deactivate a project |
| `PUT` | `/projects/{id}` | Update project settings |

### API Keys (`/projects`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/projects/api-keys` | Create a new API key for a project |
| `GET` | `/projects/api-keys/{project_id}` | List all keys for a project |
| `DELETE` | `/projects/api-keys/{key_id}` | Delete an API key |

### Security Policies (`/projects`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/projects/policies/{project_id}` | Get the current policy for a project |
| `PUT` | `/projects/policies/{project_id}` | Update the policy (enable/disable rules) |

### Audit Logs (`/projects`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/projects/{id}/audit-logs` | Get all audit events for a project |
| `DELETE` | `/projects/{id}/audit-logs/{log_id}` | Delete a specific audit log entry |

### Reports (`/projects`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/projects/{id}/generate-report` | Generate a project-wide AI security report |
| `POST` | `/projects/api-keys/{key_id}/generate-report` | Generate a per-key security report |

### AI Gateway
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/chat/completions` | Main gateway endpoint (standard) |
| `POST` | `/v1/chat/completions` | Alias for OpenAI SDK compatibility |
| `POST` | `/openai/v1/chat/completions` | Alias for LangChain/Groq SDK compatibility |

### Rules (`/rules`)
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/rules/` | List all available security rules |
| `GET` | `/rules/providers` | List all supported LLM providers |
| `GET` | `/rules/models/{provider}` | List curated models for a provider |

---

## 🛡️ Security Rule Bank

Lobster Path ships with a comprehensive set of pre-built security rules:

### Ingress Rules (Request Inspection)
| Rule | Priority | Action | Description |
|------|----------|--------|-------------|
| `block_prompt_injection` | 100 | DENY | Detects prompt injection attempts |
| `block_harm_violence` | 98 | DENY | Blocks requests for violent content |
| `block_malware_request` | 96 | DENY | Blocks malware/exploit generation |
| `block_phishing_fraud` | 94 | DENY | Blocks phishing material creation |
| `block_data_exfiltration` | 92 | DENY | Detects data exfiltration patterns |
| `block_obfuscation_evasion` | 90 | DENY | Detects encoding/obfuscation evasion |
| `review_role_impersonation` | 86 | HUMAN_REVIEW | Flags privileged role impersonation |
| `block_sensitive_paths` | 85 | DENY | Blocks access to sensitive file paths |
| `block_pii_request` | 82 | DENY | Blocks requests for personal information |
| `block_dangerous_commands` | 80 | DENY | Detects dangerous system commands |
| `review_high_risk` | 70 | HUMAN_REVIEW | Flags high risk-score prompts |
| `log_code_execution` | 30 | LOG | Logs code execution requests |

### Egress Rules (Response Inspection)
| Rule | Priority | Action | Description |
|------|----------|--------|-------------|
| `block_credential_leak` | 100 | DENY | Blocks responses containing credentials |
| `block_pii_leak` | 90 | DENY | Blocks responses containing PII |

---

## 🌐 Supported LLM Providers

| Provider | Base URL |
|----------|----------|
| OpenAI | `https://api.openai.com/v1` |
| Groq | `https://api.groq.com/openai/v1` |
| Together AI | `https://api.together.xyz/v1` |
| Mistral AI | `https://api.mistral.ai/v1` |
| DeepSeek | `https://api.deepseek.com` |
| Perplexity | `https://api.perplexity.ai` |
| OpenRouter | `https://openrouter.ai/api/v1` |

---

## ⚙️ Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_HOST` | ✅ | — | PostgreSQL host |
| `DB_PORT` | ✅ | — | PostgreSQL port |
| `DB_DATABASE` | ✅ | — | Database name |
| `DB_USER` | ✅ | — | Database user |
| `DB_PASSWORD` | ✅ | — | Database password |
| `SECRET_KEY` | ✅ | — | JWT signing secret |
| `ALGORITHM` | ✅ | — | JWT algorithm (e.g. `HS256`) |
| `MAIL_USERNAME` | ✅ | — | SMTP username |
| `MAIL_PASSWORD` | ✅ | — | SMTP password |
| `MAIL_FROM` | ✅ | — | Sender email address |
| `MAIL_PORT` | ✅ | — | SMTP port |
| `MAIL_SERVER` | ✅ | — | SMTP server hostname |
| `CORS_ORIGINS` | ❌ | `*` | Comma-separated allowed origins |
| `LOBSTERTRAP_BASE_URL` | ✅ | — | URL of the Lobster Trap Data Plane |
| `ENVIRONMENT` | ❌ | `development` | `development` or `production` |

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | FastAPI 0.136 |
| ORM | SQLModel (SQLAlchemy + Pydantic) |
| Database | PostgreSQL (asyncpg) |
| Migrations | Alembic |
| Auth | JWT (python-jose) + bcrypt (passlib) |
| Email | fastapi-mail (SMTP) |
| HTTP Client | httpx (HTTP/2) |
| Server | Uvicorn (ASGI) |

---

## 📄 License

This project is part of the Lobster Path AI-SOC platform.

---

<p align="center">
  <strong>🦞 Lobster Path</strong> — Securing AI Agents, One Request at a Time.
</p>
