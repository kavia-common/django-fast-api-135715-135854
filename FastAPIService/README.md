# FastAPIService

High-performance REST API for product listing with filtering, JWT authentication, RBAC, and OpenAPI documentation.

## Features
- GET /products/ with filtering (name, description, min_price, max_price, subcategory) and pagination (page, page_size)
- JWT Bearer authentication with RBAC (roles: admin, api_consumer)
- Pydantic validation for request/response
- Standardized error responses
- OpenAPI docs at /docs and /openapi.json
- Logging and observability hooks (placeholders)
- Secure environment variable handling
- Dockerfile for containerization
- Scaffolding for Django service and PostgreSQL integration
- Placeholder for external authentication providers

## Run locally

1. Create a `.env` file (see `.env.example`) with required environment variables.
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Start the server:
   ```
   uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
   ```

Docs: http://127.0.0.1:8000/docs

## Build & Run via Docker

```
docker build -t fastapi-service .
docker run --rm -p 8000:8000 --env-file .env fastapi-service
```

## Environment Variables

See `.env.example` for required/optional variables. Do not commit `.env`.

## Notes

- The current implementation uses mocked data for /products/ and a placeholder client for the Django Service. Replace with real HTTP calls and DB queries.
- Ensure FASTAPI_JWT_SECRET is provided; otherwise requests will fail with 500 for security.
- Tighten CORS in production with `CORS_ALLOW_ORIGINS`.
