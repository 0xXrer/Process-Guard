# API Authentication

Process Guard API requires authentication for all endpoints except `/health`.

## Authentication Methods

### 1. API Key Authentication (Recommended)

API keys use SHA-256 hashing for secure storage.

#### Generating an API Key

```bash
# Generate a secure random API key
openssl rand -hex 32

# Example output:
# a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
```

#### Hashing the API Key

```bash
# Hash the API key with SHA-256
echo -n "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456" | sha256sum

# Store the hash in config.toml
```

#### Using the API Key

Include the API key in the `Authorization` header:

```bash
curl -H "Authorization: Bearer a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456" \
     http://localhost:8080/api/processes
```

### 2. JWT Authentication

For more complex authentication flows, JWT tokens are supported.

#### JWT Structure

```json
{
  "sub": "user_id_or_username",
  "exp": 1735689600,
  "iat": 1735603200
}
```

#### Generating a JWT

```python
import jwt
import time

secret = "your-jwt-secret"
payload = {
    "sub": "admin_user",
    "exp": int(time.time()) + 3600,  # 1 hour expiration
    "iat": int(time.time())
}

token = jwt.encode(payload, secret, algorithm="HS256")
print(f"JWT Token: {token}")
```

#### Using JWT

```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
     http://localhost:8080/api/processes
```

## Security Best Practices

### 1. API Key Management

- **Never commit API keys to version control**
- **Rotate API keys regularly** (every 90 days recommended)
- **Use different keys for different environments** (dev, staging, prod)
- **Store keys in environment variables or secure vaults**

```bash
# Set API key via environment variable
export API_KEYS="hash1,hash2,hash3"

# Or use a .env file (never commit this!)
echo "API_KEYS=hash1,hash2,hash3" > .env
```

### 2. JWT Secret Management

- **Generate strong secrets** (minimum 32 bytes)
- **Never reuse secrets across environments**
- **Store in secure configuration management**

```bash
# Generate a strong JWT secret
openssl rand -base64 32

# Set via environment variable
export JWT_SECRET="your-generated-secret"
```

### 3. TLS/HTTPS

**Always use TLS in production** to protect authentication credentials in transit.

```toml
[server]
enable_tls = true
tls_cert_path = "/etc/process-guard/cert.pem"
tls_key_path = "/etc/process-guard/key.pem"
```

## Rate Limiting

All API requests are rate-limited to prevent abuse:

- **Default**: 100 requests per minute per IP
- **Burst**: 10 requests
- **Response**: HTTP 429 Too Many Requests

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1735603260
```

## Error Responses

### 401 Unauthorized

Missing or invalid authentication:

```json
{
  "error": "Unauthorized",
  "message": "Missing or invalid Authorization header"
}
```

### 403 Forbidden

Valid authentication but insufficient permissions:

```json
{
  "error": "Forbidden",
  "message": "Operation not permitted"
}
```

### 429 Too Many Requests

Rate limit exceeded:

```json
{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded. Please try again later."
}
```

## Example Usage

### PowerShell

```powershell
$apiKey = "your-api-key"
$headers = @{
    "Authorization" = "Bearer $apiKey"
    "Content-Type" = "application/json"
}

Invoke-RestMethod -Uri "http://localhost:8080/api/processes" -Headers $headers
```

### Python

```python
import requests

api_key = "your-api-key"
headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

response = requests.get("http://localhost:8080/api/processes", headers=headers)
print(response.json())
```

### JavaScript

```javascript
const apiKey = "your-api-key";

fetch("http://localhost:8080/api/processes", {
  headers: {
    "Authorization": `Bearer ${apiKey}`,
    "Content-Type": "application/json"
  }
})
.then(response => response.json())
.then(data => console.log(data));
```

## Audit Logging

All API authentication attempts are logged for security auditing:

```json
{
  "timestamp": 1735603200,
  "action": "auth_failed",
  "user": "unknown",
  "success": false,
  "error": "Invalid token",
  "ip_address": "192.168.1.100"
}
```

Audit logs can be found in the configured audit log file or system logs.

## Troubleshooting

### "Unauthorized" Error

1. Check that the API key is correct
2. Verify the key is not expired (for JWT)
3. Ensure the `Authorization` header format is correct: `Bearer <token>`
4. Check that the API key hash matches the configuration

### "Too Many Requests" Error

1. Reduce request frequency
2. Implement exponential backoff
3. Contact administrator to increase rate limits if needed

### "Forbidden" Error

1. Verify user has necessary permissions
2. Check if the resource requires elevated privileges
3. Review audit logs for details

## Security Considerations

- **Always use HTTPS in production**
- **Never log API keys or JWT tokens**
- **Implement key rotation policies**
- **Monitor audit logs for suspicious activity**
- **Use IP whitelisting for additional security**
- **Implement multi-factor authentication for key generation**

## Additional Resources

- [API Overview](README.md)
- [Error Handling](errors.md)
- [Configuration Guide](../ops/config.md)
- [Security Best Practices](../../SECURITY.md)
