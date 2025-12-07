# CORS Vulnerability Exploitation Tool

A Python-based security testing tool for identifying and exploiting misconfigured Cross-Origin Resource Sharing (CORS) policies.

## Disclaimer

For authorized security testing only. Only use on systems you own or have permission to test.

---

## Overview

### What is CORS?

Cross-Origin Resource Sharing (CORS) is a browser security mechanism that controls which web applications can access resources from a different origin (domain, protocol, or port). The Same-Origin Policy (SOP) is enforced by default to prevent malicious websites from accessing sensitive data across origins.

### The Security Problem

Improperly configured CORS policies can bypass the Same-Origin Policy, allowing unauthorized origins to:
- Read sensitive API responses
- Access authenticated endpoints using victim credentials
- Exfiltrate private user data
- Bypass security controls intended to prevent cross-origin data access

### Example Vulnerable Configuration

```http
Access-Control-Allow-Origin: http://attacker.com
Access-Control-Allow-Credentials: true
```

```http
Access-Control-Allow-Origin: http://victim.com.attacker.com
Access-Control-Allow-Credentials: true
```

This configuration instructs the browser to allow `attacker.com` to read responses from the origin AND include credentials (cookies, HTTP authentication) in cross-origin requests.

---

## Attack Methodology

### Attack Flow

1. Victim authenticates to `https://target.com` and receives session cookie
2. Attacker tricks victim into visiting `http://malicious.com` (phishing, XSS, etc.)
3. Malicious JavaScript issues cross-origin fetch to `https://target.com/api/sensitive` with `credentials: 'include'`
4. Browser includes victim's session cookies in the request (if CORS policy allows)
5. Target server responds with sensitive data
6. Attacker's JavaScript reads the response and exfiltrates data to attacker-controlled server

### Prerequisites for Successful Exploitation

- Target application has misconfigured CORS headers
- Victim has an active authenticated session with the target
- Victim visits the attacker-controlled page while authenticated

---

## Installation & Usage

### Requirements

- Python 3.6 or higher (uses standard library only)
- Network access to target system
- Browser for testing exploitation

### Basic Usage

```bash
# Start the exploit server on localhost
python3 cors_exploit.py

# Access the exploit page in your browser
# Replace the target parameter with the vulnerable endpoint
http://127.0.0.1:9999/?target=http://vulnerable-site.com/api/sensitive
```

### Command Line Arguments

```bash
# Syntax
python3 cors_exploit.py [host] [port]

# Examples
python3 cors_exploit.py                    # Default: 127.0.0.1:9999
python3 cors_exploit.py attacker.local     # Custom host, default port
python3 cors_exploit.py attacker.local 8888  # Custom host and port
```

---

## Vulnerable CORS Configurations

### Configuration 1: Wildcard with Credentials

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

**Exploitability:** Blocked by modern browsers (invalid combination per CORS specification)  
**Risk:** Some legacy proxies or middleware may incorrectly allow this configuration

### Configuration 2: Reflected Origin (Critical Vulnerability)

Server dynamically reflects the requesting origin without validation:

```http
# Request Header
Origin: http://malicious.com

# Response Headers
Access-Control-Allow-Origin: http://malicious.com
Access-Control-Allow-Credentials: true
```

**Exploitability:** Fully exploitable  
**Impact:** Complete bypass of Same-Origin Policy

### Configuration 3: Insufficient Regex Validation

Server validates origin using weak regular expressions:

```python
# Vulnerable validation
if re.search(r'\.bank\.com', origin):
    allow_origin(origin)
```

**Bypass techniques:**
```
http://malicious.com.bank.com  # Matches regex
http://bank.com.malicious.com  # Matches regex
http://evilbank.com            # Matches regex
```

### Configuration 4: Null Origin Allowance

```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

**Exploitation method:** Use sandboxed iframe to send `Origin: null`

```html
<iframe sandbox="allow-scripts allow-same-origin" 
        src="data:text/html,<script>/* exploit code */</script>">
</iframe>
```

### Configuration 5: Development Origins in Production

```http
Access-Control-Allow-Origin: http://localhost:3000
Access-Control-Allow-Credentials: true
```

**Risk:** Any attacker with local access can exploit from localhost  
**Common scenario:** Development configurations accidentally deployed to production

---

## Attack Scenarios and Examples

### Scenario 1: API Key Exfiltration

**Objective:** Extract API keys from authenticated endpoint  
**Target:** `http://api.example.com/user/apikey`

```bash
# Attack procedure:
# 1. Victim authenticates to api.example.com
# 2. Attacker delivers phishing link to victim:
#    http://127.0.0.1:9999/?target=http://api.example.com/user/apikey
# 3. Victim clicks link while authenticated
# 4. API key is exfiltrated to attacker's /leak endpoint
```

**Expected Output:**
```
LEAKED DATA CAPTURED
Target: http://api.example.com/user/apikey
Data: {"apiKey": "EXAMPLE_API_KEY_HERE"}
```

### Scenario 2: Internal Network Reconnaissance

**Objective:** Access internal corporate APIs through victim's browser  
**Target:** Internal services not accessible from external network

```bash
# Attacker tricks victim on corporate network to visit:
http://attacker.com:9999/?target=http://internal-api.corp:8080/secrets

# Victim's browser makes request from within corporate network
# Internal API response exfiltrated through victim's browser
```

**Impact:** Bypasses network segmentation and firewall rules

---

## Defensive Countermeasures

### 1. Implement Strict Origin Whitelisting

Maintain an explicit allowlist of permitted origins and validate against it:

```javascript
// Insecure: Reflects all origins
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    next();
});

// Secure: Whitelist validation
const ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://mobile.example.com'
];

app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    if (ALLOWED_ORIGINS.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    
    next();
});
```

### 2. Never Combine Wildcards with Credentials

```javascript
// INVALID: Browsers will block this configuration
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Credentials', 'true');

// Valid options:
// Option A: Wildcard without credentials (public data only)
res.setHeader('Access-Control-Allow-Origin', '*');

// Option B: Specific origin with credentials
res.setHeader('Access-Control-Allow-Origin', 'https://trusted.com');
res.setHeader('Access-Control-Allow-Credentials', 'true');
```

### 3. Use Properly Anchored Regular Expressions

```javascript
// Insecure: No anchors, easily bypassed
const originPattern = /\.example\.com/;
// Matches: https://evil.com.example.com
// Matches: https://example.com.evil.com

// Secure: Properly anchored regex
const originPattern = /^https:\/\/([a-z0-9-]+\.)?example\.com$/;
// Matches: https://app.example.com
// Matches: https://example.com
// Rejects: https://evil.com.example.com
// Rejects: https://example.com.evil.com
```

### 4. Configure SameSite Cookie Attribute

```javascript
// Prevent cookies from being sent in cross-site requests
res.cookie('session', token, {
    httpOnly: true,      // Prevents JavaScript access
    secure: true,        // HTTPS only
    sameSite: 'strict'   // Blocks cross-origin requests
});

// Alternative: 'lax' for better compatibility
// Blocks cross-origin POST but allows top-level GET navigation
sameSite: 'lax'
```

### 5. Require Custom Request Headers

Enforce custom headers or content types that trigger preflight:

```javascript
// Using Content-Type: application/json triggers preflight automatically
// Alternatively, require a custom header:
app.use((req, res, next) => {
    const customHeader = req.headers['x-requested-with'];

    if (customHeader !== 'XMLHttpRequest') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    next();
});

// Modern approach: just use application/json for API endpoints
// Browser will send preflight, which you can block at CORS level
```

### 6. Implement CSRF Tokens

```javascript
// Generate CSRF token on session creation
const csrfToken = crypto.randomBytes(32).toString('hex');
req.session.csrfToken = csrfToken;

// Validate on state-changing requests
app.post('/api/transfer', (req, res) => {
    if (req.body.csrf !== req.session.csrfToken) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    
    // Process request
});
```

---

## Testing Methodology

### Manual CORS Header Inspection

Use curl to inspect CORS headers for various origins:

```bash
# Test with arbitrary origin
curl -H "Origin: http://attacker.com" \
     -H "Cookie: session=abc123" \
     -i http://your-api.com/sensitive

# Examine response for:
# - Access-Control-Allow-Origin header
# - Access-Control-Allow-Credentials header
```

### Automated Origin Testing

Test multiple origins to identify reflection or weak validation:

```bash
#!/bin/bash
# Test various origin patterns

ORIGINS=(
    "http://malicious.com"
    "http://localhost:9999"
    "http://your-domain.com.attacker.com"
    "null"
)

for origin in "${ORIGINS[@]}"; do
    echo "Testing origin: $origin"
    curl -H "Origin: $origin" \
         -i http://your-api.com/api/endpoint \
         2>/dev/null | grep -i "access-control"
    echo "---"
done
```

### Browser-Based Testing with Developer Tools

1. Open browser Developer Tools (F12)
2. Navigate to Network tab
3. Trigger cross-origin request from console:

```javascript
fetch('http://target-api.com/sensitive', {
    method: 'GET',
    credentials: 'include'
})
.then(resp => resp.text())
.then(data => console.log('Success:', data))
.catch(err => console.error('CORS blocked:', err));
```

4. Inspect request/response headers in Network tab

### Using This Tool for Automated Testing

```bash
# Start exploit server
python3 cors_exploit.py

# Test endpoint
# Navigate to: http://127.0.0.1:9999/?target=http://your-api.com/api/endpoint

# Check for:
# - Successful data retrieval in browser status box
# - Exfiltrated data in server terminal output
```

---

## Tool Output Format

When the exploit successfully exfiltrates data, the server terminal displays:

```
======================================================================
LEAKED DATA CAPTURED
======================================================================
Timestamp: 07/Dec/2025 18:30:45
Client IP: 127.0.0.1
Origin: http://127.0.0.1:9999
Size: 234 bytes

Payload:
----------------------------------------------------------------------
{
  "target": "http://victim.com/api/key",
  "timestamp": "2025-12-07T18:30:45.123Z",
  "data": "{\"apiKey\":\"sk_live_abc123\",\"user\":\"admin\"}",
  "headers": {
    "user-agent": "Mozilla/5.0...",
    "origin": "http://127.0.0.1:9999"
  }
}
======================================================================
```

---

## Troubleshooting

### Error: "TypeError: Failed to fetch"

**Root Causes:**

1. **CORS Policy Rejection:** Target server does not include required CORS headers
2. **Missing Authentication:** No active session or cookies for target domain
3. **Preflight Failure:** OPTIONS request rejected by server
4. **Network Issues:** Target unreachable or DNS resolution failure

**Diagnostic Steps:**

```javascript
// Check browser console for specific error message
// Common errors:
// - "No 'Access-Control-Allow-Origin' header is present"
// - "The 'Access-Control-Allow-Origin' header has a value 'X' that is not equal to the supplied origin"
// - "Credentials flag is 'true', but 'Access-Control-Allow-Credentials' is not 'true'"
```

**Resolution:**

- Verify CORS headers using curl (see Testing Methodology)
- Confirm authentication to target site in same browser session
- Check Network tab for preflight (OPTIONS) request status

### Issue: Cookies Not Transmitted in Cross-Origin Request

**Root Causes:**

1. **SameSite Attribute:** Cookie configured with `SameSite=Strict` or `SameSite=Lax`
2. **Secure Flag:** Cookie requires HTTPS but request uses HTTP
3. **Third-Party Cookie Blocking:** Browser privacy settings block cross-site cookies

**Diagnostic Steps:**

1. Open Developer Tools → Application tab → Cookies
2. Locate target session cookie
3. Verify SameSite and Secure attributes

**Resolution:**

- If `SameSite=Strict` or `Lax`, cookies won't be sent cross-origin - this is a protection, not a misconfiguration
- Use HTTPS if the Secure flag is set
- Test in browser with default privacy settings (some browsers block third-party cookies by default)

### Server Response: 403 Forbidden

**Root Causes:**

1. **Missing Authentication:** No valid session token
2. **Origin/Referer Validation:** Server rejects based on request headers
3. **CSRF Protection:** Endpoint requires CSRF token
4. **IP Allowlist:** Server restricts access by source IP

**Resolution:**

- Establish authenticated session before triggering exploit
- Verify server does not perform additional origin validation beyond CORS
- Some endpoints may require additional headers or tokens
- Check if target implements additional access controls

---

## Additional Resources

### Documentation and Standards

- [MDN Web Docs: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) - Comprehensive CORS reference
- [W3C CORS Specification](https://fetch.spec.whatwg.org/#http-cors-protocol) - Official CORS standard
- [OWASP CORS Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#cross-origin-resource-policy-corp) - Security best practices

### Security Research and Articles

- [PortSwigger Web Security Academy: CORS](https://portswigger.net/web-security/cors) - Interactive CORS labs
- [James Kettle: Exploiting CORS Misconfigurations](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties) - Real-world exploitation techniques
- [OWASP Top 10 API Security - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/) - API security misconfiguration including CORS

### Related Attack Vectors

**CSRF (Cross-Site Request Forgery)**
- Forces authenticated actions without reading responses
- Complementary to CORS vulnerabilities
- Mitigated by CSRF tokens and SameSite cookies

**XSS (Cross-Site Scripting)**
- Injects malicious code directly into trusted origin
- Bypasses Same-Origin Policy entirely
- More severe than CORS misconfiguration

**JSONP Hijacking**
- Legacy cross-origin data access mechanism
- Similar exploitation to CORS misconfigurations
- Deprecated in favor of CORS
