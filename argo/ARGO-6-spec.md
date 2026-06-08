# ARGO-6: Add input sanitization

## Acceptance Criteria
1. X-Forwarded-For sanitized before use
2. IPv6 normalized
3. Malformed IP returns 400

## API Contract
N/A - middleware only

## Edge Cases
SQL injection in IP header, null bytes, IPv6 with port, IPv4-mapped IPv6
