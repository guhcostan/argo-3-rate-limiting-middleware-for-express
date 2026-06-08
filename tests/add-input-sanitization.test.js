```javascript
const { sanitizeXForwardedFor, normalizeIPv6, validateIP } = require('../middleware/inputSanitization');

// Mock express request/response objects
const mockReq = (headers = {}) => ({ headers });
const mockRes = () => {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};
const mockNext = () => jest.fn();

describe('X-Forwarded-For Input Sanitization Middleware - Edge Cases', () => {

  describe('SQL Injection in X-Forwarded-For header', () => {
    test('should reject SQL injection payload in X-Forwarded-For header', () => {
      const req = mockReq({ 'x-forwarded-for': "192.168.1.1'; DROP TABLE users; --" });
      const res = mockRes();
      const next = mockNext();

      sanitizeXForwardedFor(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: expect.stringMatching(/invalid|malformed/i) })
      );
      expect(next).not.toHaveBeenCalled();
    });

    test('should reject UNION-based SQL injection in X-Forwarded-For header', () => {
      const req = mockReq({ 'x-forwarded-for': "1.1.1.1 UNION SELECT * FROM users--" });
      const res = mockRes();
      const next = mockNext();

      sanitizeXForwardedFor(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(next).not.toHaveBeenCalled();
    });

    test('should reject hex-encoded SQL injection in X-Forwarded-For header', () => {
      const req = mockReq({ 'x-forwarded-for': "0x31 OR 0x31=0x31" });
      const res = mockRes();
      const next = mockNext();

      sanitizeXForwardedFor(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('Null Bytes in IP Header', () => {
    test('should reject null byte injection in X-Forwarded-For header', () => {
      const req = mockReq({ 'x-forwarded-for': "192.168.1.1\x00malicious" });
      const res = mockRes();
      const next = mockNext();

      sanitizeXForwardedFor(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(next).not.toHaveBeenCalled();
    });

    test('should reject null byte at start of X-Forwarded-For header', () => {
      const req = mockReq({ 'x-forwarded-for': "\x00192.168.1.1" });
      const res = mockRes();
      const next = mockNext();

      sanitizeXForwardedFor(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(next).not.toHaveBeenCalled();
    });

    test('should reject header containing only null bytes', () => {
      const req = mockReq({ 'x-forwarded-for': "\x00\x00\x00" });
      const res = mockRes();
      const next = mockNext();

      sanitizeXForwardedFor(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(next).not.toHaveBeenCalled();
    });

    test('should reject null byte encoded as unicode escape in IP header', () => {
      const req = mockReq({ 'x-forwarded-for': "10.0.0.1\u0000evil" });
      const res = mockRes();
      const next = mockNext();

      sanitizeXForwardedFor(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('IPv6 with Port Number', () => {
    test('should strip port from IPv6 address enclosed in brackets', () => {
      const req = mockReq({ 'x-forwarded-for': "[2001:db8::1]:8080" });
      const res = mockRes();
      const next = mockNext();

      sanitizeXForwardedFor(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.sanitizedIP).toBe("2001:db8::1");
    });

    test('should handle IPv6 with high port number boundary (65535)', () => {
      const req = mockReq({ 'x-forwarded-for': "[::1]:65535" });
      const res = mockRes();
      const next = mockNext();

      sanitizeXForwardedFor(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.sanitizedIP).toBe("::1");
    });

    test('should reject IPv6 with invalid port number exceeding 65535', () => {
      const req = mockReq({ 'x-forwarded-for': "[2001:db8::1]:99999" });
      const res = mockRes();
      const next = mockNext();

      sanitizeXForwardedFor(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(next).not.toHaveBeenCalled();
    });

    test('should reject IPv6 with port but missing closing bracket', () => {
      const req = mockReq({ 'x-forwarded-for': "[2001:db8::1:8080" });
      const res = mockRes();
      const next = mockNext();

      sanitizeXForwardedFor(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('IPv4-Mapped IPv6 Addresses', () => {
    test('should normalize IPv4-mapped IPv6 address ::ffff:192.168.1.1 to IPv4', () => {
      const result = normalizeIPv6("::ffff:192.168.1.1");

      expect(result).toBe("192.168.1.1");
    });

    test('should normalize full-form IPv4-mapped IPv6 address', () => {
      const result = normalizeIPv6("0000:0000:0000:0000:0000:ffff:c0a8:0101");

      expect(result).toBe("192.168.1.1");
    });

    test('should handle IPv4-mapped IPv6 in X-Forwarded-For header end-to-end', () => {
      const req = mockReq({ 'x-forwarded-for': "::ffff:10.0.0.1" });
      const res = mockRes();
      const next = mockNext();

      sanitizeXForwardedFor(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.sanitizedIP).toBe("10.0.0.1");
    });

    test('should reject invalid IPv4-mapped IPv6 with out-of-range IPv4 segment', () => {
      const req = mockReq({ 'x-forwarded-for': "::ffff:256.168.1.1" });
      const res = mockRes();
      const next = mockNext();

      sanitizeXForwardedFor(req, res, next);

      expect(res.status).toHaveBe