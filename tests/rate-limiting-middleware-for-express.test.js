```javascript
const request = require('supertest');
const app = require('../app');
const rateLimiter = require('../middleware/rateLimiter');

// Helper to simulate multiple requests from same IP
const makeLoginRequest = (agent, ip = '127.0.0.1', body = {}) => {
  return agent
    .post('/auth/login')
    .set('X-Forwarded-For', ip)
    .send(body);
};

const VALID_CREDENTIALS = { username: 'testuser', password: 'ValidPass123!' };
const INVALID_CREDENTIALS = { username: 'testuser', password: 'wrongpassword' };

describe('Rate Limiting Middleware - Edge Cases', () => {

  let agent;

  beforeEach(() => {
    agent = request(app);
    // Reset rate limiter store before each test if exposed
    if (rateLimiter.resetStore) {
      rateLimiter.resetStore();
    }
  });

  // ─── BOUNDARY VALUE TESTS ────────────────────────────────────────────────────

  describe('Boundary: Request count limits', () => {

    test('5th request from same IP should still return 200 or 401 (not 429)', async () => {
      const ip = '192.168.1.10';

      for (let i = 1; i <= 4; i++) {
        await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);
      }

      const fifthResponse = await makeLoginRequest(agent, ip, VALID_CREDENTIALS);

      expect([200, 401]).toContain(fifthResponse.status);
      expect(fifthResponse.status).not.toBe(429);
    });

    test('6th request from same IP within 1 minute should return 429', async () => {
      const ip = '192.168.1.11';

      for (let i = 1; i <= 5; i++) {
        await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);
      }

      const sixthResponse = await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);

      expect(sixthResponse.status).toBe(429);
    });

    test('Exactly 5 requests: last allowed request returns correct status (not 429)', async () => {
      const ip = '192.168.1.12';

      for (let i = 1; i <= 4; i++) {
        const res = await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);
        expect(res.status).not.toBe(429);
      }

      const exactLimitResponse = await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);
      expect(exactLimitResponse.status).not.toBe(429);
    });
  });

  // ─── 429 RESPONSE FORMAT TESTS ───────────────────────────────────────────────

  describe('429 Response: Headers and body validation', () => {

    test('429 response must include Retry-After header with positive integer value', async () => {
      const ip = '192.168.1.20';

      for (let i = 0; i < 5; i++) {
        await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);
      }

      const response = await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);

      expect(response.status).toBe(429);
      expect(response.headers).toHaveProperty('retry-after');

      const retryAfter = parseInt(response.headers['retry-after'], 10);
      expect(retryAfter).toBeGreaterThan(0);
      expect(retryAfter).toBeLessThanOrEqual(60);
      expect(Number.isInteger(retryAfter)).toBe(true);
    });

    test('429 response Retry-After header should not exceed 60 seconds window', async () => {
      const ip = '192.168.1.21';

      for (let i = 0; i < 5; i++) {
        await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);
      }

      const response = await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);

      expect(response.status).toBe(429);
      const retryAfter = parseInt(response.headers['retry-after'], 10);
      expect(retryAfter).toBeLessThanOrEqual(60);
    });

    test('429 response body should contain meaningful error message', async () => {
      const ip = '192.168.1.22';

      for (let i = 0; i < 5; i++) {
        await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);
      }

      const response = await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);

      expect(response.status).toBe(429);
      expect(response.body).toBeDefined();
      expect(response.body.message || response.body.error).toBeTruthy();
    });

    test('Multiple 429 responses should NOT reset or increment the counter further', async () => {
      const ip = '192.168.1.23';

      for (let i = 0; i < 5; i++) {
        await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);
      }

      const firstBlocked = await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);
      const secondBlocked = await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);

      expect(firstBlocked.status).toBe(429);
      expect(secondBlocked.status).toBe(429);

      const retryAfter1 = parseInt(firstBlocked.headers['retry-after'], 10);
      const retryAfter2 = parseInt(secondBlocked.headers['retry-after'], 10);

      // Retry-After should be decreasing or stable, never increase after window starts
      expect(retryAfter2).toBeLessThanOrEqual(retryAfter1);
    });
  });

  // ─── COUNTER RESET TESTS ─────────────────────────────────────────────────────

  describe('Counter Reset: Time window expiry', () => {

    test('Counter resets after 60 seconds window expires (mocked timer)', async () => {
      jest.useFakeTimers();
      const ip = '192.168.1.30';

      for (let i = 0; i < 5; i++) {
        await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);
      }

      const blockedResponse = await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);
      expect(blockedResponse.status).toBe(429);

      // Advance time by 61 seconds
      jest.advanceTimersByTime(61 * 1000);

      const afterResetResponse = await makeLoginRequest(agent, ip, VALID_CREDENTIALS);
      expect(afterResetResponse.status).not.toBe(429);

      jest.useRealTimers();
    });

    test('Counter does NOT reset before 60 seconds window expires', async () => {
      jest.useFakeTimers();
      const ip = '192.168.1.31';

      for (let i = 0; i < 5; i++) {
        await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);
      }

      // Advance time by only 59 seconds
      jest.advanceTimersByTime(59 * 1000);

      const response = await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);
      expect(response.status).toBe(429);

      jest.useRealTimers();
    });

    test('Clock drift: Retry-After value remains within expected range near window boundary', async () => {
      jest.useFakeTimers();
      const ip = '192.168.1.32';

      // Start 1 second into the window
      jest.advanceTimersByTime(1000);

      for (let i = 0; i < 5; i++) {
        await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);
      }

      const response = await makeLoginRequest(agent, ip, INVALID_CREDENTIALS);