import { init, getConfig, isInitialized, _reset } from '../../src/proxy/config';

describe('config', () => {
  beforeEach(() => {
    _reset();
  });

  describe('init', () => {
    it('should initialize with valid config', () => {
      init({ api_key: 'test_key_123' });
      expect(isInitialized()).toBe(true);
    });

    it('should throw on missing api_key', () => {
      expect(() => init({} as any)).toThrow('api_key is required');
    });

    it('should throw on empty api_key', () => {
      expect(() => init({ api_key: '' })).toThrow('api_key is required');
    });

    it('should throw on invalid ingest_url', () => {
      expect(() => init({ api_key: 'test', ingest_url: 'not-a-url' })).toThrow('invalid ingest_url');
    });

    it('should clamp sample_rate to [0, 1]', () => {
      init({ api_key: 'test', sample_rate: 1.5 });
      expect(getConfig().sample_rate).toBe(1);

      _reset();
      init({ api_key: 'test', sample_rate: -0.5 });
      expect(getConfig().sample_rate).toBe(0);
    });

    it('should apply defaults', () => {
      init({ api_key: 'test' });
      const config = getConfig();

      expect(config.environment).toBe('development');
      // ingest_url now defaults to "" (empty) — no default localhost URL
      expect(config.ingest_url).toBe('');
      expect(config.sample_rate).toBe(1.0);
      expect(config.max_payload_chars).toBe(100000);
      expect(config.disabled).toBe(false);
      expect(config.debug).toBe(false);
      expect(config.timeout).toBe(5000);
      expect(config.streaming_mode).toBe('wrap');
    });

    it('should trim trailing slash from ingest_url', () => {
      // HTTPS is required for non-localhost URLs; use localhost for this test
      init({ api_key: 'test', ingest_url: 'http://localhost:3000/' });
      expect(getConfig().ingest_url).toBe('http://localhost:3000');
    });

    it('should reject http for non-localhost ingest_url', () => {
      expect(() =>
        init({ api_key: 'test', ingest_url: 'http://example.com/' }),
      ).toThrow('plaintext HTTP');
    });

    it('should accept https for non-localhost ingest_url', () => {
      init({ api_key: 'test', ingest_url: 'https://example.com/' });
      expect(getConfig().ingest_url).toBe('https://example.com');
    });
  });

  describe('getConfig', () => {
    it('should throw if not initialized', () => {
      expect(() => getConfig()).toThrow('Call init() before using');
    });

    it('should return config after init', () => {
      init({ api_key: 'test_key' });
      const config = getConfig();
      expect(config.api_key).toBe('test_key');
    });
  });

  describe('isInitialized', () => {
    it('should return false before init', () => {
      expect(isInitialized()).toBe(false);
    });

    it('should return true after init', () => {
      init({ api_key: 'test' });
      expect(isInitialized()).toBe(true);
    });
  });
});
