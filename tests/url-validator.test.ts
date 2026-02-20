import { describe, test, expect } from 'bun:test';
import { validateURL } from '../src/lib/url-validator';

describe('URL Validator', () => {
  test('accepts valid HTTPS URL', () => {
    const result = validateURL('https://api.example.com/v1/mcp');
    expect(result.valid).toBe(true);
    expect(result.warnings.length).toBe(0);
  });

  test('warns on HTTP URL', () => {
    const result = validateURL('http://api.example.com/v1/mcp');
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('HTTP'))).toBe(true);
  });

  test('blocks localhost (SSRF)', () => {
    const result = validateURL('http://localhost:8080/mcp');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('SSRF');
  });

  test('blocks 127.0.0.1 (SSRF)', () => {
    const result = validateURL('http://127.0.0.1:3000/api');
    expect(result.valid).toBe(false);
    expect(result.severity).toBe('critical');
  });

  test('blocks private IP ranges', () => {
    expect(validateURL('http://10.0.0.1/api').valid).toBe(false);
    expect(validateURL('http://192.168.1.1/api').valid).toBe(false);
    expect(validateURL('http://172.16.0.1/api').valid).toBe(false);
  });

  test('blocks cloud metadata endpoints', () => {
    const result = validateURL('http://169.254.169.254/latest/meta-data/');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('metadata');
  });

  test('rejects invalid URL', () => {
    const result = validateURL('not-a-url');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Invalid');
  });

  test('rejects non-HTTP schemes', () => {
    const result = validateURL('ftp://files.example.com/data');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('scheme');
  });

  test('warns on embedded credentials', () => {
    const result = validateURL('https://user:pass@api.example.com/mcp');
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('credential'))).toBe(true);
  });

  test('warns on non-standard port', () => {
    const result = validateURL('https://api.example.com:9999/mcp');
    expect(result.valid).toBe(true);
    expect(result.warnings.some(w => w.includes('port'))).toBe(true);
  });
});
