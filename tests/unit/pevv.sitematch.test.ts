import { describe, expect, it } from 'vitest';
import { siteMatches } from '@/pevv/model';

describe('PEVV site matching', () => {
  it('matches exact, parent and wildcard legacy in-app form ids only', () => {
    const o = 'https://vault.example.test';
    expect(siteMatches('luciverse:notes-note:abc', 'notes-note:abc', o)).toBe(true);
    expect(siteMatches('luciverse:notes-note', 'notes-note:abc', o)).toBe(true);
    expect(siteMatches('luciverse:notes-note:abc', 'notes-note:xyz', o)).toBe(false);
    expect(siteMatches('luciverse:notes', 'notes-vault', o)).toBe(false);
    expect(siteMatches('luciverse:*', 'anything', o)).toBe(true);
    expect(siteMatches('https://evil.example', 'notes-vault', o)).toBe(false);
  });
});
