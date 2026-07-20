/**
 * Per-user subject attribution (Tier-D).
 *
 * `useSubject(subject, fn)` binds an ambient end-user identity for the duration
 * of fn (and everything it awaits) via AsyncLocalStorage. Governed calls made
 * inside then attribute to that subject WITHOUT threading user_id through every
 * call — the SDK fills user_id / service_name from the ambient subject when the
 * call doesn't specify them (explicit options always win). This improves audit
 * attribution and feeds the SDK's per-user injection-session and quota scoping,
 * which already key on metadata.user_id.
 *
 *   await useSubject('user:alice;tenant:acme', async () => {
 *     await agent.run(...);   // events attributed to alice / acme
 *   });
 *
 * A use_subject()-style ambient-context helper; additive and dependency-free.
 */

import { AsyncLocalStorage } from 'node:async_hooks';

export interface Subject {
  user_id?: string;
  tenant_id?: string;
  service_name?: string;
}

const storage = new AsyncLocalStorage<Subject>();

/**
 * Parse a subject: a Subject object, or a string like `"user:alice"`,
 * `"user:alice;tenant:acme"`, `"user=alice,service=api"`, or a bare `"alice"`
 * (treated as user_id).
 */
export function parseSubject(subject: string | Subject): Subject {
  if (typeof subject !== 'string') return { ...subject };
  const out: Subject = {};
  for (const part of subject.split(/[;,]/)) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const m = /^([a-z_]+)\s*[:=]\s*(.+)$/i.exec(trimmed);
    if (!m) {
      // bare token -> user_id
      out.user_id = trimmed;
      continue;
    }
    const key = m[1].toLowerCase();
    const value = m[2].trim();
    if (key === 'user' || key === 'user_id') out.user_id = value;
    else if (key === 'tenant' || key === 'tenant_id') out.tenant_id = value;
    else if (key === 'service' || key === 'service_name') out.service_name = value;
  }
  return out;
}

/**
 * Run `fn` with `subject` bound as the ambient subject. Nested calls merge over
 * the enclosing subject (inner values win). Works across awaits.
 */
export function useSubject<T>(subject: string | Subject, fn: () => T): T {
  const parsed = parseSubject(subject);
  const current = storage.getStore();
  return storage.run({ ...current, ...parsed }, fn);
}

/** The ambient subject, if a useSubject scope is active. */
export function getCurrentSubject(): Subject | undefined {
  return storage.getStore();
}
