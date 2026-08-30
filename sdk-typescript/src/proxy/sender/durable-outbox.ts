/** Atomic disk-backed storage for signed audit events awaiting delivery. */

import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { AuditEvent, ResolvedConfig } from '../types.js';

const FORMAT = 'obsvr-durable-outbox/1';

export interface DurableOutboxRecord {
  format: typeof FORMAT;
  id: string;
  created_at_ms: number;
  event: AuditEvent;
}

export interface DurableOutboxStatus {
  enabled: boolean;
  directory?: string;
  pending: number;
  dead_letters: number;
  bytes_on_disk: number;
  persisted: number;
  replayed: number;
  acknowledged: number;
  dead_lettered: number;
  write_failures: number;
}

let config: ResolvedConfig['durable_delivery'];
let status: DurableOutboxStatus = emptyStatus();

function emptyStatus(): DurableOutboxStatus {
  return {
    enabled: false,
    pending: 0,
    dead_letters: 0,
    bytes_on_disk: 0,
    persisted: 0,
    replayed: 0,
    acknowledged: 0,
    dead_lettered: 0,
    write_failures: 0,
  };
}

function pendingDir(): string {
  if (!config) throw new Error('durable outbox is not configured');
  return join(config.directory, 'pending');
}

function deadDir(): string {
  if (!config) throw new Error('durable outbox is not configured');
  return join(config.directory, 'dead');
}

function syncDirectory(path: string): void {
  if (!config?.fsync) return;
  const fd = openSync(path, 'r');
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function assertSafeDirectory(path: string): void {
  if (!isAbsolute(path)) throw new Error('durableDelivery.directory must be absolute');
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) {
    throw new Error('durableDelivery.directory must not be a symbolic link');
  }
}

function files(path: string): string[] {
  return readdirSync(path)
    .filter((name) => name.endsWith('.json'))
    .sort();
}

function diskUsage(): number {
  if (!config) return 0;
  let total = 0;
  for (const directory of [pendingDir(), deadDir()]) {
    for (const name of files(directory)) total += statSync(join(directory, name)).size;
  }
  return total;
}

export function configureDurableOutbox(
  value: ResolvedConfig['durable_delivery'],
): void {
  config = value;
  status = emptyStatus();
  if (!value) return;
  assertSafeDirectory(value.directory);
  const directory = resolve(value.directory);
  value.directory = directory;
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  mkdirSync(pendingDir(), { recursive: true, mode: 0o700 });
  mkdirSync(deadDir(), { recursive: true, mode: 0o700 });
  status.enabled = true;
  status.directory = directory;
  status.pending = files(pendingDir()).length;
  status.dead_letters = files(deadDir()).length;
  status.bytes_on_disk = diskUsage();
  if (status.bytes_on_disk > value.maxBytes) {
    throw new Error(
      `durable outbox already uses ${status.bytes_on_disk} bytes, above maxBytes=${value.maxBytes}`,
    );
  }
}

function parseRecord(path: string): DurableOutboxRecord {
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as DurableOutboxRecord;
  if (
    parsed?.format !== FORMAT ||
    typeof parsed.id !== 'string' ||
    !Number.isSafeInteger(parsed.created_at_ms) ||
    !parsed.event ||
    typeof parsed.event !== 'object'
  ) {
    throw new Error(`invalid durable outbox record: ${path}`);
  }
  return parsed;
}

export function persistDurableEvent(event: AuditEvent): string | undefined {
  if (!config) return undefined;
  const id = `${String(Date.now()).padStart(16, '0')}-${randomUUID()}`;
  const record: DurableOutboxRecord = {
    format: FORMAT,
    id,
    created_at_ms: Date.now(),
    event,
  };
  const bytes = Buffer.from(JSON.stringify(record), 'utf8');
  if (status.bytes_on_disk + bytes.length > config.maxBytes) {
    status.write_failures++;
    throw new Error(`durable outbox maxBytes=${config.maxBytes} would be exceeded`);
  }
  const target = join(pendingDir(), `${id}.json`);
  const temporary = join(pendingDir(), `.${id}.tmp`);
  try {
    const fd = openSync(temporary, 'wx', 0o600);
    try {
      writeFileSync(fd, bytes);
      if (config.fsync) fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temporary, target);
    syncDirectory(pendingDir());
  } catch (error) {
    status.write_failures++;
    try { unlinkSync(temporary); } catch { /* best effort */ }
    throw error;
  }
  status.persisted++;
  status.pending++;
  status.bytes_on_disk += bytes.length;
  return id;
}

export function pendingDurableRecords(): DurableOutboxRecord[] {
  if (!config) return [];
  return files(pendingDir()).map((name) => parseRecord(join(pendingDir(), name)));
}

export function markDurableRecordsReplayed(count: number): void {
  status.replayed += Math.max(0, count);
}

export function acknowledgeDurableEvent(id: string): void {
  if (!config) return;
  const path = join(pendingDir(), `${id}.json`);
  if (!existsSync(path)) return;
  const size = statSync(path).size;
  unlinkSync(path);
  syncDirectory(pendingDir());
  status.acknowledged++;
  status.pending = Math.max(0, status.pending - 1);
  status.bytes_on_disk = Math.max(0, status.bytes_on_disk - size);
}

export function deadLetterDurableEvent(id: string, reason: string): void {
  if (!config) return;
  const source = join(pendingDir(), `${id}.json`);
  if (!existsSync(source)) return;
  const safeReason = reason.replace(/[^a-z0-9_]+/gi, '_').slice(0, 64) || 'unknown';
  renameSync(source, join(deadDir(), `${id}.${safeReason}.json`));
  syncDirectory(pendingDir());
  syncDirectory(deadDir());
  status.dead_lettered++;
  status.pending = Math.max(0, status.pending - 1);
  status.dead_letters++;
}

export function durableOutboxEnabled(): boolean {
  return config !== undefined;
}

export function durableFailureMode(): 'error' | 'warn' {
  return config?.failureMode ?? 'error';
}

export function getDurableOutboxStatus(): DurableOutboxStatus {
  return { ...status };
}

/** Disable this process's handle without deleting caller-owned records. */
export function resetDurableOutbox(): void {
  config = undefined;
  status = emptyStatus();
}
