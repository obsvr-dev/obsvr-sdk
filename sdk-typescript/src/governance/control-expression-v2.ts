import { safeRegexTest, validateRegexPattern } from '../utils/safe-regex.js';

export const CONTROL_EXPRESSION_V2_SCHEMA = 'obsvr-control-expression-v2' as const;
export const CONTROL_EXPRESSION_MAX_DEPTH = 12;
export const CONTROL_EXPRESSION_MAX_NODES = 128;
export const CONTROL_EXPRESSION_MAX_SET_ITEMS = 64;

export type ControlScalar = string | number | boolean | null;

export interface ControlPredicateV2 {
  path: string;
  operator:
    | 'exists'
    | 'equals'
    | 'not_equals'
    | 'contains'
    | 'in'
    | 'greater_than'
    | 'greater_than_or_equal'
    | 'less_than'
    | 'less_than_or_equal'
    | 'matches';
  value?: ControlScalar | ControlScalar[];
}

export type ControlExpressionV2 =
  | { predicate: ControlPredicateV2 }
  | { all: ControlExpressionV2[] }
  | { any: ControlExpressionV2[] }
  | { not: ControlExpressionV2 };

export interface ControlExpressionInputV2 {
  input: { text: string; target: 'prompt' | 'response' };
  context: Record<string, unknown>;
}

export class ControlExpressionValidationError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = 'ControlExpressionValidationError';
  }
}

function fail(message: string): never {
  throw new ControlExpressionValidationError(message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validatePath(path: unknown): asserts path is string {
  if (typeof path !== 'string' || path.length === 0 || path.length > 256) {
    fail('predicate.path must be a non-empty string of at most 256 characters');
  }
  if (!/^(input|context)(\.[A-Za-z0-9_-]+)+$/.test(path)) {
    fail(`predicate.path is not a bounded input/context path: ${JSON.stringify(path)}`);
  }
  if (path.split('.').length > 10) fail('predicate.path exceeds 10 segments');
}

function validateScalar(value: unknown, field: string): void {
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) {
    if (typeof value === 'number' && !Number.isFinite(value)) fail(`${field} must be finite`);
    if (typeof value === 'string' && value.length > 4096) fail(`${field} exceeds 4096 characters`);
    return;
  }
  fail(`${field} must be a string, finite number, boolean, or null`);
}

const OPERATORS = new Set([
  'exists', 'equals', 'not_equals', 'contains', 'in', 'greater_than',
  'greater_than_or_equal', 'less_than', 'less_than_or_equal', 'matches',
]);

export function validateControlExpressionV2(expression: unknown): ControlExpressionV2 {
  let nodes = 0;
  const visit = (candidate: unknown, depth: number, field: string): ControlExpressionV2 => {
    nodes += 1;
    if (nodes > CONTROL_EXPRESSION_MAX_NODES) fail(`expression exceeds ${CONTROL_EXPRESSION_MAX_NODES} nodes`);
    if (depth > CONTROL_EXPRESSION_MAX_DEPTH) fail(`expression exceeds depth ${CONTROL_EXPRESSION_MAX_DEPTH}`);
    if (!isRecord(candidate)) fail(`${field} must be an object`);
    const branches = ['predicate', 'all', 'any', 'not'].filter((key) => Object.hasOwn(candidate, key));
    if (branches.length !== 1 || Object.keys(candidate).length !== 1) {
      fail(`${field} must contain exactly one of predicate, all, any, or not`);
    }
    if (branches[0] === 'predicate') {
      const raw = candidate.predicate;
      if (!isRecord(raw)) fail(`${field}.predicate must be an object`);
      const unknown = Object.keys(raw).filter((key) => !['path', 'operator', 'value'].includes(key));
      if (unknown.length) fail(`${field}.predicate contains unsupported field ${unknown.sort()[0]}`);
      validatePath(raw.path);
      if (typeof raw.operator !== 'string' || !OPERATORS.has(raw.operator)) {
        fail(`${field}.predicate.operator is unsupported`);
      }
      if (raw.operator === 'exists') {
        if (Object.hasOwn(raw, 'value')) fail(`${field}.predicate.value is not allowed for exists`);
      } else if (!Object.hasOwn(raw, 'value')) {
        fail(`${field}.predicate.value is required for ${raw.operator}`);
      } else if (raw.operator === 'in') {
        if (!Array.isArray(raw.value) || raw.value.length === 0 || raw.value.length > CONTROL_EXPRESSION_MAX_SET_ITEMS) {
          fail(`${field}.predicate.value must contain 1-${CONTROL_EXPRESSION_MAX_SET_ITEMS} scalar items for in`);
        }
        raw.value.forEach((value, index) => validateScalar(value, `${field}.predicate.value[${index}]`));
      } else {
        validateScalar(raw.value, `${field}.predicate.value`);
      }
      if (raw.operator === 'contains' && typeof raw.value !== 'string') {
        fail(`${field}.predicate.value must be a string for contains`);
      }
      if (['greater_than', 'greater_than_or_equal', 'less_than', 'less_than_or_equal'].includes(raw.operator)
        && typeof raw.value !== 'number') {
        fail(`${field}.predicate.value must be a number for ${raw.operator}`);
      }
      if (raw.operator === 'matches') {
        if (typeof raw.value !== 'string') fail(`${field}.predicate.value must be a string for matches`);
        const verdict = validateRegexPattern(raw.value);
        if (!verdict.ok) fail(`${field}.predicate.value was refused by the ReDoS guard (${verdict.reason})`);
      }
      return { predicate: raw as unknown as ControlPredicateV2 };
    }
    if (branches[0] === 'not') return { not: visit(candidate.not, depth + 1, `${field}.not`) };
    const branch = branches[0] as 'all' | 'any';
    const items = candidate[branch];
    if (!Array.isArray(items) || items.length === 0 || items.length > CONTROL_EXPRESSION_MAX_SET_ITEMS) {
      fail(`${field}.${branch} must contain 1-${CONTROL_EXPRESSION_MAX_SET_ITEMS} expressions`);
    }
    return { [branch]: items.map((item, index) => visit(item, depth + 1, `${field}.${branch}[${index}]`)) } as ControlExpressionV2;
  };
  return visit(expression, 1, 'expression');
}

function resolvePath(root: ControlExpressionInputV2, path: string): { found: boolean; value?: unknown } {
  const segments = path.split('.');
  let value: unknown = root;
  for (const segment of segments) {
    if (!isRecord(value) || !Object.hasOwn(value, segment)) return { found: false };
    value = value[segment];
  }
  return { found: true, value };
}

function predicateMatches(predicate: ControlPredicateV2, input: ControlExpressionInputV2): boolean {
  const resolved = resolvePath(input, predicate.path);
  if (predicate.operator === 'exists') return resolved.found;
  if (!resolved.found) return false;
  const actual = resolved.value;
  const expected = predicate.value;
  switch (predicate.operator) {
    case 'equals': return actual === expected;
    case 'not_equals': return actual !== expected;
    case 'contains':
      return typeof actual === 'string' && typeof expected === 'string' && actual.includes(expected);
    case 'in': return Array.isArray(expected) && expected.some((item) => item === actual);
    case 'greater_than': return typeof actual === 'number' && typeof expected === 'number' && actual > expected;
    case 'greater_than_or_equal': return typeof actual === 'number' && typeof expected === 'number' && actual >= expected;
    case 'less_than': return typeof actual === 'number' && typeof expected === 'number' && actual < expected;
    case 'less_than_or_equal': return typeof actual === 'number' && typeof expected === 'number' && actual <= expected;
    case 'matches': return typeof actual === 'string' && typeof expected === 'string' && safeRegexTest(expected, actual);
    default: return false;
  }
}

export function evaluateControlExpressionV2(expression: unknown, input: ControlExpressionInputV2): boolean {
  const valid = validateControlExpressionV2(expression);
  const evaluate = (node: ControlExpressionV2): boolean => {
    if ('predicate' in node) return predicateMatches(node.predicate, input);
    if ('all' in node) return node.all.every(evaluate);
    if ('any' in node) return node.any.some(evaluate);
    return !evaluate(node.not);
  };
  return evaluate(valid);
}
