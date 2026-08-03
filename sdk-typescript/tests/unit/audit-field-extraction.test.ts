/**
 * Every field the exported `AuditFields` type declares is extracted, and the
 * two halves are asserted separately.
 *
 * `user_id`, `client_ip`, `user_agent` and `service_name` are declared on the
 * public `AuditFields` type as customer-provided, and `wrapper.ts` reads all
 * four onto the event — but they were missing from the extraction set, which is
 * the only thing that moves a key from the request to the audit side. That is
 * wrong in two directions at once, and one assertion cannot cover both:
 *
 *   H1  the value is REMOVED from the args that go to the provider;
 *   H2  the value ARRIVES on the audit fields the event is built from.
 *
 * A fix satisfying only H1 would strip the field and silently lose it. A fix
 * satisfying only H2 would record it and still ship it to the provider, which
 * rejects an unknown parameter.
 *
 * The type is the contract, so the table is driven from `getAuditFieldNames()`
 * rather than from a hand-written list: a field added to the set without a case
 * in the switch fails here instead of silently extracting `undefined`.
 */
import { filterArgs, hasAuditFields, getAuditFieldNames } from '../../src/proxy/filters/filter';
import type { AuditFields } from '../../src/proxy/types';

/** One representative string value per declared field. */
const STRING_FIELDS: Array<keyof AuditFields> = [
  'request_id',
  'region',
  'source',
  'user_id',
  'client_ip',
  'user_agent',
  'service_name',
];

describe('audit field extraction', () => {
  it('declares exactly the fields the AuditFields type does', () => {
    // The set and the type must not drift. `metadata` is the one non-string
    // member and is covered separately below.
    expect(new Set(getAuditFieldNames())).toEqual(new Set([...STRING_FIELDS, 'metadata']));
  });

  describe.each(STRING_FIELDS)('%s', (field) => {
    const args = [{ model: 'gpt-4o', messages: [{ role: 'user', content: 'hi' }], [field]: 'VALUE' }];

    it('H1: is stripped from the args the provider receives', () => {
      const { cleaned_args } = filterArgs(args);
      expect(cleaned_args[0]).not.toHaveProperty(field);
      // The provider's own parameters are untouched — this is a filter, not a
      // whitelist, and a new provider parameter must keep passing through.
      expect(cleaned_args[0]).toMatchObject({ model: 'gpt-4o' });
    });

    it('H2: arrives on the audit fields', () => {
      const { audit_fields } = filterArgs(args);
      expect(audit_fields[field]).toBe('VALUE');
    });

    it('is reported by hasAuditFields', () => {
      expect(hasAuditFields(args[0])).toBe(true);
    });
  });

  it('extracts metadata as an object', () => {
    const { cleaned_args, audit_fields } = filterArgs([{ model: 'm', metadata: { tenant_id: 't1' } }]);
    expect(cleaned_args[0]).not.toHaveProperty('metadata');
    expect(audit_fields.metadata).toEqual({ tenant_id: 't1' });
  });

  it('coerces a scalar user_id and never forwards it', () => {
    // user_id is the signed principal (it sits inside the format-3 decision
    // digest), so a scalar of the wrong type is coerced to the canonical
    // string both offline verifiers recompute identically — the exact
    // strings are pinned cross-language by the user_id_coercion section of
    // conformance/fixtures/signing_vectors.json. H1 still holds: nothing
    // reaches the provider either way.
    const { cleaned_args, audit_fields } = filterArgs([{ model: 'm', user_id: 42 }]);
    expect(cleaned_args[0]).not.toHaveProperty('user_id');
    expect(audit_fields.user_id).toBe('42');
  });

  it('treats an uncoercible user_id as absent, not a rendering', () => {
    // Containers and non-finite numbers have no rendering both languages can
    // recompute, so they stay off the record entirely (absent, never "NaN"
    // or "[object Object]") — and still never reach the provider.
    for (const raw of [{ id: 1 }, ['a'], NaN, Infinity]) {
      const { cleaned_args, audit_fields } = filterArgs([{ model: 'm', user_id: raw }]);
      expect(cleaned_args[0]).not.toHaveProperty('user_id');
      expect(audit_fields.user_id).toBeUndefined();
    }
  });

  it('still drops a non-string value of the OTHER audit fields', () => {
    // The coercion is the signed principal's alone: request_id/region/source
    // and the network fields keep the drop behaviour they always had.
    const { cleaned_args, audit_fields } = filterArgs([{ model: 'm', region: 7 }]);
    expect(cleaned_args[0]).not.toHaveProperty('region');
    expect(audit_fields.region).toBeUndefined();
  });

  it('leaves a provider parameter with a similar name alone', () => {
    // Non-vacuity for H1: the filter removes these four names, not everything.
    // `user` is a real provider parameter and must survive.
    const { cleaned_args } = filterArgs([{ model: 'm', user: 'end-user-123' }]);
    expect(cleaned_args[0]).toMatchObject({ user: 'end-user-123' });
  });

  it('leaves a non-object first argument untouched', () => {
    expect(filterArgs(['plain-string']).cleaned_args).toEqual(['plain-string']);
  });
});
