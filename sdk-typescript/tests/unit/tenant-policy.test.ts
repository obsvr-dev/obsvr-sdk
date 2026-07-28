import { init, _reset, getConfig, setTenantPolicy, getTenantConfig } from '../../src/proxy/config';
import { applyPreCallPolicy } from '../../src/integrations/core';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import type { PolicyRule } from '../../src/policy/rules';

beforeEach(() => { _reset(); _resetSender(); });

describe('per-tenant policy isolation', () => {
  it('tenant A sees different rules from tenant B', async () => {
    init({ api_key: 'test' });
    const rulesA: PolicyRule[] = [{ id: 'r1', name: 'block-foo', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['tenantA-secret'] } }];
    const rulesB: PolicyRule[] = [{ id: 'r2', name: 'block-bar', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['tenantB-secret'] } }];
    setTenantPolicy('tenantA', rulesA);
    setTenantPolicy('tenantB', rulesB);

    const resultA = await applyPreCallPolicy('tenantA-secret text', {
      config: getConfig(), provider: 'openai', operation: 'chat', tenantId: 'tenantA',
    });
    expect(resultA.decision).toBe('block');

    const resultB = await applyPreCallPolicy('tenantA-secret text', {
      config: getConfig(), provider: 'openai', operation: 'chat', tenantId: 'tenantB',
    });
    expect(resultB.decision).toBe('allow'); // tenantB doesn't block tenantA-secret
  });

  it('global config unchanged by tenant overrides', () => {
    init({ api_key: 'test' });
    setTenantPolicy('tenant1', [{ id: 'r1', name: 'x', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['x'] } }]);
    const globalCfg = getConfig();
    expect(globalCfg.policyRules).toBeUndefined();
  });
});
