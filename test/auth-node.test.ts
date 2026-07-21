import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createSqliteStores,
  openOAuthDb,
  requestLock,
} from '../dist/auth-node/index.js';

test('sqlite stores round-trip state and session', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tsdk-'));
  const db = openOAuthDb(join(dir, 'oauth.sqlite'));
  const { stateStore, sessionStore } = createSqliteStores(db);

  await stateStore.set('k1', { iss: 'https://pds.tessera.at' } as never);
  assert.deepEqual(await stateStore.get('k1'), { iss: 'https://pds.tessera.at' });
  await stateStore.del('k1');
  assert.equal(await stateStore.get('k1'), undefined);

  await sessionStore.set('did:plc:abc', { tokenSet: { sub: 'did:plc:abc' } } as never);
  const s = (await sessionStore.get('did:plc:abc')) as { tokenSet: { sub: string } };
  assert.equal(s.tokenSet.sub, 'did:plc:abc');
  await sessionStore.del('did:plc:abc');
  assert.equal(await sessionStore.get('did:plc:abc'), undefined);

  db.close();
  rmSync(dir, { recursive: true, force: true });
});

test('requestLock serializes same-name work and isolates names', async () => {
  const order: string[] = [];
  const slow = requestLock('a', async () => {
    await new Promise((r) => setTimeout(r, 30));
    order.push('a1');
    return 1;
  });
  const fast = requestLock('a', async () => {
    order.push('a2');
    return 2;
  });
  const other = requestLock('b', async () => {
    order.push('b1');
    return 3;
  });
  assert.deepEqual(await Promise.all([slow, fast, other]), [1, 2, 3]);
  // b ran immediately (different name); a2 strictly after a1.
  assert.equal(order[0], 'b1');
  assert.deepEqual(order.slice(1), ['a1', 'a2']);
});

test('requestLock survives a failing predecessor', async () => {
  const failing = requestLock('c', async () => {
    throw new Error('boom');
  });
  const next = requestLock('c', async () => 'ok');
  await assert.rejects(failing, /boom/);
  assert.equal(await next, 'ok');
});
