import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isTesseraHandle,
  normalizeHandle,
  shortenDid,
} from '../dist/core/index.js';

test('isTesseraHandle accepts first-level tessera handles', () => {
  assert.ok(isTesseraHandle('mb.tessera.at'));
  assert.ok(isTesseraHandle('a001of-dev0zzz.tessera.at'));
});

test('isTesseraHandle rejects foreign or nested handles', () => {
  assert.ok(!isTesseraHandle('mb.bsky.social'));
  assert.ok(!isTesseraHandle('a.b.tessera.at'));
  assert.ok(!isTesseraHandle('-bad.tessera.at'));
  assert.ok(!isTesseraHandle('tessera.at'));
});

test('normalizeHandle strips @ and lowercases', () => {
  assert.equal(normalizeHandle('  @MB.Tessera.At '), 'mb.tessera.at');
});

test('shortenDid keeps short DIDs and shortens long ones', () => {
  assert.equal(shortenDid('did:plc:short'), 'did:plc:short');
  const long = 'did:plc:27ngznwy4vrytjkfa7ctulbv';
  const short = shortenDid(long);
  assert.ok(short.length < long.length);
  assert.ok(short.includes('…'));
});
