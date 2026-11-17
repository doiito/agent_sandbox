#!/usr/bin/env node
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {APIError, Client, Session} from '../sdk/node/index.js';

const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const client = new Client(config.url, {token: 'token-a', certFile: config.cert, keyFile: config.key, caFile: config.ca});
const session = new Session(client, {...config.session, artifactManifestSha256: config.session.artifact_manifest_sha256});
const identity = 'b'.repeat(24);
if (process.argv[3] === 'create') {
  const grant = await session.ports.createPreview(config.port, {previewId: identity, ttlMs: 20000});
  assert(grant.bootstrapURL); assert.equal(grant.id, identity);
  assert(!Object.hasOwn(await grant.info(), 'bootstrap_url'));
  await assert.rejects(session.ports.createPreview(config.port, {previewId: identity}), error =>
    error instanceof APIError && error.status === 409 && error.preview.id === identity);
  writeFileSync(config.result, JSON.stringify(grant.created), {mode: 0o600});
  console.log('PASS create once and duplicate rejection');
} else {
  const grant = session.ports.preview(config.port, identity), info = await grant.info();
  assert.equal(info.status, 'active'); assert(!Object.hasOwn(info, 'bootstrap_url'));
  assert.equal(grant.bootstrapURL, undefined);
  assert.equal((await grant.revoke()).status, 'revoked');
  assert.equal((await grant.info()).status, 'revoked');
  console.log('PASS new-process query and revoke after policy denial');
}
