/**
 * Usage:  docker compose run --rm imap-mcp node dist/tools/hash-password.js
 * Reads a password from stdin (no echo when piped) and prints the scrypt hash
 * to put in OPERATOR_PASSWORD_HASH. The plaintext is never written anywhere.
 */
import { createInterface } from 'node:readline/promises';
import { hashPassword } from '../auth/password.js';

const rl = createInterface({ input: process.stdin, output: process.stderr });
const pw = await rl.question('Password: ');
rl.close();

if (pw.length < 12) {
  console.error('Refusing: use at least 12 characters.');
  process.exit(1);
}

process.stdout.write(`${await hashPassword(pw)}\n`);
