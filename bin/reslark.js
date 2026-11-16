#!/usr/bin/env node
import { main } from '../src/cli.js';
import { asError } from '../src/errors.js';

process.stdout.on('error', (error) => { if (error.code === 'EPIPE') process.exit(0); throw error; });

main().catch((error) => {
  const failure = asError(error);
  process.stderr.write(`${JSON.stringify({ schema_version: 1, error: failure.toJSON() })}\n`);
  process.exitCode = failure.exitCode;
});
