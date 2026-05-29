#!/usr/bin/env node
import { runCli } from '../dist/cli.js';

const result = runCli(process.argv.slice(2));
if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
process.exit(result.exitCode);
