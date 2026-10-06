// One contender for a lock, run as its own process by lock.test.ts:
//   node --import tsx test/fixtures/lock-child.ts <lock file> <hold ms>
// Prints "won" (then holds the lock) or "lost".
import { LockError, acquireLock } from "../../src/lock.js";

const [file, holdMs] = process.argv.slice(2);
try {
  const release = acquireLock(file!);
  process.stdout.write("won\n");
  setTimeout(() => {
    release();
    process.exit(0);
  }, Number(holdMs));
} catch (err) {
  process.stdout.write(err instanceof LockError ? "lost\n" : `error ${(err as Error).message}\n`);
  process.exit(0);
}
