import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const projectRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const workerPath = resolve(projectRoot, "dist/server/index.js");
const manifestPath = resolve(projectRoot, "dist/.openai/hosting.json");
const migrationRoot = resolve(projectRoot, "drizzle");
const migrationJournalPath = resolve(migrationRoot, "meta/_journal.json");

const [source, manifest, migrationJournal, migrationEntries] = await Promise.all([
  readFile(workerPath, "utf8"),
  readFile(manifestPath, "utf8"),
  readFile(migrationJournalPath, "utf8").then(JSON.parse),
  readdir(migrationRoot, { withFileTypes: true }),
]);
JSON.parse(manifest);

// Sites applies source-tree Drizzle migrations before uploading the Worker.
// Keep the journal and SQL files closed over exactly the same ordered set so a
// successful Worker build cannot silently omit a pending database migration.
const journalMigrations = migrationJournal.entries.map((entry) => `${entry.tag}.sql`);
const sourceMigrations = migrationEntries.filter((entry) => entry.isFile() && entry.name.endsWith(".sql")).map((entry) => entry.name).sort();
assert.deepEqual(sourceMigrations, [...journalMigrations].sort(), "drizzle SQL files and the migration journal must describe the same deploy set");
assert.ok(journalMigrations.includes("0003_service_principals.sql"), "service-principal migration must be part of the deploy journal");
const servicePrincipalMigration = await readFile(resolve(migrationRoot, "0003_service_principals.sql"), "utf8");
assert.match(servicePrincipalMigration, /BEFORE UPDATE OF user_id, role ON user_roles/, "packaged source must enforce service-principal role separation on UPDATE");

// A data URL forces ESM parsing even though the generated output has no package.json.
const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const workerModule = await import(moduleUrl);
assert.equal(
  typeof workerModule.default?.fetch,
  "function",
  `${pathToFileURL(workerPath)} must export default.fetch`,
);

console.log("Artifact is valid ESM and exports default.fetch");
