import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { stripTypeScriptTypes } from "node:module";

const rootDir = resolve(import.meta.dirname, "..");
const srcDir = join(rootDir, "src");
const distDir = join(rootDir, "dist");

await rm(distDir, { recursive: true, force: true });

for (const inputPath of await collectTypeScriptFiles(srcDir)) {
  const relativePath = relative(srcDir, inputPath);
  const outputPath = join(distDir, relativePath.replace(/\.ts$/u, ".js"));
  const source = await readFile(inputPath, "utf8");
  const output = stripTypeScriptTypes(source, {
    mode: "transform",
    sourceUrl: inputPath
  });

  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, output, "utf8");
}

async function collectTypeScriptFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectTypeScriptFiles(fullPath)));
      continue;
    }

    if (entry.isFile() && entry.name.endsWith(".ts")) {
      files.push(fullPath);
    }
  }

  return files.sort();
}
