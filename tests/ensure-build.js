"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const rootDir = path.join(__dirname, "..");
const nodeModulesPath = path.join(rootDir, "node_modules");
const addonPath = path.join(rootDir, "build", "Release", "blocktemplate.node");
const packageJson = require(path.join(rootDir, "package.json"));

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: rootDir,
    stdio: "inherit",
    shell: process.platform === "win32"
  });

  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status || 1);
}

function hasRuntimeDependencies() {
  return Object.keys(packageJson.dependencies || {}).every((name) => {
    return fs.existsSync(path.join(nodeModulesPath, ...name.split("/")));
  });
}

if (!fs.existsSync(nodeModulesPath) || !hasRuntimeDependencies()) {
  run("npm", ["install"]);
} else if (!fs.existsSync(addonPath)) {
  run("npm", ["rebuild"]);
}

if (!fs.existsSync(addonPath)) {
  console.error(`Native addon was not built: ${addonPath}`);
  process.exit(1);
}
