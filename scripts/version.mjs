import fs from "node:fs";
import process from "node:process";

const VERSION_RE =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

const files = {
  packageJson: "package.json",
  packageLock: "package-lock.json",
  cargoToml: "src-tauri/Cargo.toml",
  cargoLock: "src-tauri/Cargo.lock",
  tauriConfig: "src-tauri/tauri.conf.json",
};

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, "utf8"));
}

function writeJson(path, value) {
  fs.writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function readText(path) {
  return fs.readFileSync(path, "utf8");
}

function writeText(path, value) {
  fs.writeFileSync(path, value);
}

function cargoPackageVersion(text, packageName) {
  const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(
    `(\\[\\[package\\]\\]\\r?\\nname = "${escaped}"\\r?\\nversion = ")([^"]+)(")`,
  );
  const match = text.match(pattern);
  if (!match) throw new Error(`Could not find ${packageName} in Cargo.lock`);
  return match[2];
}

function setCargoPackageVersion(text, packageName, version) {
  const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(
    `(\\[\\[package\\]\\]\\r?\\nname = "${escaped}"\\r?\\nversion = ")([^"]+)(")`,
  );
  if (!pattern.test(text)) {
    throw new Error(`Could not find ${packageName} in Cargo.lock`);
  }
  return text.replace(pattern, `$1${version}$3`);
}

function collectVersions() {
  const packageJson = readJson(files.packageJson);
  const packageLock = readJson(files.packageLock);
  const cargoToml = readText(files.cargoToml);
  const cargoLock = readText(files.cargoLock);
  const tauriConfig = readJson(files.tauriConfig);

  const cargoTomlMatch = cargoToml.match(/^version\s*=\s*"([^"]+)"/m);
  if (!cargoTomlMatch) throw new Error("Could not find version in Cargo.toml");

  return [
    ["package.json", packageJson.version],
    ["package-lock.json", packageLock.version],
    ['package-lock.json packages[""]', packageLock.packages?.[""]?.version],
    ["src-tauri/Cargo.toml", cargoTomlMatch[1]],
    ["src-tauri/Cargo.lock fwoosh", cargoPackageVersion(cargoLock, "fwoosh")],
    ["src-tauri/tauri.conf.json", tauriConfig.version],
  ];
}

function currentVersion() {
  const versions = collectVersions();
  const values = [...new Set(versions.map(([, version]) => version))];
  if (values.length !== 1) {
    throw new Error(
      `Version mismatch:\n${versions.map(([name, version]) => `  ${name}: ${version}`).join("\n")}`,
    );
  }
  const [version] = values;
  if (!VERSION_RE.test(version)) {
    throw new Error(`Version is not valid SemVer: ${version}`);
  }
  return version;
}

function bump(version, kind) {
  if (VERSION_RE.test(kind)) return kind;

  const match = version.match(VERSION_RE);
  if (!match) throw new Error(`Cannot bump invalid SemVer: ${version}`);
  let major = Number(match[1]);
  let minor = Number(match[2]);
  let patch = Number(match[3]);

  if (kind === "major") {
    major += 1;
    minor = 0;
    patch = 0;
  } else if (kind === "minor") {
    minor += 1;
    patch = 0;
  } else if (kind === "patch") {
    patch += 1;
  } else {
    throw new Error("Usage: node scripts/version.mjs bump <patch|minor|major|x.y.z>");
  }

  return `${major}.${minor}.${patch}`;
}

function check() {
  const version = currentVersion();
  console.log(`Fwoosh version ${version}`);
  return version;
}

function normalizeExpectedVersion(value) {
  return value?.startsWith("v") ? value.slice(1) : value;
}

function checkExpected(expected) {
  const version = check();
  const normalized = normalizeExpectedVersion(expected);
  if (!normalized) {
    throw new Error("Usage: node scripts/version.mjs check <version|vversion>");
  }
  if (version !== normalized) {
    throw new Error(`Version ${version} does not match expected ${expected}`);
  }
}

function setVersion(version) {
  if (!VERSION_RE.test(version)) {
    throw new Error(`Version is not valid SemVer: ${version}`);
  }

  const packageJson = readJson(files.packageJson);
  packageJson.version = version;
  writeJson(files.packageJson, packageJson);

  const packageLock = readJson(files.packageLock);
  packageLock.version = version;
  if (!packageLock.packages?.[""]) {
    throw new Error('Could not find packages[""] in package-lock.json');
  }
  packageLock.packages[""].version = version;
  writeJson(files.packageLock, packageLock);

  const cargoToml = readText(files.cargoToml).replace(
    /^version\s*=\s*"[^"]+"/m,
    `version = "${version}"`,
  );
  writeText(files.cargoToml, cargoToml);

  const cargoLock = setCargoPackageVersion(
    readText(files.cargoLock),
    "fwoosh",
    version,
  );
  writeText(files.cargoLock, cargoLock);

  const tauriConfig = readJson(files.tauriConfig);
  tauriConfig.version = version;
  writeJson(files.tauriConfig, tauriConfig);
}

function main() {
  const [command, arg] = process.argv.slice(2);
  if (command === "check") {
    if (arg) {
      checkExpected(arg);
    } else {
      check();
    }
    return;
  }
  if (command === "bump") {
    const from = currentVersion();
    const to = bump(from, arg);
    setVersion(to);
    console.log(`Bumped Fwoosh ${from} -> ${to}`);
    return;
  }

  throw new Error("Usage: node scripts/version.mjs <check|bump>");
}

try {
  main();
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
