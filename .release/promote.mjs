// SPDX-License-Identifier: MIT
// Shared by protected tag workflows and explicitly confirmed local releases.
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

export class ReleaseError extends Error {}
export const fail = (message) => {
  throw new ReleaseError(message);
};
export const sha256 = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");
export const digest = (path) => sha256(readFileSync(path));
export const json = (path) => JSON.parse(readFileSync(path, "utf8"));
export const save = (path, value) =>
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
export function run(executable, args, options = {}) {
  const result = spawnSync(executable, args, {
    encoding: "utf8",
    timeout: 300_000,
    maxBuffer: 32 * 1024 * 1024,
    ...options,
  });
  if (result.status !== 0)
    fail(
      `${executable} failed; output suppressed; preserve evidence and retry verification`,
    );
  return result.stdout.trim();
}
export function safePath(path) {
  if (
    typeof path !== "string" ||
    !/^[A-Za-z0-9_.@/-]+$/.test(path) ||
    path.startsWith("/") ||
    path.split("/").some((p) => !p || p === "." || p === "..")
  )
    fail("unsafe archive path");
  return path;
}
export function files(root, ignoreGitRoot = false) {
  const result = {};
  function visit(path, prefix = "") {
    for (const name of readdirSync(path).sort()) {
      if (
        ignoreGitRoot &&
        path === root &&
        name === ".git" &&
        lstatSync(join(path, name)).isDirectory()
      )
        continue;
      const rel = safePath(prefix + name);
      const absolute = join(path, name);
      const stat = lstatSync(absolute);
      if (stat.isDirectory()) visit(absolute, `${rel}/`);
      else if (stat.isFile()) result[rel] = digest(absolute);
      else fail("links and special files are forbidden");
    }
  }
  visit(root);
  return result;
}
export function equalFiles(actual, expected) {
  const canonical = (value) =>
    JSON.stringify(
      Object.entries(value).sort(([a], [b]) => a.localeCompare(b)),
    );
  if (canonical(actual) !== canonical(expected))
    fail("IMMUTABLE TREE MISMATCH; stop later releases");
}
export function extract(archive, target, kind) {
  const zip = kind === "zip";
  const listing = run(
    zip ? "unzip" : "tar",
    zip ? ["-Z1", archive] : ["-tzf", archive],
  ).split("\n");
  if (!listing.length || listing.length > 10000)
    fail("invalid archive entry count");
  const seen = new Set();
  for (const entry of listing) {
    const path = safePath(entry.replace(/\/$/, ""));
    if (seen.has(path)) fail("duplicate archive entry");
    seen.add(path);
  }
  const verbose = run(
    zip ? "zipinfo" : "tar",
    zip ? ["-l", archive] : ["-tvzf", archive],
  ).split("\n");
  // ZIP listing includes header/footer lines; Unix modes identify payload entries.
  for (const entry of verbose) {
    if (zip && !/^[bcdhlps-][rwxstST-]{9}\s/.test(entry)) continue;
    if (!["-", "d"].includes(entry[0]))
      fail("archive links/special entries are forbidden");
  }
  mkdirSync(target, { recursive: true });
  run(
    zip ? "unzip" : "tar",
    zip ? ["-q", archive, "-d", target] : ["-xzf", archive, "-C", target],
  );
  files(target); // Recheck types after extraction, before any package code runs.
}
export function validateReceipt(receipt) {
  if (
    receipt.schemaVersion !== 1 ||
    !["npm", "dart", "flutter", "composer"].includes(receipt.ecosystem) ||
    !/^[a-z][a-z0-9-]+$/.test(receipt.package ?? "") ||
    !/^(?:@[a-z0-9-]+\/)?[a-z][a-z0-9_-]*(?:\/[a-z][a-z0-9_-]*)?$/.test(
      receipt.name ?? "",
    ) ||
    !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(receipt.version ?? "") ||
    !/^Egensolve\/realtime-(?:contracts|typescript|php|dart|flutter|laravel)$/.test(
      receipt.repository ?? "",
    ) ||
    receipt.environment !== `release-${receipt.package}` ||
    receipt.tag !== `v${receipt.version}` ||
    !/^[a-f0-9]{64}$/.test(receipt.archiveSha256 ?? "") ||
    !/^[a-f0-9]{64}$/.test(receipt.promoterSha256 ?? "") ||
    !/^[a-f0-9]{64}$/.test(receipt.smokeSha256 ?? "") ||
    !/^[a-f0-9]{64}$/.test(receipt.workflowSha256 ?? "") ||
    !receipt.files ||
    Object.keys(receipt.files).length === 0
  )
    fail("invalid release receipt");
  for (const [path, hash] of Object.entries(receipt.files)) {
    safePath(path);
    if (!/^[a-f0-9]{64}$/.test(hash)) fail("invalid file digest");
  }
}
export function authorize(mode, receipt, confirmation, env = process.env) {
  if (
    !["check", "verify", "publish-manual", "publish-automatic"].includes(mode)
  )
    fail("invalid promotion mode");
  if (mode === "publish-manual") {
    if (env.GITHUB_ACTIONS === "true")
      fail("manual mode is forbidden in Actions");
    if (
      confirmation !==
      `${receipt.name}@${receipt.version}:${receipt.repository}`
    )
      fail("explicit owner confirmation required");
  }
  if (mode === "publish-automatic") {
    if (
      env.GITHUB_ACTIONS !== "true" ||
      env.GITHUB_EVENT_NAME !== "push" ||
      env.GITHUB_REPOSITORY !== receipt.repository ||
      env.GITHUB_REF !== `refs/tags/${receipt.tag}` ||
      env.RELEASE_ENVIRONMENT !== receipt.environment ||
      !/^[a-f0-9]{40}$/.test(env.GITHUB_SHA ?? "") ||
      !/^\d+$/.test(env.GITHUB_RUN_ID ?? "") ||
      env.RELEASE_ENABLED !== "true"
    )
      fail("automatic identity/tag/environment is not approved");
    if (
      receipt.ecosystem !== "composer" &&
      (!env.ACTIONS_ID_TOKEN_REQUEST_URL || !env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)
    ) {
      fail("automatic publication requires OIDC; no token fallback");
    }
    if (env.NODE_AUTH_TOKEN || env.NPM_TOKEN)
      fail("automatic publication must not inherit npm publisher tokens");
  }
}
export function anonymousEnvironment(root) {
  const home = join(root, "home");
  mkdirSync(home, { recursive: true });
  const env = Object.fromEntries(
    ["PATH", "SystemRoot", "FLUTTER_ROOT"]
      .filter((k) => process.env[k])
      .map((k) => [k, process.env[k]]),
  );
  return {
    ...env,
    HOME: home,
    USERPROFILE: home,
    XDG_CONFIG_HOME: join(home, ".config"),
    PUB_CACHE: join(home, "pub-cache"),
    PUB_HOSTED_URL: "https://pub.dev",
    COMPOSER_HOME: join(home, "composer"),
    COMPOSER_CACHE_DIR: join(home, "composer-cache"),
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
    NPM_CONFIG_USERCONFIG: join(home, "npmrc"),
    NPM_CONFIG_GLOBALCONFIG: join(home, "global-npmrc"),
    NPM_CONFIG_CACHE: join(home, "npm-cache"),
    CI: "true",
  };
}
export function pubListing(output) {
  const result = [],
    directories = [];
  let started = false;
  for (const line of output.split("\n")) {
    if (/^Publishing .+:$/.test(line)) {
      started = true;
      continue;
    }
    if (!started) continue;
    if (/^Total compressed archive size:/.test(line)) break;
    const match = /^((?:│   |    )*)(?:├── |└── )(.+)$/.exec(line);
    if (!match) continue;
    const depth = match[1].length / 4;
    const file = /^(.*) \((?:<)?[0-9.]+ [KMG]?B\)$/.exec(match[2]);
    if (!file) {
      directories[depth] = match[2];
      directories.length = depth + 1;
    } else result.push([...directories.slice(0, depth), file[1]].join("/"));
  }
  return result.sort();
}
async function request(
  url,
  { method = "GET", headers = {}, body, hosts, missing = false } = {},
) {
  const allowed = hosts ?? [
    "registry.npmjs.org",
    "pub.dev",
    "packagist.org",
    "api.github.com",
    "codeload.github.com",
  ];
  let current = new URL(url);
  for (let redirects = 0; redirects <= 4; redirects++) {
    if (
      current.protocol !== "https:" ||
      current.username ||
      current.password ||
      current.port ||
      !allowed.includes(current.hostname)
    )
      fail("unapproved registry URL");
    const response = await fetch(current, {
      method,
      headers,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(60_000),
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      if (
        method !== "GET" ||
        Object.keys(headers).some((k) => k.toLowerCase() === "authorization")
      )
        fail("authenticated redirect refused");
      current = new URL(response.headers.get("location"), current);
      continue;
    }
    if (missing && response.status === 404) return null;
    if (!response.ok)
      fail(`registry returned HTTP ${response.status}; not proof of absence`);
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > 32 * 1024 * 1024) fail("registry response exceeds budget");
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  }
  fail("too many registry redirects");
}
const requestJson = async (url, options) => {
  const body = await request(url, options);
  if (body === null) return null;
  const value = JSON.parse(body.toString("utf8"));
  if (value === null || typeof value !== "object" || Array.isArray(value))
    fail("invalid registry metadata; not proof of absence");
  return value;
};
async function version(receipt) {
  const { name, version: v, ecosystem } = receipt;
  if (ecosystem === "npm")
    return requestJson(
      `https://registry.npmjs.org/${encodeURIComponent(name)}/${v}`,
      { missing: true },
    );
  if (ecosystem !== "composer")
    return requestJson(`https://pub.dev/api/packages/${name}/versions/${v}`, {
      missing: true,
    });
  const metadata = await requestJson(
    `https://packagist.org/packages/${name}.json`,
    { missing: true },
  );
  if (metadata === null) return null;
  if (
    !metadata.package?.versions ||
    typeof metadata.package.versions !== "object"
  )
    fail("invalid Packagist metadata");
  return (
    metadata.package.versions[v] ?? metadata.package.versions[`v${v}`] ?? null
  );
}
async function automaticProtection(receipt) {
  if (!process.env.GITHUB_TOKEN)
    fail("read-only GitHub token required to verify environment protection");
  const rule = await requestJson(
    `https://api.github.com/repos/${receipt.repository}/environments/${receipt.environment}`,
    {
      hosts: ["api.github.com"],
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
      },
    },
  );
  if (
    !rule.protection_rules?.some(
      (r) => r.type === "required_reviewers" && r.reviewers?.length > 0,
    )
  )
    fail("required reviewer protection is missing");
}
function identity(root, receipt) {
  if (receipt.ecosystem === "npm" || receipt.ecosystem === "composer") {
    const metadata = json(
      join(
        root,
        receipt.ecosystem === "npm" ? "package.json" : "composer.json",
      ),
    );
    if (
      metadata.name !== receipt.name ||
      metadata.version !== receipt.version ||
      metadata.license !== "MIT"
    )
      fail("package identity/license mismatch");
    if (
      receipt.ecosystem === "npm" &&
      metadata.repository?.url !==
        `https://github.com/${receipt.repository}.git`
    )
      fail("npm repository metadata must match trusted publisher");
  } else {
    const spec = readFileSync(join(root, "pubspec.yaml"), "utf8");
    if (
      !spec.split("\n").includes(`name: ${receipt.name}`) ||
      !spec.split("\n").includes(`version: ${receipt.version}`) ||
      /^publish_to:/m.test(spec) ||
      /^(?:dependency_overrides|workspace|resolution):/m.test(spec)
    )
      fail("pub.dev metadata is not approved for publication");
  }
}
function pubPrepare(stage, receipt, anonymous) {
  const command = receipt.ecosystem === "flutter" ? "flutter" : "dart";
  // Clean extraction only. No code generation, override, lockfile, or development checkout.
  const output = run(command, ["pub", "publish", "--dry-run"], {
    cwd: stage,
    env: anonymous,
  });
  if (
    JSON.stringify(pubListing(output)) !==
    JSON.stringify(Object.keys(receipt.files).sort())
  )
    fail("pub upload selection differs from approved files");
  for (const [path, hash] of Object.entries(receipt.files))
    if (digest(join(stage, path)) !== hash)
      fail("pub validation changed an approved file");
  return command;
}
async function publish(receipt, stage, archive, anonymous) {
  if (receipt.ecosystem === "npm") {
    const npmVersion = run("npm", ["--version"]).split(".").map(Number);
    if (
      npmVersion.length !== 3 ||
      npmVersion.some((v) => !Number.isInteger(v)) ||
      npmVersion[0] < 11 ||
      (npmVersion[0] === 11 &&
        (npmVersion[1] < 5 || (npmVersion[1] === 5 && npmVersion[2] < 1)))
    )
      fail("npm >= 11.5.1 is required");
    run(
      "npm",
      [
        "publish",
        archive,
        "--access=public",
        "--registry=https://registry.npmjs.org",
        "--ignore-scripts",
      ],
      { cwd: stage },
    );
  } else if (receipt.ecosystem !== "composer") {
    const command = pubPrepare(stage, receipt, anonymous);
    run(command, ["pub", "publish", "--force"], {
      cwd: stage,
      env: { ...process.env, PUB_HOSTED_URL: "https://pub.dev" },
    });
  } else {
    if (!process.env.PACKAGIST_USERNAME || !process.env.PACKAGIST_API_TOKEN)
      fail("Packagist maintainer credentials required for explicit update");
    const url = new URL("https://packagist.org/api/update-package");
    url.searchParams.set("username", process.env.PACKAGIST_USERNAME);
    url.searchParams.set("apiToken", process.env.PACKAGIST_API_TOKEN);
    await request(url, {
      method: "POST",
      hosts: ["packagist.org"],
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        repository: { url: `https://packagist.org/packages/${receipt.name}` },
      }),
    });
  }
}
function mirrorCommit(root, receipt, anonymous) {
  run("git", ["diff", "--exit-code"], { cwd: root, env: anonymous });
  run("git", ["diff", "--cached", "--exit-code"], {
    cwd: root,
    env: anonymous,
  });
  const tag = run("git", ["rev-parse", `${receipt.tag}^{commit}`], {
    cwd: root,
    env: anonymous,
  });
  const head = run("git", ["rev-parse", "HEAD"], { cwd: root, env: anonymous });
  if (tag !== head) fail("mirror release tag must identify this checkout");
  const remote = run(
    "git",
    [
      "ls-remote",
      `https://github.com/${receipt.repository}.git`,
      `refs/tags/${receipt.tag}`,
      `refs/tags/${receipt.tag}^{}`,
    ],
    { env: anonymous },
  );
  const refs = new Map(
    remote.split("\n").map((line) => line.split(/\s+/).reverse()),
  );
  if (
    (refs.get(`refs/tags/${receipt.tag}^{}`) ??
      refs.get(`refs/tags/${receipt.tag}`)) !== tag
  )
    fail("public mirror tag is absent or differs");
  return tag;
}
async function readback(receipt, metadata, work, evidence, mirror) {
  let url;
  if (receipt.ecosystem === "npm") url = metadata.dist?.tarball;
  else if (receipt.ecosystem === "composer") {
    if (
      metadata.source?.reference !== mirror ||
      metadata.source?.url !== `https://github.com/${receipt.repository}.git` ||
      metadata.dist?.reference !== mirror
    )
      fail("Packagist source differs from approved mirror tag");
    url = metadata.dist?.url;
  } else url = metadata.archive_url;
  if (typeof url !== "string") fail("invalid registry distribution metadata");
  const hosts =
    receipt.ecosystem === "npm"
      ? ["registry.npmjs.org"]
      : receipt.ecosystem === "composer"
        ? ["api.github.com", "codeload.github.com"]
        : ["pub.dev"];
  const bytes = await request(url, { hosts });
  const zip = receipt.ecosystem === "composer";
  const archive = join(evidence, `registry.${zip ? "zip" : "tgz"}`);
  writeFileSync(archive, bytes);
  if (receipt.ecosystem === "npm" && sha256(bytes) !== receipt.archiveSha256)
    fail("IMMUTABLE ARCHIVE MISMATCH; stop later releases");
  const extracted = join(work, "registry");
  extract(archive, extracted, zip ? "zip" : "tgz");
  let root = extracted;
  if (receipt.ecosystem === "npm") root = join(extracted, "package");
  if (zip) {
    const children = readdirSync(extracted);
    if (
      children.length !== 1 ||
      !lstatSync(join(extracted, children[0])).isDirectory()
    )
      fail("invalid Composer distribution root");
    root = join(extracted, children[0]);
  }
  equalFiles(files(root), receipt.files);
  return { digest: sha256(bytes), root };
}
function consumer(receipt, root, smoke, anonymous) {
  mkdirSync(root);
  const options = { cwd: root, env: anonymous };
  if (receipt.ecosystem === "npm") {
    save(join(root, "package.json"), { private: true, type: "module" });
    run(
      "npm",
      [
        "install",
        `${receipt.name}@${receipt.version}`,
        "--registry=https://registry.npmjs.org",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
      ],
      options,
    );
    equalFiles(files(join(root, "node_modules", receipt.name)), receipt.files);
    copyFileSync(smoke, join(root, "smoke.mjs"));
    run("node", ["smoke.mjs"], options);
  } else if (receipt.ecosystem === "composer") {
    save(join(root, "composer.json"), {
      require: { [receipt.name]: receipt.version },
      config: { "allow-plugins": false },
    });
    run(
      "composer",
      [
        "install",
        "--no-interaction",
        "--no-scripts",
        "--no-plugins",
        "--prefer-dist",
      ],
      options,
    );
    equalFiles(files(join(root, "vendor", receipt.name)), receipt.files);
    copyFileSync(smoke, join(root, "smoke.php"));
    run("php", ["smoke.php"], options);
  } else {
    const flutter = receipt.ecosystem === "flutter";
    writeFileSync(
      join(root, "pubspec.yaml"),
      `name: release_consumer\nenvironment:\n  sdk: ^3.0.0\ndependencies:\n  ${receipt.name}: ${receipt.version}\n${flutter ? "  flutter:\n    sdk: flutter\ndev_dependencies:\n  flutter_test:\n    sdk: flutter\n" : ""}`,
    );
    run(flutter ? "flutter" : "dart", ["pub", "get"], options);
    const configuration = json(join(root, ".dart_tool/package_config.json"));
    const installed = configuration.packages.find(
      (p) => p.name === receipt.name,
    );
    if (!installed) fail("hosted consumer dependency missing");
    const installedRoot = fileURLToPath(
      new URL(
        installed.rootUri,
        `file://${join(root, ".dart_tool/package_config.json")}`,
      ),
    );
    equalFiles(files(installedRoot), receipt.files);
    copyFileSync(smoke, join(root, flutter ? "smoke_test.dart" : "smoke.dart"));
    run(
      flutter ? "flutter" : "dart",
      flutter ? ["test", "smoke_test.dart"] : ["run", "smoke.dart"],
      options,
    );
  }
}
export async function promote(
  directory,
  mode,
  approvedHash,
  output,
  confirmation,
) {
  const root = resolve(directory),
    support = join(root, ".release");
  if (
    !/^[a-f0-9]{64}$/.test(approvedHash ?? "") ||
    digest(join(support, "receipt.json")) !== approvedHash
  )
    fail("explicit receipt digest does not match");
  const receipt = json(join(support, "receipt.json"));
  validateReceipt(receipt);
  authorize(mode, receipt, confirmation);
  if (
    digest(join(support, "promote.mjs")) !== receipt.promoterSha256 ||
    digest(join(support, "smoke")) !== receipt.smokeSha256 ||
    digest(join(root, ".github/workflows/publish.yml")) !==
      receipt.workflowSha256
  )
    fail("release support changed after approval");
  const publicFiles = {
    ".release/receipt.json": approvedHash,
    ".release/approval.sha256": sha256(`${approvedHash}\n`),
    ".release/promote.mjs": receipt.promoterSha256,
    ".release/smoke": receipt.smokeSha256,
    ".github/workflows/publish.yml": receipt.workflowSha256,
    [`.release/candidate.${receipt.ecosystem === "composer" ? "zip" : "tgz"}`]:
      receipt.archiveSha256,
    ...(receipt.ecosystem === "composer"
      ? {
          ...receipt.files,
          ".gitattributes": sha256(
            "/.release export-ignore\n/.github export-ignore\n/.gitattributes export-ignore\n",
          ),
        }
      : { LICENSE: receipt.files.LICENSE }),
  };
  equalFiles(files(root, true), publicFiles);
  const evidence = resolve(output);
  if (evidence.startsWith(`${root}/`) || existsSync(evidence))
    fail("use a new evidence directory outside the release repository");
  mkdirSync(evidence, { recursive: true, mode: 0o700 });
  const archiveName =
    receipt.ecosystem === "composer" ? "candidate.zip" : "candidate.tgz";
  const archive = join(evidence, archiveName);
  copyFileSync(join(support, archiveName), archive);
  if (digest(archive) !== receipt.archiveSha256)
    fail("approved archive changed");
  const work = mkdtempSync(join(tmpdir(), "package-promotion-"));
  try {
    const smoke = join(work, "smoke");
    copyFileSync(join(support, "smoke"), smoke);
    if (digest(smoke) !== receipt.smokeSha256)
      fail("smoke changed during capture");
    extract(
      archive,
      join(work, "stage"),
      receipt.ecosystem === "composer" ? "zip" : "tgz",
    );
    const stage = join(
      work,
      "stage",
      receipt.ecosystem === "npm" ? "package" : "",
    );
    equalFiles(files(stage), receipt.files);
    identity(stage, receipt);
    save(join(evidence, "approval.json"), {
      receiptSha256: approvedHash,
      package: receipt.name,
      version: receipt.version,
      repository: receipt.repository,
      mode,
      archiveSha256: receipt.archiveSha256,
      workflowRun:
        mode === "publish-automatic" ? process.env.GITHUB_RUN_ID : null,
    });
    if (mode === "check") {
      console.log(
        "CHECKED: exact approved bundle; no registry publication or readback claimed",
      );
      return;
    }
    const anonymous = anonymousEnvironment(work);
    if (mode === "publish-automatic") await automaticProtection(receipt);
    let mirror;
    if (receipt.ecosystem === "composer")
      mirror = mirrorCommit(root, receipt, anonymous);
    let metadata = await version(receipt);
    const existed = metadata !== null;
    if (!existed) {
      if (mode === "verify") fail("version absent; no release success claimed");
      // Flutter's hosted dependency is resolved without overrides before any upload.
      save(join(evidence, "upload-attempt.json"), {
        status: "outcome-unknown-until-readback",
        package: receipt.name,
        version: receipt.version,
      });
      await publish(receipt, stage, archive, anonymous);
      save(join(evidence, "upload.json"), {
        status: "unverified",
        package: receipt.name,
        version: receipt.version,
      });
      for (let attempt = 0; attempt < 6 && metadata === null; attempt++) {
        if (attempt) await new Promise((resolve) => setTimeout(resolve, 5000));
        metadata = await version(receipt);
      }
      if (metadata === null)
        fail(
          "uploaded version not visible; preserve evidence and retry verify",
        );
    }
    save(join(evidence, "registry-metadata.json"), metadata);
    const downloaded = await readback(
      receipt,
      metadata,
      work,
      evidence,
      mirror,
    );
    consumer(receipt, join(work, "consumer"), smoke, anonymous);
    save(join(evidence, "readback.json"), {
      receiptSha256: approvedHash,
      package: receipt.name,
      version: receipt.version,
      registrySha256: downloaded.digest,
      tree: "exact",
      consumer: "passed",
      alreadyPublished: existed,
    });
    console.log(
      `VERIFIED: ${receipt.name}@${receipt.version}; registry tree and anonymous consumer passed`,
    );
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const [mode, approval, output, confirmation] = process.argv.slice(2);
  try {
    if (process.argv.length < 5 || process.argv.length > 6)
      fail(
        "usage: node .release/promote.mjs <check|verify|publish-manual|publish-automatic> <approved-receipt-sha256> <new-evidence-dir> [name@version:repository]",
      );
    await promote(
      dirname(dirname(fileURLToPath(import.meta.url))),
      mode,
      approval,
      output,
      confirmation,
    );
  } catch (error) {
    console.error(
      `Release stopped: ${error instanceof ReleaseError ? error.message : "invalid input or tool response; details suppressed"}`,
    );
    process.exitCode = 1;
  }
}
