const core = require("@actions/core");
const exec = require("@actions/exec");
const path = require("path");

async function run() {
  try {
    const peerIssuerUrl = core.getInput("peer-issuer-url");
    const ttlSeconds = core.getInput("ttl-seconds");
    const atticHost = core.getInput("attic-host");
    const authentikUrl = core.getInput("authentik-url");
    const authentikClientId = core.getInput("authentik-client-id");

    // setup.sh の出力を受け取るための一時ファイル
    const outputFile = `${process.env.RUNNER_TEMP}/wireguard-output.txt`;

    const exitCode = await exec.exec("bash", [path.join(__dirname, "..", "setup.sh")], {
      env: {
        ...process.env,
        PEER_ISSUER_URL: peerIssuerUrl,
        TTL_SECONDS: ttlSeconds,
        ATTIC_HOST: atticHost,
        AUTHENTIK_URL: authentikUrl,
        AUTHENTIK_CLIENT_ID: authentikClientId,
        GITHUB_OUTPUT_FILE: outputFile,
      },
    });

    if (exitCode !== 0) {
      throw new Error(`setup.sh exited with code ${exitCode}`);
    }

    // setup.sh の出力を読み取り
    const fs = require("fs");
    if (fs.existsSync(outputFile)) {
      const output = fs.readFileSync(outputFile, "utf8");
      for (const line of output.split("\n")) {
        const [key, ...valueParts] = line.split("=");
        const value = valueParts.join("=");
        if (key === "LEASE_ID") {
          core.saveState("lease-id", value);
          core.setOutput("lease-id", value);
        } else if (key === "CLIENT_IP") {
          core.saveState("client-ip", value);
          core.setOutput("client-ip", value);
        }
      }
    }

    // 入力パラメータもstateに保存（teardownで使用）
    core.saveState("peer-issuer-url", peerIssuerUrl);
    core.saveState("authentik-url", authentikUrl);
    core.saveState("authentik-client-id", authentikClientId);
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();
