const core = require("@actions/core");
const exec = require("@actions/exec");
const path = require("path");

async function run() {
  try {
    const leaseId = core.getState("lease-id");
    const peerIssuerUrl = core.getState("peer-issuer-url");
    const authentikUrl = core.getState("authentik-url");
    const authentikClientId = core.getState("authentik-client-id");

    if (!leaseId) {
      core.warning("No lease ID in state, skipping teardown");
      return;
    }

    const exitCode = await exec.exec("bash", [path.join(__dirname, "..", "teardown.sh")], {
      env: {
        ...process.env,
        LEASE_ID: leaseId,
        PEER_ISSUER_URL: peerIssuerUrl,
        AUTHENTIK_URL: authentikUrl,
        AUTHENTIK_CLIENT_ID: authentikClientId,
      },
    });

    if (exitCode !== 0) {
      core.warning(`teardown.sh exited with code ${exitCode}`);
    }
  } catch (error) {
    core.warning(`Teardown failed: ${error.message}`);
  }
}

run();
