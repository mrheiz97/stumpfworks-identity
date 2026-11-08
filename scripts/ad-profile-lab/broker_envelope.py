"""NON-DEPLOYABLE signed-request probe. No listener, key provisioning or runtime adapter."""
import json
import os
import subprocess
import tempfile
import time

from broker_candidate import Denied

MAX_BYTES = 8192
POLICY = "profile-lab-v1"
AUDIENCE = "profile.test/dc1/local-cas"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Denied("duplicate field")
        result[key] = value
    return result


def crypto(public_key, payload, signature):
    # Fixed executable/options; neither request nor actor selects an algorithm,
    # file, key, command or environment. Files stay in a private temporary dir.
    with tempfile.TemporaryDirectory(prefix="broker-proof-") as directory:
        os.chmod(directory, 0o700)
        for name, data in (("key", public_key), ("body", payload), ("sig", signature)):
            path = os.path.join(directory, name)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
        result = subprocess.run(
            ["/usr/bin/openssl", "pkeyutl", "-verify", "-pubin", "-inkey", directory + "/key",
             "-rawin", "-in", directory + "/body", "-sigfile", directory + "/sig"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=3, env={"PATH": "/usr/bin:/bin", "LANG": "C"}, check=False)
        if result.returncode:
            raise Denied("invalid proof")


class Gate:
    def __init__(self, public_key):
        # Pinned by trusted harness, never supplied in the envelope. Public only.
        self.public_key = bytes(public_key)

    def execute(self, candidate, payload, signature, username, password):
        if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_BYTES or not isinstance(signature, bytes) or len(signature) != 64:
            raise Denied("invalid frame")
        crypto(self.public_key, payload, signature)
        try:
            proof = json.loads(payload, object_pairs_hook=unique_pairs)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise Denied("invalid encoding") from error
        if not isinstance(proof, dict) or set(proof) != {"request", "actor", "issued", "expires", "policy", "audience"} or canonical(proof) != payload:
            raise Denied("noncanonical proof")
        issued, expires = proof["issued"], proof["expires"]
        def fresh():
            now = int(time.time())
            if type(issued) is not int or type(expires) is not int or not issued <= now < expires or not 0 < expires - issued <= 60:
                raise Denied("expired or invalid lifetime")
        fresh()
        if proof["policy"] != POLICY or proof["audience"] != AUDIENCE:
            raise Denied("wrong policy or audience")
        request = proof["request"]
        if not isinstance(request, dict) or set(request) != {"id", "target", "sid", "version", "domain", "dc", "changes"} or any(not isinstance(request[k], str) or not request[k] for k in request if k != "changes"):
            raise Denied("invalid request shape")
        # A signature authorizes this exact request; it NEVER substitutes for
        # fresh user authentication. Current group checks still happen in DSDB.
        actor = candidate.authenticate(username, password)
        if actor != proof["actor"]:
            raise Denied("actor mismatch")
        # Existing durable claim binds the signed request ID/content/actor and
        # blocks both repeated execution and fresh IDs on uncertain targets.
        return candidate.execute(request, username, password, authorize=fresh)
