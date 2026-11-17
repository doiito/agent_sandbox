# Guest controlled inference

These standard-library-only Python and Node modules implement the guest side of
ADR-0081. Image packaging, signed v7 profiles and actual VM acceptance are still
pending; these source files alone do not enable a production capability.

Python supports the Linux code runtime and the existing x64 OSv Python runtime:

```python
import sandbox

result = sandbox.ml.invoke("model", {"prompt": "hello"})
print(result.invocation_id, result.data)
print(sandbox.ml.bill()["settled_units"])
```

`import remote_infer` exposes the same `invoke`, `bill`, `policy` and `ml`.
Imports perform no network or C ABI calls. The first operation detects the OSv
vsock ABI lazily; OSv reports Linux through uname, so uname is not a selector.
On Linux, the SDK connects only to PID1's `127.0.0.1:3128` proxy. On OSv, it
connects through `osv_vsock_*` to host CID 2, port 5001. Neither reads proxy URLs,
task identity or credentials from environment variables.

Linux Node uses the fixed installed module:

```javascript
const sandbox = require('/opt/osv/remote-infer.cjs');
const result = await sandbox.ml.invoke('model', {prompt: 'hello'});
console.log(result.invocationId, result.data);
console.log((await sandbox.ml.bill()).settled_units);
```

Python accepts `invocation_id`, `timeout_ms` and `request_timeout` in seconds.
Node accepts `invocationId`, `timeoutMs`, `requestTimeoutMs` and `signal`.
Observation defaults to 35 seconds and is bounded to 300 seconds; the host
continues to enforce its own shorter request/relay deadline. Every operation
uses one absolute observation deadline. Invocation IDs are generated before
I/O, or callers may supply 24 lowercase hex digits. Model POSTs are never
retried. `InferenceError` retains the known ID and `delivery_unknown` /
`deliveryUnknown`; read the task bill after a timeout or lost result. A failed
metadata lookup can leave the task ID unknown. Amounts remain decimal strings.

The root proxy supplies and pins task identity and its startup policy digest.
The guest cannot select another task or replace model URLs, prices or auth.
Policy changes in a restarted egress service reject old root grants. Metadata
and invocation traffic use only `http://inference.osv.invalid/v1/...`.

Shared amount, receipt, bill, policy and plain-JSON validation is generated from
the canonical host SDK definitions. Generated files are stored in the project;
there is no runtime code generation or package installation. Run
`python3 scripts/build-guest-inference-sdk.py --check` to detect drift.
