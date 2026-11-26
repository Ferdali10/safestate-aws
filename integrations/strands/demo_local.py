import json
from pathlib import Path

from safestate_adapter import SafeStateRuntime
from safestate_tools import (
    set_runtime,
    list_ec2_instances,
    describe_ec2_instance,
    request_stop_instance,
)

audit_path = "/tmp/safestate_demo_audit.jsonl"

# Fresh local SafeState runtime: no AWS calls.
Path(audit_path).unlink(missing_ok=True)
Path(audit_path + ".lock").unlink(missing_ok=True)

runtime = SafeStateRuntime(audit_path=audit_path)
set_runtime(runtime)

def show(title, raw):
    print(f"\n{'=' * 65}")
    print(title)
    print("=" * 65)
    try:
        print(json.dumps(json.loads(raw), indent=2))
    except (TypeError, json.JSONDecodeError):
        print(raw)

# 1. Authorized read through a real Strands tool.
show("1. LIST EC2 INSTANCES", list_ec2_instances())

# 2. Authorized description through a real Strands tool.
show("2. DESCRIBE DEVELOPMENT INSTANCE",
     describe_ec2_instance(instance_id="i-dev-001"))

# 3. Production stop request must be blocked by R2.
show("3. REQUEST STOP ON PRODUCTION",
     request_stop_instance(
         instance_id="i-prod-001",
         reason="SafeState security demonstration",
     ))

# 4. Verify the audit chain.
print(f"\n{'=' * 65}")
print("4. AUDIT VERIFICATION")
print("=" * 65)

verification = runtime.audit_sink.verify()
print("Valid:", verification.valid)
print("Records checked:", verification.records_checked)
print("Audit file:", audit_path)

print("\nDEMO FINISHED")
