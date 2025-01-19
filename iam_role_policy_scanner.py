import asyncio
import subprocess
import shlex
import json
import shutil
import csv
import argparse
import time
from typing import List, Dict, Optional

start_time = time.time()

target_actions = [
    "iam:CreateRole",
    "iam:DeleteRole",
    "iam:CreateUser",
    "iam:*"
]

async def run_aws_cli(command_str: str) -> Optional[dict]:
    # Asynchronously executes an AWS CLI command and returns the output in JSON format or None in case of an error
    try:
        if not command_str:
            print("Error: an empty command string was provided.")
            return None

        command = shlex.split(command_str)
        if not shutil.which(command[0]):
            print(f"Error: the command '{command[0]}' was not found in the system.")
            return None

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            print(f"Error executing the command: {stderr.decode()}")
            return None

        return json.loads(stdout.decode())
    except json.JSONDecodeError as e:
        print(f"JSON decoding error: {e}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def check_actions_in_policy(policy_document: dict, target_actions: List[str]) -> bool:
    # Checks if the policy document contains the target actions
    if not policy_document:
        return False
    policy_document_str = json.dumps(policy_document)
    matched_actions = [action for action in target_actions if action in policy_document_str]
    return bool(matched_actions), matched_actions

async def process_inline_policies(role_name: str, role_arn: str, actions: List[str]) -> List[Dict]:
    # Processes the inline policies of a role
    inline_policies = await run_aws_cli(f"aws iam list-role-policies --role-name {role_name}")
    if not inline_policies:
        return []

    # Create tasks for parallel retrieval of all policies
    tasks = [
        run_aws_cli(f"aws iam get-role-policy --role-name {role_name} --policy-name {policy_name}")
        for policy_name in inline_policies.get("PolicyNames", [])
    ]
    
    # Execute all requests in parallel
    policies = await asyncio.gather(*tasks)
    
    results = []
    for policy_name, policy in zip(inline_policies.get("PolicyNames", []), policies):
        if policy and "PolicyDocument" in policy:
            is_matched, matched_actions = check_actions_in_policy(policy["PolicyDocument"], actions)
            if is_matched:
                results.append({
                    "role_name": role_name,
                    "role_arn": role_arn,
                    "policy_name": policy_name,
                    "policy_arn": f"inline-policy:{policy_name}",
                    "matched_actions": matched_actions
                })
    return results

async def process_managed_policy(role_name: str, role_arn: str, policy: Dict, actions: List[str]) -> Optional[Dict]:
    # Processes a specific managed policy
    policy_arn = policy["PolicyArn"]
    policy_name = policy["PolicyName"]
    
    policy_versions = await run_aws_cli(f"aws iam list-policy-versions --policy-arn {policy_arn}")
    if not policy_versions:
        return None

    # Create tasks for parallel retrieval of all policy versions
    tasks = [
        run_aws_cli(f"aws iam get-policy-version --policy-arn {policy_arn} --version-id {version.get('VersionId', '')}")
        for version in policy_versions.get('Versions', [])
    ]
    
    # Execute all requests in parallel
    policy_versions_data = await asyncio.gather(*tasks)
    
    for policy_version in policy_versions_data:
        if policy_version and "PolicyVersion" in policy_version and "Document" in policy_version["PolicyVersion"]:
            is_matched, matched_actions = check_actions_in_policy(policy_version["PolicyVersion"]["Document"], actions)
            if is_matched:
                return {
                    "role_name": role_name,
                    "role_arn": role_arn,
                    "policy_name": policy_name,
                    "policy_arn": policy_arn,
                    "matched_actions": matched_actions
                }
    return None

async def process_attached_policies(role_name: str, role_arn: str, actions: List[str]) -> List[Dict]:
    # Processes the attached policies of a role
    attached_policies = await run_aws_cli(f"aws iam list-attached-role-policies --role-name {role_name}")
    if not attached_policies:
        return []

    # Create and execute tasks in parallel
    tasks = [
        process_managed_policy(role_name, role_arn, policy, actions)
        for policy in attached_policies.get("AttachedPolicies", [])
    ]
    
    policy_results = await asyncio.gather(*tasks)
    return [result for result in policy_results if result is not None]

async def process_role(role: Dict, actions: List[str]) -> List[Dict]:
    # Processes a specific role
    role_name = role["RoleName"]
    role_arn = role["Arn"]
    print(f"Checking role: {role_name}")

    # Launch inline and attached policy processing in parallel
    inline_results, attached_results = await asyncio.gather(
        process_inline_policies(role_name, role_arn, actions),
        process_attached_policies(role_name, role_arn, actions)
    )
    
    return inline_results + attached_results

async def process_permission_set(permission_set_arn: str, instance_arn: str, actions: List[str]) -> List[Dict]:
    # Processes a specific permission set
    permission_set_name = permission_set_arn.split('/')[-1]
    print(f"Checking permission set: {permission_set_name}")

    # Get inline policy for permission set
    inline_policy = await run_aws_cli(
        f"aws sso-admin get-inline-policy-for-permission-set --instance-arn {instance_arn} "
        f"--permission-set-arn {permission_set_arn}"
    )
    
    results = []
    if inline_policy and "InlinePolicy" in inline_policy:
        policy_doc = json.loads(inline_policy["InlinePolicy"])
        is_matched, matched_actions = check_actions_in_policy(policy_doc, actions)
        if is_matched:
            results.append({
                "permission_set_name": permission_set_name,
                "permission_set_arn": permission_set_arn,
                "policy_type": "inline",
                "matched_actions": matched_actions
            })

    # Get managed policies attached to permission set
    managed_policies = await run_aws_cli(
        f"aws sso-admin list-managed-policies-in-permission-set --instance-arn {instance_arn} "
        f"--permission-set-arn {permission_set_arn}"
    )

    if managed_policies and "AttachedManagedPolicies" in managed_policies:
        for policy in managed_policies["AttachedManagedPolicies"]:
            policy_result = await process_managed_policy(
                permission_set_name,
                permission_set_arn,
                {"PolicyArn": policy["Arn"], "PolicyName": policy["Name"]},
                actions
            )
            if policy_result:
                results.append(policy_result)

    return results

async def main_async():
    parser = argparse.ArgumentParser(description="Scan IAM roles, policies and permission sets for target actions")
    parser.add_argument("--actions", nargs="+", default=target_actions, help="List of actions to search for")
    parser.add_argument("--output", choices=["csv", "json", "text"], default="text", help="Output format (csv, json, text)")
    args = parser.parse_args()

    if not shutil.which("aws"):
        print("Error: AWS CLI command not found")
        return

    results = []
    
    print("Checking IAM roles...")
    # Check IAM roles
    roles = await run_aws_cli("aws iam list-roles")
    if roles:
        tasks = [process_role(role, args.actions) for role in roles.get("Roles", [])]
        results_nested = await asyncio.gather(*tasks)
        results.extend([item for sublist in results_nested for item in sublist])

    print("\nChecking Permission Sets...")
    # Check Permission Sets (теперь всегда)
    instances = await run_aws_cli("aws sso-admin list-instances")
    if instances and "Instances" in instances:
        for instance in instances["Instances"]:
            instance_arn = instance["InstanceArn"]
            permission_sets = await run_aws_cli(
                f"aws sso-admin list-permission-sets --instance-arn {instance_arn}"
            )
            if permission_sets and "PermissionSets" in permission_sets:
                tasks = [
                    process_permission_set(ps_arn, instance_arn, args.actions)
                    for ps_arn in permission_sets["PermissionSets"]
                ]
                ps_results_nested = await asyncio.gather(*tasks)
                results.extend([item for sublist in ps_results_nested for item in sublist])

    if args.output == "csv":
        with open('results.csv', 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ["role_name", "role_arn", "policy_name", "policy_arn", "matched_actions", 
                         "permission_set_name", "permission_set_arn", "policy_type"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        print("Results saved to results.csv")
    elif args.output == "json":
        print(json.dumps(results, indent=4))
    elif args.output == "text":
        if results:
            for result in results:
                if "role_name" in result:
                    print(f"Found action in policy {result['policy_name']} for role {result['role_name']} (ARN: {result['role_arn']})")
                elif "permission_set_name" in result:
                    print(f"Found action in {result['policy_type']} policy for permission set {result['permission_set_name']} (ARN: {result['permission_set_arn']})")
        else:
            print("No matches found.")

    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Execution time: {execution_time} seconds")

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()