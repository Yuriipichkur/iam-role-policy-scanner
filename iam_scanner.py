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
    "iam:CreateUser",
    "iam:DeleteUser",
    "iam:CreateRole",
    "iam:DeleteRole",
    "iam:*",
    "ec2:CreateVpc",
    "ec2:DeleteVpc",
    "ec2:CreateSubnet",
    "ec2:DeleteSubnet",
    "ec2:CreateRouteTable",
    "ec2:DeleteRouteTable",
    "ec2:RunInstances",
    "ec2:TerminateInstances",
    "ec2:StartInstances",
    "ec2:StopInstances",
    "ec2:RebootInstances",
    "ec2:*"
]

async def run_aws_cli(command_str: str) -> Optional[dict]:
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

def check_actions_in_policy(policy_document: dict, target_actions: List[str]) -> tuple[bool, list]:
    if not policy_document:
        return False, []
    
    matched_actions = []
    
    # Convert target_actions to set for O(1) lookup
    target_actions_set = set(target_actions)
    
    # Get statements from the policy
    statements = policy_document.get("Statement", [])
    
    # Convert single statement to list if needed
    if isinstance(statements, dict):
        statements = [statements]
    elif isinstance(statements, str):
        try:
            # Try to parse if it's a JSON string
            statements = [json.loads(statements)]
        except json.JSONDecodeError:
            statements = [{"Action": statements}]
    
    # Iterate through all statements in the policy
    for statement in statements:
        if isinstance(statement, str):
            try:
                statement = json.loads(statement)
            except json.JSONDecodeError:
                continue
                
        # Get actions from the statement
        actions = statement.get("Action", [])
        
        # Convert single action to list
        if isinstance(actions, str):
            actions = [actions]
            
        # Check each action in the statement against our target actions
        for action in actions:
            # Handle wildcards in policy actions
            if action.endswith("*"):
                prefix = action[:-1]
                # Find all matching target actions for this wildcard
                matching_targets = {t for t in target_actions_set if t.startswith(prefix)}
                matched_actions.extend(matching_targets)
            elif action in target_actions_set:
                matched_actions.append(action)
                
    # Remove duplicates while preserving order
    matched_actions = list(dict.fromkeys(matched_actions))
    return bool(matched_actions), matched_actions

async def process_inline_policies(role_name: str, role_arn: str, actions: List[str], semaphore: asyncio.Semaphore) -> List[Dict]:
    async with semaphore:
        inline_policies = await run_aws_cli(f"aws iam list-role-policies --role-name {role_name}")
        if not inline_policies:
            return []

    results = []
    for policy_name in inline_policies.get("PolicyNames", []):
        async with semaphore:
            policy = await run_aws_cli(f"aws iam get-role-policy --role-name {role_name} --policy-name {policy_name}")
            if policy and "PolicyDocument" in policy:
                is_matched, matched_actions = check_actions_in_policy(policy["PolicyDocument"], actions)
                if is_matched:
                    results.append({
                        "role_name": role_name,
                        "role_arn": role_arn,
                        "policy_name": policy_name,
                        "policy_arn": f"inline-policy:{policy_name}",
                        "policy_type": "inline",
                        "matched_actions": matched_actions
                    })
    return results

async def process_managed_policy(role_name: str, role_arn: str, policy: Dict, actions: List[str], semaphore: asyncio.Semaphore) -> Optional[Dict]:
    policy_arn = policy["PolicyArn"]
    policy_name = policy["PolicyName"]
    
    async with semaphore:
        policy_versions = await run_aws_cli(f"aws iam list-policy-versions --policy-arn {policy_arn}")
        if not policy_versions:
            return None

        # Get only the default version
        default_version = next((v for v in policy_versions.get('Versions', []) if v.get('IsDefaultVersion')), None)
        if not default_version:
            return None

        policy_version = await run_aws_cli(f"aws iam get-policy-version --policy-arn {policy_arn} --version-id {default_version['VersionId']}")
        
    if policy_version and "PolicyVersion" in policy_version and "Document" in policy_version["PolicyVersion"]:
        is_matched, matched_actions = check_actions_in_policy(policy_version["PolicyVersion"]["Document"], actions)
        if is_matched:
            return {
                "role_name": role_name,
                "role_arn": role_arn,
                "policy_name": policy_name,
                "policy_arn": policy_arn,
                "policy_type": "managed",
                "matched_actions": matched_actions
            }
    return None

async def process_attached_policies(role_name: str, role_arn: str, actions: List[str], semaphore: asyncio.Semaphore) -> List[Dict]:
    async with semaphore:
        attached_policies = await run_aws_cli(f"aws iam list-attached-role-policies --role-name {role_name}")
        if not attached_policies:
            return []

    tasks = [
        process_managed_policy(role_name, role_arn, policy, actions, semaphore)
        for policy in attached_policies.get("AttachedPolicies", [])
    ]
    
    policy_results = await asyncio.gather(*tasks)
    return [result for result in policy_results if result is not None]

async def process_role(role: Dict, actions: List[str], semaphore: asyncio.Semaphore) -> List[Dict]:
    role_name = role["RoleName"]
    role_arn = role["Arn"]
    print(f"Checking role: {role_name}")

    # Launch inline and attached policy processing in parallel
    inline_results, attached_results = await asyncio.gather(
        process_inline_policies(role_name, role_arn, actions, semaphore),
        process_attached_policies(role_name, role_arn, actions, semaphore)
    )
    
    return inline_results + attached_results

async def main_async():
    parser = argparse.ArgumentParser(description="Scan IAM roles and their policies for target actions")
    parser.add_argument("--actions", nargs="+", default=target_actions, help="List of actions to search for")
    parser.add_argument("--output", choices=["csv", "json", "text"], default="text", help="Output format (csv, json, text)")
    parser.add_argument("--concurrent", type=int, default=20, help="Number of concurrent requests")
    args = parser.parse_args()

    if not shutil.which("aws"):
        print("Error: AWS CLI command not found")
        return

    # Create semaphore for limiting concurrent tasks
    semaphore = asyncio.Semaphore(args.concurrent)

    results = []
    
    print("Checking IAM roles...")
    roles = await run_aws_cli("aws iam list-roles")
    if roles:
        tasks = [process_role(role, args.actions, semaphore) for role in roles.get("Roles", [])]
        results_nested = await asyncio.gather(*tasks)
        results.extend([item for sublist in results_nested for item in sublist])
    
    print(f"\nTotal results found: {len(results)}")

    if args.output == "csv":
        with open('results.csv', 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ["role_name", "role_arn", "policy_type", "policy_name", "policy_arn", "matched_actions"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        print("Results saved to results.csv")
    elif args.output == "json":
        print(json.dumps(results, indent=4))
    elif args.output == "text":
        if results:
            for result in results:
                print(f"\nRole: {result['role_name']}")
                print(f"Policy Type: {result['policy_type']}")
                print(f"Policy Name: {result['policy_name']}")
                if 'policy_arn' in result:
                    print(f"Policy ARN: {result['policy_arn']}")
                print(f"Matched Actions: {result['matched_actions']}")
        else:
            print("No matches found.")

    end_time = time.time()
    execution_time = end_time - start_time
    print(f"\nExecution time: {execution_time} seconds")

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()