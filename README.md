# iam-role-policy-scanner
## Overview
Script for analyzing IAM roles, policies and AWS IAM Identity Center (formerly AWS SSO) permission sets in AWS.

This tool helps identify specific actions (e.g. iam:CreateRole, iam:DeleteRole, iam:CreateUser etc.) in Customer Inline and AWS managed policies, as well as in permission sets, allowing security engineers, cloud architects and developers to ensure proper access control in their AWS environments.

## Features
* Asynchronous Execution: Processes multiple roles, policies and permission sets in parallel, optimizing performance
* Flexible Target Actions: Scan for custom actions by specifying them as input parameters
* Multiple Output Formats: Supports text, CSV, and JSON formats for easy integration with other workflows
* Comprehensive Policy Analysis: Analyzes:
  * IAM role inline policies
  * IAM role attached AWS managed policies
  * AWS IAM Identity Center permission sets inline policies
  * AWS IAM Identity Center permission sets managed policies
* CLI Integration: Fully compatible with AWS CLI for seamless interaction with AWS resources

## Output
The script outputs the results in the specified format:
* For IAM Roles:
  * Role name and ARN
  * Policy name and ARN
  * Corresponding actions
* For Permission Sets:
  * Permission set name and ARN
  * Policy type (inline or managed)
  * Corresponding actions

## Key Functions
* `run_aws_cli`: Executes AWS CLI commands asynchronously and handles JSON output
* `process_inline_policies`: Analyzes inline policies for target actions
* `process_attached_policies`: Analyzes attached managed policies for target actions
* `process_permission_set`: Analyzes permission sets' inline and managed policies
* `check_actions_in_policy`: Detects target actions in policy documents

## Roadmap
Future improvements may include:
* Adding support for more actions for AWS services
* Improving error handling and logging
* Integrating with AWS Config or AWS Organizations for broader policy analysis
* Adding support for analyzing permission sets' customer managed policies
* Implementing filtering and advanced search capabilities for permission sets

Contributions are welcome!