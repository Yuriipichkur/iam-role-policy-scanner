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

## Output Options
- Multiple Formats:
  - CSV (for data analysis)
  - JSON (for integration)
  - Text (for readability)
- Detailed Results Including:
  - Role/Permission Set details
  - Policy information
  - Matched actions
  - Principal relationships

## Prerequisites
* Python 3.10+
* AWS CLI configured with appropriate credentials
* Required IAM permissions

## Installation
git clone https://github.com/Yuriipichkur/iam-role-policy-scanner.git
cd iam-role-policy-scanner
pip install -r requirements.txt

## Roadmap
* Integration with AWS Organizations
* Real-time monitoring capabilities
* Custom reporting templates
* Advanced filtering options
* CI/CD pipeline integration

## Recent Updates
* Added Identity Center (SSO) permission set analysis
* Improved wildcard pattern matching
* Enhanced error handling and logging
* Optimized performance for large-scale environments
* Added support for permission boundaries

##  Contributing
Contributions are welcome! Please feel free to submit pull requests, create issues or suggest improvements.
