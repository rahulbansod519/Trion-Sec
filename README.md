# Kube-Secure: Kubernetes Security Hardening CLI

Kube-Secure is a security hardening tool for Kubernetes clusters. It helps identify security risks and misconfigurations within your Kubernetes environment by performing various security checks. This tool is designed to ensure your Kubernetes clusters are secure by scanning for issues such as privileged containers, root user pods, exposed services, and more.

## Features

- **Scan Kubernetes resources**: It performs security scans on Pods, Deployments, Services, and other Kubernetes resources.
- **Security Checks**: Includes checks for:
  - Privileged containers
  - Pods running as root
  - Open network ports
  - Host PID and network exposure
  - Privileged volume types (hostPath)
  - RBAC misconfigurations
  - And much more.
- **Detailed Reports**: Provides detailed reports about security issues found in the cluster.

## Installation

To install Kube-Sec,

```bash
pip install kube-sec
```
## Usage
Connect to a Kubernetes Cluster
Use the connect command to authenticate and connect to your Kubernetes cluster. You can authenticate using either a Service Account token or kubeconfig.

Connect using a Service Account token
```bash
kube-sec connect https://<API_SERVER> --token-path <API_TOKEN_PATH> --ca-cert-path <CA_CERT_PATH>
```
API_SERVER: The URL of your Kubernetes API server.

API_TOKEN_PATH: Path to the Service Account token file.

CA_CERT_PATH: Path to the CA certificate for the Kubernetes API server.

## Connect using kubeconfig
```bash
kube-sec connect --kubeconfig
```
## Insecure Connection
If you need to bypass SSL verification (not recommended for production environments), you can use the --insecure flag to disable SSL verification
```bash
kube-sec connect https://<API_SERVER> --token-path <API_TOKEN_PATH> --insecure
```
## Disconnect from the Kubernetes Cluster
```bash
kube-sec disconnect
```
This will remove any active sessions and clear stored credentials.

## Run Security Scan
Run a security scan against your Kubernetes cluster using the scan command. This will run multiple predefined checks and output the results.
```bash
kube-sec scan
```
## Output Formats
The scan results can be exported in JSON or YAML formats. To specify the output format, use the --output-format flag:
## JSON/YAML:
```bash
kube-sec scan --output-format json/yaml
```
## Available Checks

### Kube-Secure performs the following security checks on your cluster:

#### Host PID and Network Exposure:

  Verifies if Pods are using host PID or host network, which may expose the cluster to security risks.

#### Root User Pods:

  Identifies if Pods are running as root, which increases the security risk by potentially allowing attackers to escalate privileges.

#### Non-Root Enforcement:

  Ensures that Pods are configured to run as non-root users to improve security.

#### RBAC Privileges:

  Detects misconfigurations in Role-Based Access Control (RBAC) policies that could grant excessive permissions.

#### Public Service Exposure:

  Identifies publicly exposed services that may open your cluster to external attacks.

#### Open Network Ports:

  Scans for open network ports on services and identifies potential vulnerabilities.

#### Privileged Containers and Hostpath Mounts:

  Flags containers running with elevated privileges or using host-mounted volumes (hostPath), which could lead to security risks.





