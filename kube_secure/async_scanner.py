# kube_secure/async_scanner.py

import asyncio
import json
import yaml
import click
from tabulate import tabulate
from datetime import datetime
from kubernetes_asyncio import config, client
from kubernetes_asyncio.client import ApiClient
from kube_secure.session import get_connection_method
import keyring

# -------------------- Connection Loader --------------------

async def async_load_k8():
    connection_method = get_connection_method()
    if connection_method == "kubeconfig":
        await config.load_kube_config()
        return ApiClient()
    elif connection_method == "token":
        api_server = keyring.get_password("kube-sec", "api_server")
        token = keyring.get_password("kube-sec", "kube_token")
        ssl_verify_str = keyring.get_password("kube-sec", "SSL_VERIFY")
        ca_cert_path = keyring.get_password("kube-sec", "CA_CERT_PATH")
        ssl_verify = ssl_verify_str.lower() == "true" if ssl_verify_str else False

        configuration = client.Configuration()
        configuration.host = api_server
        configuration.verify_ssl = ssl_verify
        if ssl_verify and ca_cert_path:
            configuration.ssl_ca_cert = ca_cert_path
        configuration.api_key = {"authorization": "Bearer " + token}
        return ApiClient(configuration)
    else:
        raise RuntimeError("❌ No valid connection method found. Please run `kube-sec connect` first.")

# -------------------- Check: Pods Running As Root --------------------

async def check_pods_running_as_root(core_v1):
    pods = (await core_v1.list_pod_for_all_namespaces()).items
    risky = []
    for pod in pods:
        pod_user = pod.spec.security_context.run_as_user if pod.spec.security_context else None
        for c in pod.spec.containers:
            c_user = c.security_context.run_as_user if c.security_context else None
            if (c_user is None or c_user == 0) and (pod_user is None or pod_user == 0):
                risky.append({"Namespace": pod.metadata.namespace, "Pod": pod.metadata.name})
    return "root-user-pods", "Critical", risky

# -------------------- Check: Non-root Enforcement --------------------

async def check_pods_running_as_non_root(core_v1):
    pods = (await core_v1.list_pod_for_all_namespaces()).items
    violations = []
    for pod in pods:
        pod_enforced = pod.spec.security_context.run_as_non_root if pod.spec.security_context else None
        for c in pod.spec.containers:
            c_enforced = c.security_context.run_as_non_root if c.security_context else None
            if not pod_enforced and not c_enforced:
                violations.append({
                    "Namespace": pod.metadata.namespace,
                    "Pod": pod.metadata.name,
                    "Message": "Missing runAsNonRoot"
                })
    return "non-root-enforcement", "Warning", violations

# -------------------- Check: Host PID and Network --------------------

async def check_host_pid_and_network(core_v1):
    pods = (await core_v1.list_pod_for_all_namespaces()).items
    issues = []
    for pod in pods:
        if pod.spec.host_pid or pod.spec.host_network:
            issues.append({
                "Namespace": pod.metadata.namespace,
                "Pod": pod.metadata.name,
                "Message": f"hostPID={pod.spec.host_pid}, hostNetwork={pod.spec.host_network}"
            })
    return "host-pid-and-network-exposure", "Warning", issues

# -------------------- Check: Privileged Containers --------------------

async def check_privileged_containers_and_hostpath(core_v1):
    pods = (await core_v1.list_pod_for_all_namespaces()).items
    issues = []
    for pod in pods:
        for c in pod.spec.containers:
            if c.security_context and c.security_context.privileged:
                issues.append({
                    "Namespace": pod.metadata.namespace,
                    "Pod": pod.metadata.name,
                    "Message": "Privileged container"
                })
            if c.volume_mounts:
                for vol in c.volume_mounts:
                    if vol.mount_path == "/":
                        issues.append({
                            "Namespace": pod.metadata.namespace,
                            "Pod": pod.metadata.name,
                            "Message": f"Mounts {vol.mount_path}"
                        })
    return "privileged-containers-and-hostpath-mounts", "Critical", issues

# -------------------- Check: Public Services --------------------

async def check_publicly_accessible_services(core_v1):
    services = (await core_v1.list_service_for_all_namespaces()).items
    issues = []
    for svc in services:
        if svc.spec.type in ["LoadBalancer", "NodePort"]:
            issues.append({
                "Namespace": svc.metadata.namespace,
                "Service": svc.metadata.name,
                "Type": svc.spec.type
            })
    return "public-service-exposure", "Critical", issues

# -------------------- Check: Open Network Ports --------------------

async def check_open_ports(core_v1):
    services = (await core_v1.list_service_for_all_namespaces()).items
    issues = []
    for svc in services:
        for port in svc.spec.ports or []:
            if port.port and port.port < 1024:
                issues.append({
                    "Namespace": svc.metadata.namespace,
                    "Service": svc.metadata.name,
                    "Port": port.port
                })
    return "open-network-ports", "Warning", issues

# -------------------- Check: Weak Firewall Rules --------------------

async def check_weak_firewall_rules(net_v1):
    policies = (await net_v1.list_network_policy_for_all_namespaces()).items
    if not policies:
        return "internal-traffic-controls", "Warning", [{"Message": "No NetworkPolicies defined"}]
    return "internal-traffic-controls", "Warning", []

# -------------------- Check: RBAC Misconfigurations --------------------

async def check_rbac_misconfigurations(rbac_v1):
    crbs = (await rbac_v1.list_cluster_role_binding()).items
    issues = []
    for crb in crbs:
        for s in crb.subjects or []:
            if s.kind == "User" and s.name == "admin":
                issues.append({
                    "Binding": crb.metadata.name,
                    "User": s.name,
                    "Role": crb.role_ref.name
                })
    return "rbac-privileges", "Critical", issues

# -------------------- Check: RBAC Least Privilege --------------------

async def check_rbac_least_privilege(rbac_v1):
    crbs = (await rbac_v1.list_cluster_role_binding()).items
    issues = []
    for crb in crbs:
        if crb.role_ref.name in ["cluster-admin", "admin"]:
            issues.append({
                "Binding": crb.metadata.name,
                "Role": crb.role_ref.name
            })
    return "rbac-least-privilege", "Warning", issues

# -------------------- Check: Network Exposure --------------------

async def check_network_exposure(core_v1):
    services = (await core_v1.list_service_for_all_namespaces()).items
    issues = []
    for svc in services:
        if svc.spec.cluster_ip != "None" and svc.spec.type == "LoadBalancer":
            issues.append({
                "Namespace": svc.metadata.namespace,
                "Service": svc.metadata.name,
                "Type": svc.spec.type
            })
    return "external-service-exposure", "Critical", issues

# -------------------- Async Scanner Runner --------------------

async def async_run_scan(disable_checks, output_format, custom_rules):
    api_client = await async_load_k8()
    async with api_client:
        core_v1 = client.CoreV1Api(api_client)
        net_v1 = client.NetworkingV1Api(api_client)
        rbac_v1 = client.RbacAuthorizationV1Api(api_client)

        # All checks, using previously defined functions
        all_checks = {
            "root-user-pods": lambda: check_pods_running_as_root(core_v1),
            "non-root-enforcement": lambda: check_pods_running_as_non_root(core_v1),
            "host-pid-and-network-exposure": lambda: check_host_pid_and_network(core_v1),
            "privileged-containers-and-hostpath-mounts": lambda: check_privileged_containers_and_hostpath(core_v1),
            "public-service-exposure": lambda: check_publicly_accessible_services(core_v1),
            "open-network-ports": lambda: check_open_ports(core_v1),
            "internal-traffic-controls": lambda: check_weak_firewall_rules(net_v1),
            "rbac-privileges": lambda: check_rbac_misconfigurations(rbac_v1),
            "rbac-least-privilege": lambda: check_rbac_least_privilege(rbac_v1),
            "external-service-exposure": lambda: check_network_exposure(core_v1),
        }

        # Apply disabled checks
        checks = {k: v for k, v in all_checks.items() if k not in disable_checks}
        results = {}
        critical = 0
        warning = 0
        security_issues = []

        click.secho("\n🚀 Starting Async Kubernetes Security Scan...\n", fg="cyan", bold=True)

        with click.progressbar(checks.items(), label="⏱️  Running security checks") as bar:
            tasks = [func() for _, func in bar]
            outputs = await asyncio.gather(*tasks)

        # Processing results
        for check_name, severity, data in outputs:
            results[check_name] = data
            click.secho(f"\n🔍 {check_name.replace('-', ' ').title()}", fg="cyan", bold=True)
            if data:
                if isinstance(data[0], dict):
                    click.echo(tabulate(data, headers="keys", tablefmt="grid"))
                else:
                    for item in data:
                        click.echo(f" - {item}")
                if severity == "Critical":
                    critical += len(data)
                else:
                    warning += len(data)
                for item in data:
                    msg = json.dumps(item)
                    security_issues.append((severity, msg))
            else:
                click.secho("✅ No issues found.", fg="green")

        # Final output after scan completes
        if not output_format:
            click.echo("\n✅ Scan Completed")
            click.secho("\n📊 Security Summary:", bold=True)
            click.secho(f"   🔴 {critical} Critical Issues", fg="red")
            click.secho(f"   🟡 {warning} Warnings", fg="yellow")

            if security_issues:
                click.echo("\n🚨 Issues Detected:")
                for severity, message in security_issues:
                    color = "red" if severity == "Critical" else "yellow"
                    click.secho(f"[{severity.upper()}] {message}", fg=color)
            else:
                click.secho("\n✅ No security issues found.", fg="green")

        # Export results in specified format (JSON/YAML)
        if output_format:
            report = {
                "scan_timestamp": datetime.utcnow().isoformat() + "Z",
                "issues_summary": {
                    "critical": critical,
                    "warnings": warning,
                },
                "scan_results": results
            }
            filename = "output.json" if output_format == "json" else "output.yaml"
            with open(filename, 'w') as f:
                if output_format == "json":
                    json.dump(report, f, indent=4)
                else:
                    yaml.dump(report, f)
            click.secho(f"\n📝 Report saved to {filename}", fg="green")

