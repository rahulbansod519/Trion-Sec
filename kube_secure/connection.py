import logging
import keyring
import requests
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def test_cluster_connection(api_server=None, token=None, ssl_verify=False, ca_cert_path=None,kubeconfig=False):
    """Test connection to the Kubernetes cluster by performing an API call."""
    try:
        if kubeconfig:
            config.load_kube_config()
            v1 = client.CoreV1Api()
            v1.list_namespace(limit=1)
            logging.info("✅ Cluster connection successful via kubeconfig.")
            return True

        configuration = client.Configuration()
        if api_server:
            configuration.host = api_server
        configuration.verify_ssl = ssl_verify

        if ca_cert_path and ssl_verify:
    
            configuration.ssl_ca_cert = ca_cert_path
        if token:
            configuration.api_key = {"authorization": "Bearer " + token}

        client.Configuration.set_default(configuration)

        v1 = client.CoreV1Api()
        v1.list_namespace(limit=1)

        logging.info("✅ Cluster connection successful via token.")
        save_credentials(api_server, token, ssl_verify, ca_cert_path)
        return True
    except ApiException as e:
        logging.error(f"❌ Cluster connection failed: {e}")
        return False
    except Exception as e:
        logging.error(f"❌ Unexpected error while connecting: {e}")
        return False

def save_credentials(api_server, token, ssl_verify=False, ca_cert_path=None):
    """Save API server, token, and SSL settings to keyring."""
    keyring.set_password("kube-sec", "api_server", api_server)
    keyring.set_password("kube-sec", "kube_token", token)
    keyring.set_password("kube-sec", "SSL_VERIFY", str(ssl_verify))
    if ca_cert_path:
        keyring.set_password("kube-sec", "CA_CERT_PATH", ca_cert_path)
    logging.info("✅ Credentials saved securely using system keyring.")

def load_credentials():
    """Load credentials from keyring."""
    api_server = keyring.get_password("kube-sec", "api_server")
    token = keyring.get_password("kube-sec", "kube_token")
    ssl_verify = keyring.get_password("kube-sec", "SSL_VERIFY")
    return api_server, token, ssl_verify

def connect_to_cluster(api_server=None, token=None, token_path=None, ssl_verify=False, kubeconfig=False, ca_cert_path=None):
    """Main entry point for connecting to the cluster using kubeconfig or token-based authentication."""
    return test_cluster_connection(
    api_server=api_server,
    token=token,
    ssl_verify=ssl_verify,
    ca_cert_path=ca_cert_path,
    kubeconfig=kubeconfig
)
