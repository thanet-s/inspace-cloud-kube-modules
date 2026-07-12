#!/usr/bin/env python3
"""Static contract test for the destructive E2E harness; never touches cloud state."""

import importlib.util
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parent


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def manifest_document(text: str, kind: str, name: str) -> str:
    matches = [
        document
        for document in text.split("\n---\n")
        if re.search(rf"(?m)^kind: {re.escape(kind)}$", document)
        and re.search(rf"(?m)^  name: {re.escape(name)}$", document)
    ]
    require(len(matches) == 1, f"expected one {kind}/{name} manifest, found {len(matches)}")
    return matches[0]


def load_script_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    host = (ROOT / "run.sh").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    playbook = (ROOT / "playbook.yml").read_text(encoding="utf-8")
    cleanup = (ROOT / "cleanup.yml").read_text(encoding="utf-8")
    entrypoint = (ROOT / "scripts/container-entrypoint.sh").read_text(encoding="utf-8")
    dockerignore = (ROOT / "Dockerfile.dockerignore").read_text(encoding="utf-8")
    account_inventory = (ROOT / "scripts/account-inventory.py").read_text(encoding="utf-8")
    cloud_audit = (ROOT / "scripts/cloud-audit.py").read_text(encoding="utf-8")
    bootstrap_discovery = (ROOT / "scripts/discover-bootstrap.py").read_text(encoding="utf-8")
    ssh_config = (ROOT / "scripts/render-ssh-config.py").read_text(encoding="utf-8")
    tunnel = (ROOT / "scripts/api-tunnel.sh").read_text(encoding="utf-8")
    worker_discovery = (ROOT / "scripts/discover-worker.py").read_text(encoding="utf-8")
    service_cloud = (ROOT / "scripts/verify-service-cloud.py").read_text(encoding="utf-8")
    nodeclass = (ROOT / "templates/karpenter.yaml.j2").read_text(encoding="utf-8")
    cluster = (ROOT / "templates/cluster.yaml.j2").read_text(encoding="utf-8")
    workload = (ROOT / "templates/workload.yaml.j2").read_text(encoding="utf-8")
    ansible_cfg = (ROOT / "ansible.cfg").read_text(encoding="utf-8")

    executable_host = "\n".join(
        line.split("#", 1)[0] for line in host.splitlines()
        if not line.lstrip().startswith("#")
    )
    for forbidden in ("ansible-playbook", " go ", "helm ", "kubectl ", "ssh ", "curl "):
        require(forbidden not in executable_host, f"host launcher executes forbidden tool marker: {forbidden!r}")
    require("docker build" in executable_host and "docker run" in executable_host, "host launcher must build and run Docker")
    require("runner_platform=${INSPACE_E2E_RUNNER_PLATFORM:-linux/amd64}" in executable_host,
            "E2E runner must default explicitly to linux/amd64")
    require("linux/amd64 | linux/arm64" in executable_host and
            "INSPACE_E2E_RUNNER_PLATFORM must be linux/amd64 or linux/arm64" in host,
            "E2E runner platform override must reject unsupported platforms")
    require(executable_host.count('--platform "$runner_platform"') == 2,
            "E2E runner platform must be passed to both Docker build and Docker run")
    require("--target published-live" in executable_host and
            "CONTROLLER_IMAGE=ghcr.io/thanet-s/inspace-cloud-controller-manager:" in executable_host,
            "destructive launcher must copy the bootstrap binary from the exact published image")
    require("--init" not in executable_host, "host launcher must not add a second init process")
    require("--env-file" not in executable_host,
            "token-bearing environment file must not be copied into Docker container metadata")
    require("--mount \"type=bind" in host and "type=volume" in host, "host launcher must explicitly validate/mount inputs")

    for tool in ("kubectl", "helm", "jq", "openssh-client", "curl", "skopeo"):
        require(tool in dockerfile, f"runner image is missing {tool}")
    require('ENTRYPOINT ["/usr/bin/tini", "-g", "--"' in dockerfile,
            "runner must use one process-group-aware Tini")
    require("FROM base AS local-validation" in dockerfile and
            "FROM base AS published-live" in dockerfile and
            "COPY --from=published-controller /usr/local/bin/inspace-cluster-controller" in dockerfile,
            "runner must separate local validation from published live acceptance")
    require('ansible-playbook "$@" --forks 10 &' in entrypoint,
            "suite Ansible process must run as an explicitly managed child")
    require('kill -TERM "$pid"' in entrypoint and 'kill -KILL "$pid"' in entrypoint,
            "signal cleanup must terminate a bounded active Ansible child")
    require("terminate_active_ansible" in entrypoint and
            "ansible-playbook /opt/e2e/cleanup.yml --forks 10" in entrypoint,
            "signal handling must terminate the suite before cleanup")
    require("mounted E2E environment file must have mode 0600" in entrypoint,
            "runner must reject an over-permissive API-token file")
    require("flock -n 9" in entrypoint and "inspace-cloud-rke2-e2e.lock" in entrypoint,
            "runner must hold one exclusive shared-state lock")
    require('value != "https://api.inspace.cloud"' in entrypoint and
            "INSPACE_API_URL must be exactly https://api.inspace.cloud" in entrypoint,
            "destructive runner must pin the exact production API origin")
    require("refusing to reuse existing E2E run ID" in entrypoint and
            "mutations-not-started" in entrypoint and
            "mutations-may-exist" in playbook and
            "missing without a mutations-not-started" in cleanup,
            "runner must journal the mutation boundary and reject run-ID reuse")
    require("[[ $retained == true ]] || ! final_audit_is_zero" in entrypoint and
            "durable retention marker" in entrypoint,
            "explicit retention must override a possibly stale zero audit")
    for forbidden_build_input in (
        "**/.env", "**/*.env", "**/id_rsa", "**/id_ed25519", "**/*.pem", "**/*.key",
        "**/__pycache__", "**/*.py[cod]",
    ):
        require(forbidden_build_input in dockerignore,
                f"Dockerfile-specific ignore is missing {forbidden_build_input}")
    require("INSPACE_CONTROL_PLANE_VIP" in entrypoint,
            "runner must require the private control-plane VIP before provisioning")
    for variable in (
        "INSPACE_PRIVATE_LOAD_BALANCER_POOL_START",
        "INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP",
    ):
        require(variable in entrypoint, f"runner must require {variable}")
        require(variable in cluster, f"cluster template must render {variable}")
        require(variable in nodeclass, f"NodeClass template must render {variable}")
    require("16 <= int(stop)-int(start)+1 <= 256" in playbook,
            "live preflight must enforce the v1alpha1 16-256-address pool bound")
    require("recovering unfinished E2E run" in entrypoint and
            "unfinished-run cleanup lacks a final zero audit" in entrypoint and
            "requires INSPACE_E2E_VERSION=" in entrypoint and
            "INSPACE_E2E_RECOVER_RETAINED" in entrypoint,
            "runner must recover unfinished state without deleting explicitly retained resources")
    require("ansible-core==" in (ROOT / "requirements.txt").read_text(), "ansible-core must be pinned")
    require(re.search(r"^forks\s*=\s*(?:[3-9]|[1-9][0-9]+)$", ansible_cfg, re.MULTILINE) is not None,
            "Ansible forks must be at least three")
    require(re.search(r"^task_timeout\s*=\s*(?:2[1-9][0-9]{2}|[3-9][0-9]{3,})$", ansible_cfg, re.MULTILINE) is not None,
            "every Ansible action must have a hard timeout of at least 2100 seconds")

    for marker in (
        "maxParallelControlPlaneCreates | int == 3",
        "e2e_bootstrap_result.apiLoadBalancerUUID is not defined",
        "e2e_bootstrap_result.bastionVMUUID | length > 0",
        "controlPlaneVMs | length == 3",
        "groups: rke2_control_plane",
        "groups: rke2_bastion",
        "strategy: free",
        "async: 2700",
        "poll: 0",
        "ansible.builtin.async_status",
        "wait_for_connection",
        "systemctl is-active rke2-server",
        "timeout --kill-after=5s 1200s sh -c",
        "KubeProxyReplacement:[[:space:]]+True",
        "Direct Routing",
        "auto-direct-node-routes",
        "enable-l2-announcements",
        "default-lb-service-ipam",
        "defaultLBServiceIPAM:[[:space:]]*none",
        "nodeIPAM:[[:space:]]*$",
        "ciliumloadbalancerippool inspace-private",
        "ciliuml2announcementpolicy inspace-private",
        "EnableL2Announcements",
        "inspace-control-plane-vip",
        "kube-vip.yaml.e2e-disabled",
        "Require uninterrupted API reachability during kube-vip failover",
        "Prove the chart launched the exact released product image tags",
        "/opt/e2e/scripts/api-tunnel.sh",
        "skopeo",
        "global.inspace.privateLoadBalancerPool.start",
        "global.inspace.privateLoadBalancerPool.stop",
        "global.inspace.controlPlaneVIP",
        "Verify Cilium native routing and full kube-proxy replacement",
    ):
        require(marker in playbook, f"playbook is missing contract marker: {marker}")

    require("version: v1.35.6+rke2r1" in cluster, "control plane must pin supported RKE2")
    require("rke2-ingress-nginx" in cluster, "unused RKE2 ingress must be disabled")
    require("virtualIPv4:" in cluster and "public:" not in cluster and "host:" not in cluster,
            "cluster endpoint must be only the configured private VIP")
    require("routing-mode" in playbook and "kube-proxy-replacement" in playbook,
            "native routing and kube-proxy replacement must be verified")
    require("rke2:" in nodeclass and "privateRegistrationEndpoint" in nodeclass,
            "NodeClass must use the private RKE2 registration endpoint")
    require("inspace-rke2-agent-token" in nodeclass, "NodeClass must use the RKE2 token secret")
    private_services = [
        manifest_document(workload, "Service", "inspace-e2e-private-a"),
        manifest_document(workload, "Service", "inspace-e2e-private-b"),
    ]
    private_ports = []
    for name, service in zip(("inspace-e2e-private-a", "inspace-e2e-private-b"), private_services):
        require("inspace.cloud/load-balancer-scope: private" in service,
                f"{name} must select the private Cilium pool")
        require("loadBalancerClass: io.cilium/l2-announcer" in service,
                f"{name} must use the Cilium L2 class")
        require("externalTrafficPolicy: Cluster" in service,
                f"{name} must use Cluster traffic policy")
        require(re.search(r"(?m)^\s+protocol: TCP$", service) is not None,
                f"{name} must expose TCP")
        ports = re.findall(r"(?m)^\s+port: ([0-9]+)$", service)
        require(len(ports) == 1, f"{name} must expose exactly one Service port")
        private_ports.append(ports[0])
    require(len(set(private_ports)) == 1,
            "the two private Cilium Services must reuse the same TCP port")
    require(workload.count("loadBalancerClass: io.cilium/l2-announcer") == 2,
            "exactly the two private Services must use the Cilium L2 class")
    require("io.cilium/node" not in workload,
            "E2E workloads must never use Cilium Node IPAM")

    public_service = manifest_document(workload, "Service", "inspace-e2e-web")
    require("inspace.cloud/load-balancer-scope: public" in public_service and
            'service.beta.kubernetes.io/inspace-load-balancer-public: "true"' in public_service,
            "public Service must use the exact InSpace scope and opt-in annotation")
    require("loadBalancerClass:" not in public_service,
            "public InSpace NLB Service must leave loadBalancerClass unset for generic CCM")
    require(re.search(r"(?m)^\s+protocol: TCP$", public_service) is not None,
            "public InSpace NLB Service must be TCP-only")

    require('"default-lb-service-ipam"] == "none"' in playbook and
            "nodeIPAM:[[:space:]]*$" in playbook and
            "enabled:[[:space:]]*false" in playbook,
            "live Cilium checks must disable default and Node IPAM paths")
    require(playbook.count("use_proxy: false") >= 4,
            "live HTTP probes must bypass ambient controller proxies")
    require("e2e-persistence-sentinel" in playbook and
            playbook.count("persistence-sentinel") >= 3,
            "CSI replacement proof must read data created after initialization")
    require("ready-api-monitor" in playbook and "Wait for the continuity monitor first successful API probe" in playbook,
            "kube-vip failover must wait for a successful monitor probe before disruption")
    require(playbook.count("kube-vip Lease holder does not resolve to exactly one pod") == 3 and
            playbook.count(".metadata.name == $holder or .spec.nodeName == $holder") == 3,
            "kube-vip ownership must correlate Lease identity through its exact pod and node")
    for lease in (
        "cilium-l2announce-default-inspace-e2e-private-a",
        "cilium-l2announce-default-inspace-e2e-private-b",
    ):
        service_name = lease.removeprefix("cilium-l2announce-default-")
        require(lease in playbook or
                ('lease="cilium-l2announce-default-$service"' in playbook and service_name in playbook),
                f"playbook must verify private L2 lease {lease}")
        require(lease in cleanup, f"cleanup must wait for private L2 lease {lease}")
    require("cilium.io/IPsUsed" in cleanup and
            "Wait for private Cilium L2 leases and LB IPAM allocations to quiesce" in cleanup,
            "cleanup must release both private VIPs before Karpenter teardown")

    require("private Cilium L2 Service unexpectedly owns an InSpace NLB" in service_cloud and
            "private Cilium L2 Service unexpectedly owns an InSpace FIP" in service_cloud and
            'choices=("present", "absent")' in service_cloud and
            "public Service NLB/FIP cleanup has not completed" in service_cloud,
            "service cloud verifier must prove private zero ownership and public transition cleanup")
    require("private_address == control_plane_vip" in service_cloud,
            "public Service proof must reject a control-plane VIP collision")
    require("targets must be exactly three control planes and one worker" in service_cloud and
            "exactly one TCP 80-to-30080 forwarding rule" in service_cloud,
            "public Service proof must bind the exact NLB forwarding and VM target contracts")
    require(playbook.count("/opt/e2e/scripts/verify-service-cloud.py") >= 2 and
            "service.beta.kubernetes.io/inspace-load-balancer-public" in playbook,
            "playbook must audit cloud ownership before and after removing public opt-in")
    require(playbook.count("systemctl is-enabled ufw.service") == 3 and
            playbook.count("systemctl is-active --quiet ufw.service") == 3 and
            playbook.count("systemctl show ufw.service --property=LoadState --value") == 3 and
            playbook.count("not-found) ;;") == 3,
            "control planes, worker, and bastion must prove guest UFW is disabled and inactive")
    digest = "sha256:49b77655f9f109bedc5eb25723bb0e4c57d8513ba33cc69c31be3f243eb2386d"
    require(playbook.count(digest) >= 2, "kube-vip tag and live pods must use the audited digest")
    require("expected one exact egress FIP for each control plane and bastion" in bootstrap_discovery and
            "enabled non-virtual InSpace type=public FIP" in bootstrap_discovery and
            'assigned_to_resource_type") != "virtual_machine"' in bootstrap_discovery and
            "private-VIP bootstrap must not create or adopt a control-plane load balancer" in bootstrap_discovery and
            "2-vCPU / 4-GiB / 30-GiB control-plane shape" in bootstrap_discovery and
            "1-vCPU / 2-GiB / 30-GiB / configured-pool shape" in bootstrap_discovery and
            "node firewall must be assigned to exactly the three control-plane VMs" in bootstrap_discovery and
            "bastion public ingress must be only management /32 TCP/22" in bootstrap_discovery,
            "bootstrap discovery must prove exact VM FIPs, zero control NLBs, and firewall isolation")
    require("ProxyJump e2e-bastion" in ssh_config and "HostName {private}" in ssh_config,
            "all control-plane and worker SSH must use private IPs through the bastion")
    require("127.0.0.1:16443:$virtual_ip:6443" in tunnel and "StrictHostKeyChecking=yes" in tunnel,
            "Kubernetes API must use the pinned bastion local forward")
    require("worker must not have an additional or foreign-named floating IPv4" in worker_discovery and
            "worker must be attached to exactly the intended managed cloud firewall" in worker_discovery and
            'ip.get("is_virtual") is False' in worker_discovery and
            "managed node firewall must protect exactly three control planes and the worker" in worker_discovery and
            "worker InternalIP collides with the private control-plane VIP" in worker_discovery,
            "worker proof must bind exactly one egress FIP, exclude reserved VIPs, and bind the managed cloud firewall")
    require('($attachments | length) == 1' in playbook and
            '$attachments[0].spec.attacher == "csi.inspace.cloud"' in playbook and
            '$attachments[0].spec.nodeName == $worker' in playbook,
            "CSI proof must require one attachment on the sole Karpenter worker")

    for resource_path in (
        "user-resource/vm/list", "network/firewalls", "network/ip_addresses",
        "network/load_balancers", "storage/disks",
    ):
        require(resource_path in account_inventory,
                f"full account inventory is missing {resource_path}")
    require("returned a non-object resource item" in account_inventory and
            "refusing to replace an existing baseline inventory" in account_inventory and
            "baseline inventory must be a mode-0600 regular file" in account_inventory,
            "full account inventory must reject malformed API/baseline state")
    require("Capture every API-visible billable resource before mutation" in playbook and
            "Require the dedicated test account to contain no billable resources" in playbook and
            "Require the complete isolated-account inventory to match its baseline" in cleanup,
            "release acceptance must compare the entire isolated account to its empty baseline")
    require("def active_resources(" in cloud_audit and
            'item.get("is_deleted") is True' in cloud_audit and
            cloud_audit.count("active_resources(") == 6,
            "deterministic cleanup audit must ignore only explicitly deleted cloud rows")
    cloud_audit_module = load_script_module("e2e_cloud_audit_static", ROOT / "scripts/cloud-audit.py")
    require(cloud_audit_module.parse_description('{"cluster":"expected"}') == {"cluster": "expected"},
            "cloud audit must parse structured VM ownership descriptions")
    cloud_audit_module.api_get = lambda _path: [
        {"uuid": "active"},
        {"uuid": "soft-deleted", "is_deleted": True},
        {"uuid": "status-deleted", "status": "DELETED"},
    ]
    require(list(cloud_audit_module.active_resources("test")) == [{"uuid": "active"}],
            "cloud audit active-resource predicate is broken")
    cloud_audit_module.api_get = lambda _path: ["malformed"]
    try:
        list(cloud_audit_module.active_resources("test"))
    except SystemExit:
        pass
    else:
        require(False, "cloud audit must reject non-object API resources")
    require("Require gratuitous ARP to update the existing VIP neighbor" in playbook and
            "Flush the VIP neighbor and prove fresh ARP" in playbook,
            "private L2 failover must separately prove GARP update and fresh ARP resolution")

    ordering = [
        "Delete workload owners before infrastructure owners",
        "Wait for E2E pods PVs and VolumeAttachments to disappear",
        "Wait for private Cilium L2 leases and LB IPAM allocations to quiesce",
        "Delete the NodePool while Karpenter is still running",
        "Wait for owned NodeClaims and worker Nodes to disappear",
        "Delete the NodeClass after all worker ownership is gone",
        "Uninstall controllers only after their owners are quiescent",
        "Persist Kubernetes owner quiescence before bootstrap deletion",
        "Destroy only bootstrap-controller-owned infrastructure asynchronously",
        "Require the final deterministic cloud audit to converge to zero",
        "Close the private API tunnel after the final zero audit",
    ]
    offsets = [cleanup.index(value) for value in ordering]
    require(offsets == sorted(offsets), "cleanup owner ordering changed")
    require(cleanup.index("Re-establish the container-local private API tunnel for cleanup") <
            cleanup.index("Wait for Kubernetes API reachability before owner quiescence"),
            "recovery must restore its private API tunnel before probing Kubernetes")
    require(re.search(r"preserving\s+cloud infrastructure is the fail-closed outcome", cleanup) is not None,
            "cleanup must fail closed when ownership is uncertain")
    require("^rke2-' + e2e_cleanup_state.owner + '-(cp-[0-2]|bastion)$" in cleanup,
            "controller uninstall must permit only the three control planes and exact bastion")
    print("E2E static contract verified (no live resources touched)")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError) as error:
        print(f"E2E static verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
