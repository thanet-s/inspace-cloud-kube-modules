#!/usr/bin/env python3
"""Static, credential-free contracts for the operator deployment lifecycle."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def task_block(playbook: str, name: str) -> str:
    start = playbook.index(f"- name: {name}\n")
    end = playbook.find("\n    - name: ", start + 1)
    return playbook[start:] if end < 0 else playbook[start:end]


def verify_gateway_api(inventory: str, cluster_template: str, preflight: str, init: str, destroy: str) -> None:
    """Optional Gateway API: pinned bundle delivered over SSH before RKE2 starts."""
    readme = read("deploy/README.md")
    load_state = read("deploy/playbooks/tasks/load-state.yml")
    gateway_go = read("modules/cloud-provider/pkg/bootstrap/gateway_api.go")
    pinned = re.search(r'GatewayAPIStandardInstallSHA256 = "([0-9a-f]{64})"', gateway_go)
    require(pinned is not None, "bootstrap lacks the pinned Gateway API bundle digest")
    digest = pinned.group(1)
    require(
        re.search(r"(?m)^    gateway_api_enabled: false$", inventory) is not None
        and "`gateway_api_enabled`" in readme
        and "--print-gateway-api-crds" in readme,
        "example inventory and README must document the default-off gateway_api_enabled option",
    )
    require(
        "{% if gateway_api_enabled | default(false) | bool %}\n    gatewayAPI:\n      enabled: true\n{% endif %}\n"
        in cluster_template,
        "cluster template must render network.gatewayAPI only when enabled so default specs stay byte-identical",
    )
    require(
        "gateway_api_enabled | default(false) is boolean" in preflight
        and "not (gateway_api_enabled | default(false)) or modules_version is version('1.1.0-rc.4', '>', version_type='semver')" in preflight
        and "deploy_gateway_api_rke2_release is version('1.37.0', '>=')" in preflight
        and "deploy_gateway_api_rke2_release is version('1.36.5', '>=')" in preflight
        and "deploy_gateway_api_rke2_release is version('1.35.9', '>=')" in preflight
        and "deploy_gateway_api_rke2_release is version('1.34.12', '>=')" in preflight
        and "      - rke2-traefik\n" in cluster_template,
        "preflight must accept gateway_api_enabled only as a boolean on an RKE2 release bundling Cilium 1.20",
    )
    require(
        ".get('gatewayAPI', {}).get('enabled', false) | bool ==" in load_state
        and "gateway_api_enabled | default(false) | bool" in load_state,
        "journal binding must keep gateway_api_enabled fixed at cluster creation",
    )
    pull_name = "Pull the exact bootstrap controller release"
    print_name = "Print the pinned Gateway API CRD bundle from the exact bootstrap controller"
    reconcile_name = "Reconcile bootstrap infrastructure synchronously to readiness"
    pin_name = "Pin private control-plane host keys"
    deliver_name = "Deliver the pinned Gateway API CRD bundle to every control plane"
    egress_name = "Prove every control plane reaches the internet through its floating IP"
    settle_name = "Settle packaged components without provisioning an elastic worker"
    accept_name = "Require Cilium Gateway API and an accepted cilium GatewayClass"
    order = [init.find(name) for name in (pull_name, print_name, reconcile_name, pin_name, deliver_name, egress_name, settle_name, accept_name)]
    require(all(offset >= 0 for offset in order) and order == sorted(order), "Gateway API init phases are missing or misordered")
    require(f"deploy_gateway_api_bundle_sha256: {digest}\n" in init, "deploy Gateway API digest differs from the bootstrap pin")
    print_task = task_block(init, print_name)
    deliver_task = task_block(init, deliver_name)
    accept_task = task_block(init, accept_name)
    # RKE2 v1.37+ installs the same v1.6.1 CRDs through rke2-gateway-api-crd.
    require(
        "deploy_gateway_api_bundle_delivery: >-" in preflight
        and "deploy_gateway_api_rke2_release is version('1.37.0', '<')" in preflight,
        "preflight must deliver the bootstrap CRD bundle only below RKE2 v1.37",
    )
    for task in (print_task, deliver_task):
        require("when: deploy_gateway_api_bundle_delivery | bool\n" in task,
                "Gateway API bundle tasks must run only when bootstrap owns the CRDs")
    require("when: gateway_api_enabled | default(false) | bool\n" in accept_task,
            "Gateway API acceptance must run whenever Gateway API is enabled")
    require(
        "--print-gateway-api-crds" in print_task
        and "--network=none" in print_task
        and "{{ bootstrap_controller_image | quote }}" in print_task
        and 'sha256sum "$bundle.partial"' in print_task
        and "deploy_gateway_api_bundle_sha256" in print_task,
        "Gateway API bundle must come offline from the exact controller image and match the pin",
    )
    require(
        "/var/lib/inspace/gateway-api-standard-install.yaml" in deliver_task
        and "deploy_gateway_api_bundle_sha256" in deliver_task
        and "register: deploy_gateway_api_delivery\n" in deliver_task
        and "until: deploy_gateway_api_delivery.rc != 255\n" in deliver_task
        and "failed_when: deploy_gateway_api_delivery.rc != 0\n" in deliver_task,
        "Gateway API delivery must verify the node copy and retry only ssh transport failures",
    )
    require(
        "enable-gateway-api" in accept_task and "gatewayclass/cilium" in accept_task and "Accepted" in accept_task,
        "init must prove Cilium accepted the cilium GatewayClass",
    )
    gateway_delete = "Delete every Gateway API Gateway before its generated LoadBalancer Services"
    require(
        0 <= destroy.find(gateway_delete) < destroy.find("Delete every LoadBalancer Service while its owning CCM is healthy")
        and "gateways.gateway.networking.k8s.io" in task_block(destroy, gateway_delete),
        "destroy must delete Gateways before LoadBalancer Services so Cilium cannot recreate a paid NLB",
    )
    upgrade = read("deploy/playbooks/tasks/apply-rke2-upgrade.yml")
    handover_name = "Hand the Gateway API CRDs to RKE2's own chart before a v1.37 upgrade"
    require(
        0 <= upgrade.find(handover_name) < upgrade.find("Upgrade the RKE2 binary one control-plane server at a time"),
        "an RKE2 v1.37 upgrade must neutralize the bootstrap CRD manifest on every server first",
    )
    handover = task_block(upgrade, handover_name)
    require(
        "/var/lib/rancher/rke2/server/manifests/inspace-gateway-api-crds.yaml.skip" in handover
        and "touch" in handover
        and "rm " not in handover
        and "loop: \"{{ deployment_state.controlPlanes }}\"" in handover
        and "gateway_api_enabled | default(false) | bool" in handover
        and "deploy_gateway_api_rke2_release is version('1.37.0', '>=')" in handover,
        "the v1.37 handover must only skip, never delete, the manifest so the CRDs and Gateways survive",
    )
    # Owner decision: Gateway API is served by Cilium only. Traefik and
    # ingress-nginx stay disabled, and the v1.37 CRD chart is never disabled.
    for label, template in (
        ("deploy", cluster_template),
        ("E2E", read("test/e2e/templates/cluster.yaml.j2")),
    ):
        # Gateway API also needs rke2-traefik-crd disabled: its bundled Gateway
        # API CRDs cannot be imported over ours, so its helm-install job would
        # crash-loop (seen live in the v1.1.0-rc.7 E2E).
        # An operator installing their own Traefik may also drop it so their
        # Helm release owns the Traefik CRDs (rke2_traefik_crd_enabled: false).
        expected = {
            "deploy": "      - rke2-ingress-nginx\n      - rke2-traefik\n"
                      "{% if (gateway_api_enabled | default(false) | bool) or "
                      "not (rke2_traefik_crd_enabled | default(true) | bool) %}\n"
                      "      - rke2-traefik-crd\n{% endif %}\n",
            "E2E": "      - rke2-ingress-nginx\n      - rke2-traefik\n      - rke2-traefik-crd\n",
        }[label]
        disabled = re.search(r"(?m)^    disable:\n((?:(?:      - .*|\{%.*%\})\n)+)", template)
        require(
            disabled is not None and disabled.group(1) == expected,
            f"{label} cluster template must disable exactly rke2-ingress-nginx and rke2-traefik, "
            "plus rke2-traefik-crd with Gateway API",
        )
        require("rke2-gateway-api-crd" not in template,
                f"{label} cluster template must never disable rke2-gateway-api-crd")
    require("needs no Traefik" in readme, "README must state that Gateway API needs no Traefik")
    require(
        re.search(r"(?m)^    rke2_traefik_crd_enabled: true$", read("deploy/inventory.example.yml")) is not None
        and "`rke2_traefik_crd_enabled`" in readme,
        "example inventory and README must document the default-on rke2_traefik_crd_enabled option",
    )
    require(
        "rke2_traefik_crd_enabled | default(true) is boolean" in read("deploy/playbooks/tasks/preflight.yml"),
        "preflight must accept rke2_traefik_crd_enabled only as a boolean",
    )
    load_state = read("deploy/playbooks/tasks/load-state.yml")
    require(
        "'rke2-traefik-crd' in persisted_inspace_cluster.spec.rke2.get('disable', [])" in load_state
        and "not (rke2_traefik_crd_enabled | default(true) | bool)" in load_state,
        "journal binding must keep rke2_traefik_crd_enabled fixed at cluster creation",
    )
    verify_optional_default_node_pool(readme)
    verify_csi_default_storage_class(readme)
    verify_public_node_local_node_class(readme)


def verify_optional_default_node_pool(readme: str) -> None:
    """GitOps-owned NodePools: the default NodeClass (the Node-LB base) always stays deploy-owned."""
    template = read("deploy/templates/karpenter.yaml.j2").replace("\r\n", "\n")
    node_class, separator, node_pool = template.partition(
        "{% if karpenter_default_node_pool_enabled | default(true) | bool %}\n---\n"
    )
    require(
        separator != ""
        and "kind: InSpaceNodeClass" in node_class and "karpenter_default_node_pool_enabled" not in node_class
        and "kind: NodePool" in node_pool and node_pool.rstrip().endswith("{% endif %}"),
        "karpenter template must always render the NodeClass and gate only the NodePool",
    )
    require(
        "karpenter_default_node_pool_enabled | default(true) is boolean" in read("deploy/playbooks/tasks/preflight.yml"),
        "preflight must accept karpenter_default_node_pool_enabled only as a boolean",
    )
    require(
        re.search(r"(?m)^    karpenter_default_node_pool_enabled: true$", read("deploy/inventory.example.yml")) is not None
        and "`karpenter_default_node_pool_enabled`" in readme,
        "example inventory and README must document karpenter_default_node_pool_enabled",
    )


def verify_csi_default_storage_class(readme: str) -> None:
    """The chart's inspace-rwo StorageClass becomes the cluster default only on request."""
    values = read("deploy/templates/chart-values.yaml.j2").replace("\r\n", "\n")
    require(
        "  storageClass:\n"
        "    name: inspace-rwo\n"
        "{% if csi_storage_class_default | default(false) | bool %}\n"
        "    annotations:\n"
        '      storageclass.kubernetes.io/is-default-class: "true"\n'
        "{% else %}\n"
        "    annotations: {}\n"
        "{% endif %}\n" in values,
        "chart values must mark inspace-rwo as the default StorageClass only when csi_storage_class_default is true, "
        "with the annotation value quoted as the chart schema requires a string",
    )
    require(
        "csi_storage_class_default | default(false) is boolean" in read("deploy/playbooks/tasks/preflight.yml"),
        "preflight must accept csi_storage_class_default only as a boolean",
    )
    require(
        re.search(r"(?m)^    csi_storage_class_default: false$", read("deploy/inventory.example.yml")) is not None
        and "`csi_storage_class_default`" in readme
        and "## Default StorageClass" in readme,
        "example inventory and README must document the default-off csi_storage_class_default option",
    )


def verify_public_node_local_node_class(readme: str) -> None:
    """An optional deploy-owned public-node-local NodeClass differs from the default only in name, profile, and disk."""
    template = read("deploy/templates/karpenter.yaml.j2").replace("\r\n", "\n")
    node_class, _, node_pool = template.partition("{% if karpenter_default_node_pool_enabled | default(true) | bool %}\n---\n")
    require(
        "{% for node_class in [" in node_class
        and "{'name': karpenter_node_class_name, 'profile': '', 'rootDiskGiB': karpenter_root_disk_gib}" in node_class
        and "'name': karpenter_public_node_local_node_class_name | default('', true)" in node_class
        and "'profile': 'public-node-local'" in node_class
        and "karpenter_public_node_local_root_disk_gib | default(30)" in node_class
        and "] if node_class.name %}" in node_class
        and "{% if not loop.first %}\n---\n{% endif %}\n" in node_class
        and node_class.rstrip().endswith("{% endfor %}")
        and node_class.count("kind: InSpaceNodeClass") == 1,
        "karpenter template must render every NodeClass from one loop over the default and the optional public-node-local entry",
    )
    require(
        node_class.count("firewallProfile:") == 1
        and "{% if node_class.profile %}\n  firewallProfile: {{ node_class.profile }}\n{% endif %}\n" in node_class,
        "only the public-node-local NodeClass may set firewallProfile; the default must render none, "
        "because the provider hashes the whole spec and any value would drift-replace every worker",
    )
    require(
        "  reservePublicIPv4: true\n  firewallUUID: {{ bootstrap_result.firewallUUID }}\n" in node_class
        and "  rootDiskGiB: {{ node_class.rootDiskGiB }}\n" in node_class
        and "  name: {{ node_class.name }}\n" in node_class
        and "name: {{ karpenter_node_class_name }}" in node_pool,
        "both NodeClasses must keep the public IPv4 and trusted worker firewall, and the NodePool must use the default NodeClass",
    )
    require(
        "  defaultNodeClass: {{ karpenter_node_class_name }}\n"
        in read("deploy/templates/chart-values.yaml.j2").replace("\r\n", "\n"),
        "Karpenter must keep defaulting to the default NodeClass",
    )
    preflight = read("deploy/playbooks/tasks/preflight.yml")
    require(
        "karpenter_public_node_local_node_class_name | default('', true) != karpenter_node_class_name" in preflight
        and "cluster_name ~ '-node-lb'" in preflight
        and "startswith('inlb-')" in preflight
        and "karpenter_public_node_local_node_class_name | default('', true) is string" in preflight
        and "is match('^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')" in preflight
        and "(karpenter_public_node_local_root_disk_gib | default(30) | string) is match('^[0-9]+$')" in preflight
        and "karpenter_public_node_local_root_disk_gib | default(30) | int >= 30" in preflight
        and "karpenter_public_node_local_root_disk_gib | default(30) | int <= 2000" in preflight,
        "preflight must require a DNS-1123 public-node-local NodeClass name clear of the default and CCM Node-LB "
        "NodeClasses, and a whole-number root disk of 30-2000 GiB",
    )
    inventory = read("deploy/inventory.example.yml")
    require(
        re.search(r'(?m)^    karpenter_public_node_local_node_class_name: ""$', inventory) is not None
        and re.search(r"(?m)^    karpenter_public_node_local_root_disk_gib: 30$", inventory) is not None
        and "`karpenter_public_node_local_node_class_name`" in readme
        and "`karpenter_public_node_local_root_disk_gib`" in readme
        and "## Public edge NodeClass for endpoint-local Services" in readme
        and "never prunes" in readme,
        "example inventory and README must document the public-node-local NodeClass options",
    )


def verify_update_cache_refresh(update: str) -> None:
    """`update` refreshes a cached bastion before any RKE2 or chart upgrade."""
    refresh = read("deploy/playbooks/tasks/refresh-bootstrap-cache.yml")
    script = read("deploy/templates/refresh-bootstrap-cache.sh")
    readme = read("deploy/README.md")
    ci = read(".github/workflows/ci.yaml")
    include = "- name: Add this release's digest-pinned entries to the bastion bootstrap cache\n"
    order = [
        update.find(value)
        for value in (
            "include_tasks: tasks/start-tunnel.yml",
            include,
            "include_tasks: tasks/apply-rke2-upgrade.yml",
            "include_tasks: tasks/apply-control-plane-config.yml",
            "- name: Upgrade the exact CRDs chart\n",
            "- name: Upgrade the exact CCM CSI and Karpenter chart\n",
            "- name: Apply the updated default NodeClass and NodePool\n",
        )
    ]
    require(
        all(offset >= 0 for offset in order) and order == sorted(order),
        "update must refresh the bastion bootstrap cache after the tunnel and before any RKE2, config, chart, or NodeClass change",
    )
    block = task_block(update, include.removeprefix("- name: ").rstrip("\n"))
    require(
        "ansible.builtin.include_tasks: tasks/refresh-bootstrap-cache.yml" in block
        and "when: not bootstrap_direct_download | bool" in block,
        "the cache refresh must run for every cached cluster and be a no-op for directDownload clusters",
    )
    print_task = task_block(refresh, "Print the target release's bootstrap cache refresh manifest offline")
    for fragment in (
        "docker run --platform linux/amd64 --rm --network=none",
        "--entrypoint /usr/local/bin/inspace-cluster-controller",
        "{{ deploy_modules_release_images['inspace-cloud-controller-manager'].releaseReference | quote }}",
        "--print-bootstrap-cache-refresh",
        "--bootstrap-cache-rke2-version",
        "--bootstrap-cache-disable",
        "persisted_inspace_cluster.spec.rke2.disable",
        'mv -f "$manifest.partial" "$manifest"',
    ):
        require(fragment in print_task, f"the refresh manifest must be printed offline by the exact target release: {fragment}")
    require(
        "deploy_recorded_rke2_version != rke2_version" in refresh
        and "if deploy_recorded_rke2_version != rke2_version else ''" in refresh,
        "the refresh must add the RKE2 release only when update moves RKE2, and chart images otherwise",
    )
    target_check = task_block(refresh, "Require the refresh manifest to target modules_version")
    require(
        all(
            f"('\\tthanet-s/{component}:' ~ modules_version ~ '\\n') in deploy_cache_refresh_lines" in target_check
            for component in ("inspace-cloud-controller-manager", "inspace-csi-driver", "karpenter-provider-inspace")
        )
        and "deploy_cache_refresh_rke2_version | regex_escape" in target_check,
        "the printed manifest must be proven to belong to modules_version and the requested RKE2 release",
    )
    run_task = task_block(refresh, "Import missing digest-verified entries into the bastion bootstrap cache")
    for fragment in (
        "- timeout\n",
        "- inspace-bastion\n",
        "sudo sh /tmp/inspace-refresh-bootstrap-cache.sh /tmp/inspace-bootstrap-cache-refresh.tsv",
        "bootstrap_result.bootstrapCacheRegistry",
        "changed_when: \"'changed' in deploy_bootstrap_cache_refresh.stdout_lines\"",
    ):
        require(fragment in run_task, f"the bastion cache refresh must run bounded over the pinned SSH hop: {fragment}")
    require(
        "templates/refresh-bootstrap-cache.sh" in refresh and "inspace-bastion:/tmp/inspace-refresh-bootstrap-cache.sh" in refresh,
        "the fixed refresh script must be copied to the bastion",
    )
    for fragment in (
        "refusing to overwrite it",
        "skopeo copy --retry-times 8 --preserve-digests --override-os linux --override-arch amd64",
        'exec 9>"$cache_root/locks-seed"',
        "REGISTRY_READONLY=true",
        "docker compose up -d --wait --force-recreate registry nginx",
        '[ "$probe" = 405 ]',
        '--cacert "$ca_file"',
        "deadline=$(( $(date +%s) + 2400 ))",
    ):
        require(fragment in script, f"the bastion refresh script lost a safety property: {fragment}")
    maintenance = re.search(
        r"const cacheMaintenanceScript = `([^`]*)`",
        read("modules/cloud-provider/pkg/bootstrap/cache_cloudinit.go"),
    )
    embedded = re.search(r"<<'MAINTAIN'\n(.*?)MAINTAIN\n", script, re.S)
    require(
        maintenance is not None and embedded is not None and embedded.group(1) == maintenance.group(1),
        "the refresh script must install exactly the bootstrap cache maintenance script",
    )
    require(
        "--print-bootstrap-cache-refresh" in readme
        and "bypassing the\n  bastion bootstrap cache" not in readme,
        "deploy README must describe the bootstrap cache refresh that update performs",
    )
    require(
        "python3 deploy/scripts/test_refresh_bootstrap_cache.py" in ci
        and "sh -n deploy/templates/refresh-bootstrap-cache.sh" in ci,
        "CI must run the offline bastion cache refresh tests",
    )


SECRET_FILE_PRELUDE = (
    "umask 077\n"
    "        secret_dir=$(mktemp -d)\n"
    "        trap 'rm -rf -- \"$secret_dir\"' EXIT\n"
    "        printf '%s' \"$INSPACE_API_TOKEN\" >\"$secret_dir/api-token\"\n"
)


def verify_secret_values_stay_off_argv(playbooks: dict[str, str]) -> None:
    """Credentials reach kubectl through a 0600 file, never a command line."""
    for name, text in playbooks.items():
        require(
            re.search(r"--from-literal=[\"']?[\w.-]*token", text, re.IGNORECASE) is None,
            f"{name} passes a token to kubectl with --from-literal, exposing it in argv",
        )
        require(
            re.search(r"apikey: \$", text) is None,
            f"{name} passes the API token in a curl command-line header",
        )
        if "inspace-cloud-credentials" not in text or "create secret generic inspace-cloud-credentials" not in text:
            continue
        require(
            SECRET_FILE_PRELUDE in text
            and '--from-file="api-token=$secret_dir/api-token"' in text,
            f"{name} must write the API token to a 0600 temporary file that is always removed",
        )


def verify_rke2_agent_token(init: str, readme: str) -> None:
    """New clusters give workers a separate agent token, never the server token."""
    stat_task = task_block(init, "Inspect durable bootstrap files")
    require(
        stat_task.index("        - state.json\n") < stat_task.index("        - rke2-agent-token\n"),
        "the RKE2 agent token file must be appended to the durable bootstrap file inspection",
    )
    generate = task_block(init, "Generate the RKE2 agent join token")
    persist = task_block(init, "Persist the RKE2 agent join token")
    require(
        "argv: [openssl, rand, -hex, \"32\"]" in generate
        and "no_log: true" in generate
        and "not deploy_bootstrap_files.results[1].stat.exists" in generate
        and "not deploy_bootstrap_files.results[6].stat.exists" in generate
        and "bootstrap_controller_version is version('1.1.0-rc.5', '>', version_type='semver')" in generate,
        "the agent token must be generated only for a new cluster whose pinned controller renders agent-token",
    )
    require(
        'dest: "{{ deploy_state_dir }}/rke2-agent-token"' in persist
        and 'mode: "0600"' in persist
        and "no_log: true" in persist,
        "the agent token must be persisted mode 0600 without logging",
    )
    require(
        init.index("- name: Persist the RKE2 agent join token\n")
        < init.index("- name: Persist the RKE2 registration token\n"),
        "the agent token must be persisted before the server token so a partial first run cannot lose it",
    )
    validate = task_block(init, "Require a valid separate RKE2 agent join token")
    require(
        "deploy_rke2_agent_token_file.stat.mode == '0600'" in validate
        and "is match('^[0-9a-f]{64}$')" in validate
        and "!= (lookup('file', deploy_state_dir + '/rke2-token') | trim)" in validate
        and "no_log: true" in validate,
        "the persisted agent token must be 0600, 256-bit hex, and distinct from the server token",
    )
    reconcile = task_block(init, "Reconcile bootstrap infrastructure synchronously to readiness")
    require(
        "          - --env\n          - INSPACE_RKE2_AGENT_TOKEN\n" in reconcile
        and "INSPACE_RKE2_AGENT_TOKEN: >-" in reconcile
        and "no_log: true" in reconcile,
        "the bootstrap controller must receive the agent token only through its environment",
    )
    require(
        re.search(r"--[a-z-]*agent-token", reconcile) is None,
        "the agent token must never be a controller command-line flag",
    )
    secret = task_block(init, "Create or update cloud and RKE2 agent-token Secrets")
    agent_secret = secret[secret.index("create secret generic inspace-rke2-agent-token"):]
    require(
        '--from-file="token={{ deploy_rke2_agent_join_token_file }}"' in agent_secret
        and "rke2-token" not in agent_secret.replace("inspace-rke2-agent-token", ""),
        "the worker Secret must be built from the selected agent join token file",
    )
    select = task_block(init, "Select the RKE2 agent join token for workers")
    require(
        "'/rke2-agent-token' if deploy_rke2_agent_token_file.stat.exists else '/rke2-token'" in select,
        "workers must get the agent token whenever the cluster has one; only a legacy cluster keeps the server token",
    )
    require(
        "rke2 token rotate" in readme and "agent-token" in readme and "rke2-agent-token" in readme,
        "README must document the agent token and a manual rotation path",
    )


def verify_release_image_digests(init: str, update: str, destroy: str) -> None:
    """The controller and chart images run by immutable digest, never by a mutable tag."""
    resolver = "{{ deploy_root }}/scripts/resolve_release_images.py"
    chart_values = read("deploy/templates/chart-values.yaml.j2")
    readme = read("deploy/README.md")
    refresh = read("deploy/playbooks/tasks/refresh-bootstrap-cache.yml")
    for label, playbook in (("init", init), ("update", update), ("destroy", destroy), ("cache refresh", refresh)):
        require(
            re.search(r"inspace-cloud-controller-manager:\{\{", playbook) is None
            and re.search(r"(?m)^\s*-?\s*\"?ghcr\.io/thanet-s/[a-z-]+:", playbook) is None,
            f"{label} must not pull or run a controller image by a mutable tag",
        )
    resolve_bootstrap = task_block(init, "Resolve the immutable bootstrap controller image")
    resolve_modules = task_block(init, "Resolve the immutable released module images")
    load_images = task_block(init, "Load the immutable release image references")
    for task, version in (
        (resolve_bootstrap, "{{ bootstrap_controller_version }}"),
        (resolve_modules, "{{ modules_version }}"),
    ):
        require(
            f"- python3\n          - \"{resolver}\"\n          - \"{version}\"\n" in task
            and "changed_when: false\n" in task,
            f"init must resolve {version} images from its immutable release records",
        )
    require(
        "bootstrap_controller_image: >-" in load_images
        and ".images['inspace-cloud-controller-manager'].releaseReference" in load_images
        and "deploy_modules_release_images: >-" in load_images,
        "init must load the resolved controller reference and module digests",
    )
    pull = task_block(init, "Pull the exact bootstrap controller release")
    print_bundle = task_block(init, "Print the pinned Gateway API CRD bundle from the exact bootstrap controller")
    reconcile = task_block(init, "Reconcile bootstrap infrastructure synchronously to readiness")
    require(
        init.index("Resolve the immutable bootstrap controller image")
        < init.index("Resolve the immutable released module images")
        < init.index("Load the immutable release image references")
        < init.index("Pull the exact bootstrap controller release"),
        "init must resolve every release digest before the first controller pull or cloud mutation",
    )
    for task in (pull, print_bundle, reconcile):
        require(
            "{{ bootstrap_controller_image }}" in task
            or "{{ bootstrap_controller_image | quote }}" in task,
            "every init controller pull and run must use the resolved immutable digest",
        )
    require(
        f"- \"{resolver}\"\n          - \"{{{{ modules_version }}}}\"\n"
        in task_block(update, "Resolve the immutable released module images")
        and update.index("Resolve the immutable released module images")
        < update.index("Render updated chart values"),
        "update must resolve module image digests before rendering chart values",
    )
    resolve_destroy = task_block(destroy, "Resolve the bootstrap controller image that owns the durable ledger")
    require(
        f"- \"{resolver}\"\n          - \"{{{{ deployment_state.bootstrapControllerVersion }}}}\"\n"
        in resolve_destroy
        and "changed_when: false\n" in resolve_destroy
        and "deploy_destroy_controller_image: >-"
        in task_block(destroy, "Load the ledger-owning controller image reference")
        and destroy.index("Require an exact typed cluster-name destruction confirmation")
        < destroy.index("Resolve the bootstrap controller image that owns the durable ledger")
        < destroy.index("Start the private API tunnel before deleting Kubernetes owners"),
        "destroy must resolve the ledger-owning controller digest before any Kubernetes deletion",
    )
    require(
        "deploy_modules_release_images: >-" in task_block(update, "Load the immutable module image digests")
        and update.index("Resolve the immutable released module images")
        < update.index("Start the private API tunnel and wait for readiness"),
        "update must resolve module image digests before any cluster change",
    )
    for name in (
        "Pull the bootstrap controller version that owns the durable ledger",
        "Delete only journaled bootstrap-owned infrastructure",
    ):
        require(
            "{{ deploy_destroy_controller_image }}" in task_block(destroy, name),
            f"destroy task '{name}' must use the resolved immutable controller digest",
        )
    for key, image in (
        ("ccm", "inspace-cloud-controller-manager"),
        ("csi", "inspace-csi-driver"),
        ("karpenter", "karpenter-provider-inspace"),
    ):
        require(
            re.search(
                rf"(?ms)^{key}:\n(?:  [^\n]*\n)*?  image:\n"
                rf"    digest: \"\{{\{{ deploy_modules_release_images\['{image}'\]\.platformDigest \}}\}}\"\n",
                chart_values,
            )
            is not None,
            f"chart values must pin {key} to the resolved linux/amd64 digest",
        )
    require(
        "resolve_release_images.py" in readme and "immutable" in readme,
        "deploy README must document release image digest resolution",
    )
    unit = subprocess.run(
        [sys.executable, str(DEPLOY / "scripts" / "test_resolve_release_images.py")],
        cwd=DEPLOY / "scripts",
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    require(
        unit.returncode == 0,
        "release image resolver unit tests failed: " + (unit.stderr.strip() or unit.stdout.strip()),
    )


def verify_journal_writers_end_with_real_newline() -> None:
    """A Jinja '\n' literal renders as backslash-n, corrupting the JSON journal.

    Only a double-quoted YAML scalar turns \n into a newline, so playbooks must
    end written JSON with `}}\n"` and never with `{{ '\n' }}`.
    """
    literal = "{{ '\\n' }}"
    offenders = sorted(
        str(path.relative_to(ROOT))
        for path in (DEPLOY / "playbooks").rglob("*.yml")
        if literal in path.read_text(encoding="utf-8")
    )
    require(
        not offenders,
        "playbooks must end written JSON with a double-quoted \\n, not the Jinja "
        f"literal {literal} (it renders as backslash-n): {', '.join(offenders)}",
    )


def main() -> None:
    inventory = read("deploy/inventory.example.yml")
    gitignore = read(".gitignore")
    dockerignore = read(".dockerignore")
    dockerfile = read("deploy/Dockerfile")
    dependency_lock = read("deploy/requirements.lock.txt")
    container_entrypoint = read("deploy/container-entrypoint.sh")
    cluster_template = read("deploy/templates/cluster.yaml.j2")
    init = read("deploy/playbooks/init-cluster.yml")
    update = read("deploy/playbooks/update-control-plane.yml")
    destroy = read("deploy/playbooks/destroy-cluster.yml")
    preflight = read("deploy/playbooks/tasks/preflight.yml")
    cloud_crd = read(
        "modules/cloud-provider/config/crd/bases/"
        "infrastructure.inspace.cloud_inspaceclusters.yaml"
    )
    chart_crd = read(
        "charts/inspace-cloud-kube-modules-crds/templates/"
        "infrastructure.inspace.cloud_inspaceclusters.yaml"
    )

    verify_journal_writers_end_with_real_newline()
    require(
        re.search(r"(?m)^\s*(?:INSPACE_API_TOKEN|inspace_api_token)\s*:", inventory)
        is None,
        "example inventory stores a token",
    )
    egress_name = "Prove every control plane reaches the internet through its floating IP"
    require(
        egress_name in init
        and init.index(egress_name) < init.index("Wait for control-plane cloud-init completion"),
        "control-plane egress must be proven before the long cloud-init wait",
    )
    egress_task = init[init.index(egress_name):init.index("Wait for control-plane cloud-init completion")]
    require(
        '"inspace-cp{{ deploy_cp_index }}"' in egress_task
        and "https://registry-1.docker.io/v2/" in egress_task
        and "https://ghcr.io/v2/" in egress_task
        and " -f" not in egress_task
        and "timeout --kill-after=5s 300s sh -c" in egress_task
        and "'until curl " in egress_task,
        "control-plane egress must be proven from inside through the bastion",
    )
    # The local ssh client exits 255 only for its own transport failure. Retry
    # that alone, so one SSH blip cannot fail init while a real in-guest
    # timeout (124) or cloud-init error still fails on its single attempt.
    cloud_init_name = "Wait for control-plane cloud-init completion"
    cloud_init_task = init[init.index(cloud_init_name):init.index("Read the administrator kubeconfig from cp0")]
    for task, register, timeout in (
        (egress_task, "deploy_control_plane_egress", "300s"),
        (cloud_init_task, "deploy_control_plane_cloud_init", "2400s"),
    ):
        require(
            f"timeout --kill-after=5s {timeout} sh -c" in task
            and f"register: {register}\n" in task
            and f"until: {register}.rc != 255\n" in task
            and f"failed_when: {register}.rc != 0\n" in task
            and "retries: 3\n" in task
            and "delay: 10\n" in task,
            f"{register} must retry only ssh transport failures (255) around one {timeout} in-guest deadline",
        )

    karpenter_template = read("deploy/templates/karpenter.yaml.j2")
    readme = read("deploy/README.md")
    for label, template in (("cluster", cluster_template), ("Karpenter", karpenter_template)):
        require(
            'osVersion: "{{ deploy_os_version }}"' in template
            and '"26.04"' not in template
            and '"24.04"' not in template,
            f"{label} template must render the validated inventory os_version",
        )
    require(
        "deploy_os_version: \"{{ os_version | default(deploy_persisted_os_version, true) | string }}\"" in preflight
        and ".spec.controlPlane.machine.image.osVersion" in preflight
        and "if deploy_persisted_cluster_spec.stat.exists else '26.04'" in preflight
        and "deploy_os_version in ['24.04', '26.04']" in preflight
        and "deploy_os_version == '24.04' or modules_version is version('1.1.0-rc.3', '>=', version_type='semver')"
        in preflight
        and preflight.index("Require the complete deployment inventory")
        < preflight.index("Require cloud modules that accept the selected Ubuntu release"),
        "preflight must keep a persisted release (else 26.04), allow only 24.04/26.04, "
        "and require 1.1.0-rc.3+ for 26.04",
    )
    require(
        re.search(r"(?m)^    os_version: \"26\.04\"$", inventory) is not None
        and re.search(r"(?m)^    modules_version: 1\.1\.0-rc\.4$", inventory) is not None
        and "`os_version`" in readme,
        "example inventory and README must document os_version with a 26.04-capable modules_version",
    )
    load_state = read("deploy/playbooks/tasks/load-state.yml")
    require(
        "{% if deploy_load_balancer_algorithm %}\n"
        "    loadBalancerAlgorithm: {{ deploy_load_balancer_algorithm }}\n"
        "{% endif %}\n"
        "{% if deploy_service_topology | bool %}\n"
        "    serviceTopology: true\n"
        "{% endif %}" in cluster_template,
        "cluster template must render Cilium load-balancer fields only when the inventory selects them",
    )
    require(
        "deploy_load_balancer_algorithm: \"{{ load_balancer_algorithm | default('', true) | string }}\"" in preflight
        and "deploy_service_topology: \"{{ service_topology | default(false) | bool }}\"" in preflight
        and "deploy_load_balancer_algorithm in ['', 'random', 'maglev']" in preflight
        and "service_topology is not defined or service_topology is boolean" in preflight
        and "(deploy_load_balancer_algorithm == '' and not (deploy_service_topology | bool)) or "
        "modules_version is version('1.1.0-rc.4', '>', version_type='semver')" in preflight,
        "preflight must allow only supported Cilium load-balancer settings on a supporting release",
    )
    require(
        "persisted_inspace_cluster.spec.network.get('loadBalancerAlgorithm', '') == deploy_load_balancer_algorithm"
        in load_state
        and "persisted_inspace_cluster.spec.network.get('serviceTopology', false) | bool == deploy_service_topology | bool"
        in load_state,
        "every lifecycle command must refuse Cilium load-balancer settings that differ from the immutable bootstrap spec",
    )
    require(
        "`load_balancer_algorithm`" in readme
        and "`service_topology`" in readme
        and "creation-time" in readme
        and re.search(r"(?m)^    # load_balancer_algorithm: maglev$", inventory) is not None
        and re.search(r"(?m)^    # service_topology: true$", inventory) is not None,
        "README and example inventory must document the creation-time Cilium load-balancer settings",
    )
    drift_script = read("deploy/scripts/verify-cilium-config-drift.sh")
    require(
        "cilium_drift_checker_config_delta" in drift_script
        and "cilium-dbg metrics list -p drift_checker_config_delta -o json" in drift_script,
        "deploy Cilium drift proof must read the agent drift metric",
    )
    helm_wait = "Wait for the rke2-cilium chart install Job after control-plane changes"
    drift_check = "Require every Cilium agent to run the current cilium-config"
    require(
        update.index("tasks/apply-control-plane-config.yml") < update.index(helm_wait) < update.index(drift_check)
        and update.index(drift_check) < update.index("Upgrade the exact CCM CSI and Karpenter chart"),
        "update must prove Cilium applied its ConfigMap after RKE2 changes and before chart upgrades",
    )
    drift_task = update[update.index(drift_check):update.index("Refresh the cloud API Secret")]
    require(
        "{{ deploy_root }}/scripts/verify-cilium-config-drift.sh" in drift_task
        and "register: deploy_cilium_config_drift" in drift_task
        and "until: deploy_cilium_config_drift.rc == 0" in drift_task
        and "retries: 30" in drift_task
        and "delay: 10" in drift_task,
        "update Cilium drift proof must be a bounded wait",
    )
    for ignored in ("deploy/inventory.yml", "deploy/inventory/", "deploy/.state/"):
        require(ignored in gitignore, f"missing Git exclusion {ignored}")
        require(ignored in dockerignore, f"missing Docker exclusion {ignored}")
    require(
        "ubuntu:26.04@sha256:" in dockerfile
        and "docker:29.8.1-cli@sha256:" in dockerfile,
        "deploy runner base or Docker CLI image is not digest locked",
    )
    require(
        "ansible-core==2.21.4 \\" in dependency_lock
        and all(
            line == ""
            or line.startswith("#")
            or re.search(r"^[A-Za-z0-9_.-]+==[^=\s]+ \\$", line)
            or re.search(r"^    --hash=sha256:[0-9a-f]{64}(?: \\)?$", line)
            for line in dependency_lock.splitlines()
        )
        and "--require-hashes" in dockerfile,
        "deploy Python dependency lock contains an unpinned or unhashed requirement",
    )
    require(
        "KUBECTL_VERSION=v1.36.4" in dockerfile
        and "alpine/helm:4.3.0@sha256:" in dockerfile
        and dockerfile.count("sha256sum --check") == 1,
        "deploy kubectl or Helm dependency is not exactly verified",
    )
    require(
        "replicas: {{ control_plane_replicas }}" in cluster_template,
        "cluster template pins a topology instead of using inventory",
    )
    require(
        "control_plane_replicas | int in [1, 3]" in preflight,
        "preflight does not reject two-server topology",
    )
    require(
        "control-plane replica count is immutable after cluster creation" in cloud_crd
        and "\n                        - 1\n                        - 3" in cloud_crd,
        "source CRD lacks immutable one-or-three replica contract",
    )
    require(cloud_crd == chart_crd, "source and packaged cluster CRDs differ")

    for fragment in (
        "cluster.desired.yaml",
        "persisted bootstrap spec differs",
        "deploy_persisted_bootstrap_spec_normalized",
        "INSPACE_ALLOW_REMOTE_MUTATIONS",
        "bootstrap_controller_version",
        "--until-ready",
        "discover_bootstrap.py",
        "tasks/start-tunnel.yml",
        "tasks/settle-single-control-plane.yml",
        "inspace-cloud-kube-modules-crds",
        "inspace-cloud-kube-modules",
        "tasks/apply-control-plane-config.yml",
    ):
        require(fragment in init, f"init lifecycle lacks {fragment}")
    require(
        init.index("cluster.desired.yaml") < init.index("--until-ready"),
        "desired-spec fence does not precede bootstrap mutation",
    )
    require(
        init.index("bootstrap-controller-version")
        < init.index("INSPACE_ALLOW_REMOTE_MUTATIONS"),
        "bootstrap destroy authority is not pinned before bootstrap mutation",
    )
    require(
        "ansible.builtin.import_tasks: tasks/settle-single-control-plane.yml" in init,
        "single-control-plane tasks are not statically parsed by syntax checks",
    )
    require(
        init.count("linux/amd64") == 3 and destroy.count("linux/amd64") == 2,
        "bootstrap controller pull/run/print does not pin the published x86 platform",
    )
    verify_gateway_api(inventory, cluster_template, preflight, init, destroy)
    verify_update_cache_refresh(update)
    verify_rke2_agent_token(init, read("deploy/README.md"))
    verify_secret_values_stay_off_argv({
        str(path.relative_to(ROOT)): path.read_text(encoding="utf-8")
        for path in sorted((DEPLOY / "playbooks").rglob("*.yml"))
    })
    verify_release_image_digests(init, update, destroy)
    load_state = read("deploy/playbooks/tasks/load-state.yml")
    single_cp_settle = read("deploy/playbooks/tasks/settle-single-control-plane.yml")
    for fragment in (
        "control_plane_replicas | int == 1",
        "Temporarily make cp0 schedulable",
        "Wait for every expected RKE2 packaged install Job",
        "Temporarily remove the cloud-provider startup taint",
        "Restore the original cloud-provider startup taint",
        "Restore the durable control-plane NoSchedule taint",
        "zero-worker state",
    ):
        require(fragment in single_cp_settle, f"single-control-plane settling lacks {fragment}")
    for optional_false in ("skipOSUpgrade", "directDownload"):
        require(
            f".get('{optional_false}', false)" in load_state,
            f"persisted bootstrap state does not default omitted {optional_false}",
        )

    for forbidden in (
        "'token'",
        "'cluster-cidr'",
        "'service-cidr'",
        "'node-ip'",
        "'system-default-registry'",
        "'data-dir'",
    ):
        require(forbidden in preflight, f"extra config does not block {forbidden}")
    require(
        "one control-plane server at a time" in update
        or "one-at-a-time" in update,
        "update does not declare rolling control-plane behavior",
    )
    require(
        "bootstrapControllerVersion" in update,
        "module update does not preserve bootstrap destroy authority",
    )
    require(
        "tasks/apply-rke2-upgrade.yml" in update,
        "update lifecycle does not roll out in-place RKE2 binary upgrades",
    )
    rke2_upgrade_task = read("deploy/playbooks/tasks/apply-rke2-upgrade.yml")
    rke2_upgrade_validator = read("deploy/scripts/validate_rke2_upgrade.py")
    run_launcher = read("deploy/run.sh")
    require(
        "INSPACE_CONFIRM_RKE2_VERSION_SKIP" in rke2_upgrade_task
        and "INSPACE_CONFIRM_RKE2_VERSION_SKIP" in rke2_upgrade_validator
        and "INSPACE_CONFIRM_RKE2_VERSION_SKIP" in run_launcher,
        "RKE2 upgrade lacks a downgrade/minor-skip safety confirmation",
    )
    require(
        "is_downgrade" in rke2_upgrade_validator and "skips_minor" in rke2_upgrade_validator,
        "RKE2 upgrade does not guard against downgrade or multi-minor-version skew",
    )
    # A regex, so the pin-refresh sed in DEVELOPMENT.md cannot rewrite it.
    require(
        re.search(r'RELEASED_PRERELEASES = frozenset\(\{[^}]*"v1\.36\.5-rc2\+rke2r1"', rke2_upgrade_validator)
        is not None
        and "parse_version(current, AUDITED_PRERELEASES | RELEASED_PRERELEASES)" in rke2_upgrade_validator,
        "RKE2 upgrade guard no longer accepts every released candidate as an upgrade source",
    )
    rke2_upgrade_script = read("deploy/templates/upgrade-rke2-server.sh")
    require(
        "sha256sum" in rke2_upgrade_script and "systemctl stop rke2-server" in rke2_upgrade_script,
        "RKE2 binary upgrade script does not verify checksums or stop the service before replacing it",
    )
    # The init-time InSpaceCluster record keeps its original RKE2 version (it is
    # bootstrap/destroy authority), so the journal records the version the
    # control plane was last upgraded to and only `update` may move it.
    require(
        "persisted_inspace_cluster.spec.rke2.version == rke2_version" not in load_state
        and "deployment_state.get('rke2Version', persisted_inspace_cluster.spec.rke2.version)" in load_state
        and "deploy_allow_rke2_version_change | default(false) | bool" in load_state
        and "deploy_allow_rke2_version_change: true" in update,
        "deployment journal blocks the documented in-place RKE2 version upgrade",
    )
    require(
        "deploy_recorded_rke2_version != rke2_version" in rke2_upgrade_task
        and "- \"{{ deploy_recorded_rke2_version }}\"" in rke2_upgrade_task
        and "combine({'rke2Version': rke2_version}" in rke2_upgrade_task,
        "RKE2 upgrade is not gated on and does not record the exact journaled RKE2 version",
    )
    # RKE2 release candidates ship the GA hardened kubelet, whose reported
    # version omits the -rcN suffix.
    kubelet_form = "rke2_version | regex_replace('-rc[0-9]+[+]', '+')"
    one_upgrade = read("deploy/playbooks/tasks/upgrade-one-control-plane.yml")
    require(
        kubelet_form in rke2_upgrade_task and "deploy_expected_kubelet_version" in one_upgrade
        and "failed_when: deploy_control_plane_upgraded_version.stdout != rke2_version" not in one_upgrade,
        "RKE2 upgrade readback does not map a release candidate to its kubelet version",
    )
    go_pattern = re.search(
        r"rke2VersionPattern = regexp\.MustCompile\(`([^`]+)`\)",
        read("modules/cloud-provider/api/v1alpha1/types.go"),
    )
    require(
        go_pattern is not None
        and f"rke2_version is match('{go_pattern.group(1).replace(chr(92), chr(92) * 2)}')" in preflight,
        "deploy preflight RKE2 version pattern differs from the InSpaceCluster validator",
    )

    ordered_destroy = (
        "Refuse bootstrap deletion while PVC or PV ownership remains",
        "Delete every LoadBalancer Service while its owning CCM is healthy",
        "Delete every Karpenter NodePool",
        "Wait for all NodeClaims and non-control-plane nodes to disappear",
        "Refuse controller removal while volume attachments remain",
        "Uninstall CCM CSI and Karpenter",
        "Delete only journaled bootstrap-owned infrastructure",
    )
    offsets = [destroy.find(value) for value in ordered_destroy]
    require(all(value >= 0 for value in offsets), "destroy lacks a safety phase")
    require(offsets == sorted(offsets), "destroy safety phases are misordered")
    require(
        "confirm_cluster_name" in destroy
        and "deployment_state.bootstrapControllerVersion" in destroy
        and "--delete" in destroy,
        "destroy lacks confirmation or ledger-bound controller authority",
    )
    for dangerous in (
        "network/network/",
        "delete network",
        "delete floating-ip --all",
        "git clean",
    ):
        require(
            dangerous not in destroy.lower(),
            f"destroy contains broad or unrelated deletion text: {dangerous}",
        )

    for path in (
        "deploy/Dockerfile",
        "deploy/container-entrypoint.sh",
        "deploy/requirements.lock.txt",
        "deploy/run.sh",
        "deploy/scripts/api-tunnel.sh",
        "deploy/scripts/discover_bootstrap.py",
        "deploy/playbooks/init-cluster.yml",
        "deploy/playbooks/update-control-plane.yml",
        "deploy/playbooks/status.yml",
        "deploy/playbooks/tunnel.yml",
        "deploy/playbooks/destroy-cluster.yml",
    ):
        require((ROOT / path).is_file(), f"missing deployment artifact {path}")

    run = read("deploy/run.sh")
    require(
        re.search(r"init \| update \| status \| tunnel \| destroy", run) is not None,
        "launcher does not expose the full lifecycle",
    )
    for fragment in (
        "type=bind,src=$inventory,dst=/run/config/inventory.yml,readonly",
        "type=bind,src=$ssh_dir,dst=$ssh_dir,readonly",
        "type=bind,src=$state_root,dst=$state_root",
        "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock",
        "local/inspace-deploy-runner:$runner_arch-$fingerprint",
    ):
        require(fragment in run, f"containerized launcher lacks {fragment}")
    require(
        "ansible-playbook" not in run,
        "host launcher still depends on a host Ansible installation",
    )
    require(
        "INSPACE_DEPLOY_RUNNER_PLATFORM:-linux/amd64" not in run
        and 'INSPACE_DEPLOY_RUNNER_PLATFORM:-}' in run,
        "deploy runner forces x86 instead of using the management host architecture",
    )
    require(
        "INSPACE_DEPLOY_STATE_ROOT" in preflight
        and "INSPACE_DEPLOY_STATE_ROOT" in container_entrypoint,
        "container state path is not shared with nested Docker safely",
    )
    require(
        "/state/ssh-public-key" in init
        and "src={{ ssh_public_key_file_expanded }}" not in init,
        "nested bootstrap still asks the host daemon to mount a container-only SSH path",
    )
    print("deploy static contracts: ok")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        print(f"deploy static verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
