package bootstrap

import (
	"bytes"
	_ "embed"
	"strconv"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
)

// The Gateway API standard bundle is ~1.2 MB, far larger than any control-plane
// cloud-init payload should be, and nodes must not download it at boot. The
// exact upstream release asset is therefore embedded here; lifecycle tooling
// prints it with `inspace-cluster-controller --print-gateway-api-crds` and
// copies it to each control plane over SSH. Bootstrap waits for those exact
// bytes, verifies GatewayAPIStandardInstallSHA256, and installs them as an
// RKE2 server manifest before RKE2 starts, so Cilium sees the CRDs at its
// first start.
const (
	GatewayAPIBundleVersion = "v1.6.1"
	// GatewayAPIStandardInstallSHA256 is the GitHub release asset digest of
	// kubernetes-sigs/gateway-api v1.6.1 standard-install.yaml.
	GatewayAPIStandardInstallSHA256 = "24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73"
	// GatewayAPIStandardInstallNodePath is where lifecycle tooling delivers the
	// bundle on every control plane.
	GatewayAPIStandardInstallNodePath = "/var/lib/inspace/gateway-api-standard-install.yaml"

	gatewayAPIServerManifestPath = "/var/lib/rancher/rke2/server/manifests/inspace-gateway-api-crds.yaml"
	gatewayAPIDeliverySeconds    = 1800
)

//go:embed gateway-api/v1.6.1/standard-install.yaml
var gatewayAPIStandardInstall []byte

// GatewayAPIStandardInstall returns a copy of the pinned upstream bundle.
func GatewayAPIStandardInstall() []byte {
	return bytes.Clone(gatewayAPIStandardInstall)
}

// renderGatewayAPIServerManifestInstall waits for the delivered bundle, proves
// its exact digest, and stages it as an RKE2 server manifest. It runs before
// RKE2 starts on every control plane so all servers carry the same manifest.
// From RKE2 v1.37 the default rke2-gateway-api-crd chart installs the same
// v1.6.1 standard CRDs, so nothing is staged or awaited there.
func renderGatewayAPIServerManifestInstall(input CloudInitInput) string {
	if !input.GatewayAPI || v1alpha1.RKE2BundlesGatewayAPICRDs(input.RKE2Version) {
		return ""
	}
	return `gateway_api_bundle='` + GatewayAPIStandardInstallNodePath + `'
gateway_api_sha256='` + GatewayAPIStandardInstallSHA256 + `'
gateway_api_deadline=$(( $(date +%s) + ` + strconv.Itoa(gatewayAPIDeliverySeconds) + ` ))
until [ -f "$gateway_api_bundle" ] && [ "$(sha256sum "$gateway_api_bundle" | awk '{print $1}')" = "$gateway_api_sha256" ]; do
  if [ "$(date +%s)" -ge "$gateway_api_deadline" ]; then
    echo "Gateway API ` + GatewayAPIBundleVersion + ` bundle was not delivered to $gateway_api_bundle; copy the output of inspace-cluster-controller --print-gateway-api-crds there" >&2
    exit 1
  fi
  sleep 5
done
install -m 0600 "$gateway_api_bundle" ` + gatewayAPIServerManifestPath + `
`
}

// renderGatewayAPICiliumValues enables Cilium's Gateway API controller.
// gatewayClass.create is forced to "true" rather than "auto": the bundle is
// staged before RKE2 starts, and forcing it makes the chart fail and retry
// instead of silently omitting the cilium GatewayClass if the CRDs are ever
// missing when Helm renders.
func renderGatewayAPICiliumValues() string {
	return `    gatewayAPI:
      enabled: true
      gatewayClass:
        create: "true"
`
}
