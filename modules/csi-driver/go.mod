module github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver

go 1.26.5

replace github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider => ../cloud-provider

require (
	github.com/container-storage-interface/spec v1.12.0
	github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider v0.0.0
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.11
)

require (
	go.opentelemetry.io/otel/sdk/metric v1.43.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
)
