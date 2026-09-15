module github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver

go 1.26.6

replace github.com/thanet-s/inspace-cloud-kube-modules/modules/client => ../client

require (
	github.com/container-storage-interface/spec v1.13.0
	github.com/thanet-s/inspace-cloud-kube-modules/modules/client v0.0.0
	google.golang.org/grpc v1.83.1
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.39.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)
