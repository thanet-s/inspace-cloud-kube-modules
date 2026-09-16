module github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver

go 1.27.1

replace github.com/thanet-s/inspace-cloud-kube-modules/modules/client => ../client

require (
	github.com/container-storage-interface/spec v1.13.0
	github.com/thanet-s/inspace-cloud-kube-modules/modules/client v0.0.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260911204522-f61a6ca850bd // indirect
)
