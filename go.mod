module docker-restore-iptables

go 1.20

require (
	github.com/docker/libnetwork v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.0
)

require (
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/docker/libkv v0.2.2-0.20180912205406-458977154600 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/ishidawataru/sctp v0.0.0-20210226210310-f2269e66cdee // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/net v0.6.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
	gotest.tools/v3 v3.5.0 // indirect
)

require (
	github.com/docker/distribution v2.8.1+incompatible
	github.com/docker/docker v0.0.0-20230504133305-5df983c7dbe2
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/vishvananda/netlink v1.1.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/sys v0.5.0 // indirect
)

replace github.com/docker/libnetwork => github.com/moby/libnetwork v0.0.0-20230724092029-67e0588f1ddf

replace github.com/docker/docker => github.com/moby/moby v0.0.0-20230504133305-5df983c7dbe2
