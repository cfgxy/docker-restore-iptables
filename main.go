package main

import (
	"fmt"
	"github.com/docker/distribution/context"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/plugingetter"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/drivers/bridge"
	"github.com/docker/libnetwork/iptables"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/options"
	"github.com/sirupsen/logrus"
	"net"
	"strconv"
	"strings"
)

const DockerUserChain = "DOCKER-USER"

//var strHostIP *string

type DrvRegistry struct {
	driverapi.DriverCallback
}

type networkInfo struct {
	driverapi.NetworkInfo
}

func main() {
	//strHostIP = flag.String("host", "", "IP address of host")
	//
	//flag.Usage = func() {
	//	fmt.Println("Usage: docker-restore-iptables -host <host-ip>")
	//}
	//flag.Parse()

	r := &DrvRegistry{}
	data := make(options.Generic)
	data["EnableIPForwarding"] = true
	data["EnableIPTables"] = true
	data["EnableIP6Tables"] = true
	data["EnableUserlandProxy"] = true
	data["UserlandProxyPath"] = "/usr/local/bin/docker-proxy"

	cfg := make(map[string]interface{})
	cfg[netlabel.GenericData] = data

	bridge.Init(r, cfg)
}

func (r *DrvRegistry) GetPluginGetter() plugingetter.PluginGetter {
	return nil
}

func (r *DrvRegistry) RegisterDriver(name string, driver driverapi.Driver, capability driverapi.Capability) error {
	ctx := context.Background()
	cli, _ := client.NewClientWithOpts()
	networks, _ := cli.NetworkList(ctx, types.NetworkListOptions{})

	//if *strHostIP == "" {
	//	hostIPs := DetectHostIPs(GetBridgeNames(networks))
	//	if len(hostIPs) == 0 {
	//		return fmt.Errorf("No host IP found")
	//	}
	//	if len(hostIPs) > 1 {
	//		msg := "Multiple host IPs found, please specify one"
	//		for _, hostIP := range hostIPs {
	//			msg += "\n" + hostIP
	//		}
	//		return fmt.Errorf(msg)
	//	}
	//	*strHostIP = hostIPs[0]
	//}
	//
	var hostIP net.IP
	//if *strHostIP != "nil" {
	//	hostIP = net.ParseIP(*strHostIP)
	//} else {
	//	hostIP = nil
	//}
	hostIP = nil

	fullNetworks := make([]types.NetworkResource, len(networks))
	for i, ne := range networks {
		fullNetworks[i], _ = cli.NetworkInspect(ctx, ne.ID, types.NetworkInspectOptions{})
		ne = fullNetworks[i]
		bridgeName := getBridgeNameOfNetwork(ne)
		if bridgeName == "" {
			continue
		}

		_, subnet, _ := net.ParseCIDR(ne.IPAM.Config[0].Subnet)
		gw := *subnet
		gw.IP = net.ParseIP(ne.IPAM.Config[0].Gateway)

		data := make(options.Generic)
		data["ID"] = ne.ID
		data["BridgeName"] = bridgeName
		data["EnableIPv6"] = false
		data["EnableIPMasquerade"] = true
		data["Internal"] = ne.Internal
		data["EnableICC"] = true
		data["AddressIPv4"] = subnet
		data["DefaultGatewayIPv4"] = gw.IP
		if hostIP != nil {
			data["HostIP"] = hostIP
		}

		strMtu, ok := ne.Options[netlabel.DriverMTU]
		if ok {
			mtu, _ := strconv.Atoi(strMtu)
			data["Mtu"] = mtu
		}

		strIcc, ok := ne.Options[netlabel.Prefix+".bridge.enable_icc"]
		if ok {
			icc, _ := strconv.ParseBool(strIcc)
			data["EnableICC"] = icc
		}

		strDefaultBridge, ok := ne.Options[netlabel.Prefix+".bridge.default_bridge"]
		if ok {
			defaultBridge, _ := strconv.ParseBool(strDefaultBridge)
			data["DefaultBridge"] = defaultBridge
		}

		strEnableIpMasq, ok := ne.Options[netlabel.Prefix+".bridge.enable_ip_masquerade"]
		if ok {
			enableIpMasq, _ := strconv.ParseBool(strEnableIpMasq)
			data["EnableIPMasquerade"] = enableIpMasq
		}

		cfg := make(map[string]interface{})
		cfg[netlabel.GenericData] = data

		fmt.Println("Restoring network", ne.Name, "with subnet", subnet, "and interface", bridgeName)
		err := driver.CreateNetwork(
			ne.ID,
			cfg,
			&networkInfo{},
			[]driverapi.IPAMData{
				{
					Pool:    subnet,
					Gateway: &gw,
				},
			},
			[]driverapi.IPAMData{},
		)
		if err != nil {
			logrus.Error(err)
		}
	}

	ArrangeUserFilterRule()

	for _, ne := range fullNetworks {
		for containerId, con := range ne.Containers {
			cfg := &network.EndpointSettings{
				IPAMConfig: &network.EndpointIPAMConfig{
					IPv4Address: strings.Split(con.IPv4Address, "/")[0],
				},
			}

			if ne.Name == "bridge" {
				cfg.IPAMConfig = &network.EndpointIPAMConfig{}
			}

			fmt.Println("Restoring container", con.Name, "with IP", con.IPv4Address, "in network", ne.Name)
			err := cli.NetworkDisconnect(ctx, ne.ID, containerId, true)
			if err == nil {
				err2 := cli.NetworkConnect(ctx, ne.ID, containerId, cfg)
				if err2 != nil {
					fmt.Println("Retry connect container", con.Name, "with dynamic IP in network", ne.Name)
					logrus.Error(err2)
					cfg.IPAMConfig = &network.EndpointIPAMConfig{}
					err3 := cli.NetworkConnect(ctx, ne.ID, containerId, cfg)
					if err3 != nil {
						logrus.Error(err3)
					}
				}
			} else {
				logrus.Error(err)
			}
		}
	}
	return nil
}

func getBridgeNameOfNetwork(network types.NetworkResource) string {
	var bridgeName string
	if network.Name == "host" {
		return ""
	} else if network.Name == "none" {
		return ""
	} else {
		if network.Options["com.docker.network.bridge.name"] != "" {
			bridgeName = network.Options["com.docker.network.bridge.name"]
		} else {
			bridgeName = "br-" + network.ID[:12]
		}
	}
	return bridgeName
}

func ArrangeUserFilterRule() {
	ipVer := iptables.IPv4
	iptable := iptables.GetIptable(ipVer)
	_, err := iptable.NewChain(DockerUserChain, iptables.Filter, false)
	if err != nil {
		logrus.WithError(err).Warnf("Failed to create %s %v chain", DockerUserChain, ipVer)
		return
	}

	if err = iptable.AddReturnRule(DockerUserChain); err != nil {
		logrus.WithError(err).Warnf("Failed to add the RETURN rule for %s %v", DockerUserChain, ipVer)
		return
	}

	err = iptable.EnsureJumpRule("FORWARD", DockerUserChain)
	if err != nil {
		logrus.WithError(err).Warnf("Failed to ensure the jump rule for %s %v", DockerUserChain, ipVer)
	}
}

//func GetBridgeNames(networks []types.NetworkResource) (bridgeNames []string) {
//	bridgeNames = make([]string, len(networks))
//	for i, network := range networks {
//		bridgeNames[i] = getBridgeNameOfNetwork(network)
//	}
//	return
//}

//func contains(s []string, e string) bool {
//	for _, a := range s {
//		if a == e {
//			return true
//		}
//	}
//
//	return false
//}

//func DetectHostIPs(ignoreInterfaces []string) (hostIPs []string) {
//	interfaces, _ := net.Interfaces()
//	hostIPs = make([]string, 0)
//	for _, i := range interfaces {
//		if i.Flags&net.FlagUp == 0 {
//			continue // interface down
//		}
//		if i.Flags&net.FlagLoopback != 0 {
//			continue // loopback interface
//		}
//		if i.Flags&net.FlagPointToPoint != 0 {
//			continue // point-to-point interface
//		}
//		if strings.Contains(i.Name, "docker") {
//			continue // docker interface
//		}
//		if contains(ignoreInterfaces, i.Name) {
//			continue
//		}
//		addrs, _ := i.Addrs()
//		for _, addr := range addrs {
//			var ip net.IP
//			switch v := addr.(type) {
//			case *net.IPNet:
//				ip = v.IP
//			case *net.IPAddr:
//				ip = v.IP
//			}
//
//			if ip.To4() != nil {
//				hostIPs = append(hostIPs, ip.String())
//			}
//		}
//	}
//	return
//}
