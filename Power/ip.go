package Power

/*
网络信息模块
功能：
1. 获取WAN IP(外网IP)
2. 获取MAC地址
3. 获取LAN IP(内网IP)
*/

import (
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
)

func GetWANIP() string {
	/*
		获取外网IP地址
		通过访问ipip.net获取
		返回: IP地址字符串或"None"
	*/
	responseClient, errClient := http.Get("http://myip.ipip.net") // 获取外网 IP
	if errClient != nil {
		return "None"
	}
	defer responseClient.Body.Close()
	body, _ := ioutil.ReadAll(responseClient.Body)
	myRegex, _ := regexp.Compile(`((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}`)
	found := myRegex.FindString(string(body))
	return found
}

func GetMacAddr() string {
	/*
		获取MAC地址
		返回: 第一个非空MAC地址或"None"
	*/
	var macAddrs []string
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return "None"
	}

	for _, netInterface := range netInterfaces {
		macAddr := netInterface.HardwareAddr.String()
		if len(macAddr) == 0 {
			continue
		}

		macAddrs = append(macAddrs, macAddr)
	}
	return macAddrs[0]
}

func GetLANIP() string {
	/*
		获取内网IP地址
		返回: 第一个非回环IPv4地址或"None"
	*/
	var ips []string
	interfaceAddr, err := net.InterfaceAddrs()
	if err != nil {
		return "None"
	}

	for _, address := range interfaceAddr {
		ipNet, isValidIpNet := address.(*net.IPNet)
		if isValidIpNet && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ips = append(ips, ipNet.IP.String())
			}
		}
	}
	return ips[0]
}
