package main

import (
	"bytes"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	ips := ""
	apPassword := ""
	apUsername := ""
	apPort := ""
	flag.StringVar(&ips, "ips", "192.168.1.1-192.168.1.255,192.168.2.1-192.168.2.255,192.168.3.1-192.168.3.255,192.168.4.1-192.168.4.255,192.168.6.1-192.168.6.255,192.168.10.1-192.168.10.255", "scan ips , eg : 192.168.1.1-192.168.1.255,192.168.2.1-192.168.2.255")
	flag.StringVar(&apPassword, "apPassword", "4rfvG^yhn", "ap password")
	flag.StringVar(&apUsername, "apUsername", "root", "ap username")
	flag.StringVar(&apPort, "apPort", "22", "ap port")
	flag.Parse()
	ipArr := strings.Split(ips, ",")
	s := &APScanner{
		IPArr:      ipArr,
		APPassword: apPassword,
		APUsername: apUsername,
		APPort:     apPort,
	}
	s.Scan()
}

type APScanner struct {
	IPArr      []string
	APPassword string
	APUsername string
	APPort     string
	sync.WaitGroup
}

func (s *APScanner) Scan() {
	ch := make(chan int, 1)
	go func() {
		for {
			select {
			case <-ch:
				fmt.Println("scan end !")
			case <-time.After(300 * time.Second):
				fmt.Println("scan end , timeout !")
				os.Exit(-1)
			}
		}
	}()
	fmt.Println("scan start !")
	for _, ip := range s.IPArr {
		s.scanIp(ip)
	}
	s.Wait()
	ch <- 1

}

var i int

func (s *APScanner) scanIp(ip string) {
	isRangeIp := false
	var (
		startIp, endIp IP
	)
	ipRange := strings.Split(ip, "-")
	if len(ipRange) >= 2 {
		startIp = IP(ipRange[0])
		endIp = IP(ipRange[1])
		isRangeIp = true
	}
	if isRangeIp {
		ip := &startIp
		s.scanIp(string(*ip))
		for ip.NextIP(&endIp) {
			s.scanIp(string(*ip))
		}
		return
	}
	s.Add(1)
	go func() {
		defer func() {
			if err := recover(); err != nil {
				fmt.Println(err)
			}
		}()
		i++
		if i > 10000 {
			panic("too many ip")
		}
		defer s.Done()
		ap := &AP{
			IP:          ip,
			SSHPassword: s.APPassword,
			SSHUsername: s.APUsername,
			SSHPort:     s.APPort,
		}
		if ap.IsAPAvailable() {
			fmt.Printf("%-18v%-30v%-20v%-20v%-10v%-30v%-15v\n", ap.IP, ap.getDeviceModel(), ap.getMAC(), ap.getSN(), ap.getMode(), ap.getModeAddr(), ap.getVersion())
		}
	}()

}

/*
    Company Name:HAN Networks Co., Ltd.
              SN:WKS172101044
    Device Model:TopAP 8000 TAP-42200
             MAC:00:13:32:10:41:30
         Country:CN
   Software Name:HOS
Software Version:3.0.6
Hardware Version:1.10
              Oid:1.3.6.1.4.1.47030
 License Control:110101101
    Essid Prefix:mywifi
Cluster Describe:HAP cluster
         Website:www.han-networks.com
         Cspsite:haptocloud.han-networks.com
           Legal:All Rights Reserved © 2017,HAN Networks Co., Ltd.
Product Platform:HAN CLOUD
*/
type AP struct {
	IP          string
	SSHPassword string
	SSHUsername string
	SSHPort     string
	systemInfo  map[string]interface{}
	version     string
	mode        string
	modeAddr    string

	systemInfoOnce sync.Once
	versionOnce    sync.Once
	modeOnce       sync.Once
	modeAddrOnce   sync.Once

	available     bool
	availableOnce sync.Once
}

func (ap *AP) initSystemInfo() {

	ap.systemInfoOnce.Do(func() {
		var stdOut, stdErr bytes.Buffer
		session, err := sshConnect(ap.SSHUsername, ap.SSHPassword, ap.IP, ap.SSHPort)
		if err != nil {

		}
		defer session.Close()

		session.Stdout = &stdOut
		session.Stderr = &stdErr

		err = session.Run("showsysinfo")
		if err != nil {
			//log.Println(err)
		}
		ap.systemInfo = parseStr2Map(stdOut.String())
	})

}

func parseStr2Map(s string) (m map[string]interface{}) {
	m = map[string]interface{}{}
	infos := strings.Split(s, "\n")
	for _, info := range infos {
		info := strings.Replace(info, ":", "&", 1)
		i := strings.Split(info, "&")
		if len(i) >= 2 {
			m[strings.Trim(i[0], " ")] = strings.Trim(i[1], " ")
		}
	}
	return m
}
func (ap *AP) IsAPAvailable() (available bool) {
	ap.availableOnce.Do(func() {
		ap.available = true
		session, err := sshConnect(ap.SSHUsername, ap.SSHPassword, ap.IP, ap.SSHPort)
		if err != nil {
			ap.available = false
		}
		if session != nil {
			defer session.Close()
		}
	})
	return ap.available
}
func (ap *AP) getMAC() (mac string) {
	ap.initSystemInfo()
	return ap.systemInfo["MAC"].(string)
}
func (ap *AP) getDeviceModel() (deviceModel string) {
	ap.initSystemInfo()
	return ap.systemInfo["Device Model"].(string)
}

func (ap *AP) getSN() (sn string) {
	ap.initSystemInfo()
	return ap.systemInfo["SN"].(string)
}

func (ap *AP) initVersion() {
	ap.versionOnce.Do(func() {
		var stdOut, stdErr bytes.Buffer
		session, err := sshConnect(ap.SSHUsername, ap.SSHPassword, ap.IP, ap.SSHPort)
		if err != nil {
			//log.Fatal(err)
		}
		defer session.Close()

		session.Stdout = &stdOut
		session.Stderr = &stdErr

		err = session.Run("showver")
		if err != nil {
			//log.Println(err)
		}
		ap.version = strings.ReplaceAll(stdOut.String(), "\n", "")
	})

}

func (ap *AP) getVersion() (version string) {
	ap.initVersion()
	return ap.version
}

func (ap *AP) initMode() {
	ap.modeOnce.Do(func() {
		var stdOut, stdErr bytes.Buffer
		session, err := sshConnect(ap.SSHUsername, ap.SSHPassword, ap.IP, ap.SSHPort)
		if err != nil {
			//log.Fatal(err)
		}
		defer session.Close()

		session.Stdout = &stdOut
		session.Stderr = &stdErr

		err = session.Run("getmode")
		if err != nil {
			//log.Println(err)
		}
		ap.mode = strings.ReplaceAll(stdOut.String(), "\n", "")
	})

}

func (ap *AP) getModeAddr() (version string) {
	ap.initModeAddr()
	return ap.modeAddr
}
func (ap *AP) initModeAddr() {
	ap.modeAddrOnce.Do(func() {
		var stdOut, stdErr bytes.Buffer
		session, err := sshConnect(ap.SSHUsername, ap.SSHPassword, ap.IP, ap.SSHPort)
		if err != nil {
			//log.Fatal(err)
		}
		defer session.Close()

		session.Stdout = &stdOut
		session.Stderr = &stdErr

		err = session.Run("getmodeaddr")
		if err != nil {
			//log.Println(err)
		}
		ap.modeAddr = strings.ReplaceAll(stdOut.String(), "\n", "")
	})

}

func (ap *AP) getMode() (version string) {
	ap.initMode()
	return ap.mode
}
func sshConnect(user, password, host, port string) (*ssh.Session, error) {
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		client       *ssh.Client
		session      *ssh.Session
		err          error
	)
	// get auth method
	auth = make([]ssh.AuthMethod, 0)
	auth = append(auth, ssh.Password(password))

	hostKeyCallbk := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return nil
	}

	clientConfig = &ssh.ClientConfig{
		User: user,
		Auth: auth,
		// Timeout:             30 * time.Second,
		HostKeyCallback: hostKeyCallbk,
	}

	// connet to ssh
	addr = fmt.Sprintf("%s:%v", host, port)

	if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return nil, err
	}

	// create session
	if session, err = client.NewSession(); err != nil {
		return nil, err
	}

	return session, nil
}

type IP string

func (i *IP) ParseIP(ipStr string) {
	*i = IP(net.ParseIP(ipStr))
}

// 1,0,-1 > = <
func (i *IP) Eq(ip *IP) (r int64) {
	ip1s := strings.Split(string(*i), ".")
	ip2s := strings.Split(string(*ip), ".")

	r = eq(ip1s[0], ip2s[0])
	if r != 0 {
		return r
	}

	r = eq(ip1s[1], ip2s[1])
	if r != 0 {
		return r
	}
	r = eq(ip1s[2], ip2s[2])
	if r != 0 {
		return r
	}
	r = eq(ip1s[3], ip2s[3])
	if r != 0 {
		return r
	}
	return 0
}
func eq(a, b string) (r int64) {
	ai, _ := strconv.ParseInt(a, 10, 64)
	bi, _ := strconv.ParseInt(b, 10, 64)
	if ai > bi {
		return 1
	} else if ai < bi {
		return -1
	}
	return 0
}
func (i *IP) NextIP(maxIP *IP) (success bool) {
	r := i.Eq(maxIP)
	if r == 0 || r > 0 {
		return false
	}

	ip1s := strings.Split(string(*i), ".")
	ip13, _ := strconv.ParseInt(ip1s[3], 10, 64)
	if ip13 != 255 {
		ip13 += 1
		ip1s[3] = fmt.Sprint(ip13)
		*i = IP(strings.Join(ip1s, "."))
		return true
	}
	ip12, _ := strconv.ParseInt(ip1s[2], 10, 64)
	if ip12 != 255 {
		ip12 += 1
		ip13 = 1
		ip1s[2] = fmt.Sprint(ip12)
		ip1s[3] = fmt.Sprint(ip13)
		*i = IP(strings.Join(ip1s, "."))
		return true
	}
	ip11, _ := strconv.ParseInt(ip1s[1], 10, 64)
	if ip11 != 255 {
		ip11 += 1
		ip13 = 1
		ip12 = 1
		ip1s[1] = fmt.Sprint(ip11)
		ip1s[2] = fmt.Sprint(ip12)
		ip1s[3] = fmt.Sprint(ip13)
		*i = IP(strings.Join(ip1s, "."))
		return true
	}
	ip10, _ := strconv.ParseInt(ip1s[0], 10, 64)
	if ip10 != 255 {
		ip10 += 1
		ip11 = 1
		ip13 = 1
		ip12 = 1
		ip1s[0] = fmt.Sprint(ip10)
		ip1s[1] = fmt.Sprint(ip11)
		ip1s[2] = fmt.Sprint(ip12)
		ip1s[3] = fmt.Sprint(ip13)
		*i = IP(strings.Join(ip1s, "."))
		return true
	}
	return false
}
