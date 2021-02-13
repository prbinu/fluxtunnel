/*
Copyright (c) 2021,  NVIDIA CORPORATION

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/prbinu/fluxtunnel"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

var versionNumber, releaseDate string

func server(args []string) {
	server := flag.NewFlagSet("server", flag.ExitOnError)
	var listen, tlsCertFile, tlsPrivateKeyFile, logDir, tlsClientCACertFile, src, target string
	server.StringVar(&listen, "listen", ":8010", "Proxy listening ip:port; format: [ip]:port")
	server.StringVar(&src, "source", "", "Proxy source port-forwarding (listening) ip:port; format: [ip]:port")
	server.StringVar(&target, "target", "", "The target endpoint, proxied through fluxtunnel client; format: ip:port or host:port")
	server.StringVar(&tlsCertFile, "tls-cert-file", "", "TLS X.509 server (proxy) certificate")
	server.StringVar(&tlsPrivateKeyFile, "tls-key-file", "", "TLS server (proxy) private key")
	server.StringVar(&logDir, "log-dir", "", "Directory where the fluxtunnel log file resides (default: logs to stderr)")
	server.StringVar(&tlsClientCACertFile, "tls-client-cacert-file", "", "TLS X.509 client root CA certificate")
	server.SetOutput(os.Stdout)
	server.Usage = func() {
		server.PrintDefaults()
		os.Exit(0)
	}
	server.Parse(args)

	if len(src) == 0 && len(target) == 0 {
		if len(src) == 0 {
			fmt.Fprintf(os.Stderr, "error: missing parameter: -target (or -source)\n")
			os.Exit(2)
		}
	}

	if len(logDir) > 0 {
		fp, err := os.OpenFile(logDir+"/fluxtunnel.log", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to create log file in: %s\n", logDir)
			os.Exit(2)
		}

		log.SetOutput(fp)
	}

	cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsPrivateKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	caCert, err := ioutil.ReadFile(tlsClientCACertFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
	}
	tlsConfig.BuildNameToCertificate()

	p, err := fluxtunnel.ProxyListenTLS(listen, tlsConfig)
	if err != nil {
		fmt.Println(err)
		return
	}

	if len(src) > 0 && len(target) > 0 {
		p.AddSrcTarget(src, target)
	} else if len(target) > 0 {
		p.AddTarget(target)
	} else {
		fmt.Fprintf(os.Stderr, "error: missing -target field\n")
	}

	p.Run()
}

func client(args []string) {

	client := flag.NewFlagSet("client", flag.ExitOnError)
	var connect, tlsCertFile, tlsPrivateKeyFile, logDir, tlsServerCACertFile, tlsServerName, target string
	client.StringVar(&connect, "connect", "127.0.0.1:8010", "Target fluxtunnel ip:port; format: [ip]:port")
	//client.StringVar(&src, "source", "", "Proxy source port-forwarding (listening) ip:port; format: [ip]:port")
	client.StringVar(&target, "target", "", "The target endpoint; format: ip:port or host:port")
	client.StringVar(&tlsCertFile, "tls-cert-file", "", "TLS X.509 client (proxy) certificate")
	client.StringVar(&tlsPrivateKeyFile, "tls-key-file", "", "TLS client (proxy) private key")
	client.StringVar(&logDir, "log-dir", "", "Directory where the fluxtunnel log file resides (default: logs to stderr)")
	client.StringVar(&tlsServerCACertFile, "tls-server-cacert-file", "", "TLS X.509 client root CA certificate")
	client.StringVar(&tlsServerName, "tls-server-name", "", "Name (CNAME/SAN) to match in the Server TLS X.509 certificate")
	client.SetOutput(os.Stdout)
	client.Usage = func() {
		client.PrintDefaults()
		os.Exit(0)
	}
	client.Parse(args)

	if len(target) == 0 {
		fmt.Fprintf(os.Stderr, "error: missing parameter: -target\n")
		os.Exit(2)
	}

	if len(logDir) > 0 {
		fp, err := os.OpenFile(logDir+"/fluxtunnel.log", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to create log file in: %s\n", logDir)
			os.Exit(2)
		}

		log.SetOutput(fp)
	}

	cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsPrivateKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	caCert, err := ioutil.ReadFile(tlsServerCACertFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	if len(tlsServerName) == 0 {
		s := strings.Split(connect, ":")
		if len(s[0]) == 0 {
			fmt.Fprintf(os.Stderr, "Error: missing field: `-tls-server-name`\n")
			os.Exit(1)
		}

		tlsServerName = s[0]
	}

	TLSClientConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
		ServerName:   tlsServerName,
	}
	time.Sleep(2 * time.Second)
	p, err := fluxtunnel.ProxyDialTLS(connect, TLSClientConfig)
	if err != nil {
		fmt.Println(err)
		return
	}

	p.AddTarget(target)
	p.Run()
}

func main() {
	if len(os.Args) == 1 {
		fmt.Fprintln(os.Stderr, "Usage: fluxtunnel <command> [-h] [<args>]")
		fmt.Fprintln(os.Stderr, "The commands are: ")
		fmt.Fprintln(os.Stderr, " server    Configure fluxtunnel as client")
		fmt.Fprintln(os.Stderr, " client    Configure fluxtunnel as client")
		fmt.Fprintln(os.Stderr, " version   Display version information and exit")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		server(os.Args[2:])

	case "client":
		client(os.Args[2:])

	case "version":
		fmt.Printf("fluxtunnel %s %s/%s %s\n", versionNumber, runtime.GOOS, runtime.GOARCH, releaseDate)
		os.Exit(0)

	default:
		os.Exit(0)
	}

}
