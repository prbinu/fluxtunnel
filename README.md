# fluxtunnel

A reverse direction TLS proxy

```
+------+         +------------------+    mTLS   +------------------+        +------+ 
|client| ------> | fluxtunnel server| <======== | fluxtunnel client|------> |target|
+------+         +------------------+   tunnel  +------------------+        +------+
```

**Purpose:**
To expose services inside private networks (behind firewalls)

Example use cases: share your local desktop, terminal or web applications over Internet to customer, partner or coworker

## Usage

### Build

```bash
git clone https://github.com/prbinu/fluxtunnel.git
cd fluxtunnel/cmd/fluxtunnel
# Mac:
make darwin
# Linux 
make linux
# Windows
go build -o fluxtunnel.exe main.go
```

### Example

To access a NoVNC (docker container)  hosted on a localhost:

```bash
# start a noVNC docker contiainer (for testing only)
docker run -p 6080:80 centminmod/docker-ubuntu-vnc-desktop

# Server on terminal 1:
./fluxtunnel server -listen 127.0.0.1:6445 -tls-cert-file ../../test/server.crt -tls-key-file ../../test/server.key -tls-client-cacert-file ../../test/server.crt  -source :6123 -target :6080

# Client on terminal 2:
./fluxtunnel client -connect 127.0.0.1:6445 -tls-cert-file ../../test/server.crt -tls-key-file ../../test/server.key -tls-server-cacert-file ../../test/server.crt -tls-server-name proxy.conduit.local -target :6080

```

To access VNC in browser, visit:
http://127.0.0.1:6123

To expose a local terminal, try `fluxtunnel` with [gotty](https://github.com/yudai/gotty):

```bash
gotty -p 6080 -w bash
```

