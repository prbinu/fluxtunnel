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

package fluxtunnel

import (
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Proxy packet type
const (
	PT_OPEN byte = iota + 1
	PT_OPEN_SUCCESS
	PT_OPEN_ERROR
	PT_SESSION
	PT_SESSION_ERROR
	PT_CLOSE
	PT_CLOSE_SUCCESS
	PT_CLOSE_ERROR
)

type Packet struct {
	Cmd     byte
	Id      int
	Channel string
	Buff    []byte
}

type channel struct {
	name        string
	addr        string
	open        chan *Packet
	openSuccess chan *Packet
	openError   chan *Packet
	err         chan string
}

type Conn struct {
	id         int
	channel    *channel
	proxy      *Proxy
	read       chan *Packet
	readError  chan *Packet
	close      chan bool
	peerClosed bool
}

type Proxy struct {
	isListener  bool
	conn        net.Conn
	listener    net.Listener
	address     string
	encoder     *gob.Encoder
	decoder     *gob.Decoder
	id          int // session counter
	mutx        sync.RWMutex
	pConn       map[int]*Conn
	aMutx       sync.RWMutex
	aChannels   map[string]*channel
	dChannels   map[string]*channel
	write       chan *Packet
	tlsConfig   *tls.Config
	isConnected bool
}

func ProxyDial(address string) (*Proxy, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}

	return proxyDial(address, conn, nil)
}

func ProxyDialTLS(address string, config *tls.Config) (*Proxy, error) {
	conn, err := tls.Dial("tcp", address, config)
	if err != nil {
		return nil, err
	}

	return proxyDial(address, conn, config)
}

func proxyDial(address string, conn net.Conn, config *tls.Config) (*Proxy, error) {
	p := new(Proxy)
	p.isListener = false
	p.address = address
	p.conn = conn
	p.encoder = gob.NewEncoder(conn)
	p.decoder = gob.NewDecoder(conn)
	p.pConn = make(map[int]*Conn)
	p.aChannels = make(map[string]*channel)
	p.dChannels = make(map[string]*channel)
	p.write = make(chan *Packet, 100)
	p.id = 0
	p.tlsConfig = config
	p.isConnected = true
	return p, nil
}

func ProxyListen(address string) (*Proxy, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}

	return proxyListen(address, listener, nil)
}

func ProxyListenTLS(address string, config *tls.Config) (*Proxy, error) {
	listener, err := tls.Listen("tcp", address, config)
	if err != nil {
		return nil, err
	}

	return proxyListen(address, listener, config)
}

func proxyListen(address string, listener net.Listener, config *tls.Config) (*Proxy, error) {
	conn, err := listener.Accept()
	if err != nil {
		return nil, err
	}

	p := new(Proxy)
	p.isListener = true
	p.listener = listener
	p.address = address
	p.conn = conn
	p.encoder = gob.NewEncoder(conn)
	p.decoder = gob.NewDecoder(conn)
	p.pConn = make(map[int]*Conn)
	p.aChannels = make(map[string]*channel)
	p.dChannels = make(map[string]*channel)
	p.write = make(chan *Packet)
	p.id = 0
	p.tlsConfig = config
	p.isConnected = true
	return p, nil
}

func (p *Proxy) AddSrcTarget(src, target string) {
	if _, ok := p.aChannels[target]; ok {
		log.Printf("Duplicate Listner channel, skipping...: %s\n", target)
		return
	}

	p.aChannels[target] = &channel{
		name:        target,
		addr:        src,
		open:        make(chan *Packet),
		openSuccess: make(chan *Packet),
		openError:   make(chan *Packet),
		err:         make(chan string),
	}
}

func (p *Proxy) AddTarget(target string) {
	if _, ok := p.dChannels[target]; ok {
		log.Printf("Duplicate Dialer channel, skipping...: %s\n", target)
		return
	}

	p.dChannels[target] = &channel{
		name:        target,
		addr:        target,
		open:        make(chan *Packet),
		openSuccess: make(chan *Packet),
		openError:   make(chan *Packet),
		err:         make(chan string),
	}
}

func (p *Proxy) Run() {
	var wg sync.WaitGroup

	go p.readLoop()
	go p.writeLoop()

	for _, ch := range p.aChannels {
		wg.Add(1)
		log.Printf("Listen: %s %s\n", ch.name, ch.addr)
		go p.listen(wg, ch)
	}

	for _, ch := range p.dChannels {
		wg.Add(1)
		log.Printf("Dialer: %s %s\n", ch.name, ch.addr)
		go p.dialer(wg, ch)
	}

	wg.Wait()
}

func (p *Proxy) Dial(ch *channel) (*Conn, error) {
	pkt := new(Packet)
	pkt.Cmd = PT_OPEN
	pkt.Id = -1
	pkt.Channel = ch.name
	pkt.Buff = []byte("PT_OPEN")
	err := p.Write(pkt)
	if err != nil {
		return nil, err
	}

	select {
	case pkt2 := <-ch.openSuccess:
		p.mutx.Lock()
		if _, ok := p.pConn[pkt2.Id]; !ok {
			p.pConn[pkt2.Id] = &Conn{
				id:         pkt2.Id,
				channel:    ch,
				proxy:      p,
				read:       make(chan *Packet),
				readError:  make(chan *Packet),
				close:      make(chan bool),
				peerClosed: false,
			}
		}
		p.mutx.Unlock()
		return p.pConn[pkt2.Id], nil

	case pkt2 := <-ch.openError:
		return nil, fmt.Errorf("%v", pkt2.Buff[:len(pkt2.Buff)])

	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("Dial TIMEOUT CLOSE>>>: %s", ch.name)
	}

	// create conn, and return
}

func (p *Proxy) Accept(ch *channel) (*Conn, error) {
	select {
	case pkt := <-ch.open:
		// TODO need to validate by comparing pkt.channel with ch.name?
		log.Printf("Listner: %v Accept OPEN: %c, %d, %s", p.isListener, pkt.Cmd, pkt.Id, pkt.Channel)
		p.mutx.Lock()
		p.id++
		if _, ok := p.pConn[p.id]; !ok {
			p.pConn[p.id] = &Conn{
				id:         p.id,
				channel:    ch,
				proxy:      p,
				read:       make(chan *Packet),
				readError:  make(chan *Packet),
				close:      make(chan bool),
				peerClosed: false,
			}
		}
		p.mutx.Unlock()
		return p.pConn[p.id], nil

	case pkt := <-ch.openError:
		return nil, fmt.Errorf("%v", pkt.Buff[:len(pkt.Buff)])
	}

	return nil, fmt.Errorf("Accept Unknown Error: %s", ch.name)
}

func (p *Proxy) dialer(wg sync.WaitGroup, ch *channel) {

	for {
		client, err := p.Accept(ch)
		if err != nil {
			log.Printf("dialer Aceept error: %v", err)
			return
		}

		pkt := &Packet{Id: client.id, Channel: ch.name}

		server, err := net.Dial("tcp", ch.addr)
		if err != nil {
			log.Printf("dialer Dial error: %v", err)
			pkt.Cmd = PT_OPEN_ERROR
			pkt.Buff = []byte("PT_OPEN_ERROR")
			err := p.Write(pkt)
			if err != nil {
				log.Println(err)
			}

			p.mutx.Lock()
			delete(p.pConn, client.id)
			p.mutx.Unlock()
			continue
		}

		pkt.Cmd = PT_OPEN_SUCCESS
		pkt.Buff = []byte("PT_OPEN_SUCCESS")
		err = p.Write(pkt)
		if err != nil {
			log.Println(err)
			continue
		}

		go func() {
			stop1 := make(chan bool)
			//stop2 := make(chan bool)
			go relay(client, server, stop1, "Peer2Conn-1")
			go relay(server, client, stop1, "Peer2Conn-2")

			<-stop1
			//<-stop2
			p.mutx.Lock()
			delete(p.pConn, client.id)
			p.mutx.Unlock()
			return
		}()
	}
}

func (p *Proxy) listen(wg sync.WaitGroup, ch *channel) {
	defer wg.Done()

	l, err := net.Listen("tcp", ch.addr)
	if err != nil {
		log.Println(err)
		return
	}

	for {
		client, err := l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		server, err := p.Dial(ch)
		if err != nil {
			log.Println(err)
			continue
		}

		go func() {
			stop := make(chan bool)
			go relay(client, server, stop, "Peer1Conn-1")
			go relay(server, client, stop, "Peer1Conn-2")

			select {
			case <-stop:
				p.mutx.Lock()
				delete(p.pConn, server.id)
				p.mutx.Unlock()
				return //continue
			}
		}()

		log.Printf("Peer1Conn completed\n")
	}
}

func relay(src net.Conn, dst net.Conn, stop chan<- bool, typ string) {
	if n, err := io.Copy(dst, src); err != nil {
		if err != nil {
			log.Println(err, n, typ)
		}
	}

	dst.Close()
	src.Close()
	stop <- true
	return
}

func (p *Proxy) Close() {

}

func (p *Proxy) Write(pkt *Packet) error {
	p.write <- pkt
	return nil
}

func (p *Proxy) getChannelConn(channel string) *channel {
	if session, ok := p.aChannels[channel]; ok {
		return session
	}

	if session, ok := p.dChannels[channel]; ok {
		return session
	}

	return nil
}

func (p *Proxy) writeLoop() {
	for {
		select {
		case pkt := <-p.write:
			p.encoder.Encode(pkt)
		}
	}
}

func (p *Proxy) reConnect() error {
	p.mutx.Lock()
	defer p.mutx.Unlock()

	if p.isConnected {
		return nil
	}

	var err error
	err = nil
	for i := 0; i < 4; i++ {
		var conn net.Conn
		if p.isListener {
			conn, err = p.listener.Accept()
		} else {
			if p.tlsConfig != nil {
				conn, err = tls.Dial("tcp", p.address, p.tlsConfig)
			} else {
				conn, err = net.Dial("tcp", p.address)
			}
		}
		if err != nil {
			log.Println(err)
			time.Sleep(time.Duration((i+1)*2) * time.Second)
			continue
		}

		p.conn = conn
		p.encoder = gob.NewEncoder(conn)
		p.decoder = gob.NewDecoder(conn)
		p.isConnected = true
		err = nil
		break
	}

	return err
}

func (p *Proxy) readLoop() {
	for {
		pkt := new(Packet)
		err := p.decoder.Decode(pkt)
		if err != nil {
			log.Printf("READ ERR: %v", err)
			p.mutx.Lock()
			p.isConnected = false
			p.mutx.Unlock()
			err := p.reConnect()
			if err != nil {
				// TODO should this be fatal?
				log.Fatal(err)
			}
		}
		switch pkt.Cmd {
		case PT_OPEN:
			session := p.getChannelConn(pkt.Channel)
			if session != nil {
				session.open <- pkt
			} else { /* TODO send err msg to peer*/
			}

		case PT_OPEN_SUCCESS:
			session := p.getChannelConn(pkt.Channel)
			if session != nil {
				session.openSuccess <- pkt
			} else { /* TODO send err msg to peer*/
			}

		case PT_OPEN_ERROR:
			session := p.getChannelConn(pkt.Channel)
			if session != nil {
				session.openError <- pkt
			} else { /* TODO send err msg to peer*/
			}
		case PT_SESSION:
			conn, ok := p.pConn[pkt.Id]
			if ok {
				conn.read <- pkt
			} else { /* TODO send err msg to peer*/
				pkt2 := new(Packet)
				pkt2.Cmd = PT_SESSION_ERROR
				pkt2.Id = pkt.Id
				pkt2.Channel = pkt.Channel
				pkt2.Buff = []byte("PT_SESSION_ERROR: No session exists")
				err := p.Write(pkt2)
				if err != nil {
					log.Printf("Listner: %v, PT_SESSION WRITE ERROR: %v", p.isListener, err)
				}
			}
		case PT_SESSION_ERROR:
			log.Printf("Pkt: PT_SESSION_ERROR\n")
			conn, ok := p.pConn[pkt.Id]
			if ok {
				conn.readError <- pkt
			} else { /* TODO send err msg to peer*/
				log.Printf("Pkt: PT_SESSION_ERROR NOT FOUND: (%d) id:%d\n", len(pkt.Buff), pkt.Id)
			}
		case PT_CLOSE:
			conn, ok := p.pConn[pkt.Id]
			if ok {
				conn.close <- true
			} else { /* TODO send err msg to peer*/
				log.Printf("Pkt: PT_CLOSE NOT FOUND: (%d) id:%d\n", len(pkt.Buff), pkt.Id)
			}
		case PT_CLOSE_SUCCESS:
			conn, ok := p.pConn[pkt.Id]
			if ok {
				conn.close <- true
			} else { /* TODO send err msg to peer */
				log.Printf("Pkt: PT_CLOSE_SUCCESS NOT FOUND: (%d) id:%d\n", len(pkt.Buff), pkt.Id)
			}
		case PT_CLOSE_ERROR:
			log.Printf("Pkt: PT_CLOSE_ERROR\n")
			conn, ok := p.pConn[pkt.Id]
			if ok {
				conn.readError <- pkt
			} else { /* TODO send err msg to peer*/
				log.Printf("Pkt: PT_CLOSE_ERROR NOT FOUND: (%d) id:%d\n", len(pkt.Buff), pkt.Id)
			}
		}
	}
}

// net.Conn interface
// Read reads data from the connection.
func (c *Conn) Read(b []byte) (int, error) {

	select {
	case pkt := <-c.read:
		copy(b, pkt.Buff[:len(pkt.Buff)])
		//log.Printf("Listner: %v, READ: (%d) CMD: %d, %d, %s", c.proxy.isListener, len(pkt.Buff), pkt.Cmd, pkt.Id, pkt.Channel)
		return len(pkt.Buff), nil
	case pkt := <-c.readError:
		c.peerClosed = true
		//log.Printf("Listner: %v READ_ERROR: %c, %d, %s", c.proxy.isListener, pkt.Cmd, pkt.Id, pkt.Channel)
		return -1, fmt.Errorf("CLOSE>>>: %s", pkt.Buff[:len(pkt.Buff)])
	case <-c.close:
		c.peerClosed = true
		//log.Printf("Listner: %v READ_CLOSE: %s %s", c.proxy.isListener, c.channel.name, c.channel.addr)
		return 0, fmt.Errorf("CLOSE>>>: %s", c.channel)
	}
}

// Write writes data to the connection.
func (c *Conn) Write(b []byte) (int, error) {
	pkt := new(Packet)
	pkt.Cmd = PT_SESSION
	pkt.Id = c.id
	pkt.Channel = c.channel.name
	pkt.Buff = make([]byte, len(b))
	copy(pkt.Buff, b)

	err := c.proxy.Write(pkt)
	if err != nil {
		log.Printf("Listner: %v, WRITE ERROR: %v", c.proxy.isListener, err)
		return -1, err
	}
	return len(b), err
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *Conn) Close() error {
	if c.peerClosed {
		return nil
	}

	pkt := new(Packet)
	pkt.Cmd = PT_CLOSE
	pkt.Id = c.id
	pkt.Channel = c.channel.name
	pkt.Buff = []byte("PT_CLOSE")
	err := c.proxy.Write(pkt)

	return err
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.proxy.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.proxy.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
// *Unused
func (c *Conn) SetDeadline(t time.Time) error {
	//return c.conn.SetDeadline(t)
	return nil
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
// *Unused
func (c *Conn) SetReadDeadline(t time.Time) error {
	//return c.conn.SetReadDeadline(t)
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// *Unused
func (c *Conn) SetWriteDeadline(t time.Time) error {
	//return c.conn.SetWriteDeadline(t)
	return nil
}
