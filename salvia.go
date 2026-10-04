package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	TOKEN         = ""
	GUILD_ID      = "1544968686291652608"
	DISCORD_HOST  = "canary.discord.com"
	DISCORD_IP    = "162.159.135.232"
	SESSION_COUNT = 12
	SUPER_PROPS   = "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzQ1Njc4LCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUifQ=="
	WS_KEY        = "dGhlIHNhbXBsZSBub25jZQ=="
)

type Payload struct {
	code         string
	buffer       []byte
	guildIdBuf   []byte
	codeQuoteBuf []byte
}

type vanityEntry struct {
	id   string
	code string
}

type Session struct {
	conn    *tls.Conn
	wmu     sync.Mutex
	waiting atomic.Bool
	sentAt  atomic.Int64
}

var (
	isSniped   int32
	snipeCode  atomic.Value // string
	sessions   [SESSION_COUNT]atomic.Pointer[Session]
	vanityList atomic.Pointer[[]*Payload]
	watched    atomic.Pointer[[]vanityEntry]
	currentMfa atomic.Value // string

	guildUpdateBuf   = []byte(`"t":"GUILD_UPDATE"`)
	vanityNullBuf    = []byte(`"vanity_url_code":null`)
	readyBuf         = []byte(`"t":"READY"`)
	op10Buf          = []byte(`"op":10`)
	op7Buf           = []byte(`"op":7`)
	powerupDeleteBuf = []byte(`"t":"GUILD_POWERUP_ENTITLEMENTS_DELETE"`)
	endsBuf          = []byte(`"ends"`)
	endsAtBuf        = []byte(`"ends_at"`)

	h2Init = append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 0, 0, 0, 4, 0, 0, 0, 0, 0)
	h2Ping = []byte{0, 0, 8, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	identifyPayload  = []byte(`{"op":2,"d":{"token":"` + TOKEN + `","intents":1,"properties":{"os":"Windows","browser":"Chrome"}}}`)
	heartbeatPayload = []byte(`{"op":1,"d":null}`)

	tlsConfig = &tls.Config{
		ServerName:         DISCORD_HOST,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
		NextProtos:         []string{"h2"},
	}

	gwSessionCache = tls.NewLRUClientSessionCache(32)
)

func getMfa() string {
	v := currentMfa.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

func loadMfaFile() string {
	b, err := os.ReadFile("mfa.txt")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func encodeHpack(name, value string) []byte {
	valLen := len(value)
	b := make([]byte, 0, 2+len(name)+3+valLen)
	b = append(b, 0x00, byte(len(name)))
	b = append(b, name...)
	if valLen < 127 {
		b = append(b, byte(valLen))
	} else {
		b = append(b, 127)
		l := valLen - 127
		for l >= 128 {
			b = append(b, byte(l%128)|128)
			l /= 128
		}
		b = append(b, byte(l))
	}
	b = append(b, value...)
	return b
}

func buildRequest(code string) *Payload {
	headers := [][2]string{
		{":method", "PATCH"},
		{":path", "/api/v10/guilds/" + GUILD_ID + "/vanity-url"},
		{":authority", DISCORD_HOST},
		{":scheme", "https"},
		{"authorization", TOKEN},
		{"x-discord-mfa-authorization", getMfa()},
		{"content-type", "application/json"},
		{"user-agent", "Mozilla/5.0"},
		{"x-super-properties", SUPER_PROPS},
	}

	var hpack []byte
	for _, h := range headers {
		hpack = append(hpack, encodeHpack(h[0], h[1])...)
	}
	hpackLen := len(hpack)
	codeLen := len(code)
	bodyLen := 11 + codeLen

	buf := make([]byte, 0, 18+hpackLen+bodyLen)
	buf = append(buf, byte(hpackLen>>16), byte(hpackLen>>8), byte(hpackLen))
	buf = append(buf, 1, 4, 0, 0, 0, 1)
	buf = append(buf, hpack...)
	buf = append(buf, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))
	buf = append(buf, 0, 1, 0, 0, 0, 1)
	buf = append(buf, `{"code":"`...)
	buf = append(buf, code...)
	buf = append(buf, `"}`...)

	return &Payload{code: code, buffer: buf, codeQuoteBuf: []byte(`"` + code + `"`)}
}

func rebuild() {
	wp := watched.Load()
	if wp == nil {
		return
	}
	list := make([]*Payload, 0, len(*wp))
	for _, e := range *wp {
		p := buildRequest(e.code)
		p.guildIdBuf = []byte(e.id)
		list = append(list, p)
	}
	vanityList.Store(&list)
}

var (
	fireMu    sync.Mutex
	fireCond  = sync.NewCond(&fireMu)
	fireBufSh []byte
	fireGen   uint64
)

func fireWorker(index int) {
	runtime.LockOSThread()
	lastGen := uint64(0)
	for {
		fireMu.Lock()
		for fireGen == lastGen {
			fireCond.Wait()
		}
		lastGen = fireGen
		buf := fireBufSh
		fireMu.Unlock()

		s := sessions[index].Load()
		if s == nil {
			continue
		}
		s.sentAt.Store(time.Now().UnixNano())
		s.waiting.Store(true)
		s.wmu.Lock()
		s.conn.Write(buf)
		s.wmu.Unlock()
	}
}

func fire(p *Payload) {
	if !atomic.CompareAndSwapInt32(&isSniped, 0, 1) {
		return
	}
	snipeCode.Store(p.code)
	fireMu.Lock()
	fireBufSh = p.buffer
	fireGen++
	fireMu.Unlock()
	fireCond.Broadcast()
}

func readIso(data []byte, keyIdx, keyLen int) (time.Time, bool) {
	p := keyIdx + keyLen
	for p < len(data) {
		c := data[p]
		if c == '"' {
			break
		}
		if c == ',' || c == '}' {
			return time.Time{}, false
		}
		p++
	}
	if p >= len(data) {
		return time.Time{}, false
	}
	start := p + 1
	end := start
	for end < len(data) && data[end] != '"' {
		end++
	}
	if end >= len(data) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, string(data[start:end]))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func extractEnds(data []byte) (time.Time, bool) {
	if i := bytes.Index(data, endsAtBuf); i != -1 {
		return readIso(data, i, len(endsAtBuf))
	}
	if i := bytes.Index(data, endsBuf); i != -1 {
		return readIso(data, i, len(endsBuf))
	}
	return time.Time{}, false
}

func createSession(index int) {
	if old := sessions[index].Load(); old != nil {
		old.conn.Close()
	}

	raddr := &net.TCPAddr{IP: net.ParseIP(DISCORD_IP), Port: 443}
	tcp, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		time.AfterFunc(50*time.Millisecond, func() { createSession(index) })
		return
	}
	tcp.SetNoDelay(true)
	tcp.SetKeepAlive(true)
	tcp.SetKeepAlivePeriod(3 * time.Second)

	conn := tls.Client(tcp, tlsConfig)
	if err := conn.Handshake(); err != nil {
		conn.Close()
		time.AfterFunc(50*time.Millisecond, func() { createSession(index) })
		return
	}

	if _, err := conn.Write(h2Init); err != nil {
		conn.Close()
		time.AfterFunc(50*time.Millisecond, func() { createSession(index) })
		return
	}

	s := &Session{conn: conn}
	sessions[index].Store(s)
	go readLoop(index, s)
}

func readLoop(index int, s *Session) {
	r := bufio.NewReaderSize(s.conn, 1<<16)
	hdr := make([]byte, 9)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			break
		}
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		ftype := hdr[3]
		flags := hdr[4]
		streamID := binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff

		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(r, payload); err != nil {
				break
			}
		}

		if s.waiting.Load() && streamID == 1 {
			now := time.Now().UnixNano()
			if ftype == 0 {
				ms := float64(now-s.sentAt.Load()) / 1e6
				body := payload
				if len(body) > 500 {
					body = body[:500]
				}
				fmt.Printf("Result for %s: %s %.3fms\n", snipeCode.Load(), body, ms)
				s.waiting.Store(false)
			} else if ftype == 1 && flags&1 != 0 {
				ms := float64(now-s.sentAt.Load()) / 1e6
				fmt.Printf("Bax abi bax abi abi %s [HEADERS END_STREAM] %.3fms\n", snipeCode.Load(), ms)
				s.waiting.Store(false)
			}
		}
	}
	s.conn.Close()
	time.AfterFunc(50*time.Millisecond, func() { createSession(index) })
}

func detectGuildUpdate(data []byte) {
	if atomic.LoadInt32(&isSniped) == 1 {
		return
	}
	lp := vanityList.Load()
	if lp == nil {
		return
	}
	for _, cached := range *lp {
		if bytes.Contains(data, cached.guildIdBuf) && (bytes.Contains(data, vanityNullBuf) || !bytes.Contains(data, cached.codeQuoteBuf)) {
			fire(cached)
			return
		}
	}
}

func detectPowerup(data []byte) {
	if atomic.LoadInt32(&isSniped) == 1 {
		return
	}
	lp := vanityList.Load()
	if lp == nil {
		return
	}
	for _, cached := range *lp {
		if bytes.Contains(data, cached.guildIdBuf) {
			if endsT, ok := extractEnds(data); ok {
				d := time.Until(endsT)
				cc := cached
				if d <= 0 {
					fire(cc)
				} else {
					time.AfterFunc(d, func() { fire(cc) })
				}
			}
			return
		}
	}
}

type gwMsg struct {
	T  string          `json:"t"`
	Op int             `json:"op"`
	D  json.RawMessage `json:"d"`
}

func handleReady(d json.RawMessage) {
	var rd struct {
		Guilds []struct {
			ID     string  `json:"id"`
			Vanity *string `json:"vanity_url_code"`
		} `json:"guilds"`
	}
	if err := json.Unmarshal(d, &rd); err != nil {
		return
	}
	fmt.Println("req", SESSION_COUNT)

	entries := make([]vanityEntry, 0)
	for _, g := range rd.Guilds {
		if g.Vanity != nil && *g.Vanity != "" {
			entries = append(entries, vanityEntry{id: g.ID, code: *g.Vanity})
		}
	}
	watched.Store(&entries)
	rebuild()

	for i := 0; i < len(entries) && i < 25; i++ {
		fmt.Printf("{ guild_id: \x1b[32m'%s'\x1b[0m, vanity_url_code: \x1b[32m'%s'\x1b[0m },\n", entries[i].id, entries[i].code)
	}
	if len(entries) > 25 {
		fmt.Printf("ve %d tane daha fazla server\n", len(entries)-25)
	}
}

// ---- hand-written WebSocket client (RFC 6455) over TLS ----

type wsConn struct {
	conn net.Conn
	r    *bufio.Reader
	wmu  sync.Mutex
}

func wsDial(host, path string) (*wsConn, error) {
	tcp, err := net.Dial("tcp", host+":443")
	if err != nil {
		return nil, err
	}
	if t, ok := tcp.(*net.TCPConn); ok {
		t.SetNoDelay(true)
		t.SetKeepAlive(true)
		t.SetKeepAlivePeriod(3 * time.Second)
	}
	conn := tls.Client(tcp, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS13,
		ClientSessionCache: gwSessionCache,
	})
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + WS_KEY + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	r := bufio.NewReaderSize(conn, 1<<16)
	status, err := r.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.Contains(status, " 101 ") {
		conn.Close()
		return nil, fmt.Errorf("ws upgrade failed: %s", strings.TrimSpace(status))
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return &wsConn{conn: conn, r: r}, nil
}

func (w *wsConn) readMessage() ([]byte, error) {
	var msg []byte
	for {
		h0, err := w.r.ReadByte()
		if err != nil {
			return nil, err
		}
		h1, err := w.r.ReadByte()
		if err != nil {
			return nil, err
		}
		fin := h0&0x80 != 0
		opcode := h0 & 0x0f
		masked := h1&0x80 != 0
		length := int(h1 & 0x7f)
		if length == 126 {
			var b [2]byte
			if _, err := io.ReadFull(w.r, b[:]); err != nil {
				return nil, err
			}
			length = int(binary.BigEndian.Uint16(b[:]))
		} else if length == 127 {
			var b [8]byte
			if _, err := io.ReadFull(w.r, b[:]); err != nil {
				return nil, err
			}
			length = int(binary.BigEndian.Uint64(b[:]))
		}
		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(w.r, maskKey[:]); err != nil {
				return nil, err
			}
		}
		payload := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(w.r, payload); err != nil {
				return nil, err
			}
		}
		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i&3]
			}
		}

		switch opcode {
		case 0x0, 0x1, 0x2:
			if fin && msg == nil {
				return payload, nil
			}
			msg = append(msg, payload...)
			if fin {
				return msg, nil
			}
		case 0x9:
			w.writeFrame(0xA, payload)
		case 0xA:
		case 0x8:
			return nil, io.EOF
		}
	}
}

func (w *wsConn) writeFrame(opcode byte, payload []byte) error {
	n := len(payload)
	var hdr [10]byte
	hdr[0] = 0x80 | opcode
	var idx int
	if n < 126 {
		hdr[1] = 0x80 | byte(n)
		idx = 2
	} else if n <= 0xffff {
		hdr[1] = 0x80 | 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		idx = 4
	} else {
		hdr[1] = 0x80 | 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		idx = 10
	}

	var mask [4]byte
	binary.LittleEndian.PutUint32(mask[:], uint32(time.Now().UnixNano()))

	out := make([]byte, idx+4+n)
	copy(out, hdr[:idx])
	copy(out[idx:], mask[:])
	for i := 0; i < n; i++ {
		out[idx+4+i] = payload[i] ^ mask[i&3]
	}

	w.wmu.Lock()
	_, err := w.conn.Write(out)
	w.wmu.Unlock()
	return err
}

func runGateway(host, path string) {
	w, err := wsDial(host, path)
	if err != nil {
		return
	}
	defer w.conn.Close()

	stopHB := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(stopHB) })

	fmt.Println("ws ok")

	for {
		data, err := w.readMessage()
		if err != nil {
			return
		}

		if bytes.Contains(data, guildUpdateBuf) {
			detectGuildUpdate(data)
			continue
		}
		if bytes.Contains(data, powerupDeleteBuf) {
			detectPowerup(data)
			continue
		}
		if !bytes.Contains(data, readyBuf) && !bytes.Contains(data, op10Buf) && !bytes.Contains(data, op7Buf) {
			continue
		}

		var msg gwMsg
		if json.Unmarshal(data, &msg) != nil {
			continue
		}

		if msg.T == "READY" {
			handleReady(msg.D)
		} else if msg.Op == 10 {
			fmt.Println("orda her kiminleysen")
			w.writeFrame(0x1, identifyPayload)
			var hd struct {
				HeartbeatInterval float64 `json:"heartbeat_interval"`
			}
			json.Unmarshal(msg.D, &hd)
			ticker := time.NewTicker(time.Duration(hd.HeartbeatInterval) * time.Millisecond)
			go func() {
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						if w.writeFrame(0x1, heartbeatPayload) != nil {
							return
						}
					case <-stopHB:
						return
					}
				}
			}()
		} else if msg.Op == 7 {
			return
		}
	}
}

func startGateway(host, path string) {
	for {
		runGateway(host, path)
		time.Sleep(50 * time.Millisecond)
	}
}

func watchMfa() {
	last := loadMfaFile()
	for range time.Tick(1 * time.Second) {
		cur := loadMfaFile()
		if cur != last {
			last = cur
			currentMfa.Store(cur)
			fmt.Println("mfa ok")
			rebuild()
		}
	}
}

func main() {
	debug.SetGCPercent(300)
	runtime.GOMAXPROCS(runtime.NumCPU())
	snipeCode.Store("")
	currentMfa.Store(loadMfaFile())

	for i := 0; i < SESSION_COUNT; i++ {
		go fireWorker(i)
		createSession(i)
	}

	go func() {
		t := time.NewTicker(5 * time.Second)
		for range t.C {
			for i := 0; i < SESSION_COUNT; i++ {
				if s := sessions[i].Load(); s != nil {
					s.wmu.Lock()
					s.conn.Write(h2Ping)
					s.wmu.Unlock()
				}
			}
		}
	}()

	go watchMfa()

	go startGateway("gateway.discord.gg", "/?v=10&encoding=json")
	go startGateway("us-east1-c.gateway.discord.gg", "/?v=10&encoding=json")
	go startGateway("eu-west1.gateway.discord.gg", "/?v=10&encoding=json")
	go startGateway("ap-southeast1.gateway.discord.gg", "/?v=10&encoding=json")

	select {}
}
