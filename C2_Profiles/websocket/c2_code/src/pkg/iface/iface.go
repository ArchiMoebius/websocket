package iface

import (
	"ArchiMoebius/mythic_c2_websocket/pkg/logger"
	"ArchiMoebius/mythic_c2_websocket/pkg/profile/common"
	"ArchiMoebius/mythic_c2_websocket/pkg/profile/poseidon"
	"ArchiMoebius/mythic_c2_websocket/pkg/profile/zippy"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

// TransportConfig
type TransportConfig struct {
	Transport   TransportConfigData
	Debug       bool
	Verbose     bool
	RelayServer string
	BaseURL     string
	Server      *http.Server
	Listener    net.Listener
}

// UnmarshalJSON hack to get JSON loaded in a 'dynamic' fashion
func (b *TransportConfig) UnmarshalJSON(data []byte) error {
	var tmpHeader struct {
		common.BaseTransportConfig
	}

	if err := json.Unmarshal(data, &tmpHeader); err != nil {
		return err
	}

	switch tmpHeader.Type {
	case "zippy":
		b.Transport = new(zippy.Transport)
	case "poseidon":
		b.Transport = new(poseidon.Transport)
	}

	if err := json.Unmarshal(data, b.Transport); err != nil {
		return err
	}

	b.RelayServer = os.Getenv("MYTHIC_ADDRESS")
	b.BaseURL = fmt.Sprintf("http://%s", b.RelayServer)

	return b.Transport.Load()
}

// TransportConfigData lightweight plug
type TransportConfigData interface {
	MarshalString() (string, error)
	HasCertificateAndKey() bool
	HasCertificateAuthority() bool
	GetCertificates() []tls.Certificate
	GetCertificateAuthority() *x509.CertPool
	UseMTLS() bool
	GetLogPath(string) string
	GetHTTPFilename() string
	GetWebSocketFilename() string
	GetServerAddress() string
	ParseClientMessage(blob []byte) ([]byte, error)
	Load() error
}

// WebSocketHandler - Websockets handler
func (s *TransportConfig) WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	//Upgrade the websocket connection
	common.Upgrader.CheckOrigin = func(r *http.Request) bool { return true }
	conn, err := common.Upgrader.Upgrade(w, r, nil)
	if err != nil {

		if s.Debug {
			logger.Log(fmt.Sprintf("[!] Websocket upgrade failed: %s\n", err.Error()))
		}
		http.Error(w, "websocket connection failed", http.StatusBadRequest)
		return
	}

	if s.Debug {
		logger.Log("[I] Received new websocket client")
	}

	go s.manageClient(conn)

}

// decodeNextMythicMessage - data on the wire for Mthic Agents follows: https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/agent-message-format
// base64EncodedBlob(uuid + payload)
func (s *TransportConfig) decodeNextMythicMessage(c *websocket.Conn) (string, []byte, error) {
	_, r, err := c.NextReader()

	if err != nil {
		return "", []byte{}, err
	}

	blob, err := io.ReadAll(r)

	if err != nil {
		logger.Log(fmt.Sprintf("[!] Failed to io.ReadAll: %s", err.Error()))
		return "", []byte{}, err
	}

	msg := make([]byte, len(blob)*len(blob)/base64.StdEncoding.DecodedLen(len(blob)))

	_, err = base64.StdEncoding.Decode(msg, blob)

	if err != nil {
		logger.Log(fmt.Sprintf("[!] Failed to base64 decode: %s", err.Error()))
		return "", []byte{}, err
	}

	return string(msg[0:36]), msg[36:], err
}

// PostMythicMessage HTTP POST function
func (s *TransportConfig) PostMythicMessage(apiEndpoint string, sendData []byte) []byte {
	url := s.BaseURL

	if apiEndpoint != "" {
		url = fmt.Sprintf("%s/%s", s.BaseURL, apiEndpoint)
	}

	if s.Debug {
		logger.Log(fmt.Sprintf("[I] POST request to URL: %s", url))
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(sendData))

	if err != nil {
		logger.Log(fmt.Sprintf("[!] Error creating POST request: %s", err.Error()))
		return make([]byte, 0)
	}

	req.Header.Add("Mythic", "websocket")
	contentLength := len(sendData)
	req.ContentLength = int64(contentLength)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)

	if err != nil {
		logger.Log(fmt.Sprintf("[!] Error sending POST request: %s", err.Error()))
		return make([]byte, 0)
	}

	if resp.StatusCode != 200 {
		logger.Log(fmt.Sprintf("[!] Did not receive 200 response code: %d", resp.StatusCode))
		return make([]byte, 0)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		logger.Log(fmt.Sprintf("[!] Error reading response body: %s", err.Error()))
		return make([]byte, 0)
	}

	return body
}

// GetMythicMessage - HTTP GET request for data
func (s *TransportConfig) GetMythicMessage(url string) []byte {

	if s.Debug {
		logger.Log(fmt.Sprintf("[I] Sending HTML GET request to url: %s", url))
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	var respBody []byte

	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Mythic", "websocket")

	if err != nil {
		logger.Log(fmt.Sprintf("[!] Error creating http request: %s", err.Error()))
		return make([]byte, 0)
	}

	resp, err := client.Do(req)

	if err != nil {
		logger.Log(fmt.Sprintf("[!] Error completing GET request: %s", err.Error()))
		return make([]byte, 0)
	}

	if resp.StatusCode != 200 {
		logger.Log(fmt.Sprintf("[!] Did not receive 200 response code: %d", resp.StatusCode))
		return make([]byte, 0)
	}

	defer resp.Body.Close()

	respBody, _ = io.ReadAll(resp.Body)

	return respBody
}

func (s *TransportConfig) manageClient(c *websocket.Conn) {

	defer c.Close()

LOOP:
	for {
		uuid, blob, err := s.decodeNextMythicMessage(c)

		// TODO: add uuid check? Keep listing of 'checked in / active agents' - do...we...care?
		logger.Log(fmt.Sprintf("[I] Client %s sent a message", uuid))

		if err != nil {
			logger.Log(fmt.Sprintf("[!] Read error %s. Exiting session", err.Error()))
			break LOOP
		}

		data, err := s.Transport.ParseClientMessage(blob)

		if err != nil {
			logger.Log(fmt.Sprintf("[!] Read ParseClientMessage failed %s. Exiting session", err.Error()))
			break LOOP
		}

		if s.Debug {
			logger.Log(fmt.Sprintf("[D] Received agent message %s\n", string(data)))
		}

		resp := s.PostMythicMessage("/api/v1.4/agent_message", data)

		w, err := c.NextWriter(websocket.TextMessage)

		if err != nil {
			logger.Log(fmt.Sprintf("[!] Failed to obtain writer %s", err.Error()))
			break LOOP
		}

		w.Write(resp)

		if err := w.Close(); err != nil {
			logger.Log(fmt.Sprintf("[!] Failed to close writer %s", err.Error()))
			break LOOP
		}
	}
}

// HTTPHandler - HTTP handler
func (s *TransportConfig) HTTPHandler(w http.ResponseWriter, r *http.Request) {
	if s.Debug {
		logger.Log(fmt.Sprintf("[!] Received request: %s", r.URL))
		logger.Log(fmt.Sprintf("[!] URI Path %s", r.URL.Path))
	}

	if (r.URL.Path == "/" || r.URL.Path == "/index.html") && r.Method == "GET" {
		// Serve the default page if we receive a GET request at the base URI
		http.ServeFile(w, r, s.Transport.GetHTTPFilename())
	}

	http.Error(w, "Not Found", http.StatusNotFound)
}

// Run - main function for the websocket profile
func (s *TransportConfig) Run() error {
	http.HandleFunc("/", s.HTTPHandler)
	http.HandleFunc(fmt.Sprintf("/%s", s.Transport.GetWebSocketFilename()), s.WebSocketHandler)

	s.Server = &http.Server{
		IdleTimeout: 120 * time.Second,
		Addr:        s.Transport.GetServerAddress(),
	}

	if s.Transport.HasCertificateAndKey() {
		s.Server.ReadTimeout = time.Minute
		s.Server.WriteTimeout = time.Minute
		s.Server.TLSConfig = &tls.Config{
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			Renegotiation:            tls.RenegotiateNever,
			MinVersion:               tls.VersionTLS12,
			MaxVersion:               tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
			Certificates: s.Transport.GetCertificates(),
		}

		if s.Transport.HasCertificateAuthority() {
			s.Server.TLSConfig.ClientCAs = s.Transport.GetCertificateAuthority()
			s.Server.TLSConfig.RootCAs = s.Transport.GetCertificateAuthority()
		}

		if s.Transport.UseMTLS() {
			s.Server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		logger.Log("[+] API configured to utilize TLS")

		lsnr, err := tls.Listen("tcp", s.Transport.GetServerAddress(), s.Server.TLSConfig)

		if err != nil {
			logger.Log(err.Error())
			return err
		}

		s.Listener = lsnr

	} else {
		lsnr, err := net.Listen("tcp", s.Transport.GetServerAddress())

		if err != nil {
			logger.Log(err.Error())
			return err
		}

		s.Listener = lsnr
	}

	if s.Verbose {
		logger.Log(fmt.Sprintf("[+] API Listening at %s", s.Transport.GetServerAddress()))
	}

	go func() {
		if err := s.Server.Serve(s.Listener); err != nil && err != http.ErrServerClosed {
			log.Fatal(fmt.Sprintf("[!] Failed to server listener %s", s.Transport.GetServerAddress()))
		}
	}() // TODO: add chan. for error notification ...

	return nil
}

func (s *TransportConfig) Shutdown(ctx context.Context) error {
	if s.Debug {
		logger.Log("[I] Entering Transport Shutdown")
	}

	return s.Server.Shutdown(ctx)
}
