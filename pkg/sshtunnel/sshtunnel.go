package sshtunnel

import (
	"encoding/base64"
	"fmt"
	"time"

	go_tunnel "github.com/elliotchance/sshtunnel"
	"golang.org/x/crypto/ssh"
)

type SSHTunnelService interface {
	Start() error
	Stop()
	GetLocalPort() int
}

type SSHTunnelConfig struct {
	TunnelAddress      string
	DestinationAddress string
	LocalPort          string
	Password           string
	PrivateKey         string
	AuthType           string
}

type SSHTunnel struct {
	*go_tunnel.SSHTunnel
}

var _ SSHTunnelService = (*SSHTunnel)(nil)

func (s *SSHTunnel) Start() error {

	go s.SSHTunnel.Start()

	time.Sleep(100 * time.Millisecond)

	return nil
}

func (s *SSHTunnel) Stop() {
	s.SSHTunnel.Close()
}

func (s *SSHTunnel) GetLocalPort() int {
	return s.SSHTunnel.Local.Port
}

func NewSSHTunnel(config SSHTunnelConfig) SSHTunnelService {
	authMethod := func() ssh.AuthMethod {
		switch config.AuthType {
		case "password":
			return ssh.Password(config.Password)
		case "privatekey":
			decodedPrivateKey, err := base64.StdEncoding.DecodeString(config.PrivateKey)
			if err != nil {
				fmt.Printf("error decoding private key: %s\n", err.Error())
				return nil
			}

			key, err := ssh.ParsePrivateKey(decodedPrivateKey)
			if err != nil {
				fmt.Printf("error parsing private key: %s\n", err.Error())
				return nil
			}

			return ssh.PublicKeys(key)
		default:
			return ssh.Password(config.Password)
		}
	}

	tunnel, err := go_tunnel.NewSSHTunnel(
		config.TunnelAddress,
		authMethod(),
		config.DestinationAddress,
		config.LocalPort,
	)

	if err != nil {
		fmt.Printf("error creating tunnel: %s\n", err.Error())
		return nil
	}

	return &SSHTunnel{
		SSHTunnel: tunnel,
	}
}
