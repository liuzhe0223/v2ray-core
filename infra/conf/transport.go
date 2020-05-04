package conf

import (
	"v2ray.com/core/common/serial"
	"v2ray.com/core/transport"
	"v2ray.com/core/transport/internet"
)

type TransportConfig struct {
	TCPConfig *TCPConfig       `json:"tcpSettings"`
	WSConfig  *WebSocketConfig `json:"wsSettings"`
}

// Build implements Buildable.
func (c *TransportConfig) Build() (*transport.Config, error) {
	config := new(transport.Config)

	if c.TCPConfig != nil {
		ts, err := c.TCPConfig.Build()
		if err != nil {
			return nil, newError("failed to build TCP config").Base(err).AtError()
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}

	if c.WSConfig != nil {
		ts, err := c.WSConfig.Build()
		if err != nil {
			return nil, newError("failed to build WebSocket config").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "websocket",
			Settings:     serial.ToTypedMessage(ts),
		})
	}

	return config, nil
}
