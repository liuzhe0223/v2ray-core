package websocket_test

import (
	"context"
	"testing"
	"time"

	"v2ray.com/core/common"
	"v2ray.com/core/common/net"
	"v2ray.com/core/transport/internet"
	. "v2ray.com/core/transport/internet/websocket"
)

func Test_listenWSAndDial(t *testing.T) {
	listen, err := ListenWS(context.Background(), net.LocalHostIP, 13146, &internet.MemoryStreamConfig{
		ProtocolName: "websocket",
		ProtocolSettings: &Config{
			Path: "ws",
		},
	}, func(conn internet.Connection) {
		go func(c internet.Connection) {
			defer c.Close()

			var b [1024]byte
			_, err := c.Read(b[:])
			if err != nil {
				return
			}

			common.Must2(c.Write([]byte("Response")))
		}(conn)
	})
	common.Must(err)

	ctx := context.Background()
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "websocket",
		ProtocolSettings: &Config{Path: "ws"},
	}
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), 13146), streamSettings)

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, err := conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(conn.Close())
	<-time.After(time.Second * 5)
	conn, err = Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), 13146), streamSettings)
	common.Must(err)
	_, err = conn.Write([]byte("Test connection 2"))
	common.Must(err)
	n, err = conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}
	common.Must(conn.Close())

	common.Must(listen.Close())
}

func TestDialWithRemoteAddr(t *testing.T) {
	listen, err := ListenWS(context.Background(), net.LocalHostIP, 13148, &internet.MemoryStreamConfig{
		ProtocolName: "websocket",
		ProtocolSettings: &Config{
			Path: "ws",
		},
	}, func(conn internet.Connection) {
		go func(c internet.Connection) {
			defer c.Close()

			var b [1024]byte
			_, err := c.Read(b[:])
			//common.Must(err)
			if err != nil {
				return
			}

			_, err = c.Write([]byte("Response"))
			common.Must(err)
		}(conn)
	})
	common.Must(err)

	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), 13148), &internet.MemoryStreamConfig{
		ProtocolName:     "websocket",
		ProtocolSettings: &Config{Path: "ws", Header: []*Header{{Key: "X-Forwarded-For", Value: "1.1.1.1"}}},
	})

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, err := conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(listen.Close())
}
