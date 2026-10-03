package controlplane

import (
	"net"
	"testing"
	"time"
)

func TestLimitListenerBoundsIdleConnections(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	limited := LimitListener(base, 1)
	defer limited.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			conn, err := limited.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	first, err := net.DialTimeout("tcp", base.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	var serverFirst net.Conn
	select {
	case serverFirst = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("first connection not accepted")
	}
	second, err := net.DialTimeout("tcp", base.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	var byteBuf [1]byte
	if _, err := second.Read(byteBuf[:]); err == nil {
		t.Fatal("capacity connection was not closed")
	}
	select {
	case <-accepted:
		t.Fatal("excess connection reached application")
	default:
	}
	serverFirst.Close()
	third, err := net.DialTimeout("tcp", base.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	select {
	case serverThird := <-accepted:
		serverThird.Close()
	case <-time.After(time.Second):
		t.Fatal("slot not released")
	}
}
