package launcher

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"strings"
	"testing"
)

func tlsInstanceBody(name string) []byte { return []byte("synthetic-private-" + name) }
func tlsInstanceArchive(name, mode string) []byte {
	body := tlsInstanceBody(name)
	header := tar.Header{Name: name, Mode: 0400, Size: int64(len(body)), Typeflag: tar.TypeReg}
	if mode == "tls-name" {
		header.Name = "../" + name
	}
	if mode == "tls-mode" {
		header.Mode = 0444
	}
	if mode == "tls-owner" {
		header.Uid = 1000
	}
	if mode == "tls-digest" {
		body = []byte("different-private-file")
		header.Size = int64(len(body))
	}
	if mode == "tls-size" {
		body = bytes.Repeat([]byte{'x'}, 16*1024+1)
		header.Size = int64(len(body))
	}
	if mode == "tls-link" {
		header.Typeflag = tar.TypeSymlink
		header.Linkname = "/other"
		header.Size = 0
		body = nil
	}
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	writer.WriteHeader(&header)
	writer.Write(body)
	if mode == "tls-extra" {
		writer.WriteHeader(&tar.Header{Name: "other", Mode: 0400, Size: 1, Typeflag: tar.TypeReg})
		writer.Write([]byte{'x'})
	}
	writer.Close()
	if mode == "tls-tail" {
		output.WriteString("private-trailing-data")
	}
	return output.Bytes()
}

func TestOwnedTLSBrokerBindsBothPrivateFiles(t *testing.T) {
	for _, mode := range []string{"running", "stopped", "absent", "tls-name", "tls-mode", "tls-owner", "tls-digest", "tls-size", "tls-link", "tls-extra", "tls-tail"} {
		t.Run(mode, func(t *testing.T) {
			driver, log := instanceSetup(t, mode)
			t.Setenv("AMX_BROKER_TLS_ARCHIVES", "1")
			actual, err := driver.InspectOwnedTLSBroker(context.Background(), instanceOwner(), instanceImage(), 43210, sha256.Sum256(instanceConfig()), sha256.Sum256(tlsInstanceBody("server-cert.pem")), sha256.Sum256(tlsInstanceBody("server-key.pem")))
			if mode == "running" || mode == "stopped" || mode == "absent" {
				if err != nil || actual.State != mode {
					t.Fatal("actual controlled TLS-file inspection refused")
				}
			} else if err == nil || actual != (OwnedBroker{}) {
				t.Fatal("unbound private TLS files returned trusted broker state")
			}
			if err != nil && (strings.Contains(err.Error(), "synthetic-private") || strings.Contains(err.Error(), "different-private")) {
				t.Fatal("private archive bytes entered the error")
			}
			noMutation(t, log)
		})
	}
}

func TestOwnedTLSBrokerMissingDigestsHaveNoEffects(t *testing.T) {
	driver, log := instanceSetup(t, "running")
	for _, field := range []string{"certificate", "key"} {
		certificate, key := sha256.Sum256(tlsInstanceBody("server-cert.pem")), sha256.Sum256(tlsInstanceBody("server-key.pem"))
		if field == "certificate" {
			certificate = [32]byte{}
		} else {
			key = [32]byte{}
		}
		actual, err := driver.InspectOwnedTLSBroker(context.Background(), instanceOwner(), instanceImage(), 43210, sha256.Sum256(instanceConfig()), certificate, key)
		if err == nil || actual != (OwnedBroker{}) {
			t.Fatal("missing private-file expectation admitted inspection")
		}
	}
	if commands(log) != "" {
		t.Fatal("missing private-file expectations started a process")
	}
}
