package launcher

import (
	"context"
	"sync"
)

// These three literal reads are separate from the general read batch. Only
// the owned-broker TLS inspector calls this helper after all identity checks.
// No path, command, callback or successful subset is returned to a caller.
func (d *Docker) verifyOwnedTLSArchives(parent context.Context, id string, config, certificate, key [32]byte) error {
	if parent == nil || !fullID.MatchString(id) || config == ([32]byte{}) || certificate == ([32]byte{}) || key == ([32]byte{}) {
		return refusal("broker_tls_expectation_invalid")
	}
	if parent.Err() != nil {
		return refusal("command_timeout_outcome_unknown")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var joined sync.WaitGroup
	var first sync.Once
	var failure error
	files := [3]struct {
		name   string
		digest [32]byte
		limit  int64
	}{
		{"private.conf", config, 64 * 1024},
		{"server-cert.pem", certificate, 16 * 1024},
		{"server-key.pem", key, 8 * 1024},
	}
	joined.Add(len(files))
	for index, file := range files {
		go func(index int, name string, digest [32]byte, limit int64) {
			defer joined.Done()
			raw, err := d.run(ctx, nil, "cp", id+":/etc/nats/"+name, "-")
			if err == nil {
				err = verifyPrivateFileArchive(raw, digest, name, limit)
				clear(raw)
				if err != nil && index != 0 {
					err = refusal("broker_tls_file_mismatch")
				}
			}
			if err != nil {
				first.Do(func() { failure = err; cancel() })
			}
		}(index, file.name, file.digest, file.limit)
	}
	joined.Wait()
	if failure != nil {
		return failure
	}
	if parent.Err() != nil {
		return refusal("command_timeout_outcome_unknown")
	}
	return nil
}
