package launcher

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"
)

type dockerEngineInfo struct {
	ID            string `json:"ID"`
	OS            string `json:"OSType"`
	ServerVersion string `json:"ServerVersion"`
}

const dockerInfoStdioRequest = "GET /info HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"

// This hidden CLI helper is qualified only for the selected Windows 29.8.0
// installation. Callers first verify context endpoint and actual client version.
// No generic request, caller headers, daemon discovery or fallback is provided.
func (d *Docker) readEngineInfoStdio(parent context.Context, actualClientVersion string) (result dockerEngineInfo, failure error) {
	started := time.Time{}
	remaining := time.Duration(0)
	effectiveCap := time.Duration(0)
	attempted := false
	defer func() {
		if attempted && failure != nil {
			failure = failedDockerRead("engine_stdio", parent, started, remaining, effectiveCap, failure)
		}
	}()
	empty := dockerEngineInfo{}
	if d == nil || parent == nil || d.config.Backend != WindowsInterop || d.config.Versions.Client != "29.8.0" || d.config.Versions.Server != "29.8.0" || actualClientVersion != "29.8.0" {
		return empty, refusal("stdio_transport_unqualified")
	}
	if err := d.environment(); err != nil {
		return empty, err
	}
	if d.config.Timeout <= 0 || d.config.Timeout > 60*time.Second {
		return empty, refusal("invalid_timeout")
	}
	limit := d.config.Timeout
	if limit > 4*time.Second {
		limit = 4 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, limit)
	defer cancel()
	if ctx.Err() != nil {
		return empty, refusal("command_timeout_outcome_unknown")
	}
	cmd := exec.CommandContext(ctx, d.config.Executable, "--context", d.config.Context, "system", "dial-stdio")
	cmd.Env = dockerEnvironment()
	cmd.WaitDelay = time.Second
	cmd.Stderr = io.Discard
	var output limitedOutput
	cmd.Stdout = &output
	input, err := cmd.StdinPipe()
	if err != nil {
		return empty, refusal("stdio_pipe_failed")
	}
	defer input.Close()
	started = time.Now()
	if deadline, ok := parent.Deadline(); ok {
		remaining = time.Until(deadline)
	}
	if deadline, ok := ctx.Deadline(); ok {
		effectiveCap = time.Until(deadline)
	}
	if effectiveCap > remaining {
		effectiveCap = remaining
	}
	attempted = true
	if cmd.Start() != nil {
		return empty, refusal("command_failed")
	}
	// The request fits in the owned pipe. Keep the writer open until reply/exit:
	// an early EOF failed the actual Windows named-pipe transport diagnostic.
	_, writeErr := io.WriteString(input, dockerInfoStdioRequest)
	if writeErr != nil {
		cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return empty, refusal("command_timeout_outcome_unknown")
	}
	if writeErr != nil || waitErr != nil {
		return empty, refusal("command_failed")
	}
	if output.exceeded {
		return empty, refusal("output_limit_exceeded")
	}
	info, err := decodeDockerInfoStdio(output.Bytes())
	if err != nil {
		return empty, err
	}
	if info.ID != d.config.EngineID || info.OS != "linux" || info.ServerVersion != d.config.Versions.Server {
		return empty, refusal("backend_mismatch")
	}
	if ctx.Err() != nil {
		return empty, refusal("command_timeout_outcome_unknown")
	}
	return info, nil
}

func decodeDockerInfoStdio(raw []byte) (dockerEngineInfo, error) {
	empty := dockerEngineInfo{}
	if len(raw) == 0 || len(raw) > 1024*1024 {
		return empty, refusal("invalid_observation")
	}
	headEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headEnd < 0 || headEnd > 16*1024 {
		return empty, refusal("invalid_response_framing")
	}
	// Reject folded/duplicate framing headers before the standard parser can
	// normalize them. Ordinary unknown engine headers are not returned or logged.
	framing := map[string]bool{}
	for _, line := range bytes.Split(raw[:headEnd], []byte("\r\n"))[1:] {
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' || bytes.ContainsAny(line, "\r\n") {
			return empty, refusal("invalid_response_framing")
		}
		name, value, ok := strings.Cut(string(line), ":")
		if !ok {
			return empty, refusal("invalid_response_framing")
		}
		if strings.TrimSpace(name) != name {
			return empty, refusal("invalid_response_framing")
		}
		name = strings.ToLower(name)
		if name == "transfer-encoding" && strings.TrimSpace(strings.ToLower(value)) != "chunked" {
			return empty, refusal("invalid_response_framing")
		}
		if name == "content-length" || name == "transfer-encoding" || name == "content-encoding" {
			if framing[name] {
				return empty, refusal("invalid_response_framing")
			}
			framing[name] = true
		}
	}
	if framing["content-length"] && framing["transfer-encoding"] {
		return empty, refusal("invalid_response_framing")
	}
	reader := bufio.NewReader(bytes.NewReader(raw))
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		return empty, refusal("invalid_response_framing")
	}
	defer response.Body.Close()
	media, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.Proto != "HTTP/1.1" || response.StatusCode != http.StatusOK || mediaErr != nil || media != "application/json" || response.Header.Get("Content-Encoding") != "" || response.Header.Get("Upgrade") != "" || len(response.Trailer) != 0 || response.ContentLength > 1024*1024 || len(response.TransferEncoding) > 1 || (len(response.TransferEncoding) == 1 && response.TransferEncoding[0] != "chunked") {
		return empty, refusal("invalid_response_framing")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(body) > 1024*1024 || len(response.Trailer) != 0 || !utf8.Valid(body) {
		return empty, refusal("invalid_observation")
	}
	extra, err := io.ReadAll(reader)
	if err != nil || len(extra) != 0 {
		return empty, refusal("invalid_response_framing")
	}
	if !dockerInfoJSONUnique(body) {
		return empty, refusal("invalid_observation")
	}
	var fields map[string]json.RawMessage
	var info dockerEngineInfo
	if json.Unmarshal(body, &fields) != nil || json.Unmarshal(fields["ID"], &info.ID) != nil || json.Unmarshal(fields["OSType"], &info.OS) != nil || json.Unmarshal(fields["ServerVersion"], &info.ServerVersion) != nil || info.ID == "" || info.OS == "" || info.ServerVersion == "" {
		return empty, refusal("invalid_observation")
	}
	return info, nil
}

func dockerInfoJSONUnique(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 64 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		mark, container := token.(json.Delim)
		if !container {
			return true
		}
		switch mark {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !value(depth + 1) {
					return false
				}
			}
		case '[':
			for decoder.More() {
				if !value(depth + 1) {
					return false
				}
			}
		default:
			return false
		}
		_, err = decoder.Token()
		return err == nil
	}
	if !value(0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}
