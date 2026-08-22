package deployer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// HelperContainerOpts configures a short-lived "do one job and exit"
// container — used by the SystemUpgrade flow to spawn a docker:cli
// pod with the host's compose mount, and could be reused by other
// admin-triggered tasks (backups, postgres migrations) in the future.
//
// Auto-remove is default-on because helpers leave nothing of value
// behind; their value is the streamed log output the caller already
// captured.
type HelperContainerOpts struct {
	Image string
	Name  string // optional; daemon assigns one when blank
	Cmd   []string
	Env   map[string]string
	// Binds are "host:container[:ro]" entries. Helpers typically need
	// /var/run/docker.sock and a host config dir.
	Binds      []string
	Labels     map[string]string
	AutoRemove bool
	// Init=true makes Docker inject tini as PID 1 so child processes
	// are reaped and signals propagate cleanly. Without it, `sh -c`
	// runs as PID 1 with no signal handlers, which can leave the
	// container in surprising states when subcommands abort.
	Init bool
}

// RunHelperContainer creates and starts a helper container. The caller
// is expected to:
//   1. Read from `logs` until EOF (or close it to abort).
//   2. Call `wait()` to learn the exit code.
//
// If anything before Start succeeds, the caller MUST drain `logs` and
// either receive `wait()` or cancel the context to avoid daemon-side
// goroutine leaks. The combination is unusual, but matches Docker's
// own SDK — attaching to logs *before* start is the only way to not
// miss the first few lines.
func (c *DockerClient) RunHelperContainer(ctx context.Context, opts HelperContainerOpts) (id string, logs io.ReadCloser, wait func() (int64, error), err error) {
	envSlice := make([]string, 0, len(opts.Env))
	for k, v := range opts.Env {
		envSlice = append(envSlice, k+"="+v)
	}
	if opts.Labels == nil {
		opts.Labels = map[string]string{}
	}
	// Helper containers are intentionally NOT labelled muvon.managed=true:
	// reconcileOrphanContainers iterates that label set and would SIGTERM
	// any helper that lacks a matching live instance row. Helpers manage
	// their own lifecycle (success path: explicit remove; failure path:
	// preserved for `docker logs` inspection).
	opts.Labels["muvon.helper"] = "true"

	hc := hostConfig{
		Binds:      opts.Binds,
		AutoRemove: opts.AutoRemove,
	}
	if opts.Init {
		t := true
		hc.Init = &t
	}
	req := containerCreateRequest{
		Image:      opts.Image,
		Cmd:        opts.Cmd,
		Env:        envSlice,
		Labels:     opts.Labels,
		HostConfig: hc,
	}
	cid, err := c.ContainerCreate(ctx, opts.Name, req)
	if err != nil {
		return "", nil, nil, err
	}

	// Attach to logs *before* start so we never miss the first lines.
	rc, err := c.ContainerLogs(ctx, cid, ContainerLogsOptions{
		Stdout: true, Stderr: true, Follow: true,
	})
	if err != nil {
		_ = c.ContainerRemove(context.Background(), cid, true)
		return "", nil, nil, err
	}
	if err := c.ContainerStart(ctx, cid); err != nil {
		_ = rc.Close()
		_ = c.ContainerRemove(context.Background(), cid, true)
		return "", nil, nil, err
	}

	waitFn := func() (int64, error) { return c.ContainerWait(ctx, cid) }
	return cid, rc, waitFn, nil
}

// ContainerExecCapture runs a command inside a running container and
// returns its captured stdout, byte for byte. Used by the upgrade flow to
// invoke `pg_dump` inside the postgres container without the deployer
// needing PG client tools of its own. A non-zero exit is reported as an
// error, with the command's stderr folded into the message.
func (c *DockerClient) ContainerExecCapture(ctx context.Context, containerID string, cmd []string) ([]byte, error) {
	var buf bytes.Buffer
	code, errOut, err := c.ContainerExecStream(ctx, containerID, cmd, &buf)
	if err != nil {
		return buf.Bytes(), err
	}
	if code != 0 {
		return buf.Bytes(), fmt.Errorf("exec exited with code %d: %s", code, strings.TrimSpace(string(errOut)))
	}
	return buf.Bytes(), nil
}

// ContainerExecStream runs cmd inside containerID and copies its stdout to w
// verbatim, returning the exit code and a bounded tail of stderr.
//
// This is the path for anything whose output is not text. Docker frames the
// two streams over one connection and the payload inside a frame is opaque
// bytes; treating it as lines (splitting on '\n', trimming trailing CR/LF,
// dropping empty lines) silently rewrites the content. That is what the log
// demuxer does by design, which is correct for container logs and destroys a
// pg_dump.
func (c *DockerClient) ContainerExecStream(ctx context.Context, containerID string, cmd []string, w io.Writer) (int, []byte, error) {
	return c.execAttachedStream(ctx, containerID, cmd, w)
}

// ContainerExecCaptureCode runs a command inside a running container and
// returns its combined stdout+stderr (line-oriented, arrival order) plus
// the exit code. Unlike ContainerExecCapture, a non-zero exit is NOT an
// error — it is returned via exitCode so scheduled-job exec runs can record
// it. err is reserved for transport/protocol failures.
func (c *DockerClient) ContainerExecCaptureCode(ctx context.Context, containerID string, cmd []string) ([]byte, int, error) {
	buf, code, err := c.execAttached(ctx, containerID, cmd)
	out := []byte(nil)
	if buf != nil {
		out = buf.Bytes()
	}
	return out, code, err
}

// execAttached creates and runs an exec instance attached, collecting
// line-oriented output into a single buffer, then reads the exit code.
// Both streams are folded together in arrival order with line breaks
// re-added, which is what scheduled-job logs want.
//
// This path is NOT byte-exact: it runs through the log demuxer, which splits
// on newlines and trims trailing CR/LF. Anything binary must use
// ContainerExecStream instead. err is non-nil only on transport/protocol
// failure.
func (c *DockerClient) execAttached(ctx context.Context, containerID string, cmd []string) (*bytes.Buffer, int, error) {
	body, execID, err := c.execStart(ctx, containerID, cmd)
	if err != nil {
		return nil, 0, err
	}
	defer body.Close()

	buf := &bytes.Buffer{}
	dem := NewLogDemuxer(body, DemuxOptions{MaxLine: 1 << 20})
	for chunk := range dem.Out() {
		buf.WriteString(chunk.Line)
		buf.WriteByte('\n')
	}

	code, err := c.execExitCode(ctx, execID)
	if err != nil {
		return buf, 0, err
	}
	return buf, code, nil
}

// execAttachedStream is the byte-exact counterpart of execAttached: stdout
// frames are copied to w untouched and stderr is kept as a bounded tail for
// error reporting.
func (c *DockerClient) execAttachedStream(ctx context.Context, containerID string, cmd []string, w io.Writer) (int, []byte, error) {
	body, execID, err := c.execStart(ctx, containerID, cmd)
	if err != nil {
		return 0, nil, err
	}
	defer body.Close()

	stderrTail, err := copyDockerFrames(body, w, execStderrTailLimit)
	if err != nil {
		return 0, stderrTail, err
	}

	code, err := c.execExitCode(ctx, execID)
	if err != nil {
		return 0, stderrTail, err
	}
	return code, stderrTail, nil
}

// execStart creates an exec instance and starts it attached, handing back the
// raw multiplexed stream plus the exec id so the caller can decode the payload
// the way its content requires.
func (c *DockerClient) execStart(ctx context.Context, containerID string, cmd []string) (io.ReadCloser, string, error) {
	createBody, _ := json.Marshal(map[string]any{
		"AttachStdout": true,
		"AttachStderr": true,
		"Cmd":          cmd,
		"Tty":          false,
	})
	resp, err := c.do(ctx, http.MethodPost,
		"/containers/"+url.PathEscape(containerID)+"/exec", createBody)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, "", dockerError(resp)
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, "", err
	}

	startBody, _ := json.Marshal(map[string]any{
		"Detach": false,
		"Tty":    false,
	})
	startResp, err := c.do(ctx, http.MethodPost,
		"/exec/"+url.PathEscape(created.ID)+"/start", startBody)
	if err != nil {
		return nil, "", err
	}
	if startResp.StatusCode >= 300 {
		defer startResp.Body.Close()
		return nil, "", dockerError(startResp)
	}
	return startResp.Body, created.ID, nil
}

func (c *DockerClient) execExitCode(ctx context.Context, execID string) (int, error) {
	resp, err := c.do(ctx, http.MethodGet, "/exec/"+url.PathEscape(execID)+"/json", nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return 0, dockerError(resp)
	}
	var inspect struct {
		ExitCode int  `json:"ExitCode"`
		Running  bool `json:"Running"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		return 0, err
	}
	return inspect.ExitCode, nil
}

// execStderrTailLimit caps how much stderr we keep from a streaming exec. It
// only ever feeds an error message, so a chatty command must not be able to
// grow the deployer's heap while its real output goes to disk.
const execStderrTailLimit = 32 * 1024

// copyDockerFrames decodes Docker's stream multiplexing and copies the stdout
// payload to stdout verbatim, returning up to stderrLimit bytes of stderr.
//
// Frame layout: stream(1) + reserved(3) + size(uint32 BE) + payload. A frame
// that ends early means the connection died mid-command, which for a backup
// has to surface as an error instead of a short file that looks finished.
func copyDockerFrames(r io.Reader, stdout io.Writer, stderrLimit int) ([]byte, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	header := make([]byte, 8)
	var errTail bytes.Buffer

	for {
		if _, err := io.ReadFull(br, header); err != nil {
			if err == io.EOF {
				return errTail.Bytes(), nil // clean end, on a frame boundary
			}
			if err == io.ErrUnexpectedEOF {
				return errTail.Bytes(), fmt.Errorf("docker exec stream ended mid-header")
			}
			return errTail.Bytes(), err
		}
		size := int64(binary.BigEndian.Uint32(header[4:8]))
		if size == 0 {
			continue
		}

		var dst io.Writer
		switch header[0] {
		case 1:
			dst = stdout
		case 2:
			if remaining := int64(stderrLimit) - int64(errTail.Len()); remaining > 0 {
				dst = &limitedWriter{w: &errTail, remaining: remaining}
			} else {
				dst = io.Discard
			}
		default:
			dst = io.Discard
		}

		n, err := io.CopyN(dst, br, size)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return errTail.Bytes(), fmt.Errorf("docker exec stream ended after %d of %d payload bytes", n, size)
			}
			return errTail.Bytes(), err
		}
	}
}

// limitedWriter writes at most remaining bytes and silently drops the rest,
// so a stderr tail cannot grow without bound but the copy still consumes the
// whole frame.
type limitedWriter struct {
	w         io.Writer
	remaining int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.remaining <= 0 {
		return len(p), nil
	}
	keep := p
	if int64(len(keep)) > l.remaining {
		keep = keep[:l.remaining]
	}
	if _, err := l.w.Write(keep); err != nil {
		return 0, err
	}
	l.remaining -= int64(len(keep))
	return len(p), nil
}
