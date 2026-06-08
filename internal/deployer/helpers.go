package deployer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
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
// returns its captured stdout. Used by the upgrade flow to invoke
// `pg_dump` inside the postgres container without the deployer needing PG
// client tools of its own. A non-zero exit is reported as an error.
func (c *DockerClient) ContainerExecCapture(ctx context.Context, containerID string, cmd []string) ([]byte, error) {
	buf, code, err := c.execAttached(ctx, containerID, cmd, false)
	out := []byte(nil)
	if buf != nil {
		out = buf.Bytes()
	}
	if err != nil {
		return out, err
	}
	if code != 0 {
		return out, fmt.Errorf("exec exited with code %d", code)
	}
	return out, nil
}

// ContainerExecCaptureCode runs a command inside a running container and
// returns its combined stdout+stderr (line-oriented, arrival order) plus
// the exit code. Unlike ContainerExecCapture, a non-zero exit is NOT an
// error — it is returned via exitCode so scheduled-job exec runs can record
// it. err is reserved for transport/protocol failures.
func (c *DockerClient) ContainerExecCaptureCode(ctx context.Context, containerID string, cmd []string) ([]byte, int, error) {
	buf, code, err := c.execAttached(ctx, containerID, cmd, true)
	out := []byte(nil)
	if buf != nil {
		out = buf.Bytes()
	}
	return out, code, err
}

// execAttached creates and runs an exec instance attached, collecting
// output into a single buffer in arrival order, then reads the exit code.
// includeStderr folds stderr in and re-adds line breaks (job logs are
// line-oriented); when false only stdout is kept verbatim (binary-safe for
// pg_dump). err is non-nil only on transport/protocol failure.
func (c *DockerClient) execAttached(ctx context.Context, containerID string, cmd []string, includeStderr bool) (*bytes.Buffer, int, error) {
	createBody, _ := json.Marshal(map[string]any{
		"AttachStdout": true,
		"AttachStderr": true,
		"Cmd":          cmd,
		"Tty":          false,
	})
	resp, err := c.do(ctx, http.MethodPost,
		"/containers/"+url.PathEscape(containerID)+"/exec", createBody)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, 0, dockerError(resp)
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, 0, err
	}

	startBody, _ := json.Marshal(map[string]any{
		"Detach": false,
		"Tty":    false,
	})
	startResp, err := c.do(ctx, http.MethodPost,
		"/exec/"+url.PathEscape(created.ID)+"/start", startBody)
	if err != nil {
		return nil, 0, err
	}
	defer startResp.Body.Close()
	if startResp.StatusCode >= 300 {
		return nil, 0, dockerError(startResp)
	}
	buf := &bytes.Buffer{}
	dem := NewLogDemuxer(startResp.Body, DemuxOptions{MaxLine: 1 << 20})
	for chunk := range dem.Out() {
		if chunk.Stream == "stdout" || (includeStderr && chunk.Stream == "stderr") {
			buf.WriteString(chunk.Line)
			if includeStderr {
				buf.WriteByte('\n')
			}
		}
	}

	inspectResp, err := c.do(ctx, http.MethodGet, "/exec/"+url.PathEscape(created.ID)+"/json", nil)
	if err != nil {
		return buf, 0, err
	}
	defer inspectResp.Body.Close()
	if inspectResp.StatusCode >= 300 {
		return buf, 0, dockerError(inspectResp)
	}
	var inspect struct {
		ExitCode int  `json:"ExitCode"`
		Running  bool `json:"Running"`
	}
	if err := json.NewDecoder(inspectResp.Body).Decode(&inspect); err != nil {
		return buf, 0, err
	}
	return buf, inspect.ExitCode, nil
}

var _ = time.Time{}
