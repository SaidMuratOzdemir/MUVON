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
	opts.Labels["muvon.managed"] = "true"

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
// returns its captured stdout. Stderr is folded into stdout (Docker's
// multiplexed stream — we run with detach=false). Used by the upgrade
// flow to invoke `pg_dump` inside the postgres container without
// the deployer needing PG client tools of its own.
func (c *DockerClient) ContainerExecCapture(ctx context.Context, containerID string, cmd []string) ([]byte, error) {
	// 1) Create exec instance
	createBody, _ := json.Marshal(map[string]any{
		"AttachStdout": true,
		"AttachStderr": true,
		"Cmd":          cmd,
		"Tty":          false,
	})
	resp, err := c.do(ctx, http.MethodPost,
		"/containers/"+url.PathEscape(containerID)+"/exec", createBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, dockerError(resp)
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return nil, err
	}

	// 2) Start exec, streaming attached. tty=false → multiplexed stream
	//    with 8-byte headers; reuse LogDemuxer on the receiving side.
	startBody, _ := json.Marshal(map[string]any{
		"Detach": false,
		"Tty":    false,
	})
	startResp, err := c.do(ctx, http.MethodPost,
		"/exec/"+url.PathEscape(created.ID)+"/start", startBody)
	if err != nil {
		return nil, err
	}
	defer startResp.Body.Close()
	if startResp.StatusCode >= 300 {
		return nil, dockerError(startResp)
	}
	// Both streams folded into a single buffer — pg_dump writes binary
	// to stdout and progress to stderr; caller wants the binary.
	stdout := &bytes.Buffer{}
	dem := NewLogDemuxer(startResp.Body, DemuxOptions{MaxLine: 1 << 20})
	for chunk := range dem.Out() {
		if chunk.Stream == "stdout" {
			stdout.WriteString(chunk.Line)
		}
	}

	// 3) Read exit code from inspect.
	inspectResp, err := c.do(ctx, http.MethodGet, "/exec/"+url.PathEscape(created.ID)+"/json", nil)
	if err != nil {
		return stdout.Bytes(), err
	}
	defer inspectResp.Body.Close()
	if inspectResp.StatusCode >= 300 {
		return stdout.Bytes(), dockerError(inspectResp)
	}
	var inspect struct {
		ExitCode int  `json:"ExitCode"`
		Running  bool `json:"Running"`
	}
	if err := json.NewDecoder(inspectResp.Body).Decode(&inspect); err != nil {
		return stdout.Bytes(), err
	}
	if inspect.ExitCode != 0 {
		return stdout.Bytes(), fmt.Errorf("exec exited with code %d", inspect.ExitCode)
	}
	return stdout.Bytes(), nil
}

var _ = time.Time{}
