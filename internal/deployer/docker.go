package deployer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type DockerClient struct {
	http          *http.Client
	base          string
	registryAuths map[string]registryAuth // hostname -> credentials
}

type registryAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Auth     string `json:"auth"`
}

func NewDockerClient(host string) (*DockerClient, error) {
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}
	auths := loadDockerConfigAuths()
	if strings.HasPrefix(host, "unix://") {
		socketPath := strings.TrimPrefix(host, "unix://")
		transport := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		}
		return &DockerClient{http: &http.Client{Transport: transport, Timeout: 0}, base: "http://docker", registryAuths: auths}, nil
	}
	if strings.HasPrefix(host, "tcp://") {
		host = "http://" + strings.TrimPrefix(host, "tcp://")
	}
	return &DockerClient{http: &http.Client{Timeout: 0}, base: strings.TrimRight(host, "/"), registryAuths: auths}, nil
}

type containerCreateRequest struct {
	Image            string            `json:"Image"`
	Cmd              []string          `json:"Cmd,omitempty"`
	Env              []string          `json:"Env,omitempty"`
	Labels           map[string]string `json:"Labels,omitempty"`
	HostConfig       hostConfig        `json:"HostConfig"`
	NetworkingConfig networkingConfig  `json:"NetworkingConfig,omitempty"`
}

type hostConfig struct {
	NetworkMode   string        `json:"NetworkMode,omitempty"`
	RestartPolicy restartPolicy `json:"RestartPolicy,omitempty"`
	Mounts        []dockerMount `json:"Mounts,omitempty"`
}

type restartPolicy struct {
	Name string `json:"Name,omitempty"`
}

// dockerMount maps to the Docker Engine "Mount" object embedded in
// HostConfig.Mounts. Only the fields MUVON populates are declared;
// omitempty keeps unused options out of the wire payload so Docker
// applies its own defaults.
type dockerMount struct {
	Type          string                     `json:"Type"`
	Source        string                     `json:"Source,omitempty"`
	Target        string                     `json:"Target"`
	ReadOnly      bool                       `json:"ReadOnly,omitempty"`
	BindOptions   *dockerMountBindOptions    `json:"BindOptions,omitempty"`
	VolumeOptions *dockerMountVolumeOptions  `json:"VolumeOptions,omitempty"`
}

type dockerMountBindOptions struct {
	Propagation      string `json:"Propagation,omitempty"`
	CreateMountpoint bool   `json:"CreateMountpoint,omitempty"`
}

type dockerMountVolumeOptions struct {
	NoCopy bool              `json:"NoCopy,omitempty"`
	Labels map[string]string `json:"Labels,omitempty"`
}

type networkingConfig struct {
	EndpointsConfig map[string]endpointSettings `json:"EndpointsConfig,omitempty"`
}

type endpointSettings struct {
	Aliases []string `json:"Aliases,omitempty"`
}

type containerCreateResponse struct {
	ID       string   `json:"Id"`
	Warnings []string `json:"Warnings"`
}

type containerWaitResponse struct {
	StatusCode int64 `json:"StatusCode"`
	Error      *struct {
		Message string `json:"Message"`
	} `json:"Error,omitempty"`
}

func (c *DockerClient) ImagePull(ctx context.Context, imageRef string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/images/create?fromImage="+url.QueryEscape(imageRef), nil)
	if err != nil {
		return err
	}
	if authHeader := c.registryAuthHeader(imageRef); authHeader != "" {
		req.Header.Set("X-Registry-Auth", authHeader)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return dockerError(resp)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// registryAuthHeader returns the base64-encoded X-Registry-Auth header value
// for the registry that hosts the given image reference.
func (c *DockerClient) registryAuthHeader(imageRef string) string {
	if len(c.registryAuths) == 0 {
		return ""
	}
	// Extract registry hostname from the image reference.
	// Examples: ghcr.io/org/repo:tag -> ghcr.io, library/nginx:latest -> docker.io
	registry := "docker.io"
	parts := strings.SplitN(imageRef, "/", 2)
	if len(parts) == 2 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		registry = parts[0]
	}

	// Look up auth for this registry in the config.
	// Try exact match first, then try common aliases.
	for _, candidate := range []string{registry, "https://" + registry, "https://" + registry + "/v1/", "https://" + registry + "/v2/"} {
		if auth, ok := c.registryAuths[candidate]; ok {
			return encodeRegistryAuth(auth)
		}
	}
	return ""
}

func encodeRegistryAuth(auth registryAuth) string {
	// If username/password are set, use those; otherwise use the raw "auth" field.
	var payload map[string]string
	if auth.Username != "" {
		payload = map[string]string{
			"username": auth.Username,
			"password": auth.Password,
		}
	} else if auth.Auth != "" {
		// "auth" is base64(username:password), decode and split.
		decoded, err := base64.StdEncoding.DecodeString(auth.Auth)
		if err != nil {
			return ""
		}
		user, pass, _ := strings.Cut(string(decoded), ":")
		payload = map[string]string{
			"username": user,
			"password": pass,
		}
	} else {
		return ""
	}
	b, _ := json.Marshal(payload)
	return base64.URLEncoding.EncodeToString(b)
}

// loadDockerConfigAuths reads the Docker config.json and returns registry
// credentials. It respects the DOCKER_CONFIG env var, falling back to ~/.docker/.
func loadDockerConfigAuths() map[string]registryAuth {
	configDir := os.Getenv("DOCKER_CONFIG")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		configDir = filepath.Join(home, ".docker")
	}
	configPath := filepath.Join(configDir, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		slog.Debug("docker config not found", "path", configPath, "error", err)
		return nil
	}
	var cfg struct {
		Auths map[string]registryAuth `json:"auths"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		slog.Warn("failed to parse docker config", "path", configPath, "error", err)
		return nil
	}
	if len(cfg.Auths) > 0 {
		slog.Info("loaded docker registry credentials", "registries", len(cfg.Auths))
	}
	return cfg.Auths
}

func (c *DockerClient) EnsureNetwork(ctx context.Context, name string) error {
	if name == "" {
		return nil
	}
	resp, err := c.do(ctx, http.MethodGet, "/networks/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		return nil
	}
	if resp.StatusCode != http.StatusNotFound {
		err := dockerError(resp)
		resp.Body.Close()
		return err
	}
	resp.Body.Close()

	body, _ := json.Marshal(map[string]any{"Name": name, "CheckDuplicate": true})
	resp, err = c.do(ctx, http.MethodPost, "/networks/create", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusConflict {
		return dockerError(resp)
	}
	return nil
}

func (c *DockerClient) ContainerCreate(ctx context.Context, name string, req containerCreateRequest) (string, error) {
	body, _ := json.Marshal(req)
	resp, err := c.do(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", dockerError(resp)
	}
	var out containerCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.ID, nil
}

func (c *DockerClient) ContainerStart(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotModified {
		return dockerError(resp)
	}
	return nil
}

func (c *DockerClient) ContainerRestart(ctx context.Context, id string, timeoutSeconds int) error {
	resp, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/containers/%s/restart?t=%d", url.PathEscape(id), timeoutSeconds), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return dockerError(resp)
	}
	return nil
}

func (c *DockerClient) ContainerStop(ctx context.Context, id string, timeoutSeconds int) error {
	resp, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/containers/%s/stop?t=%d", url.PathEscape(id), timeoutSeconds), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotModified && resp.StatusCode != http.StatusNotFound {
		return dockerError(resp)
	}
	return nil
}

func (c *DockerClient) ContainerRemove(ctx context.Context, id string, force bool) error {
	resp, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/containers/%s?force=%t", url.PathEscape(id), force), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		return dockerError(resp)
	}
	return nil
}

type ContainerSummary struct {
	ID      string
	Names   []string
	Image   string
	Labels  map[string]string
	State   string // running, exited, paused, ...
	Status  string // human readable: "Up 5 minutes (healthy)"
	Created int64
}

func (c *DockerClient) ContainerList(ctx context.Context, labelFilter string) ([]ContainerSummary, error) {
	filterJSON, _ := json.Marshal(map[string][]string{"label": {labelFilter}})
	resp, err := c.do(ctx, http.MethodGet, "/containers/json?filters="+url.QueryEscape(string(filterJSON)), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, dockerError(resp)
	}
	var raw []struct {
		ID      string            `json:"Id"`
		Names   []string          `json:"Names"`
		Image   string            `json:"Image"`
		Labels  map[string]string `json:"Labels"`
		State   string            `json:"State"`
		Status  string            `json:"Status"`
		Created int64             `json:"Created"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	out := make([]ContainerSummary, len(raw))
	for i, r := range raw {
		out[i] = ContainerSummary{
			ID:      r.ID,
			Names:   r.Names,
			Image:   r.Image,
			Labels:  r.Labels,
			State:   r.State,
			Status:  r.Status,
			Created: r.Created,
		}
	}
	return out, nil
}

// ContainerListAll lists containers across all states. Pass managedOnly=true
// to filter to muvon.managed=true (the typical shipper enumeration).
func (c *DockerClient) ContainerListAll(ctx context.Context, managedOnly bool) ([]ContainerSummary, error) {
	q := "all=1"
	if managedOnly {
		filterJSON, _ := json.Marshal(map[string][]string{"label": {"muvon.managed=true"}})
		q += "&filters=" + url.QueryEscape(string(filterJSON))
	}
	resp, err := c.do(ctx, http.MethodGet, "/containers/json?"+q, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, dockerError(resp)
	}
	var raw []struct {
		ID      string            `json:"Id"`
		Names   []string          `json:"Names"`
		Image   string            `json:"Image"`
		Labels  map[string]string `json:"Labels"`
		State   string            `json:"State"`
		Status  string            `json:"Status"`
		Created int64             `json:"Created"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	out := make([]ContainerSummary, len(raw))
	for i, r := range raw {
		out[i] = ContainerSummary{
			ID:      r.ID,
			Names:   r.Names,
			Image:   r.Image,
			Labels:  r.Labels,
			State:   r.State,
			Status:  r.Status,
			Created: r.Created,
		}
	}
	return out, nil
}

// ContainerInspectResult captures the fields we use from /containers/{id}/json.
type ContainerInspectResult struct {
	ID         string
	Name       string
	Image      string // "sha256:..." digest
	ImageRef   string // human image reference from Config.Image
	Labels     map[string]string
	State      string // running, exited, paused, ...
	Status     string // human readable
	StartedAt  time.Time
	FinishedAt time.Time
	ExitCode   int
}

func (c *DockerClient) ContainerInspect(ctx context.Context, id string) (ContainerInspectResult, error) {
	var out ContainerInspectResult
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return out, dockerError(resp)
	}
	var raw struct {
		ID    string `json:"Id"`
		Name  string `json:"Name"`
		Image string `json:"Image"`
		State struct {
			Status     string `json:"Status"`
			Running    bool   `json:"Running"`
			ExitCode   int    `json:"ExitCode"`
			StartedAt  string `json:"StartedAt"`
			FinishedAt string `json:"FinishedAt"`
		} `json:"State"`
		Config struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return out, err
	}
	out.ID = raw.ID
	out.Name = strings.TrimPrefix(raw.Name, "/")
	out.Image = raw.Image
	out.ImageRef = raw.Config.Image
	out.Labels = raw.Config.Labels
	out.State = raw.State.Status
	out.Status = raw.State.Status
	out.ExitCode = raw.State.ExitCode
	if t, err := time.Parse(time.RFC3339Nano, raw.State.StartedAt); err == nil && !t.IsZero() {
		out.StartedAt = t
	}
	if t, err := time.Parse(time.RFC3339Nano, raw.State.FinishedAt); err == nil && !t.IsZero() && t.Year() > 1 {
		out.FinishedAt = t
	}
	return out, nil
}

// ContainerLogsOptions configures the /containers/{id}/logs streaming
// request. Mirrors the Docker Engine API querystring; zero values mean
// "use API default" (e.g. Tail=0 == "all").
type ContainerLogsOptions struct {
	Stdout     bool
	Stderr     bool
	Follow     bool
	Timestamps bool
	Since      time.Time // empty = no filter
	Until      time.Time
	Tail       string // "all", "100", or empty (= all on follow=false, 0 on follow=true)
}

// ContainerLogs returns the daemon's multiplexed log stream for the
// container. The caller must Close the body to terminate the daemon's
// tail goroutine. The stream uses Docker's 8-byte header framing — pair
// with NewLogDemuxer to get individual stdout/stderr lines.
//
// Timeout is intentionally zero on this client (set in NewDockerClient);
// follow streams are unbounded by design.
func (c *DockerClient) ContainerLogs(ctx context.Context, id string, opts ContainerLogsOptions) (io.ReadCloser, error) {
	q := url.Values{}
	if opts.Stdout {
		q.Set("stdout", "1")
	}
	if opts.Stderr {
		q.Set("stderr", "1")
	}
	if opts.Follow {
		q.Set("follow", "1")
	}
	if opts.Timestamps {
		q.Set("timestamps", "1")
	}
	if !opts.Since.IsZero() {
		q.Set("since", fmt.Sprintf("%d.%09d", opts.Since.Unix(), opts.Since.Nanosecond()))
	}
	if !opts.Until.IsZero() {
		q.Set("until", fmt.Sprintf("%d.%09d", opts.Until.Unix(), opts.Until.Nanosecond()))
	}
	if opts.Tail != "" {
		q.Set("tail", opts.Tail)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/containers/"+url.PathEscape(id)+"/logs?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		body := dockerError(resp)
		resp.Body.Close()
		return nil, body
	}
	return resp.Body, nil
}

// ContainerEventKind enumerates the events we forward to subscribers.
// Other Docker event types (image, network, ...) are dropped silently.
type ContainerEventKind string

const (
	ContainerEventStart   ContainerEventKind = "start"
	ContainerEventDie     ContainerEventKind = "die"
	ContainerEventDestroy ContainerEventKind = "destroy"
	ContainerEventStop    ContainerEventKind = "stop"
)

// ContainerEvent describes a relevant container lifecycle event. ID is
// always set; the rest is best-effort (Docker's events stream gives us
// labels + image on the same payload).
type ContainerEvent struct {
	Time    time.Time
	Kind    ContainerEventKind
	ID      string
	Name    string
	Image   string
	Labels  map[string]string
}

// EventsStream subscribes to /events?type=container and emits one
// ContainerEvent per relevant Docker event. The returned channel closes
// when ctx is canceled or the stream errors. errCh receives the terminal
// error (nil on clean exit).
//
// Filter is server-side (type=container), so unrelated events never hit
// the wire. Reconnects are the caller's responsibility — the shipper's
// manager wraps this in a backoff loop.
func (c *DockerClient) EventsStream(ctx context.Context) (<-chan ContainerEvent, <-chan error, error) {
	filterJSON, _ := json.Marshal(map[string][]string{"type": {"container"}})
	q := url.Values{}
	q.Set("filters", string(filterJSON))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/events?"+q.Encode(), nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 300 {
		err := dockerError(resp)
		resp.Body.Close()
		return nil, nil, err
	}

	out := make(chan ContainerEvent, 64)
	errCh := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errCh)
		defer resp.Body.Close()
		dec := json.NewDecoder(resp.Body)
		for {
			if ctx.Err() != nil {
				errCh <- ctx.Err()
				return
			}
			var raw struct {
				Type   string `json:"Type"`
				Action string `json:"Action"`
				Time   int64  `json:"time"`
				Actor  struct {
					ID         string            `json:"ID"`
					Attributes map[string]string `json:"Attributes"`
				} `json:"Actor"`
			}
			if err := dec.Decode(&raw); err != nil {
				if errors.Is(err, io.EOF) || ctx.Err() != nil {
					errCh <- ctx.Err()
					return
				}
				errCh <- err
				return
			}
			if raw.Type != "container" {
				continue
			}
			var kind ContainerEventKind
			switch raw.Action {
			case "start":
				kind = ContainerEventStart
			case "die":
				kind = ContainerEventDie
			case "destroy":
				kind = ContainerEventDestroy
			case "stop":
				kind = ContainerEventStop
			default:
				continue
			}
			ev := ContainerEvent{
				Time:   time.Unix(raw.Time, 0),
				Kind:   kind,
				ID:     raw.Actor.ID,
				Name:   raw.Actor.Attributes["name"],
				Image:  raw.Actor.Attributes["image"],
				Labels: copyLabelMap(raw.Actor.Attributes),
			}
			select {
			case out <- ev:
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			}
		}
	}()
	return out, errCh, nil
}

// copyLabelMap strips Docker's synthetic "name"/"image" attributes from
// the actor map so we don't double-record them; the rest is treated as
// container labels.
func copyLabelMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if k == "name" || k == "image" {
			continue
		}
		out[k] = v
	}
	return out
}

func (c *DockerClient) ContainerWait(ctx context.Context, id string) (int64, error) {
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/wait?condition=not-running", nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return 0, dockerError(resp)
	}
	var out containerWaitResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	if out.Error != nil && out.Error.Message != "" {
		return out.StatusCode, errors.New(out.Error.Message)
	}
	return out.StatusCode, nil
}

func (c *DockerClient) NetworkConnect(ctx context.Context, network, containerID, alias string) error {
	if network == "" || containerID == "" {
		return nil
	}
	payload := map[string]any{"Container": containerID}
	if alias != "" {
		payload["EndpointConfig"] = map[string]any{
			"Aliases": []string{alias},
		}
	}
	body, _ := json.Marshal(payload)
	resp, err := c.do(ctx, http.MethodPost, "/networks/"+url.PathEscape(network)+"/connect", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusConflict {
		return dockerError(resp)
	}
	return nil
}

func (c *DockerClient) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func dockerError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		return fmt.Errorf("docker API returned HTTP %d", resp.StatusCode)
	}
	return fmt.Errorf("docker API returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 2 * time.Second}
}
