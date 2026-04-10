package deployer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type DockerClient struct {
	http *http.Client
	base string
}

func NewDockerClient(host string) (*DockerClient, error) {
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}
	if strings.HasPrefix(host, "unix://") {
		socketPath := strings.TrimPrefix(host, "unix://")
		transport := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		}
		return &DockerClient{http: &http.Client{Transport: transport, Timeout: 0}, base: "http://docker"}, nil
	}
	if strings.HasPrefix(host, "tcp://") {
		host = "http://" + strings.TrimPrefix(host, "tcp://")
	}
	return &DockerClient{http: &http.Client{Timeout: 0}, base: strings.TrimRight(host, "/")}, nil
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
}

type restartPolicy struct {
	Name string `json:"Name,omitempty"`
}

type networkingConfig struct {
	EndpointsConfig map[string]endpointSettings `json:"EndpointsConfig,omitempty"`
}

type endpointSettings struct{}

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
	resp, err := c.do(ctx, http.MethodPost, "/images/create?fromImage="+url.QueryEscape(imageRef), nil)
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

func (c *DockerClient) NetworkConnect(ctx context.Context, network, containerID string) error {
	if network == "" || containerID == "" {
		return nil
	}
	body, _ := json.Marshal(map[string]any{"Container": containerID})
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
