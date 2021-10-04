package handlers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/release"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
	"sigs.k8s.io/yaml"

	"github.com/openshift/console/pkg/auth"
	"github.com/openshift/console/pkg/helm/actions"
	"github.com/openshift/console/pkg/helm/chartproxy"
	"github.com/openshift/console/pkg/serverutils"
	"github.com/openshift/console/pkg/version"
)

func New(apiUrl string, transport http.RoundTripper, kubeversionGetter version.KubeVersionGetter) *helmHandlers {
	h := &helmHandlers{
		ApiServerHost:           apiUrl,
		Transport:               transport,
		getActionConfigurations: actions.GetActionConfigurations,
		renderManifests:         actions.RenderManifests,
		installChart:            actions.InstallChart,
		listReleases:            actions.ListReleases,
		getRelease:              actions.GetRelease,
		getChart:                actions.GetChart,
		upgradeRelease:          actions.UpgradeRelease,
		uninstallRelease:        actions.UninstallRelease,
		rollbackRelease:         actions.RollbackRelease,
		getReleaseHistory:       actions.GetReleaseHistory,
	}

	h.newProxy = func(bearerToken string) (getter chartproxy.Proxy, err error) {
		return chartproxy.New(func() (*rest.Config, error) {
			return h.restConfig(bearerToken), nil
		}, kubeversionGetter)
	}

	return h
}

// helmHandlers provides handlers to handle helm related requests
type helmHandlers struct {
	ApiServerHost string
	Transport     http.RoundTripper

	// helm action configurator
	getActionConfigurations func(string, string, string, *http.RoundTripper) *action.Configuration

	// helm actions
	renderManifests   func(string, string, map[string]interface{}, *action.Configuration) (string, error)
	installChart      func(string, string, string, map[string]interface{}, *action.Configuration) (*release.Release, error)
	listReleases      func(*action.Configuration) ([]*release.Release, error)
	upgradeRelease    func(string, string, string, map[string]interface{}, *action.Configuration) (*release.Release, error)
	uninstallRelease  func(string, *action.Configuration) (*release.UninstallReleaseResponse, error)
	rollbackRelease   func(string, int, *action.Configuration) (*release.Release, error)
	getRelease        func(string, *action.Configuration) (*release.Release, error)
	getChart          func(chartUrl string, conf *action.Configuration) (*chart.Chart, error)
	getReleaseHistory func(releaseName string, conf *action.Configuration) ([]*release.Release, error)
	newProxy          func(bearerToken string) (chartproxy.Proxy, error)
}

func (h *helmHandlers) restConfig(bearerToken string) *rest.Config {
	return &rest.Config{
		Host:        h.ApiServerHost,
		BearerToken: bearerToken,
		Transport:   h.Transport,
	}
}

func (h *helmHandlers) HandleHelmRenderManifests(user *auth.User, w http.ResponseWriter, r *http.Request) {
	var req HelmRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	conf := h.getActionConfigurations(h.ApiServerHost, req.Namespace, user.Token, &h.Transport)
	resp, err := h.renderManifests(req.Name, req.ChartUrl, req.Values, conf)
	if err != nil {
		serverutils.SendResponse(w, http.StatusBadGateway, serverutils.ApiError{Err: fmt.Sprintf("Failed to render manifests: %v", err)})
		return
	}

	w.Header().Set("Content-Type", "text/yaml")
	w.Write([]byte(resp))
}

func (h *helmHandlers) HandleHelmInstall(user *auth.User, w http.ResponseWriter, r *http.Request) {
	var req HelmRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		serverutils.SendResponse(w, http.StatusBadGateway, serverutils.ApiError{Err: fmt.Sprintf("Failed to parse request: %v", err)})
		return
	}

	conf := h.getActionConfigurations(h.ApiServerHost, req.Namespace, user.Token, &h.Transport)
	resp, err := h.installChart(req.Namespace, req.Name, req.ChartUrl, req.Values, conf)
	if err != nil {
		serverutils.SendResponse(w, http.StatusBadGateway, serverutils.ApiError{Err: fmt.Sprintf("Failed to install helm chart: %v", err)})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	res, _ := json.Marshal(resp)
	w.Write(res)
}

func (h *helmHandlers) HandleHelmList(user *auth.User, w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	ns := params.Get("ns")

	conf := h.getActionConfigurations(h.ApiServerHost, ns, user.Token, &h.Transport)
	resp, err := h.listReleases(conf)
	if err != nil {
		serverutils.SendResponse(w, http.StatusBadGateway, serverutils.ApiError{Err: fmt.Sprintf("Failed to list helm releases: %v", err)})
		return
	}

	w.Header().Set("Content-Type", "application/json")

	res, _ := json.Marshal(resp)
	w.Write(res)
}

func (h *helmHandlers) HandleGetRelease(user *auth.User, w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	ns := queryParams.Get("ns")
	chartName := queryParams.Get("name")

	conf := h.getActionConfigurations(h.ApiServerHost, ns, user.Token, &h.Transport)
	release, err := h.getRelease(chartName, conf)
	if err != nil {
		serverutils.SendResponse(w, http.StatusBadGateway, serverutils.ApiError{Err: fmt.Sprintf("Failed to find helm release: %v", err)})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	rawManifest, err := json.Marshal(release)
	if err != nil {
		serverutils.SendResponse(w, http.StatusInternalServerError, serverutils.ApiError{Err: fmt.Sprintf("Failed to find helm release: %v", err)})
		return
	}
	w.Write(rawManifest)
}

func (h *helmHandlers) HandleChartGet(user *auth.User, w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	chartUrl := params.Get("url")

	// scope request to default namespace
	conf := h.getActionConfigurations(h.ApiServerHost, "default", user.Token, &h.Transport)
	resp, err := h.getChart(chartUrl, conf)
	if err != nil {
		serverutils.SendResponse(w, http.StatusBadRequest, serverutils.ApiError{Err: fmt.Sprintf("Failed to retrieve chart: %v", err)})
		return
	}

	w.Header().Set("Content-Type", "application/json")

	res, _ := json.Marshal(resp)
	w.Write(res)
}

func (h *helmHandlers) HandleUpgradeRelease(user *auth.User, w http.ResponseWriter, r *http.Request) {
	var req HelmRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		serverutils.SendResponse(w, http.StatusBadRequest, serverutils.ApiError{Err: fmt.Sprintf("Failed to parse request: %v", err)})
		return
	}

	conf := h.getActionConfigurations(h.ApiServerHost, req.Namespace, user.Token, &h.Transport)
	resp, err := h.upgradeRelease(req.Namespace, req.Name, req.ChartUrl, req.Values, conf)
	if err != nil {
		if err.Error() == actions.ErrReleaseRevisionNotFound.Error() {
			serverutils.SendResponse(w, http.StatusNotFound, serverutils.ApiError{Err: fmt.Sprintf("Failed to rollback helm releases: %v", err)})
			return
		}
		serverutils.SendResponse(w, http.StatusBadGateway, serverutils.ApiError{Err: fmt.Sprintf("Failed to upgrade helm release: %v", err)})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	res, _ := json.Marshal(resp)
	w.Write(res)
}

func (h *helmHandlers) HandleUninstallRelease(user *auth.User, w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	ns := params.Get("ns")
	rel := params.Get("name")

	conf := h.getActionConfigurations(h.ApiServerHost, ns, user.Token, &h.Transport)
	resp, err := h.uninstallRelease(rel, conf)
	if err != nil {
		if err.Error() == actions.ErrReleaseNotFound.Error() {
			serverutils.SendResponse(w, http.StatusNotFound, serverutils.ApiError{Err: fmt.Sprintf("Failed to uninstall helm release: %v", err)})
			return
		}
		serverutils.SendResponse(w, http.StatusBadGateway, serverutils.ApiError{Err: fmt.Sprintf("Failed to uninstall helm release: %v", err)})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	res, _ := json.Marshal(resp)
	w.Write(res)
}

func (h *helmHandlers) HandleRollbackRelease(user *auth.User, w http.ResponseWriter, r *http.Request) {
	var req HelmRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		serverutils.SendResponse(w, http.StatusBadGateway, serverutils.ApiError{Err: fmt.Sprintf("Failed to parse request: %v", err)})
		return
	}

	conf := h.getActionConfigurations(h.ApiServerHost, req.Namespace, user.Token, &h.Transport)
	rel, err := h.rollbackRelease(req.Name, req.Version, conf)
	if err != nil {
		if err.Error() == actions.ErrReleaseRevisionNotFound.Error() {
			serverutils.SendResponse(w, http.StatusNotFound, serverutils.ApiError{Err: fmt.Sprintf("Failed to rollback helm releases: %v", err)})
			return
		}
		serverutils.SendResponse(w, http.StatusBadGateway, serverutils.ApiError{Err: fmt.Sprintf("Failed to rollback helm releases: %v", err)})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	res, _ := json.Marshal(rel)
	w.Write(res)
}

func (h *helmHandlers) HandleGetReleaseHistory(user *auth.User, w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	name := params.Get("name")
	ns := params.Get("ns")
	conf := h.getActionConfigurations(h.ApiServerHost, ns, user.Token, &h.Transport)
	rels, err := h.getReleaseHistory(name, conf)
	if err != nil {
		if err.Error() == actions.ErrReleaseNotFound.Error() {
			serverutils.SendResponse(w, http.StatusNotFound, serverutils.ApiError{Err: fmt.Sprintf("Failed to list helm release history: %v", err)})
			return
		}
		serverutils.SendResponse(w, http.StatusBadGateway, serverutils.ApiError{Err: fmt.Sprintf("Failed to list helm release history: %v", err)})
		return
	}
	res, _ := json.Marshal(rels)
	w.Header().Set("Content-Type", "application/json")
	w.Write(res)
}

func (h *helmHandlers) HandleIndexFile(user *auth.User, w http.ResponseWriter, r *http.Request) {

	proxy, err := h.newProxy(user.Token)

	if err != nil {
		serverutils.SendResponse(w, http.StatusInternalServerError, serverutils.ApiError{Err: fmt.Sprintf("Failed to get k8s config: %v", err)})
		return
	}

	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "no-store, must-revalidate")

	// Setting this by default to true, this always serves helm index file with compatible chart lists.
	onlyCompatible := true
	onlyCompatibleParam := r.URL.Query().Get("onlyCompatible")
	if onlyCompatibleParam != "" {
		// set default to true if not provided in the query param
		var err error
		onlyCompatible, err = strconv.ParseBool(onlyCompatibleParam)
		if err != nil {
			serverutils.SendResponse(w, http.StatusBadRequest, serverutils.ApiError{Err: fmt.Sprintf("Supported value for onlyCompatible query param is true or false, received: %s", onlyCompatibleParam)})
			return
		}
	}

	indexFile, err := proxy.IndexFile(onlyCompatible)

	if err != nil {
		serverutils.SendResponse(w, http.StatusInternalServerError, serverutils.ApiError{Err: fmt.Sprintf("Failed to get index file: %v", err)})
		return
	}

	out, err := yaml.Marshal(indexFile)

	if err != nil {
		serverutils.SendResponse(w, http.StatusInternalServerError, serverutils.ApiError{Err: fmt.Sprintf("Failed to deserialize index file to yaml: %v", err)})
		return
	}

	w.Write(out)
}

func (h *helmHandlers) HandleHelmMetrics(user *auth.User, w http.ResponseWriter, r *http.Request) {
	// Redirect to the "/metrics" endpoint in "openshift-console-operator" namespace
	url := "https://metrics.openshift-console-operator.svc/metrics"
	// ips, err := net.LookupIP("metrics.openshift-console-operator.svc")
	// if err != nil {
	// 	klog.Infof("Could not get IPs: %v\n", err)
	// 	return
	// }
	// klog.Info("Redirected to metrics.openshift-console-operator: %s", ips[0].String())
	// klog.Infof("user token %s", user.Token)
	bearer := "Bearer " + user.Token
	r.Header.Add("Authorization", bearer)
	// http.Redirect(w, r, url, http.StatusSeeOther)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	r.Body = ioutil.NopCloser(bytes.NewReader(body))
	proxyReq, err := http.NewRequest(r.Method, url, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	proxyReq.Header = make(http.Header)
	for h, v := range r.Header {
		proxyReq.Header[h] = v
	}

	// Mitigate: x509: certificate signed by unknown authority
	klog.Info("Disable the client side certificate verification")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := http.Client{Transport: tr}
	klog.Infof("httpClient: %+v", httpClient)
	resp, err := httpClient.Do(proxyReq)
	if err != nil {
		klog.Infof("/metrics err: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	klog.Infof("/metrics response: %+v", resp)

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			klog.Fatal(err)
		}
		bodyString := string(bodyBytes)
		klog.Infof("/metrics response body: %s", bodyString)
	}

	// Set response header
	for h, v := range resp.Header {
		w.Header()[h] = v
	}
	// Set response body
	io.Copy(w, resp.Body)

	defer resp.Body.Close()
	// // parse the url
	// url, _ := url.Parse("https://metrics.openshift-console-operator.svc/metrics")

	// // create the reverse proxy
	// proxy := httputil.NewSingleHostReverseProxy(url)
	// proxy.Transport = &http.Transport{
	// 	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	// }

	// // Update the headers to allow for SSL redirection
	// r.URL.Host = url.Host
	// r.URL.Scheme = url.Scheme
	// r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	// r.Host = url.Host

	// bearer := "Bearer " + user.Token
	// r.Header.Add("Authorization", bearer)

	// // Note that ServeHttp is non blocking and uses a go routine under the hood
	// proxy.ServeHTTP(w, r)
}
