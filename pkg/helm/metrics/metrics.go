package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

var (
	consoleHelmInstallCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "console_helm_install_count",
			Help: "Number of Helm installation from console.",
		},
		[]string{"releaseName", "chartName", "chartVersion"},
	)
)

func init() {
	prometheus.MustRegister(consoleHelmInstallCount)
}

// func HandleHelmMetrics(user *auth.User, w http.ResponseWriter, r *http.Request) {
// 	klog.Info("/metrics handler called")
// 	k8smetrics.HandlerFor(legacyregistry.DefaultGatherer, k8smetrics.HandlerOpts{})
// }

func HandleconsoleHelmInstallCount(releaseName, chartName, chartVersion string) {
	defer recoverMetricPanic()

	klog.Infof("metric console_helm_install_count: %s %s %s", releaseName, chartName, chartVersion)
	consoleHelmInstallCount.WithLabelValues(releaseName, chartName, chartVersion).Add(1)
}

// We will never want to panic our operator because of metric saving.
// Therefore, we will recover our panics here and error log them
// for later diagnosis but will never fail the operator.
// Reference: https://github.com/openshift/console-operator/blob/master/pkg/console/metrics/metrics.go#L80
func recoverMetricPanic() {
	if r := recover(); r != nil {
		klog.Errorf("Recovering from metric function - %v", r)
	}
}
