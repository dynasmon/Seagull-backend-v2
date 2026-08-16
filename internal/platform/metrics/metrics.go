package metrics

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/dynasmon/Seagull-v2/internal/platform/buildinfo"
)

const Namespace = "seagull"

type Registry struct {
	prometheus *prometheus.Registry
}

func New(service string) *Registry {
	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	build := buildinfo.Read()
	info := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "build_info",
		Help:      "Identity of the running binary.",
	}, []string{"service", "version", "revision", "modified", "go_version"})
	info.WithLabelValues(
		service,
		build.Version,
		build.Revision,
		strconv.FormatBool(build.Modified),
		build.GoVersion,
	).Set(1)
	registry.MustRegister(info)

	return &Registry{prometheus: registry}
}

func (r *Registry) MustRegister(collectors ...prometheus.Collector) {
	r.prometheus.MustRegister(collectors...)
}

func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.prometheus, promhttp.HandlerOpts{
		ErrorHandling:       promhttp.HTTPErrorOnError,
		MaxRequestsInFlight: 4,
	})
}
