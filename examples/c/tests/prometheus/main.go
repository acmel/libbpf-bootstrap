// Build it:
//
// go mod init main
// go mod tidy
// go build
// ./main
//
// from another terminal and you’ll see the metric increasing
//
// curl 127.0.0.1:8080/metrics | grep -B 2 fake_counter
package main

import (
	"context"
	"fmt"
	"time"

	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilwait "k8s.io/apimachinery/pkg/util/wait"

	"k8s.io/klog/v2"
)

var fake_counter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "fake_counter",
	Help: "Increments at every second",
})

var another_fake_counter = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "another_fake_counter",
	Help: "Increments twice every second",
})

var fake_gauge = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "fake_gauge",
	Help: "Increments at every second",
})

// StartMetricsServer runs the prometheus listener so that KPNG metrics can be collected
// TODO add TLS Auth if configured
func StartMetricsServer(bindAddress string,
	stopChan <-chan struct{}) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	klog.Infof("Starting metrics server at %s", bindAddress)

	go func() {
		var server *http.Server
		go utilwait.Until(func() {
			var err error
			server = &http.Server{
				Addr:    bindAddress,
				Handler: mux,
			}
			err = server.ListenAndServe()

			if err != nil && err != http.ErrServerClosed {
				utilruntime.HandleError(fmt.Errorf("starting metrics server failed: %v", err))
			}
		}, 5*time.Second, stopChan)

		<-stopChan
		klog.Infof("Stopping metrics server %s", server.Addr)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			klog.Errorf("Error stopping metrics server: %v", err)
		}
	}()
}

func main() {
	fmt.Println("Prometheus demo")

	prometheus.MustRegister(fake_counter)
	prometheus.MustRegister(another_fake_counter)
	prometheus.MustRegister(fake_gauge)

	ctx := context.Background()

	StartMetricsServer("127.0.0.1:8080", ctx.Done())

	// Create a ticker that ticks every second
	ticker := time.NewTicker(time.Second)

	// Run a Goroutine increment fake counter ever second
	go func() {
		for {
			select {
			case <-ticker.C:
				fake_counter.Inc()
			}
		}
	}()

	// Run a another Goroutine increment fake counter ever second
	go func() {
		for {
			select {
			case <-ticker.C:
				another_fake_counter.Inc()
				another_fake_counter.Inc()
			}
		}
	}()

	// Run a another Goroutine increment fake gauge every second
	go func() {
		for {
			select {
			case <-ticker.C:
				fake_gauge.Inc()
			}
		}
	}()

	// Keep the main Goroutine running indefinitely
	select {}
}
