package main

import (
	"context"
	"net/http"
	"time"

	"fmt"

	"os"

	"sync"

	"github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

var (
	urls    []string
	defUrl  string
	ip      string
	host    string
	verbose bool
	secure  bool
	timeout time.Duration
	proto   string
)

func main() {
	flag.StringVar(&defUrl, "default-url", "/lb_status", "Override the default URL")
	flag.StringArrayVarP(&urls, "url", "u", nil, "List of custom healthcheck that will be called on IP with HOST Host header")
	flag.StringVarP(&ip, "ip", "i", "127.0.0.1", "IP to use with healthchecks")
	flag.BoolVarP(&secure, "https", "s", false, "Use Https when calling endpoints")
	flag.StringVarP(&host, "host", "H", "", "HOST to use when calling custom healthchecks")
	flag.BoolVarP(&verbose, "debug", "v", true, "Verbose output")
	flag.DurationVarP(&timeout, "timeout", "t", 1*time.Second, "Set the timeout for calls before returning")

	flag.Parse()

	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if secure {
		proto = "https"
	} else {
		proto = "http"
	}

	l := logrus.WithFields(logrus.Fields{"urls": urls, "defaultUrl": defUrl, "ip": ip, "host": host})
	l.Debugln("Starting: Hello world")

	client := http.Client{Timeout: timeout}

	ctx, cancel := context.WithCancel(context.TODO())
	wg := sync.WaitGroup{}
	wg.Add(1 + len(urls))

	time.AfterFunc(timeout, cancel)
	time.AfterFunc(timeout*2, func() {
		l.Fatalf("CRITICAL ERROR: Shouldn't be happening: Requests in unfinished state and not error")
		os.Exit(4)
	})

	for _, url := range urls {

		go func(url string) {
			req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s://%s%s", proto, ip, url), nil)
			req.WithContext(ctx)
			req.Host = host
			res, err := client.Do(req)
			if err != nil {
				cancel()
				l.Fatalf("Error: %s", err.Error())
				os.Exit(2)
			}
			if res.StatusCode < 200 || res.StatusCode > 299 {
				cancel()
				l.Fatalf("Error during the call of %s://%s%s : %d", proto, ip, url, res.StatusCode)
				os.Exit(3)
			}
			wg.Done()

		}(url)
	}

	go func() {
		proto = "http"
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s://%s%s", proto, ip, defUrl), nil)
		req.WithContext(ctx)
		res, err := client.Do(req)
		if err != nil {
			cancel()
			l.Fatalf("Error during the call of %s://%s%s : %s", proto, ip, defUrl, err.Error())
			os.Exit(2)
		}
		if res.StatusCode < 200 || res.StatusCode > 299 {
			cancel()
			l.Fatalf("Error during the call of %s://%s%s : %d", proto, ip, defUrl, res.StatusCode)
			os.Exit(3)
		}
		wg.Done()

	}()
	wg.Wait()
	l.Infoln("Success !")

}
