package main

import (
	"context"
	"log/syslog"
	"net/http"
	"path/filepath"
	"time"

	"fmt"

	"os"

	"sync"

	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"

	"strings"

	flag "github.com/spf13/pflag"
)

var (
	urls                []string
	defUrl              string
	ip                  string
	host                string
	userAgent           string
	verbose             bool
	disableDefaultCheck bool
	secure              bool
	timeout             time.Duration
	customHeaders       []string
	proto               string
)

func main() {
	flag.StringVar(&defUrl, "default-url", "/lb_status", "Override the default URL")
	flag.BoolVarP(&disableDefaultCheck, "disable-default", "d", false, "Use this when you only need custom checks")
	flag.StringArrayVarP(&urls, "url", "u", nil, "List of custom healthcheck that will be called on IP with HOST Host header")
	flag.StringArrayVarP(&customHeaders, "header", "k", nil, "List of headers injected with custom url checks.")
	flag.StringVar(&userAgent, "user-agent", "Healthchecker", "Use this to define user-agent used for calls")
	flag.StringVarP(&ip, "ip", "i", "127.0.0.1", "IP to use with healthchecks")
	flag.BoolVarP(&secure, "https", "s", false, "Use Https when calling endpoints")
	flag.StringVarP(&host, "host", "H", "", "HOST to use when calling custom healthchecks")
	flag.BoolVarP(&verbose, "debug", "v", false, "Verbose output")
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

	l := logrus.WithFields(logrus.Fields{"urls": urls, "defaultUrl": defUrl, "ip": ip, "host": host, "headers": customHeaders})
	l.Debugln("Starting: Hello world")

	if logrus.IsTerminal(os.Stderr) {
		hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_INFO, filepath.Base(os.Args[0]))

		if err == nil {
			logrus.StandardLogger().Hooks.Add(hook)
		} else {
			l.Warnf("Can't connect to syslog: %s", err.Error())
		}
	}

	client := http.Client{Timeout: timeout}

	ctx, cancel := context.WithCancel(context.TODO())
	wg := sync.WaitGroup{}
	wg.Add(len(urls))

	time.AfterFunc(timeout, cancel)
	time.AfterFunc(timeout*2, func() {
		l.Fatalf("CRITICAL ERROR: Shouldn't be happening: Requests in unfinished state and not error")
		os.Exit(4)
	})

	for _, url := range urls {

		go func(url string) {
			req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s://%s%s", proto, ip, url), nil)
			if err != nil {
				l.Fatalf("Error during req initialization: %s", err.Error())
				os.Exit(2)
			}
			req.WithContext(ctx)
			req.Host = host
			req.Header.Set("User-Agent", userAgent)
			for _, head := range customHeaders {
				s := strings.Split(head, ":")
				if len(s) != 2 {
					l.Fatalf("Error during the Headers parsing, please check: '%s'", head)
				}
				req.Header.Set(strings.TrimSpace(s[0]), strings.TrimSpace(s[1]))
			}
			res, err := client.Do(req)
			if err != nil {
				cancel()
				l.Fatalf("Error: %s", err.Error())
				os.Exit(2)
			}
			defer res.Body.Close()
			if res.StatusCode < 200 || res.StatusCode > 299 {
				cancel()
				l.Fatalf("Error during the call of %s://%s%s : %d", proto, ip, url, res.StatusCode)
				os.Exit(3)
			}
			l.Debugf("Call success: %s", fmt.Sprintf("%s://%s%s", proto, ip, url))
			wg.Done()

		}(url)
	}

	if !disableDefaultCheck {
		wg.Add(1)
		go func() {
			proto = "http"
			req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s://%s%s", proto, ip, defUrl), nil)
			req.WithContext(ctx)
			req.Header.Set("User-Agent", userAgent)
			res, err := client.Do(req)
			if err != nil {
				cancel()
				l.Fatalf("Error during the call of %s://%s%s : %s", proto, ip, defUrl, err.Error())
				os.Exit(2)
			}
			defer res.Body.Close()
			if res.StatusCode < 200 || res.StatusCode > 299 {
				cancel()
				l.Fatalf("Error during the call of %s://%s%s : %d", proto, ip, defUrl, res.StatusCode)
				os.Exit(3)
			}
			l.Debugf("Call success: %s", fmt.Sprintf("%s://%s%s", proto, ip, defUrl))
			wg.Done()

		}()
	}
	wg.Wait()
	l.Infoln("OK")

}
