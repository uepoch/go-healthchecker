package main

import (
	"context"
	"crypto/tls"
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
	retries             int
	delayRetry          time.Duration
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
	flag.IntVarP(&retries, "retry", "r", 2, "Maximum retries for HTTP Get on failure")
	flag.DurationVar(&delayRetry, "delay", 500*time.Millisecond, "Time to wait before successive retries")
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

	l := logrus.WithFields(logrus.Fields{"ip": ip, "host": host, "headers": customHeaders})
	l.Debugln("Starting: Hello world")

	if !logrus.IsTerminal(os.Stderr) {
		hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_WARNING, filepath.Base(os.Args[0]))

		if err == nil {
			logrus.StandardLogger().Hooks.Add(hook)
		} else {
			l.Warnf("Can't connect to syslog: %s", err.Error())
		}
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := http.Client{Timeout: timeout, Transport: tr}

	ctx, cancel := context.WithCancel(context.TODO())
	wg := sync.WaitGroup{}
	wg.Add(len(urls))

	// time.AfterFunc(timeout, cancel)
	// Timeout is calculed as (Max tries * timeout + delay) + a little processing time overhead
	// e.g : for default values, timeout is (3 * 1,5s) + 100ms = 4,6 seconds if all tries timeout
	time.AfterFunc(time.Duration(retries+1)*(delayRetry+timeout)+100*time.Millisecond, func() {
		l.Fatalf("CRITICAL ERROR: Shouldn't be happening: Requests in unfinished state and not error")
		os.Exit(4)
	})

	for _, url := range urls {

		go func(url string) {
			var ok bool
			url = fmt.Sprintf("%s://%s%s", proto, ip, url)
			l := l.WithField("url", url)
			for i := 0; i <= retries; i++ {
				l := l.WithField("try", i)

				req, err := http.NewRequest(http.MethodGet, url, nil)
				if err != nil {
					l.Fatalf("Error during req initialization: %s", err.Error())
					os.Exit(1)
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
					l.Errorf("Error: %s", err.Error())
					time.Sleep(delayRetry)
					continue
				}
				defer res.Body.Close()
				if res.StatusCode < 200 || res.StatusCode > 299 {
					l.Errorf("Error Status-Code: %d", res.StatusCode)
					time.Sleep(delayRetry)
					continue
				}
				ok = true
				break
			}
			if ok {
				l.Debugf("OK")
				wg.Done()
			} else {
				cancel()
				os.Exit(1)
			}

		}(url)
	}

	if !disableDefaultCheck {
		wg.Add(1)
		go func() {
			var ok bool
			proto := "http"
			url := fmt.Sprintf("%s://%s%s", proto, ip, defUrl)
			l := l.WithField("url", url)
			for i := 0; i <= retries; i++ {
				req, _ := http.NewRequest(http.MethodGet, url, nil)
				req.WithContext(ctx)
				req.Header.Set("User-Agent", userAgent)
				res, err := client.Do(req)
				if err != nil {
					l.Errorf("Request Error: %s", err.Error())
					time.Sleep(delayRetry)
					continue
				}
				defer res.Body.Close()
				if res.StatusCode < 200 || res.StatusCode > 299 {
					l.Errorf("Error Status-Code: %d", res.StatusCode)
					time.Sleep(delayRetry)
					continue
				}
				ok = true
				break
			}
			if ok {
				l.Debugf("OK", url)
				wg.Done()
			} else {
				cancel()
				os.Exit(1)
			}
		}()
	}
	wg.Wait()
	l.Debugln("OK")

}
