package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"encoding/gob"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/go-chi/chi/v5"
	"github.com/rs/xid"
	"golang.org/x/exp/slog"
)

var (
	host, port, email, domain, certKey, cert string
	dev                                      bool
	indexPage, deletePage                    []byte
	decPageTmpl                              *template.Template
	err                                      error

	visitFile *os.File
	visits    = make(map[string]int)
)

const (
	ext = ".inc"
)

//go:embed templates/*
var tmpl embed.FS

func main() {
	if err = run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	setupFlags()

	loadVisitCounts()

	visitFile, err = os.OpenFile("counts.gob", os.O_RDWR|os.O_CREATE, 0600)
	defer visitFile.Close()

	loadHTMLTemplates()

	mux := newRouter()

	srv, err := setupServer(mux)
	if err != nil {
		return err
	}

	go func() {
		if dev {
			slog.Info("server starting", "path", fmt.Sprintf("http://%s:%s", host, port))
		}

		_ = srv.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	<-sigCh

	return nil
}

func loadVisitCounts() {
	countVals, err := os.ReadFile("counts.gob")
	if err != nil {
		return
	}

	gob.NewDecoder(bytes.NewReader(countVals)).Decode(&visits)
}

func saveCounts(v map[string]int) {
	err = gob.NewEncoder(visitFile).Encode(v)
	if err != nil {
		slog.Error("gob.NewEncoder", err)
	}
}

func setupServer(mux http.Handler) (*http.Server, error) {
	srv := http.Server{
		Addr:              fmt.Sprintf("%s:%s", host, port),
		Handler:           mux,
		ReadTimeout:       time.Second * 60,
		ReadHeaderTimeout: time.Second * 30,
		WriteTimeout:      time.Second * 30,
		MaxHeaderBytes:    1 << 12,
	}

	if cert == "" && certKey == "" {
		domains := strings.Split(domain, ",")

		ca := certmagic.LetsEncryptStagingCA

		if !dev {
			ca = certmagic.LetsEncryptProductionCA
		}

		magic := certmagic.NewDefault()
		issuer := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
			CA:     ca,
			Email:  email,
			Agreed: true,
		})
		magic.Issuers = []certmagic.Issuer{issuer}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		err := magic.ManageSync(ctx, domains)
		if err != nil {
			return nil, fmt.Errorf("magic.ManageSync: %w", err)
		}

		tlsConfig := magic.TLSConfig()

		tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)

		srv.Handler = issuer.HTTPChallengeHandler(mux)
		srv.TLSConfig = tlsConfig
	}

	if cert != "" && certKey != "" {
		cer, err := tls.LoadX509KeyPair(cert, certKey)
		if err != nil {
			slog.Error("tls.LoadX509KeyPair", err)
			return nil, err
		}

		tlsConfig := &tls.Config{
			Certificates:     []tls.Certificate{cer},
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		}
		srv.TLSConfig = tlsConfig
	}

	return &srv, nil
}

func newRouter() http.Handler {
	mux := chi.NewRouter()
	mux.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write(indexPage)
	})

	mux.Post("/", func(w http.ResponseWriter, r *http.Request) {
		type NewContent struct {
			Data     string `json:"data"`
			Password string `json:"password"`
			Submit   string `json:"submit"`
		}
		var nc NewContent
		//err = json.NewDecoder(r.Body).Decode(&nc)
		//if err != nil {
		//	http.Error(w, err.Error(), http.StatusInternalServerError)
		//	return
		//}
		nc.Data = r.PostFormValue("data")
		nc.Password = r.PostFormValue("password")
		nc.Submit = r.PostFormValue("submit")

		// iflen([]byte(nc.Password))!=32{}
		if len([]byte(nc.Password)) != 32 {
			http.Error(w, "password must be 32 char", http.StatusInternalServerError)
			return
		}

		encd, err := EncryptAES([]byte(nc.Password), []byte(nc.Data))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		name := xid.New().String()

		err = os.WriteFile(name+ext, encd, 0600)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		link := fmt.Sprintf("http://%s:%s/%s.txt", host, port, name)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`<a href="%s">%s</a>`, link, link)))
	})

	mux.Get("/{file}.txt", func(w http.ResponseWriter, r *http.Request) {
		// http://127.0.0.1:4430/ceid8micnjmqu3i77sf0.txt
		// iflen([]byte(nc.Password))!=32{}
		visitText := "This data has never been opened."
		file := chi.URLParam(r, "file")
		count := visits[file]
		if count > 0 {
			visitText = fmt.Sprintf("This data has been opened for %d time(s).", count)
		}

		data := struct {
			Visit    string
			BasePath string
		}{
			Visit:    visitText,
			BasePath: r.RequestURI,
		}
		decPageTmpl.Execute(w, data)
		//w.Write(decPage)
	})

	mux.Post("/{file}.txt", func(w http.ResponseWriter, r *http.Request) {
		// @TODO: check the sumbit?
		pass := r.PostFormValue("password")
		file := chi.URLParam(r, "file")

		content, err := os.ReadFile(file + ext)
		if err != nil {
			// don't return 404 even if it's a fs.PathError
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"message": "something went wrong "}`, http.StatusInternalServerError)
			return
		}
		res, err := DecryptAES([]byte(pass), content)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		incVisit(file)

		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write(res)
	})

	mux.Get("/{file}.txt/delete", func(w http.ResponseWriter, r *http.Request) {
		w.Write(deletePage)
	})

	mux.Post("/{file}.txt/delete", func(w http.ResponseWriter, r *http.Request) {
		// @TODO: check the sumbit?
		pass := r.PostFormValue("password")
		file := chi.URLParam(r, "file")

		content, err := os.ReadFile(file + ext)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"message": "something went wrong "}`, http.StatusInternalServerError)
			return
		}

		_, err = DecryptAES([]byte(pass), content)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// key is valid
		// delete the file
		err = os.Remove(file + ext)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "success"}`))
	})

	return mux
}

func incVisit(file string) {
	visits[file] += 1

	saveCounts(visits)
}

func loadHTMLTemplates() {
	indexPage, err = tmpl.ReadFile("templates/index.html")
	if err != nil {
		slog.Error("tmpl.ReadFile", err)
		os.Exit(1)
	}

	decPage, err := tmpl.ReadFile("templates/decrypt.html")
	if err != nil {
		slog.Error("tmpl.ReadFile", err)
		os.Exit(1)
	}

	decPageTmpl, err = template.New("decrypt").Parse(string(decPage))
	if err != nil {
		slog.Error("template.New", err)
		os.Exit(1)
	}

	deletePage, err = tmpl.ReadFile("templates/delete.html")
	if err != nil {
		slog.Error("tmpl.ReadFile", err)
		os.Exit(1)
	}
}

func setupFlags() {
	flag.BoolVar(&dev, "dev", true, "set true while in development")
	flag.StringVar(&host, "host", "localhost", "host to run the server")
	flag.StringVar(&port, "port", "80", "port to run the server")
	flag.StringVar(&email, "email", "", "email to be used by autocert")
	flag.StringVar(&domain, "domain", "", "domain to be used by autocert. If empty, the value for host will be used")
	flag.StringVar(&certKey, "cert-key", "", "certificate key file")
	flag.StringVar(&cert, "cert", "", "certificate file")
	flag.Parse()

	flag.VisitAll(func(f *flag.Flag) {
		name := strings.ToUpper(strings.Replace(f.Name, "-", "_", -1))
		if value, ok := os.LookupEnv(name); ok {
			err2 := flag.Set(f.Name, value)
			if err2 != nil {
				err = fmt.Errorf("failed setting flag from environment: %w", err2)
			}
		}
	})

	if domain == "" {
		domain = host
	}
}
