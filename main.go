package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"embed"
	"encoding/gob"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"log/slog"

	"github.com/go-chi/chi/v5"
	"github.com/rs/xid"

	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/jmoiron/sqlx"
)

var (
	host, port, email, domain, certKey, cert, database_url string
	dev                                                    bool
	indexPage, deletePage                                  []byte
	decPageTmpl                                            *template.Template
	db                                                     *sqlx.DB

	visitFile *os.File
	visits    = make(map[string]int)

	//go:embed templates/*
	tmpl embed.FS

	// id content openned created_at updated_at
	schema = `CREATE TABLE IF NOT EXISTS files (
		id			varchar(255) PRIMARY KEY,
		content		bytea,
		openned		integer DEFAULT 0,
		created_at	timestamp with time zone,
		updated_at	timestamp with time zone
	);`
)

const (
	ext = ".inc"
)

type RespError struct {
	Status bool
	Error  string
}

func main() {
	if err := run(); err != nil {
		slog.Error("failed to run the application", "error", err)
		os.Exit(1)
	}
}

func run() error {
	slog.Info("starting the application...")
	setupFlags()

	var err error
	db, err = sqlx.Open("pgx", database_url)
	if err != nil {
		slog.Error("failed connect to the db", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		return fmt.Errorf("failed to ping the db: %w", err)
	}

	db.MustExec(schema)

	err = loadVisitCounts()
	if err != nil {
		return fmt.Errorf("failed to load openned: %w", err)
	}

	visitFile, err = os.OpenFile("counts.gob", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("failed to open the visit file: %w", err)
	}
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

		err = srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("failed to run server", "error", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	<-sigCh

	slog.Info("shutting down the server...")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	srv.Shutdown(ctx)

	return nil
}

func loadVisitCounts() error {
	res := []struct {
		ID      string
		Openned int
	}{}

	err := db.Select(&res, "SELECT id, openned FROM files")
	if err != nil {
		return err
	}

	for _, v := range res {
		visits[v.ID] = v.Openned
	}

	return nil
}

func saveCounts(v map[string]int) {
	err := gob.NewEncoder(visitFile).Encode(v)
	if err != nil {
		slog.Error("gob.NewEncoder", "error", err)
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

		ctx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
		defer cancel()

		db.NamedExecContext(ctx, `INSERT INTO files (id, content, created_at) VALUES (:id, :content, NOW())`, map[string]interface{}{
			"id":      name,
			"content": encd,
		})

		link := fmt.Sprintf("%s/%s.txt", domain, name)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<a href="%s">%s</a>`, link, link)
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

		var content []byte
		err := db.Get(&content, "SELECT content FROM files WHERE id=$1", file)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				slog.Error("failed to db.Get", "error", err)
			}
			// don't return 404
			http.Error(w, `{"message": "something went wrong"}`, http.StatusInternalServerError)
			return
		}

		res, err := DecryptAES([]byte(pass), content)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			res := RespError{Error: err.Error()}
			err = json.NewEncoder(w).Encode(res)
			if err != nil {
				slog.Error("failed to write the response on decryption failure", "error", err)
			}
			return
		}

		err = incVisit(file)
		if err != nil {
			slog.Error("failed to incVisit", "error", err)
			w.Header().Set("Content-Type", "application/json")
			e := RespError{Error: err.Error()}
			err = json.NewEncoder(w).Encode(e)
			if err != nil {
				slog.Error("failed to write the response on incVisit failure", "error", err)
			}
			return
		}

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

		var content []byte
		err := db.Get(&content, "SELECT content FROM files WHERE id=$1", file)
		if err != nil {
			slog.Error("failed to db.Get", "error", err)
			http.Error(w, `{"message": "something went wrong"}`, http.StatusInternalServerError)
			return
		}

		_, err = DecryptAES([]byte(pass), content)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			res := RespError{Error: err.Error()}
			err = json.NewEncoder(w).Encode(res)
			if err != nil {
				slog.Error("failed to write the response on decryption failure", "error", err)
			}
			return
		}

		// key is valid
		// delete the row
		ctx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
		defer cancel()

		_, err = db.ExecContext(ctx, "DELETE FROM files WHERE id=$1", file)
		if err != nil {
			slog.Error("failed to db.ExecContext", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		delete(visits, file)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "success"}`))
	})

	return mux
}

func incVisit(file string) error {
	// inc db visits
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
	defer cancel()

	_, err := db.NamedExecContext(ctx, `UPDATE files SET openned=openned+1 WHERE id=:id`, map[string]interface{}{
		"id": file,
	})
	if err != nil {
		return fmt.Errorf("failed to increase the openned count: %w", err)
	}

	visits[file] += 1

	return nil
}

func loadHTMLTemplates() {
	var err error
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
	flag.StringVar(&domain, "domain", "http://127.0.0.1", "domain with schema (and port if needed) to be used for url generation")
	flag.StringVar(&database_url, "database-url", "", "database url")
	flag.StringVar(&certKey, "cert-key", "", "certificate key file")
	flag.StringVar(&cert, "cert", "", "certificate file")
	flag.Parse()

	var err error
	flag.VisitAll(func(f *flag.Flag) {
		name := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if value, ok := os.LookupEnv(name); ok {
			err2 := flag.Set(f.Name, value)
			if err2 != nil {
				err = fmt.Errorf("failed setting flag from environment: %w", err2)
			}
		}
	})

	if err != nil {
		slog.Error("failed to load envs", "error", err)
	}

	if domain == "" {
		domain = fmt.Sprintf("http://%s:%s", host, port)
	}
}
