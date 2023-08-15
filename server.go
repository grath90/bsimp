package main

import (
	"encoding/json"
	// "embed"
	"errors"
	"fmt"
	// "html/template"
	// "io/fs"
	"math/rand"
	"net/http"
	"strings"

	"github.com/clerkinc/clerk-sdk-go/clerk"
	"github.com/gorilla/mux"
	"golang.org/x/exp/slog"
)

// var embedFS embed.FS

type Server struct {
	mediaLib *MediaLibrary
	// tmpl          *template.Template
	staticVersion string
}

func httpError(r *http.Request, w http.ResponseWriter, err error, code int) {
	http.Error(w, err.Error(), code)
	slog.Error("failed request",
		err,
		slog.String("url", r.URL.String()),
		slog.Int("code", code),
	)
}

// ValidatePath provides a basic protection from the path traversal vulnerability.
func ValidatePath(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "./") || strings.Contains(r.URL.Path, ".\\") {
			httpError(r, w, errors.New("invalid path"), http.StatusBadRequest)
			return
		}
		h(w, r)
	}
}

// NormalizePath normalizes the request URL by removing the delimeter suffix.
func NormalizePath(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimRight(r.URL.Path, Delimiter)
		h(w, r)
	}
}

// DisableFileListing disables file listing under directories. It can be used with the built-in http.FileServer.
func DisableFileListing(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

type TemplateData struct {
	StaticVersion string
	*MediaListing
}

func (s *Server) ListingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	path := r.URL.Path
	vars := mux.Vars(r)

	if strings.Contains(path, "/library") {
		path = strings.Replace(path, "/library", "", 1)
	}

	if vars["album"] != "" {
		path = vars["album"]
	}

	listing, err := s.mediaLib.List(path)

	if err != nil {
		httpError(r, w, err, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)

	err = json.NewEncoder(w).Encode(listing)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type SongRedirect struct {
	Url string `json:"url"`
}

func (s *Server) StreamHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	vars := mux.Vars(r)
	song := vars["song"]
	album := vars["album"]
	var SongRedirect = new(SongRedirect)

	url, err := s.mediaLib.ContentURL(album + "/" + song)

	if err != nil {
		httpError(r, w, err, http.StatusInternalServerError)
		return
	}

	SongRedirect.Url = url

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)

	err = json.NewEncoder(w).Encode(SongRedirect)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Don't include sprig just for one function.
var templateFunctions = map[string]any{
	"defaultString": func(s string, def string) string {
		if s == "" {
			return def
		}
		return s
	},
}

// StartServer starts HTTP server.
func StartServer(mediaLib *MediaLibrary, addr string, clerkClient clerk.Client) error {
	// tmpl, err := template.New("").Funcs(templateFunctions).ParseFS(embedFS, "templates/*.gohtml")
	// if err != nil {
	// 	return err
	// }
	staticVersion := fmt.Sprintf("%x", rand.Uint64())
	s := Server{
		mediaLib: mediaLib,
		// tmpl:          tmpl,
		staticVersion: staticVersion,
	}

	r := mux.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the JWT from the request header
			token := r.Header.Get("Authorization")

			// If the token is empty...
			if token == "" {
				// ...return an error
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Verify the JWT
			_, err := clerkClient.VerifyToken(token)

			// If the JWT is invalid...
			if err != nil {
				// ...return an error
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// If the JWT is valid, call the next handler
			next.ServeHTTP(w, r)
		})
	})

	sub := r.PathPrefix("/api").Subrouter()
	// r.HandleFunc("/library/", ValidatePath(NormalizePath(s.ListingHandler))).Methods("GET")
	// r.HandleFunc("/stream/", ValidatePath(NormalizePath(s.StreamHandler))).Methods("GET")
	sub.HandleFunc("/library", s.ListingHandler).Methods("GET")
	sub.HandleFunc("/library/{album}", s.ListingHandler).Methods("GET")
	sub.HandleFunc("/stream/{album}/{song}", s.StreamHandler).Methods("GET")
	// mux := http.NewServeMux()

	//mux.Handle("/", http.RedirectHandler("/library/", http.StatusMovedPermanently))

	// staticFS, err := fs.Sub(embedFS, "static")
	// if err != nil {
	// 	return err
	// }
	// staticPath := fmt.Sprintf("/static/%s/", staticVersion)
	// mux.Handle(staticPath, DisableFileListing(http.StripPrefix(staticPath, http.FileServer(http.FS(staticFS)))))

	// mux.Handle("/library/", http.StripPrefix("/library/", ValidatePath(NormalizePath(s.ListingHandler))))
	// mux.Handle("/stream/", http.StripPrefix("/stream/", ValidatePath(NormalizePath(s.StreamHandler))))

	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}
	return srv.ListenAndServe()
	// return http.ListenAndServe(addr, mux)
}
