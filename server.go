package main

import (
	"encoding/json"
	"golang.org/x/exp/slog"

	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strings"

	"github.com/clerkinc/clerk-sdk-go/clerk"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

type Server struct {
	mediaLib      *MediaLibrary
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

func (s *Server) ListingHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if strings.HasPrefix(path, "/") {
		path = strings.Replace(path, "/", "", 1)
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
	path := r.URL.Path

	var SongRedirect = new(SongRedirect)

	url, err := s.mediaLib.ContentURL(path)

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

// StartServer starts HTTP server.
func StartServer(mediaLib *MediaLibrary, addr string, clerkClient clerk.Client) error {
	staticVersion := fmt.Sprintf("%x", rand.Uint64())
	s := Server{
		mediaLib:      mediaLib,
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
				http.Error(w, "Invalid Token", http.StatusUnauthorized)
				return
			}

			// If the JWT is valid, call the next handler
			next.ServeHTTP(w, r)
		})
	})

	// Middleware to strip /api/library prefix from path
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/api/library") {
				r.URL.Path = strings.Replace(r.URL.Path, "/api/library", "", 1)
			} else if strings.Contains(r.URL.Path, "/api/stream") {
				r.URL.Path = strings.Replace(r.URL.Path, "/api/stream", "", 1)
			}
			next.ServeHTTP(w, r)
		})
	})

	sub := r.PathPrefix("/api").Subrouter()
	sub.PathPrefix("/library").Handler(ValidatePath(NormalizePath(s.ListingHandler))).Methods(http.MethodGet, http.MethodOptions)
	sub.PathPrefix("/stream").Handler(ValidatePath(NormalizePath(s.StreamHandler))).Methods(http.MethodGet, http.MethodOptions)

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "OPTIONS", "PUT"},
		AllowedHeaders: []string{"Origin", "Content-Type", "Authorization"},
	})

	handler := c.Handler(r)
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}
	return srv.ListenAndServe()
	// return http.ListenAndServe(addr, mux)
}
