package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"

	"github.com/0xPolygonID/onchain-issuer-integration-demo/server/config"
	"github.com/0xPolygonID/onchain-issuer-integration-demo/server/handlers"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/rs/cors"
	"golang.ngrok.com/ngrok"
	ngrokCfg "golang.ngrok.com/ngrok/config"
)

var isDevFlag = flag.Bool("dev", false, "run in dev mode")

func main() {
	fmt.Println("Main Method started")
	flag.Parse()
	cfg, err := config.ParseConfig()
	if err != nil {
		fmt.Printf("can't parse config, err: %v", err)
	}
	if err = cfg.GetIssuerIdentityDIDFromAddress(); err != nil {
		fmt.Printf("can't get issuer identity did from address, err: %v", err)
	}
	h := handlers.NewHandler(cfg)
	r := newRouter(h)

	if *isDevFlag {
		go func() {
			err := runNgrok(r)
			if err != nil {
				fmt.Printf("can't run ngrok, err: %v", err)
			}
		}()
	} else {
		handlers.NgrokCallbackURL = cfg.HostUrl
	}
	fmt.Println(http.ListenAndServe(":6543", r))
}

func runNgrok(r chi.Router) error {
	fmt.Println("Inside the ngrok")
	tun, err := ngrok.Listen(
		context.Background(),
		ngrokCfg.HTTPEndpoint(),
		ngrok.WithAuthtokenFromEnv(),
	)
	if err != nil {
		return err
	}
	url := tun.URL()
	handlers.NgrokCallbackURL = url
	fmt.Println("ngrok url: ", url)
	return http.Serve(tun, r)
}

func newRouter(h *handlers.Handler) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)

	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://*", "https://*", "*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	r.Use(corsMiddleware.Handler)

	r.Route("/api/v1", func(root chi.Router) {
		root.Use(render.SetContentType(render.ContentTypeJSON))

		root.Route("/requests", func(reqs chi.Router) {
			reqs.Get("/auth", h.GetAuthVerificationRequest)
		})

		root.Route("/callback", func(agent chi.Router) {
			agent.Post("/", h.Callback)
		})
		root.Route("/status", func(agent chi.Router) {
			agent.Get("/", h.GetRequestStatus)
		})
	})

	return r
}
