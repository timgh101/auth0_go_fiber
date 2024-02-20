package main

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/template/html/v2"
	"github.com/joho/godotenv"
	"github.com/timgh101/auth0_go_fiber/internal/auth"
	"github.com/timgh101/auth0_go_fiber/internal/handlers"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Failed to load the env vars: %v", err)
	}

	engine := html.New("./web/views", ".html")
	app := fiber.New(fiber.Config{
		Views:             engine,
		PassLocalsToViews: true,
	})

	auth, err := auth.New()
	if err != nil {
		log.Fatalf("Failed to initialize the authenticator: %v", err)
	}

	store := session.New()

	// middleware
	app.Use(handlers.IsAuthenticated(store))

	// routes
	app.Get("/", handlers.Home)
	app.Get("/login", handlers.Login(auth, store))
	app.Get("/callback", handlers.Callback(auth, store))
	app.Get("/logout", handlers.Logout)
	app.Get("/user", handlers.User)

	log.Fatal(app.Listen(os.Getenv("APP_URL")))
}
