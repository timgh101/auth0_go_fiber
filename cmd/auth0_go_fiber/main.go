package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/joho/godotenv"
	"github.com/timgh101/auth0_go_fiber/internal/auth"
	"github.com/timgh101/auth0_go_fiber/internal/handlers"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Failed to load the env vars: %v", err)
	}

	app := fiber.New()

	auth, err := auth.New()
	if err != nil {
		log.Fatalf("Failed to initialize the authenticator: %v", err)
	}

	store := session.New()

	app.Get("/login", handlers.Login(auth, store))

	log.Fatal(app.Listen(":3000"))
}
