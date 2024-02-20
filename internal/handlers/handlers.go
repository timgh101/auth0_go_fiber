package handlers

import (
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/timgh101/auth0_go_fiber/internal/auth"
	"github.com/timgh101/auth0_go_fiber/internal/state"
)

// Handler for our login.
func Login(auth *auth.Authenticator, store *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		state, err := state.GenerateRandomState()
		if err != nil {
			fmt.Println("error: ", err)
			c.Status(http.StatusInternalServerError)
			return c.SendString("error in state")
		}

		// Save the state inside the session.
		session, err := store.Get(c)
		if err != nil {
			fmt.Println("error in Login handler while getting session")
			c.Status(http.StatusInternalServerError)
			return c.SendString("error in session")
		}
		session.Set("state", state)
		err = session.Save()
		if err != nil {
			fmt.Println("error in Login handler while saving session")
			c.Status(http.StatusInternalServerError)
			return c.SendString("error in session")
		}

		return c.Redirect(auth.AuthCodeURL(state), http.StatusTemporaryRedirect)
	}
}
