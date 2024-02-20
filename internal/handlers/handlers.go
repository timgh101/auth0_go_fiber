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

func CallbackHandler(auth *auth.Authenticator, store *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {

		session, err := store.Get(c)
		if err != nil {
			fmt.Println("error in Login handler while getting session")
			c.Status(http.StatusInternalServerError)
			return c.SendString("error in session")
		}

		// Exchange an authorization code for a token.
		token, err := auth.Exchange(c.Context(), c.Params("code"))
		if err != nil {
			fmt.Println("error in CallbackHandler while getting token")
			c.Status(http.StatusInternalServerError)
			return c.SendString("error")
		}

		idToken, err := auth.VerifyIDToken(c.Context(), token)
		if err != nil {
			fmt.Println("error in CallbackHandler failed to verify token")
			c.Status(http.StatusInternalServerError)
			return c.SendString("error")
		}

		var profile map[string]interface{}
		if err := idToken.Claims(&profile); err != nil {
			fmt.Println("error in CallbackHandler failed to put token into profile")
			c.Status(http.StatusInternalServerError)
			return c.SendString("error")
		}

		session.Set("access_token", token.AccessToken)
		session.Set("profile", profile)
		err = session.Save()
		if err != nil {
			fmt.Println("error in Login CallbackHandler while saving session")
			c.Status(http.StatusInternalServerError)
			return c.SendString("error")
		}

		// Redirect to logged in page.
		return c.Redirect("/user", http.StatusTemporaryRedirect)
		// ctx.Redirect(http.StatusTemporaryRedirect, "/user")
	}
}
