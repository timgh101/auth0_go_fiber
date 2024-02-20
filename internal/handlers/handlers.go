package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"os"

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

func Callback(auth *auth.Authenticator, store *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {

		session, err := store.Get(c)
		if err != nil {
			fmt.Println("error in Login handler while getting session")
			c.Status(http.StatusInternalServerError)
			return c.SendString("error in session")
		}

		// Exchange an authorization code for a token.
		token, err := auth.Exchange(c.Context(), c.Query("code"))
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
			fmt.Println("error in Login CallbackHandler while saving session: ")
			fmt.Println(err)
			c.Status(http.StatusInternalServerError)
			return c.SendString("error")
		}

		// Redirect to logged in page.
		return c.Redirect("/user", http.StatusTemporaryRedirect)
	}
}

func Logout(c *fiber.Ctx) error {
	logoutUrl, err := url.Parse("https://" + os.Getenv("AUTH0_DOMAIN") + "/v2/logout")
	if err != nil {
		fmt.Println("error in LogoutHandler failed to parse url")
		c.Status(http.StatusInternalServerError)
		return c.SendString("error")
	}

	scheme := c.Protocol()

	returnTo, err := url.Parse(scheme + "://" + string(c.Request().Host()))
	if err != nil {
		fmt.Println("error in LogoutHandler failed to parse url 222")
		c.Status(http.StatusInternalServerError)
		return c.SendString("error")
	}

	parameters := url.Values{}
	parameters.Add("returnTo", returnTo.String())
	parameters.Add("client_id", os.Getenv("AUTH0_CLIENT_ID"))
	logoutUrl.RawQuery = parameters.Encode()

	return c.Redirect(logoutUrl.String(), http.StatusTemporaryRedirect)
}

func IsAuthenticated(store *session.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// get "profile" from session
		// Get session from storage
		sess, err := store.Get(c)
		if err != nil {
			fmt.Println("error in IsAuthenticated while getting session")
			c.Status(http.StatusInternalServerError)
			return c.SendString("error")
		}

		// Get value
		profile := sess.Get("profile")
		if profile == nil {
			return c.Next()
		}

		c.Locals("profile", profile)

		return c.Next()
	}
}

func User(c *fiber.Ctx) error {

	// var profile map[string]interface{}
	// gottenProfile := c.Locals("profile")
	// profile, ok := gottenProfile.(map[string]interface{})
	// if !ok {
	// 	fmt.Println("error in UserHandler while casting locals profile")
	// 	c.Status(http.StatusInternalServerError)
	// 	return c.SendString("error")
	// }

	return c.Render("user", fiber.Map{})
}

func Test(c *fiber.Ctx) error {

	gottenProfile := c.Locals("profile")
	profile, ok := gottenProfile.(map[string]interface{})
	if !ok {
		fmt.Println("error in UserHandler while casting locals profile")
		c.Status(http.StatusInternalServerError)
		return c.SendString("error")
	}

	fmt.Println("got this profile: ")
	fmt.Println(profile)

	return c.JSON(profile)
}

func Home(c *fiber.Ctx) error {
	return c.Render("index", fiber.Map{})
}
