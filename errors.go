package bw

import (
	"errors"
	"strings"

	"github.com/oneryx/bw/internal/api"
)

// Errors returned by Client methods. Messages match the official Bitwarden
// CLI so they can be shown to users as they are.
var (
	ErrNotLoggedIn     = errors.New("You are not logged in.")
	ErrLocked          = errors.New("Vault is locked.")
	ErrNotFound        = errors.New("Not found.")
	ErrInvalidPassword = errors.New("Invalid master password.")
	ErrLogoutRequired  = errors.New("Logout required before server config update.")
	// ErrNoOrgKey means the organization is unknown or its key is unavailable.
	ErrNoOrgKey = errors.New("No encryption key for this organization.")
	// ErrOrgNotFound means the user is not a member of the organization.
	ErrOrgNotFound = errors.New("Organization not found.")
	// ErrTwoFactorFailed is returned when the two-step login code was rejected.
	ErrTwoFactorFailed = errors.New("Login failed.")
	// ErrSendPasswordRequired is returned by ReceiveSend for password
	// protected Sends when no password was given.
	ErrSendPasswordRequired = errors.New("Password required")
	// ErrSendInvalidPassword is returned by ReceiveSend for a wrong password.
	ErrSendInvalidPassword = errors.New("Invalid password")
	// ErrSendEmailVerification is returned by ReceiveSend for Sends that
	// require email verification, which is not supported.
	ErrSendEmailVerification = errors.New("Email-verified Sends are not supported by this CLI.")
	// ErrSendForeignHost is returned by ReceiveSend when the Send is hosted
	// on another server and ReceiveOptions.AllowForeignHost is not set.
	ErrSendForeignHost = errors.New("Send access will not be attempted: the domain in the Send URL does not match the configured domain.")
)

// APIError is an error response from the server.
type APIError = api.Error

// MultipleResultsError is returned when a search term matches more than one
// object.
type MultipleResultsError struct {
	IDs []string
}

func (e *MultipleResultsError) Error() string {
	return "More than one result was found. Try getting a specific object by `id` instead. " +
		"The following objects were found:\n" + strings.Join(e.IDs, "\n")
}

func multipleResults[T any](items []T, id func(T) string) error {
	ids := make([]string, len(items))
	for i, it := range items {
		ids[i] = id(it)
	}
	return &MultipleResultsError{IDs: ids}
}
