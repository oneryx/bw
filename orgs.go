package bw

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/oneryx/bw/internal/api"
	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/vault"
)

// Organization member types and statuses.
const (
	OrgUserOwner   = 0
	OrgUserAdmin   = 1
	OrgUserUser    = 2
	OrgUserManager = 3
	OrgUserCustom  = 4

	OrgMemberRevoked   = -1
	OrgMemberInvited   = 0
	OrgMemberAccepted  = 1
	OrgMemberConfirmed = 2
)

// Collections returns the decrypted collections the user can access,
// sorted by name.
func (c *Client) Collections() ([]vault.Collection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	return v.Collections(), nil
}

// Organizations returns the user's organizations sorted by name.
func (c *Client) Organizations() ([]vault.ProfileOrganization, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	return v.Organizations(), nil
}

func findOrg(v *vault.Vault, orgID string) (*vault.ProfileOrganization, error) {
	for _, o := range v.Data.Profile.Organizations {
		if o.ID == orgID {
			return &o, nil
		}
	}
	return nil, ErrOrgNotFound
}

// OrgCollections returns all collections of an organization the user can
// see: every collection for owners and admins, otherwise the assigned ones.
func (c *Client) OrgCollections(ctx context.Context, orgID string) ([]vault.Collection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	org, err := findOrg(v, orgID)
	if err != nil {
		return nil, err
	}
	var res struct {
		Data []vault.Collection `json:"data"`
	}
	path := "/collections"
	if org.Type <= OrgUserAdmin {
		path = "/organizations/" + orgID + "/collections"
	}
	if err := c.api().Get(ctx, path, &res); err != nil {
		return nil, err
	}
	cols := []vault.Collection{}
	for _, col := range res.Data {
		if col.OrganizationID == orgID {
			col.Name = v.DecryptCollectionName(orgID, col.Name)
			cols = append(cols, col)
		}
	}
	return cols, nil
}

// OrgCollection is an organization collection with its access lists.
type OrgCollection struct {
	ID             string
	OrganizationID string
	Name           string
	ExternalID     *string
	Groups         []vault.SelectionReadOnly
	Users          []vault.SelectionReadOnly
}

// OrgCollection returns a collection with its group and user access.
func (c *Client) OrgCollection(ctx context.Context, orgID, id string) (*OrgCollection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	if _, err := v.OrgKey(orgID); err != nil {
		return nil, ErrNoOrgKey
	}
	var res struct {
		vault.Collection
		Groups []vault.SelectionReadOnly `json:"groups"`
		Users  []vault.SelectionReadOnly `json:"users"`
	}
	if err := c.api().Get(ctx, "/organizations/"+orgID+"/collections/"+id+"/details", &res); err != nil {
		return nil, err
	}
	return &OrgCollection{
		ID: res.ID, OrganizationID: res.OrganizationID, Name: v.DecryptCollectionName(orgID, res.Name),
		ExternalID: res.ExternalID, Groups: res.Groups, Users: res.Users,
	}, nil
}

// SaveOrgCollection creates (empty ID) or updates an organization
// collection. When creating with nil Users, the current member gets manage
// access.
func (c *Client) SaveOrgCollection(ctx context.Context, col OrgCollection) (*OrgCollection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(col.Name) == "" {
		return nil, errors.New("Collection name is required.")
	}
	orgID := col.OrganizationID
	key, err := v.OrgKey(orgID)
	if err != nil {
		return nil, ErrNoOrgKey
	}
	name, err := crypto.EncryptString(key, col.Name)
	if err != nil {
		return nil, err
	}
	cl := c.api()
	users := col.Users
	if users == nil && col.ID == "" {
		var orgs struct {
			Data []struct {
				ID                 string `json:"id"`
				OrganizationUserID string `json:"organizationUserId"`
			} `json:"data"`
		}
		if err := cl.Get(ctx, "/organizations", &orgs); err == nil {
			for _, o := range orgs.Data {
				if o.ID == orgID && o.OrganizationUserID != "" {
					users = []vault.SelectionReadOnly{{ID: o.OrganizationUserID, Manage: true}}
				}
			}
		}
	}
	body := map[string]any{"name": name, "externalId": col.ExternalID, "groups": col.Groups, "users": users}
	var res struct {
		ID     string                    `json:"id"`
		Groups []vault.SelectionReadOnly `json:"groups"`
		Users  []vault.SelectionReadOnly `json:"users"`
	}
	path, method := "/organizations/"+orgID+"/collections", http.MethodPost
	if col.ID != "" {
		path, method = path+"/"+col.ID, http.MethodPut
	}
	if err := cl.Do(ctx, method, path, body, &res); err != nil {
		return nil, err
	}
	if res.Groups == nil {
		res.Groups = []vault.SelectionReadOnly{}
	}
	if res.Users == nil {
		res.Users = []vault.SelectionReadOnly{}
	}
	return &OrgCollection{
		ID: res.ID, OrganizationID: orgID, Name: col.Name, ExternalID: col.ExternalID,
		Groups: res.Groups, Users: res.Users,
	}, nil
}

// DeleteOrgCollection deletes an organization collection.
func (c *Client) DeleteOrgCollection(ctx context.Context, orgID, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.open(); err != nil {
		return err
	}
	if err := c.api().Do(ctx, http.MethodDelete, "/organizations/"+orgID+"/collections/"+id, nil, nil); err != nil {
		return err
	}
	_ = c.st.Account.DeleteVaultObject("collections", id)
	return c.save()
}

// OrgMember is a member of an organization.
type OrgMember struct {
	ID               string
	Email            string
	Name             *string
	Status           int
	Type             int
	TwoFactorEnabled bool
}

// OrgMembers lists the members of an organization.
func (c *Client) OrgMembers(ctx context.Context, orgID string) ([]OrgMember, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	if _, err := findOrg(v, orgID); err != nil {
		return nil, err
	}
	var res struct {
		Data []struct {
			ID               string  `json:"id"`
			Email            string  `json:"email"`
			Name             *string `json:"name"`
			Status           int     `json:"status"`
			Type             int     `json:"type"`
			TwoFactorEnabled bool    `json:"twoFactorEnabled"`
		} `json:"data"`
	}
	if err := c.api().Get(ctx, "/organizations/"+orgID+"/users", &res); err != nil {
		return nil, err
	}
	out := []OrgMember{}
	for _, u := range res.Data {
		out = append(out, OrgMember(u))
	}
	return out, nil
}

// ConfirmOrgMember confirms an accepted member, sharing the organization key
// with them. Check the member's Fingerprint out of band first.
func (c *Client) ConfirmOrgMember(ctx context.Context, orgID, memberID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return err
	}
	orgKey, err := v.OrgKey(orgID)
	if err != nil {
		return ErrNoOrgKey
	}
	cl := c.api()
	var member struct {
		UserID string `json:"userId"`
		Status int    `json:"status"`
	}
	if err := cl.Get(ctx, "/organizations/"+orgID+"/users/"+memberID, &member); err != nil {
		if api.IsNotFound(err) {
			return errors.New("Member id does not exist for this organization.")
		}
		return err
	}
	switch member.Status {
	case OrgMemberAccepted:
	case OrgMemberInvited:
		return errors.New("User must accept the invitation before they can be confirmed.")
	case OrgMemberConfirmed:
		return errors.New("User is already confirmed.")
	case OrgMemberRevoked:
		return errors.New("User is revoked and cannot be confirmed.")
	default:
		return errors.New("User is not in a valid state to be confirmed.")
	}
	var pk struct {
		PublicKey string `json:"publicKey"`
	}
	if err := cl.Get(ctx, "/users/"+member.UserID+"/public-key", &pk); err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(pk.PublicKey)
	if err != nil {
		return err
	}
	wrapped, err := crypto.EncryptRSA(pub, orgKey.Bytes())
	if err != nil {
		return err
	}
	collName, err := crypto.EncryptString(orgKey, "My items")
	if err != nil {
		return err
	}
	body := map[string]string{"key": wrapped, "defaultUserCollectionName": collName}
	return cl.Do(ctx, http.MethodPost, "/organizations/"+orgID+"/users/"+memberID+"/confirm", body, nil)
}

// Fingerprint returns the fingerprint phrase of a user's public key; use
// "me" for the current user.
func (c *Client) Fingerprint(ctx context.Context, userID string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return "", err
	}
	if userID == "me" {
		pub, err := v.PublicKey()
		if err != nil {
			return "", errors.New("No public key available for the active user.")
		}
		phrase, err := crypto.Fingerprint(c.st.Account.UserID, pub)
		if err != nil {
			return "", ErrNotFound
		}
		return phrase, nil
	}
	if !IsGUID(userID) {
		return "", ErrNotFound
	}
	var res struct {
		PublicKey string `json:"publicKey"`
	}
	if c.api().Get(ctx, "/users/"+userID+"/public-key", &res) != nil {
		return "", ErrNotFound
	}
	pub, err := base64.StdEncoding.DecodeString(res.PublicKey)
	if err != nil {
		return "", ErrNotFound
	}
	phrase, err := crypto.Fingerprint(userID, pub)
	if err != nil {
		return "", ErrNotFound
	}
	return phrase, nil
}
