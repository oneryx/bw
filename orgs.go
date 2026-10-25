package bw

import (
	"context"

	"github.com/oneryx/bw/vault"
)

// Organization member types (ProfileOrganization.Type, OrgMember.Type) and
// statuses (ProfileOrganization.Status, OrgMember.Status).
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

// Folders returns the decrypted folders sorted by name.
func (c *Client) Folders() ([]vault.Folder, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	return v.folders(), nil
}

// Collections returns the decrypted collections the user can access,
// sorted by name.
func (c *Client) Collections() ([]vault.Collection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	return v.collections(), nil
}

// Organizations returns the user's organizations sorted by name.
func (c *Client) Organizations() ([]vault.ProfileOrganization, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	return v.organizations(), nil
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
	org, err := v.findOrg(orgID)
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
			col.Name = v.collectionName(orgID, col.Name)
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
	if _, err := v.orgKey(orgID); err != nil {
		return nil, err
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
		ID: res.ID, OrganizationID: res.OrganizationID, Name: v.collectionName(orgID, res.Name),
		ExternalID: res.ExternalID, Groups: res.Groups, Users: res.Users,
	}, nil
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
	if _, err := v.findOrg(orgID); err != nil {
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
