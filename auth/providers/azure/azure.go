package azure

import (
	"context"
	"fmt"

	"github.com/appscode/guard/auth"
	"github.com/appscode/guard/auth/providers/azure/graph"
	"github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	authv1 "k8s.io/api/authentication/v1"
)

/*
    ref:
	https://www.youtube.com/watch?v=WygwzN9FfMQ
	https://www.youtube.com/watch?v=ujzrq8Fg9Gc
	https://cloudblogs.microsoft.com/enterprisemobility/2014/12/18/azure-active-directory-now-with-group-claims-and-application-roles/
	https://azure.microsoft.com/en-us/resources/samples/active-directory-dotnet-webapp-groupclaims/
	https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-openid-connect-code
	https://github.com/kubernetes/kubernetes/pull/43987
	https://github.com/cosmincojocar/kubernetes/blob/682d5ec01f37c65117b2496865cc9bf0cd9e0902/staging/src/k8s.io/client-go/plugin/pkg/client/auth/azure/README.md
*/

const (
	OrgType            = "azure"
	azureIssuerURL     = "https://sts.windows.net/"
	azureUsernameClaim = "upn"
	azureObjectIDClaim = "oid"
)

func init() {
	auth.SupportedOrgs = append(auth.SupportedOrgs, OrgType)
}

var (
	// ErrorClaimNotFound indicates the given key was not found in the claims
	ErrClaimNotFound = fmt.Errorf("claim not found")
)

// claims represents a map of claims provided with a JWT
type claims map[string]interface{}

type Authenticator struct {
	Options
	graphClient *graph.UserInfo
	verifier    *oidc.IDTokenVerifier
	ctx         context.Context
}

func New(opts Options) (auth.Interface, error) {
	c := &Authenticator{
		Options: opts,
		ctx:     context.Background(),
	}

	var err error
	provider, err := oidc.NewProvider(c.ctx, azureIssuerURL+c.TenantID+"/")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create provider for azure")
	}

	c.verifier = provider.Verifier(&oidc.Config{SkipClientIDCheck: true})

	c.graphClient, err = graph.New(c.ClientID, c.ClientSecret, c.TenantID, c.UseGroupUID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ms graph client")
	}
	return c, nil
}

func (s Authenticator) UID() string {
	return OrgType
}

func (s Authenticator) Check(token string) (*authv1.UserInfo, error) {
	idToken, err := s.verifier.Verify(s.ctx, token)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify token for azure")
	}

	claims, err := getClaims(idToken)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing claims")
	}

	resp, err := claims.getUserInfo(azureUsernameClaim, azureObjectIDClaim)
	if err != nil {
		return nil, err
	}
	resp.Groups, err = s.graphClient.GetGroups(resp.Username)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get groups")
	}
	return resp, nil
}

// GetClaims returns a Claims object
func getClaims(token *oidc.IDToken) (claims, error) {
	var c = claims{}
	err := token.Claims(&c)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling claims: %s", err)
	}
	return c, nil
}

// ReviewFromClaims creates a new TokenReview object from the claims object
// the claims object
func (c claims) getUserInfo(usernameClaim, userObjectIDClaim string) (*authv1.UserInfo, error) {
	username, err := c.string(usernameClaim)
	if err != nil && err == ErrClaimNotFound {
		username, err = c.string(userObjectIDClaim)
	}
	if err != nil {
		if err == ErrClaimNotFound {
			return nil, errors.Errorf("username: %s and objectID: %s claims not found", usernameClaim, userObjectIDClaim)
		}
		return nil, errors.Wrap(err, "unable to get username claim")
	}

	return &authv1.UserInfo{Username: username}, nil
}

// String gets a string value from claims given a key. Returns error if
// the key does not exist
func (c claims) string(key string) (string, error) {
	v, ok := c[key]
	if !ok {
		return "", ErrClaimNotFound
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("claim %s is not a string, found %v", key, v)
	}
	return s, nil
}
