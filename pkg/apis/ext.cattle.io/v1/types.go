// +kubebuilder:skip
package v1

import (
	apiv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Token is the main extension Token structure
type Token struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the spec of RancherToken
	Spec TokenSpec `json:"spec"`
	// +optional
	Status TokenStatus `json:"status"`
}

// TokenSpec contains the user-specifiable parts of the Token
type TokenSpec struct {
	// UserID is the user id
	UserID string `json:"userID"`
	// Human readable description
	// +optional
	Description string `json:"description, omitempty"`
	// ClusterName is the cluster that the token is scoped to. If empty, the
	// token can be used for all clusters.
	// +optional
	ClusterName string `json:"clusterName,omitempty"`
	// TTL is the time-to-live of the token, in milliseconds
	TTL int64 `json:"ttl"`
	// Enabled indicates an active token
	// +optional
	Enabled bool `json:"enabled,omitempty"`
	// Indicates a login/session token. Non-session tokens are derived from
	// some other token.
	IsLogin bool `json:"isLogin"`
}

// TokenStatus contains the data derived from the specification or otherwise generated.
type TokenStatus struct {
	// TokenValue is the access key. Shown only on token creation. Not saved.
	TokenValue string `json:"tokenValue,omitempty"`
	// TokenHash is the hash of the value. Only thing saved.
	TokenHash string `json:"tokenHash,omitempty"`

	// Time derived data. These fields are not stored in the backing secret.
	// Both values can be trivially computed from the secret's/token's
	// creation time, the time to live, and the current time.

	// Expired flag, derived from creation time and time-to-live
	Expired bool `json:"expired"`
	// ExpiresAt is creation time + time-to-live, i.e. when the token
	// expires.  This is set to the empty string if the token does not
	// expire at all.
	ExpiresAt string `json:"expiredAt"`

	// User derived data. This information is complex to determine. As such
	// this is stored in the backing secret to avoid recomputing it whenever
	// the token is retrieved.

	// AuthProvider names the auth provider managing the user. This
	// information is retrieved from the UserAttribute resource referenced
	// by `Spec.UserID`.
	AuthProvider string `json:"authProvider"`

	// UserPrincipal holds the detailed user data. Most of the fields can be
	// given standard values or are not relevant. Display name and login
	// name are retrieved from the User resource referenced by `Spec.UserID`.
	// Provider is the `AuthProvider`. Meta.name is retrieved from the
	// UserAttribute resource referenced by `Spec.UserID`.
	UserPrincipal apiv3.Principal `json:"userPrincipal"`

	// GroupPrincipals holds detailed group information
	// This is not supported here.
	// The primary location for this information are the UserAttribute resources.
	// The norman tokens maintain this only as legacy.
	// The ext tokens here shed this legacy.

	// ProviderInfo provides provider-specific information.
	// This is not supported here.
	// The actual primary storage for this is a regular k8s Secret associated with the User.
	// The norman tokens maintains this only as legacy for the `access_token` of OIDC-based auth providers.
	// The ext tokens here shed this legacy.

	// Time of last change to the token
	LastUpdateTime string `json:"lastUpdateTime"`
}

// Implement the TokenAccessor interface

func (t *Token) GetName() string {
	return t.ObjectMeta.Name
}

func (t *Token) GetIsEnabled() bool {
	return t.Spec.Enabled
}

func (t *Token) GetIsDerived() bool {
	return !t.Spec.IsLogin
}

func (t *Token) GetUserID() string {
	return t.Spec.UserID
}

func (t *Token) ObjClusterName() string {
	return t.Spec.ClusterName
}

func (t *Token) GetAuthProvider() string {
	return t.Status.AuthProvider
}

func (t *Token) GetUserPrincipal() apiv3.Principal {
	return t.Status.UserPrincipal
}

func (t *Token) GetGroupPrincipals() []apiv3.Principal {
	// Not supported. Legacy in Norman tokens.
	return []apiv3.Principal{}
}

func (t *Token) GetProviderInfo() map[string]string {
	// Not supported. Legacy in Norman tokens.
	return map[string]string{}
}
