package app

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialSerialization(t *testing.T) {
	want := webauthn.Credential{
		ID:              []byte{0, 1, 254, 255},
		PublicKey:       []byte{10, 20, 30},
		AttestationType: "none",
		Transport:       []protocol.AuthenticatorTransport{protocol.Internal, protocol.USB},
		Flags:           webauthn.CredentialFlags{UserPresent: true, UserVerified: true, BackupEligible: true, BackupState: true},
		Authenticator: webauthn.Authenticator{
			AAGUID:       []byte{1, 2, 3},
			SignCount:    42,
			CloneWarning: true,
			Attachment:   protocol.Platform,
		},
		Attestation: webauthn.CredentialAttestation{
			ClientDataJSON:     []byte(`{"type":"webauthn.create"}`),
			ClientDataHash:     []byte{4, 5, 6},
			AuthenticatorData:  []byte{7, 8, 9},
			PublicKeyAlgorithm: -7,
			Object:             []byte{10, 11, 12},
		},
	}
	data, err := marshalCredential(&want)
	require.NoError(t, err)
	got, err := unmarshalCredential(data)
	require.NoError(t, err)
	assert.Equal(t, want, got, "credential changed after storage round trip")
}

func TestUnmarshalCredentialRejectsInvalidData(t *testing.T) {
	for _, data := range []string{"", "{", `{"id":123}`, `{"id":"invalid base64!"}`, `{"authenticator":{"signCount":-1}}`} {
		_, err := unmarshalCredential([]byte(data))
		assert.Error(t, err, "accepted invalid credential %q", data)
	}
}
