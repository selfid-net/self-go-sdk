package siggraph

import (
	"crypto/rand"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"

	"gopkg.in/square/go-jose.v2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testHistory struct {
	signer string
	op     *Operation
}

func testop(keys map[string]ed25519.PrivateKey, signer string, op *Operation) (json.RawMessage, []byte) {
	sk := keys[signer]

	data, err := json.Marshal(op)
	if err != nil {
		panic(err)
	}

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": signer,
		},
	}

	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
	if err != nil {
		panic(err)
	}

	jws, err := s.Sign(data)
	if err != nil {
		panic(err)
	}

	return json.RawMessage(jws.FullSerialize()), jws.Signatures[0].Signature
}

func TestSignatureGraph(t *testing.T) {
	keys := make(map[string]ed25519.PrivateKey)

	for i := 0; i < 10; i++ {
		_, sk, err := ed25519.GenerateKey(rand.Reader)
		require.Nil(t, err)

		keys[strconv.Itoa(i)] = sk
	}

	now := time.Now().Unix()

	cases := []struct {
		name    string
		history []testHistory
		err     error
	}{
		{
			"valid-single-entry",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			nil,
		},
		{
			"valid-multi-entry",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "2",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 1,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  2,
						Version:   "1.0.0",
						Timestamp: now + 2,
						Actions: []Action{
							{
								KID:           "3",
								DID:           "device-3",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 2,
								Key:           dec.EncodeToString(keys["3"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"2",
					&Operation{
						Sequence:  3,
						Version:   "1.0.0",
						Timestamp: now + 3,
						Actions: []Action{
							{
								KID:           "4",
								DID:           "device-4",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 3,
								Key:           dec.EncodeToString(keys["4"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"3",
					&Operation{
						Sequence:  4,
						Version:   "1.0.0",
						Timestamp: now + 4,
						Actions: []Action{
							{
								KID:           "2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyRevoke,
								EffectiveFrom: now + 4,
							},
							{
								KID:           "5",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 4,
								Key:           dec.EncodeToString(keys["5"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			nil,
		},
		{
			"valid-multi-entry-with-recovery",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "2",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 1,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  2,
						Version:   "1.0.0",
						Timestamp: now + 2,
						Actions: []Action{
							{
								KID:           "3",
								DID:           "device-3",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 2,
								Key:           dec.EncodeToString(keys["3"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"2",
					&Operation{
						Sequence:  3,
						Version:   "1.0.0",
						Timestamp: now + 3,
						Actions: []Action{
							{
								KID:           "4",
								DID:           "device-4",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 3,
								Key:           dec.EncodeToString(keys["4"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"3",
					&Operation{
						Sequence:  4,
						Version:   "1.0.0",
						Timestamp: now + 4,
						Actions: []Action{
							{
								KID:           "2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyRevoke,
								EffectiveFrom: now + 4,
							},
							{
								KID:           "5",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 4,
								Key:           dec.EncodeToString(keys["5"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"1",
					&Operation{
						Sequence:  5,
						Version:   "1.0.0",
						Timestamp: now + 5,
						Actions: []Action{
							{
								KID:           "1",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyRevoke,
								EffectiveFrom: now + 5,
							},
							{
								KID:           "6",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 5,
								Key:           dec.EncodeToString(keys["6"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "7",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 5,
								Key:           dec.EncodeToString(keys["7"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			nil,
		},
		{
			"invalid-sequence-ordering",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  3,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "2",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 1,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			ErrSequenceOutOfOrder,
		},
		{
			"invalid-timestamp",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "2",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			ErrInvalidTimestamp,
		},
		{
			"invalid-previous-signature",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Previous:  "invalid",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "2",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  2,
						Version:   "1.0.0",
						Timestamp: now + 2,
						Actions: []Action{
							{
								KID:           "3",
								DID:           "device-3",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["3"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			ErrInvalidPreviousSignature,
		},
		{
			"invalid-duplicate-key-identifier",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "1",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  2,
						Version:   "1.0.0",
						Timestamp: now + 2,
						Actions: []Action{
							{
								KID:           "3",
								DID:           "device-3",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["3"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			ErrKeyDuplicate,
		},
		{
			"invalid-no-active-keys",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "0",
								Type:          TypeDeviceKey,
								Action:        ActionKeyRevoke,
								EffectiveFrom: now + 1,
							},
							{
								KID:           "1",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyRevoke,
								EffectiveFrom: now + 1,
							},
						},
					},
				},
			},
			ErrNoValidKeys,
		},
		{
			"invalid-no-active-recovery-keys",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "1",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyRevoke,
								EffectiveFrom: now + 1,
							},
						},
					},
				},
			},
			ErrNoValidRecoveryKey,
		},
		{
			"invalid-multiple-recovery-keys",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "2",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 1,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			ErrMultipleActiveRecoveryKeys,
		},
		{
			"invalid-multiple-device-keys",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "2",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 1,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			ErrMultipleActiveDeviceKeys,
		},
		{
			"invalid-revoked-key-creation",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "2",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyRevoke,
								EffectiveFrom: now + 1,
							},
						},
					},
				},
				{
					"1",
					&Operation{
						Sequence:  2,
						Version:   "1.0.0",
						Timestamp: now + 2,
						Actions: []Action{
							{
								KID:           "3",
								DID:           "device-3",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 2,
								Key:           dec.EncodeToString(keys["3"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			ErrSignatureKeyRevoked,
		},
		{
			"invalid-signing-key",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "2",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"3",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "3",
								DID:           "device-3",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 1,
								Key:           dec.EncodeToString(keys["3"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			ErrInvalidSigningKey,
		},
		{
			"invalid-recovery-no-revoke",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "2",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"2",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "3",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 1,
								Key:           dec.EncodeToString(keys["3"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "4",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 1,
								Key:           dec.EncodeToString(keys["4"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			ErrInvalidAccountRecoveryAction,
		},
		{
			"invalid-empty-actions",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "2",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"2",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions:   []Action{},
					},
				},
			},
			ErrOperationNOOP,
		},
		{
			"invalid-already-revoked-key",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "2",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"1",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "0",
								Type:          TypeDeviceKey,
								Action:        ActionKeyRevoke,
								EffectiveFrom: now + 1,
							},
						},
					},
				},
				{
					"1",
					&Operation{
						Sequence:  2,
						Version:   "1.0.0",
						Timestamp: now + 2,
						Actions: []Action{
							{
								KID:           "0",
								Type:          TypeDeviceKey,
								Action:        ActionKeyRevoke,
								EffectiveFrom: now + 2,
							},
						},
					},
				},
			},
			ErrKeyAlreadyRevoked,
		},
		{
			"invalid-key-reference",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "2",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"1",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "10",
								Type:          TypeDeviceKey,
								Action:        ActionKeyRevoke,
								EffectiveFrom: now + 1,
							},
						},
					},
				},
			},
			ErrKeyMissing,
		},
		{
			"invalid-root-operation-key-revocation",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "0",
								Type:          TypeDeviceKey,
								Action:        ActionKeyRevoke,
								EffectiveFrom: now,
							},
							{
								KID:           "2",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			ErrInvalidKeyRevocation,
		},
		{
			"invalid-operation-signature",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								// set the public key of this key to differ from what we store in the test key set
								Key: dec.EncodeToString(keys["9"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "2",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"1",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "3",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now + 1,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			ErrInvalidOperationSignature,
		},
		{
			"invalid-operation-signature-root",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								// set the public key of this key to differ from what we store in the test key set
								Key: dec.EncodeToString(keys["9"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "2",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			ErrInvalidOperationSignature,
		},
		{
			"invalid-revocation-before-root-operation-timestamp",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "1.0.0",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "2",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
				{
					"0",
					&Operation{
						Sequence:  1,
						Version:   "1.0.0",
						Timestamp: now + 1,
						Actions: []Action{
							{
								KID:           "0",
								Type:          TypeDeviceKey,
								Action:        ActionKeyRevoke,
								EffectiveFrom: now - 100,
							},
						},
					},
				},
			},
			ErrSignatureKeyRevoked,
		},
		{
			"invalid-operation-version",
			[]testHistory{
				{
					"0",
					&Operation{
						Sequence:  0,
						Version:   "invalid",
						Previous:  "-",
						Timestamp: now,
						Actions: []Action{
							{
								KID:           "0",
								DID:           "device-1",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["0"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "1",
								DID:           "device-2",
								Type:          TypeDeviceKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
							},
							{
								KID:           "2",
								Type:          TypeRecoveryKey,
								Action:        ActionKeyAdd,
								EffectiveFrom: now,
								Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
							},
						},
					},
				},
			},
			ErrInvalidOperationVersion,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			history := make([]json.RawMessage, len(tc.history))
			signatures := make([]string, len(tc.history))

			// chain the signatures of the last and sign them
			for i := 0; i < len(tc.history); i++ {
				if tc.history[i].op.Previous == "" {
					tc.history[i].op.Previous = signatures[i-1]
				}

				op, sig := testop(keys, tc.history[i].signer, tc.history[i].op)

				history[i] = op
				signatures[i] = dec.EncodeToString(sig)
			}

			s, err := New(history)
			assert.Equal(t, tc.err, err)
			if tc.err == nil {
				assert.NotNil(t, s)
			}
		})
	}
}

func TestSignatureGraphExecute(t *testing.T) {
	keys := make(map[string]ed25519.PrivateKey)

	for i := 0; i < 10; i++ {
		_, sk, err := ed25519.GenerateKey(rand.Reader)
		require.Nil(t, err)

		keys[strconv.Itoa(i)] = sk
	}

	now := time.Now().Unix()

	op1, sig := testop(keys, "1", &Operation{
		Sequence:  0,
		Version:   "1.0.0",
		Timestamp: now,
		Actions: []Action{
			{
				KID:           "1",
				DID:           "device-1",
				Type:          TypeDeviceKey,
				Action:        ActionKeyAdd,
				EffectiveFrom: now,
				Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
			},
			{
				KID:           "2",
				Type:          TypeRecoveryKey,
				Action:        ActionKeyAdd,
				EffectiveFrom: now,
				Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
			},
		},
	})

	history := []json.RawMessage{
		op1,
	}

	s, err := New(history)
	require.Nil(t, err)

	op2, _ := testop(keys, "1", &Operation{
		Sequence:  1,
		Version:   "1.0.0",
		Previous:  dec.EncodeToString(sig),
		Timestamp: now + 1,
		Actions: []Action{
			{
				KID:           "1",
				Type:          TypeDeviceKey,
				Action:        ActionKeyRevoke,
				EffectiveFrom: now + 1,
			},
			{
				KID:           "3",
				DID:           "device-1",
				Type:          TypeDeviceKey,
				Action:        ActionKeyAdd,
				EffectiveFrom: now + 1,
				Key:           dec.EncodeToString(keys["3"].Public().(ed25519.PublicKey)),
			},
		},
	})

	err = s.Execute(op2)
	require.Nil(t, err)
	assert.Len(t, s.ops, 2)
}

func TestSignatureGraphIsKeyValid(t *testing.T) {

	keys := make(map[string]ed25519.PrivateKey)

	for i := 0; i < 10; i++ {
		_, sk, err := ed25519.GenerateKey(rand.Reader)
		require.Nil(t, err)

		keys[strconv.Itoa(i)] = sk
	}

	now := time.Now().Unix()

	op1, sig := testop(keys, "1", &Operation{
		Sequence:  0,
		Version:   "1.0.0",
		Timestamp: now,
		Actions: []Action{
			{
				KID:           "1",
				DID:           "device-1",
				Type:          TypeDeviceKey,
				Action:        ActionKeyAdd,
				EffectiveFrom: now,
				Key:           dec.EncodeToString(keys["1"].Public().(ed25519.PublicKey)),
			},
			{
				KID:           "2",
				Type:          TypeRecoveryKey,
				Action:        ActionKeyAdd,
				EffectiveFrom: now,
				Key:           dec.EncodeToString(keys["2"].Public().(ed25519.PublicKey)),
			},
		},
	})

	op2, _ := testop(keys, "1", &Operation{
		Sequence:  1,
		Version:   "1.0.0",
		Previous:  dec.EncodeToString(sig),
		Timestamp: now + 1,
		Actions: []Action{
			{
				KID:           "1",
				Type:          TypeDeviceKey,
				Action:        ActionKeyRevoke,
				EffectiveFrom: now + 1,
			},
			{
				KID:           "3",
				DID:           "device-1",
				Type:          TypeDeviceKey,
				Action:        ActionKeyAdd,
				EffectiveFrom: now + 1,
				Key:           dec.EncodeToString(keys["3"].Public().(ed25519.PublicKey)),
			},
		},
	})

	history := []json.RawMessage{
		op1,
		op2,
	}

	s, err := New(history)
	require.Nil(t, err)

	assert.True(t, s.IsKeyValid("1", now))
	assert.False(t, s.IsKeyValid("1", now+1))
	assert.False(t, s.IsKeyValid("1", now+2))
	assert.False(t, s.IsKeyValid("1", now-1))
	assert.True(t, s.IsKeyValid("3", now+1))
	assert.True(t, s.IsKeyValid("3", now+2))
	assert.False(t, s.IsKeyValid("3", now-1))
}
