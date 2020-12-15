// Copyright 2020 Self Group Ltd. All Rights Reserved.

package siggraph

import "errors"

var (
	// ErrSequenceOutOfOrder returned when an operation's sequence number in the history log is out of order
	ErrSequenceOutOfOrder = errors.New("signature graph contains an operation sequence that is out of order")
	// ErrInvalidPreviousSignature returned when an operation specifies the signature of an invalid or non-existent previous operation
	ErrInvalidPreviousSignature = errors.New("signature graph contains an operation that specifies an invalid previous operatation signature")
	// ErrInvalidTimestamp returned when an operations timestamp has not increased from the previous operation
	ErrInvalidTimestamp = errors.New("signature graph contains an operation with a timestamp that is the same or before the previous operations timestamp")
	// ErrInvalidSigningKey returned when an operation is signed with a key that is invalid or does not exist
	ErrInvalidSigningKey = errors.New("signature graph contains an operation that has been signed with a key that cannot be found")
	// ErrInvalidOperationSignature returned when the signature of an operation was not signed with the specified key
	ErrInvalidOperationSignature = errors.New("signature graph contains an operation that has an invalid signature")
	// ErrOperationNOOP returned when an operation specifies no valid actions
	ErrOperationNOOP = errors.New("signature graph contains an operation with no valid actions")
	// ErrInvalidKeyEncoding returned when an operations action contains a key that has not been correctly encoded
	ErrInvalidKeyEncoding = errors.New("signature graph contains an operation action that specifies an badly encoded key")
	// ErrKeyDuplicate returned when more than one key is added with the same key identifier
	ErrKeyDuplicate = errors.New("signature graph contains an operation action that creates a key with the same identifier as an existing key")
	// ErrKeyMissing returned when an action references a key that does not exist
	ErrKeyMissing = errors.New("signature graph contains an operation action that references an existing key that does not exist")
	// ErrKeyAlreadyRevoked returned when an action attempts to revoke a key that has already been revoked
	ErrKeyAlreadyRevoked = errors.New("signature graph contains an operation action that revokes an already revoked key")
	// ErrInvalidKeyRevocation returned when the first operation in the history log attempts to revoke a key
	ErrInvalidKeyRevocation = errors.New("signature graph root operation contains an invalid key revocation")
	// ErrSignatureKeyRevoked returned when the operation was signed by a key that was either not created or revoked at the time the signature was made
	ErrSignatureKeyRevoked = errors.New("signature graph contains an operation that was signed with a key that was invalid for that time period")
	// ErrMultipleActiveDeviceKeys returned when an identity has more than one active key for a device
	ErrMultipleActiveDeviceKeys = errors.New("signature graph contains more than one active key for a given device")
	// ErrMultipleActiveRecoveryKeys returned when an identity has more than one active recovery keys
	ErrMultipleActiveRecoveryKeys = errors.New("signature graph contains more than one active recovery key")
	// ErrInvalidAccountRecoveryAction returned when the first action in an operation that is an account recovery does not revoke the existing recovery key
	ErrInvalidAccountRecoveryAction = errors.New("signature graph contains an account recovery operation that does not invalidate the existing recovery key")
	// ErrInvalidActionKeyID returned when an action does not contain a valid key identifier
	ErrInvalidActionKeyID = errors.New("action contains an invalid key identifier")
	// ErrUnknownActionType returned when an action is not of a known type
	ErrUnknownActionType = errors.New("action contains an invalid action type")
	// ErrUnknownAction returned when the specified action is not valid
	ErrUnknownAction = errors.New("action is not valid")
	// ErrInvalidActionKey returned when the action provides an invalid or empty key
	ErrInvalidActionKey = errors.New("action must specify a valid public key")
	// ErrInvalidActionDID returned when the action does not provide a valid device identifier
	ErrInvalidActionDID = errors.New("action must specify a valid device identifier")
	// ErrInvalidActionEffectiveFromTime returned when the unix timestamp for when the action takes effect is not provided
	ErrInvalidActionEffectiveFromTime = errors.New("action must specify when a time the action takes effect from")
	// ErrNoValidRecoveryKey returned when there are no valid recovery keys on the graph
	ErrNoValidRecoveryKey = errors.New("signature graph contains no active recovery keys")
	// ErrNoValidKeys returned when there are no valid or active keys on the graph
	ErrNoValidKeys = errors.New("signature graph contains no active or valid keys")
	// ErrInvalidPublicKeyEncoding is returned when the identities public key is not valid base64
	ErrInvalidPublicKeyEncoding = errors.New("identity public key is not a valid base64 url encoded string")
	// ErrInvalidPublicKeyLength is returned when a specfied public key's length is less than 32
	ErrInvalidPublicKeyLength = errors.New("specified public key length is invalid")
	// ErrInvalidOperationVersion is returned when an operation does not specify a valid version
	ErrInvalidOperationVersion = errors.New("signature graph contains an operation that does not contain a valid version")
	// ErrKeyNotFound returned when the caller asks for a key that cannot be found on the graph
	ErrKeyNotFound = errors.New("signature graph does not contain a key with the specified identifier")
	// ErrDeviceNotFound returned when the caller asks for a device that cannot be found on the graph
	ErrDeviceNotFound = errors.New("signature graph does not contain a device with the specified identifier")
	// ErrKeyRevoked returned when the caller asks for a key that has been revoked
	ErrKeyRevoked = errors.New("the specified key has been revoked")
	// ErrNotDeviceKey returned when the caller asks for a device ID by it's key identifier, but the key is not a device key
	ErrNotDeviceKey = errors.New("the specified key identifier is not a device key")
)
