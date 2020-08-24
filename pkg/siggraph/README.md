# Signature Graph

## Features
- [x] Operations to add and revoke keys are chained together with signatures
- [x] Add and Revoke multiple keys in a single transaction
- [x] Retroactive Revocation of device keys
- [x] Implicit revocation of all existing keys when recovering an account
- [x] Graphviz output of the key graph

# Design

Keys are added and revoked from an identity through a series of `operations`, which can each have a number of different `actions` that add and revoke public keys. The current state of an identity is represented as a list of json web signatures. Each addition to the list includes in its payload the signature of its predecessor. 

An identities representation will be stored on the chain as follows. Each JWS represents an operation that may contain a number of actions that add or revoke keys.
```json
{
    "id": "1234567890",
    "history": [
        {
            "protected": "signed-header",
            "payload": "signed-payload",
            "signature": "signature"
        },
        {
            "protected": "signed-header",
            "payload": "signed-payload",
            "signature": "signature"
        },
        {
            "protected": "signed-header",
            "payload": "signed-payload",
            "signature": "signature"
        }
    ]
}
```

### Protected Header

Each protected header will contain the following:
```json
{
    "alg": "EdDSA",
    "kid": "key-identifier"
}
```

It denotes the algorithm and ID of the key used to sign the operation. For the first (root) operation in a tree, it will be self signed. 


### Payload/Operation

Each payload will represent an operation on the identity:

```json
{
    "sequence": 0,
    "previous": "-",
    "timestamp": 1597315919,
    "actions": [
        {
            "kid": "0",
            "type": "device.key",
            "action": "key.add",
            "effective_from": 1597315919,
            "key": "w9U2Wbf3IvP8tq4tGa9m1AFqkRjCf8NLwZvKwOfAaGg"
        },
        {
            "kid": "1",
            "type": "recovery.key",
            "action": "key.add",
            "effective_from": 1597315919,
            "key": "8OKgkjZh73vqWbdq_wLlo307FwZVC8ld29B0nRIfCh8"
        }
    ]
}
```

An operation defines a sequence, which denotes the order that the operation appears in. This is an monotonically increasing number, starting from `0`.

The previous field is used to specify the signature of the previous operation. For the first operation in the identites history, this will be set to `-`.

Every operation should include a unix timestamp of the time when the request was issued.