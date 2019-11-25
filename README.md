# Self Go SDK

An sdk for interacting with the self API.

## Setup

To run tests against this repo, you must run dep:

`$ make deps`

## Running tests

To run unit tests on the contract:

`$ make test`

## SDK Setup

```go
import (
    selfsdk "github.com/selfid-net/self-go-sdk"
)

func main() {
    self, err := client.New("application_id", "private_key_seed")
    ...
}
```


## Getting an Identity

```go
identity, err := self.GetIdentity("self-id")
...
```

## Getting an App

```go
app, err := self.GetApp("app-id")
...
```

## Authenticating a user

To authenticate a user, you must provide the identity of the user you want to authenticate, in addition to a publicly exposed HTTP endpoint that the response will be sent to.

The returned `requestID` will allow you to keep track of requests when receiving a response.

```go
requestID, err := self.Authenticate("self-id", "https://example.com/myCallbackURL")
if err != nil {
    panic(err)
}
```

## Validating an authentication response

Upon receiving an authentication response from self, you can validate it by using the `ValidateAuth` method. This will return the id of the original request, as well as an error if the authentication attempt was unsuccessful.

```go
response, _ := ioutil.ReadAll(r.Body)

requestID, err := self.ValidateAuth(response)
...
```
