# SelfID based authentication request

A Self identity can be authenticated on your platform by only providing its _SelfID_. The identity will then accept or reject the authentication request on their phone and send a cryptographically signed response.

As part of this process, you will provide your users with a user interface so that they can fill in their _SelfID_.

## Running this example

In order to run this example, you must have a valid app id and private key. Self credentials are issued by the [Self Developer portal](https://developer.joinself.com/) when you create a new app.

Once you have your valid `SELF_APP_ID` and `SELF_APP_SECRET` you can run this example with:

```bash
$ SELF_APP_ID=XXXXX SELF_APP_SECRET=XXXXXXXX go run authentication.go <your_users_self_id>
```

Note you must provide a valid user self_id for `your_users_self_id`. This example will send an authentication request to this self_id, so keep an eye on the user's device to look for the authentication request.


## Process diagram

This diagram shows how the Self authentication process works.

![Diagram](https://static.joinself.com/images/authentication_diagram.png)

1. Request specific identity authentication through self-sdk
2. Self-SDK will send the authentication request to the specified users devices.
3. The user sends back a signed approved or rejected response
4. Self SDK verifies the response has been signed by the user based on its public keys.
5. Your app gets an approved verified auth response
