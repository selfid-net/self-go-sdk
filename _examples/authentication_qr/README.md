# QR based authentication request

A Self identity can be authenticated on your platform by displaying a qr code that can be scanned with their device. The identity will then accept or reject the authentication request on their phone and send a cryptographically signed response.

As part of this process, you have to share the generated QR code with your users, and wait for a response.

## Running this example

In order to run this example, you must have a valid app id and private key. Self credentials are issued by the [Self Developer portal](https://developer.selfid.net/) when you create a new app.

Once you have your valid `SELF_APP_ID` and `SELF_APP_SECRET` you can run this example with:

```bash
$ SELF_APP_ID=XXXXX SELF_APP_SECRET=XXXXXXXX go run authentication.go
```

Running this command will open the qr code in a browser, which you will need to scan with the self app on your device.

## Process diagram

This diagram shows how the Self authentication process works when using a qr code.

![Diagram](https://storage.googleapis.com/static.selfid.net/images/authentication_qr_diagram.png)

1. Generate Self authentication request QR code
2. Share generated QR code with your user
3. The user scans the Self authentication request QR code
4. The user sends back a signed approved response
5. Self SDK verifies the response has been signed by the user based on its public keys.
6. Your app gets an approved verified auth response
