# SelfID based fact request

Your app can request your users to share attested facts about themselves. To do this, you'll only need the identities _SelfID_ and the facts you want to request. You can find a list of updated valid facts and their respective sources [here](https://github.com/joinself/self-go-sdk/blob/master/fact/fact.go).

## Running this example

In order to run this example, you must have a valid app id and private key. Self credentials are issued by the [Self Developer portal](https://developer.joinself.com/) when you create a new app.

Once you have your valid `SELF_APP_ID` and `SELF_APP_DEVICE_SECRET` you can run this example with:

```bash
$ SELF_APP_ID=XXXXX SELF_APP_DEVICE_SECRET=XXXXXXXX go run fact.go <your_users_self_id>
```

Note you must provide a valid user self_id for `your_users_self_id`. This example will send a fact request to this self_id's devices, so keep an eye on the user's device to look for the fact request.

If the identity has no attested facts matching the criteria of the request, they will be prompted to validate them through the self app.

## Process diagram

This diagram shows how the fact request process works.

![Diagram](https://static.joinself.com/images/fact_request_diagram.png)


1. Request information through the self SDK.
2. SDK will send a fact request to an identity already connected to you.
3. The user will select the requested facts and accept sharing them with you.
4. The user’s device will send back a signed response with specific facts.
5. Self SDK verifies the response has been signed by the user based on its public keys.
6. Self SDK verifies each fact is signed by the user/app specified on each fact.
7. Your app gets a verified response with a list of requested verified facts.
