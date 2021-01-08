# Fact request witnessed by an independent intermediary

An intermediary fact request allows you do assertions on an identities.facts. through _Self Intermediary_ without having to directly hold or view any of the users sensitive information.

This reduces the liabilities of having to securely store user information and complying with data regulations on your organisation, whilst being able to ensure that your criteria for that data is met.

## Running this example

In order to run this example, you must have a valid app id and private key. Self credentials are issued by the [Self Developer portal](https://developer.joinself.com/) when you create a new app.

Once you have your valid `SELF_APP_ID` and `SELF_APP_DEVICE_SECRET` you can run this example with:

```bash
$ SELF_INTERMEDIARY=XXXX SELF_APP_ID=XXXXX SELF_APP_DEVICE_SECRET=XXXXXXXX go run fact.go <your_users_self_id>
```

Note you must provide a valid user self_id for `your_users_self_id`. This example will send a fact request to this self_id's devices, so keep an eye on the user's device to look for the fact request.


## Process diagram

This diagram shows how the intermediary witnessed fact request process works internally.

![Diagram](https://static.joinself.com/images/intermediary_fact_request_diagram.png)

1. Request intermediary to check an identities.facts. through the self SDK with the data you want to assert, like age > 18.
2. SDK will send a fact request to the intermediary.
3. Intermediary will send a fact request with the same facts you want to assert to your already connected identity.
4. The user will select the requested facts and accept sharing them with the intermediary.
5. The user’s device will send back a signed response with the requested facts.
6. Intermediary verifies the response has been signed by the user based on its public keys.
7. Intermediary verifies each fact is signed by the user/app specified on each fact.
8. Intermediary does its calculations and signs specific facts with the result, and it sends it back to your app.
9. SDK on your app verifies the response and facts have been signed by the intermediary based on its public keys.
10. Your app gets a verified response with the result of the attestation.
