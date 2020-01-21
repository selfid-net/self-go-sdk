# Self - Authenticate Example

This example shows a simple web application using Self for authentication.

It consists of five HTTP endpoints:

`/`  - Landing page (authentication challenge).  
`/qrcode`  - Generates QR Code which is used by the landing page.  
`/auth`  - Provides a websocket connection between the application and browser.  
`/accept`  - Authentication accepted.  
`/reject`  - Authentication rejected.

> Note: In this example we use websockets for communication between the browser and application. This isn't a requirement so feel free to replace this with whatever best fits your usecase.

## Usage

Start the application:
```
cd examples/authentication
APP_ID=<SELF-APP-ID> APP_KEY=<SELF-APP-KEY> go run *.go
```

The application should now be available at http://localhost:4000.
