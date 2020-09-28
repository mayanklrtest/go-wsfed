# go-wsfed

High-level API library for implementing WSFed client based on  [etree](https://github.com/beevik/etree) and [signedxml](https://github.com/ma314smith/signedxml), a pure Go implementation.
The library provides the Identity Provider implementation.

## Features

- Generating Token (SAML v1.1) based on the Request Param for login


## Installation
Install `go-wsfed` into your `$GOPATH` using go get:
```
go get github.com/LoginRadius/go-wsfed
```
## Usage
Below are samples to show how you might use the library.

### Create Configuration
```
wsFedConfig := &wsfed.Config{
    Issuer:               "https://id-provider.example.com",
    Audiences:            "https://service-provider.test.com",
    Cert:                 "<IDPCert PEM Format>",
    Key:                  "<IDPKey PEM Format>",
    NameIdentifier:       "6789876543234567898765456789",
    NameIdentifierFormat: wsfed.NameIdFormatUnspecified,
    Claims:               map[string]string{
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "john@idp.com"
    }
    WReplyURL:            "https://service-provider.test.com/sp/login",
    WsFedRequestParam:    wsfed.WsFedRequestParam{
        Wa:      "<Wa RequestParam>", //Get from the wsfed request
        Wctx:    "<Wctx RequestParam>", //Get from the wsfed request
        Wtrealm: "<Wtrealm RequestParam>", //Get from the wsfed request
    },
}

//You can add calims in config itself as map[string]string or use below helper function
wsFedConfig.AddClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "john@idp.com")
```

### Generate WsFed Login Response
```
signedXML, err := wsFedConfig.GetSignedResponse()
if wErr != nil {
    return err
}

//Generate Post Html Form
responseHTML, err := wsFedConfig.ResponseHtml(signedXML)
if wErr != nil {
    return err
}
```
## Contributing
Would love any contributions you, having including better documentation, tests, or more robust functionality. Please follow the [contributing guide](CONTRIBUTING.md)

## License
[MIT](LICENSE)
