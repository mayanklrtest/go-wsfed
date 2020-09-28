package wsfed

import (
	"bytes"
	"errors"
	"github.com/mayanklrtest/go-wsfed/internal"
	"github.com/mayanklrtest/go-wsfed/internal/templates"
	"github.com/mayanklrtest/go-wsfed/internal/util"
)

const (
	NameIdFormatEmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIdFormatUnspecified  = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
)

var wsFedtemplate = templates.WSFedPostForm()

type WsFedRequestParam struct {
	Wa      string `json:"wa"`
	Wtrealm string `json:"wtrealm"`
	Wreply  string `json:"wreply"`
	Wctx    string `json:"wctx"`
	Wct     string `json:"wct"`
	Wfresh  string `json:"wfresh"`
}

type wsFedResponse struct {
	Wreply  string
	Wctx    string
	Wresult string
}

type Config struct {
	Issuer               string
	Cert                 string
	Key                  string
	Audiences            []string
	Wctx                 string
	WReplyURL            string
	Claims               map[string]string
	SignatureAlgorithm   string
	DigestAlgorithm      string
	LifetimeInSeconds    int64
	NameIdentifier       string
	NameIdentifierFormat string
	WsFedRequestParam    WsFedRequestParam
}

func getAssertion(conf *Config) (*internal.Assertion, error) {
	if conf.Issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if len(conf.Audiences) == 0 {
		return nil, errors.New("audience is required")
	}
	if conf.Key == "" {
		return nil, errors.New("key is required")
	}
	if conf.Cert == "" {
		return nil, errors.New("cert is required")
	}
	if len(conf.Claims) == 0 {
		return nil, errors.New("claims is required")
	}
	if conf.NameIdentifier == "" {
		return nil, errors.New("nameIdentifier is required")
	}
	if conf.NameIdentifierFormat == "" {
		return nil, errors.New("nameIdentifierFormat is required")
	}
	assertion := internal.NewAssertion()
	assertion.Issuer = conf.Issuer
	assertion.Signature.SignedInfo.SamlReference.URI = "#" + assertion.AssertionID
	assertion.Signature.KeyInfo.X509Data.X509Certificate.Cert = util.ParseCertificateStr(conf.Cert)
	assertion.AuthenticationStatement.Subject.NameIdentifier.Format = conf.NameIdentifierFormat
	assertion.AuthenticationStatement.Subject.NameIdentifier.Value = conf.NameIdentifier
	assertion.AttributeStatement.Subject.NameIdentifier.Format = conf.NameIdentifierFormat
	assertion.AttributeStatement.Subject.NameIdentifier.Value = conf.NameIdentifier
	for claim, value := range conf.Claims {
		claimAttr := util.GetClaimAttribute(claim)
		assertion.AddAttribute(claimAttr.Format, claimAttr.Name, value)
	}
	for _, audience := range conf.Audiences {
		assertion.AddAudience(audience)
	}
	return assertion, nil
}

func (conf *Config) AddClaim(format, value string) {
	conf.Claims[format] = value
}

func (conf *Config) GetSignedResponse() (string, error) {
	assertion, err := getAssertion(conf)
	if err != nil {
		return "", err
	}
	str, err := assertion.SignedString(conf.Key, conf.Wctx)
	return str, err
}

func (conf *Config) ResponseHtml(xml string) (string, error) {
	wsFedRes := &wsFedResponse{
		Wreply:  conf.WReplyURL,
		Wctx:    conf.WsFedRequestParam.Wctx,
		Wresult: xml,
	}
	return wsFedRes.ResponseHtml()
}

func (res *wsFedResponse) ResponseHtml() (string, error) {
	var b bytes.Buffer
	if err := wsFedtemplate.Execute(&b, *res); err != nil {
		return "", err
	}
	return b.String(), nil
}
