package internal

import (
	"encoding/xml"
	"github.com/mayanklrtest/go-wsfed/internal/util"
)

type Signature struct {
	XMLName        xml.Name
	XMLNS          string `xml:"xmlns,attr"`
	SignedInfo     SignedInfo
	SignatureValue SignatureValue
	KeyInfo        KeyInfo
}

type SignedInfo struct {
	XMLName                xml.Name
	CanonicalizationMethod CanonicalizationMethod
	SignatureMethod        SignatureMethod
	SamlReference          SamlReference
}

type SignatureValue struct {
	XMLName xml.Name
	Value   string `xml:",innerxml"`
}

type KeyInfo struct {
	XMLName  xml.Name
	X509Data X509Data `xml:",innerxml"`
}

type CanonicalizationMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type SignatureMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type SamlReference struct {
	XMLName      xml.Name
	URI          string       `xml:"URI,attr"`
	Transforms   Transforms   `xml:",innerxml"`
	DigestMethod DigestMethod `xml:",innerxml"`
	DigestValue  DigestValue  `xml:",innerxml"`
}

type X509Data struct {
	XMLName         xml.Name
	X509Certificate X509Certificate `xml:",innerxml"`
}

type Transforms struct {
	XMLName   xml.Name
	Transform []Transform
}

type DigestMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type DigestValue struct {
	XMLName xml.Name
}

type X509Certificate struct {
	XMLName xml.Name
	Cert    string `xml:",innerxml"`
}

type Transform struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

/*type Response struct {
	XMLName      xml.Name
	SAMLP        string `xml:"xmlns:samlp,attr"`
	SAML         string `xml:"xmlns:saml,attr"`
	SAMLSIG      string `xml:"xmlns:samlsig,attr"`
	Destination  string `xml:"Destination,attr"`
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`

	Issuer    Issuer    `xml:"Issuer"`
	Status    Status    `xml:"Status"`
	Assertion Assertion `xml:"Assertion"`

	originalString string
}
<t:RequestSecurityTokenResponse
Context=\"" + escapedWctx + "\"
xmlns:t=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">
<t:RequestedSecurityToken>" + assertion + "</t:RequestedSecurityToken>
</t:RequestSecurityTokenResponse>
*/

type RequestSecurityTokenResponse struct {
	XMLName                xml.Name
	Context                string `xml:"Context,attr"`
	XMLNS                  string `xml:"xmlns:t,attr"`
	RequestedSecurityToken RequestedSecurityToken
}

type RequestedSecurityToken struct {
	XMLName   xml.Name
	Assertion string `xml:",innerxml"`
}

type Assertion struct {
	XMLName                 xml.Name
	XMLNS                   string `xml:"xmlns:saml,attr"`
	MajorVersion            string `xml:"MajorVersion,attr"`
	MinorVersion            string `xml:"MinorVersion,attr"`
	AssertionID             string `xml:"AssertionID,attr"`
	IssueInstant            string `xml:"IssueInstant,attr"`
	Issuer                  string `xml:"Issuer,attr"`
	Conditions              Conditions
	AttributeStatement      AttributeStatement
	AuthenticationStatement AuthenticationStatement
	Signature               Signature `xml:"Signature"`
}

type Conditions struct {
	XMLName             xml.Name
	NotBefore           string              `xml:",attr"`
	NotOnOrAfter        string              `xml:",attr"`
	AudienceRestriction AudienceRestriction `xml:"AudienceRestriction,omitempty"`
}

type AudienceRestriction struct {
	XMLName   xml.Name
	Audiences []Audience `xml:"Audience"`
}

type Audience struct {
	XMLName xml.Name
	Value   string `xml:",innerxml"`
}

type AuthenticationStatement struct {
	XMLName               xml.Name
	AuthenticationMethod  string `xml:",attr"`
	AuthenticationInstant string `xml:",attr"`
	Subject               Subject
}

type Subject struct {
	XMLName             xml.Name
	NameIdentifier      NameIdentifier
	SubjectConfirmation SubjectConfirmation
}

type NameIdentifier struct {
	XMLName xml.Name
	Format  string `xml:"Format,attr"`
	Value   string `xml:",innerxml"`
}

type SubjectConfirmation struct {
	XMLName            xml.Name
	ConfirmationMethod ConfirmationMethod
}

type ConfirmationMethod struct {
	XMLName xml.Name
	Value   string `xml:",innerxml"`
}

type StatusCode struct {
	XMLName xml.Name
	Value   string `xml:",attr"`
}

type AttributeValue struct {
	XMLName xml.Name
	Value   string `xml:",innerxml"`
}

type Attribute struct {
	XMLName            xml.Name
	AttributeNamespace string         `xml:"AttributeNamespace,attr"`
	AttributeName      string         `xml:"AttributeName,attr"`
	AttributeValues    AttributeValue `xml:"AttributeValue"`
}

type AttributeStatement struct {
	XMLName    xml.Name
	Subject    Subject
	Attributes []Attribute `xml:"Attribute,omitempty"`
}

func (a *Assertion) String() (string, error) {
	b, err := xml.MarshalIndent(a, "", "")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (a *RequestSecurityTokenResponse) String() (string, error) {
	b, err := xml.MarshalIndent(a, "", "")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (a *Assertion) AddAttribute(claim string, name string, value string) {
	a.AttributeStatement.Attributes = append(a.AttributeStatement.Attributes, Attribute{
		XMLName: xml.Name{
			Local: "saml:Attribute",
		},
		AttributeNamespace: claim,
		AttributeName:      name,
		AttributeValues: AttributeValue{
			XMLName: xml.Name{
				Local: "saml:AttributeValue",
			},
			Value: value,
		},
	})
}

func (a *Assertion) AddAudience(audience string) {
	a.Conditions.AudienceRestriction.Audiences = append(a.Conditions.AudienceRestriction.Audiences, Audience{
		XMLName: xml.Name{
			Local: "saml:Audience",
		},
		Value: audience,
	})
}

func (a *Assertion) SignedString(privateKey string, context string) (string, error) {
	s, err := a.String()
	if err != nil {
		return "", err
	}
	k, err := util.ParseRsaPrivateKeyFromPemStr(privateKey)
	if err != nil {
		return "", err
	}
	signedXML, err := util.Sign(s, k)
	if err != nil {
		return "", err
	}
	requestSecurityTokenResponse := GetRequestSecurityTokenResponse(signedXML, context)
	return requestSecurityTokenResponse.String()
}
