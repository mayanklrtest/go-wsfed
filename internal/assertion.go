package internal

import (
	"encoding/xml"
	"github.com/mayanklrtest/go-wsfed/internal/util"
	"time"
)

func NewAssertion() *Assertion {
	notBeforeTime := time.Now().UTC().Format(time.RFC3339)
	NotOnOrAfterTIme := time.Now().Add(time.Minute * 10).UTC().Format(time.RFC3339)
	return &Assertion{
		XMLName: xml.Name{
			Local: "saml:Assertion",
		},
		XMLNS:        "urn:oasis:names:tc:SAML:1.0:assertion",
		MajorVersion: "1",
		MinorVersion: "1",
		AssertionID:  util.ID(),
		IssueInstant: notBeforeTime,
		Issuer:       "",
		Conditions: Conditions{
			XMLName: xml.Name{
				Local: "saml:Conditions",
			},
			NotBefore:    notBeforeTime,
			NotOnOrAfter: NotOnOrAfterTIme,
			AudienceRestriction: AudienceRestriction{
				XMLName: xml.Name{
					Local: "saml:AudienceRestrictionCondition",
				},
				Audiences: []Audience{},
			},
		},
		AttributeStatement: AttributeStatement{
			XMLName: xml.Name{
				Local: "saml:AttributeStatement",
			},
			Subject: Subject{
				XMLName: xml.Name{
					Local: "saml:Subject",
				},
				NameIdentifier: NameIdentifier{
					XMLName: xml.Name{
						Local: "saml:NameIdentifier",
					},
					Format: "",
					Value:  "",
				},
				SubjectConfirmation: SubjectConfirmation{
					XMLName: xml.Name{
						Local: "saml:SubjectConfirmation",
					},
					ConfirmationMethod: ConfirmationMethod{
						XMLName: xml.Name{
							Local: "saml:ConfirmationMethod",
						},
						Value: "urn:oasis:names:tc:SAML:1.0:cm:bearer",
					},
				},
			},
			Attributes: []Attribute{},
		},
		AuthenticationStatement: AuthenticationStatement{
			XMLName: xml.Name{
				Local: "saml:AuthenticationStatement",
			},
			AuthenticationMethod:  "urn:oasis:names:tc:SAML:1.0:am:password",
			AuthenticationInstant: NotOnOrAfterTIme,
			Subject: Subject{
				XMLName: xml.Name{
					Local: "saml:Subject",
				},
				NameIdentifier: NameIdentifier{
					XMLName: xml.Name{
						Local: "saml:NameIdentifier",
					},
					Format: "",
					Value:  "",
				},
				SubjectConfirmation: SubjectConfirmation{
					XMLName: xml.Name{
						Local: "saml:SubjectConfirmation",
					},
					ConfirmationMethod: ConfirmationMethod{
						XMLName: xml.Name{
							Local: "saml:ConfirmationMethod",
						},
						Value: "urn:oasis:names:tc:SAML:1.0:cm:bearer",
					},
				},
			},
		},
		Signature: Signature{
			XMLName: xml.Name{
				Local: "Signature",
			},
			XMLNS: "http://www.w3.org/2000/09/xmldsig#",
			SignedInfo: SignedInfo{
				XMLName: xml.Name{
					Local: "SignedInfo",
				},
				CanonicalizationMethod: CanonicalizationMethod{
					XMLName: xml.Name{
						Local: "CanonicalizationMethod",
					},
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
				},
				SignatureMethod: SignatureMethod{
					XMLName: xml.Name{
						Local: "SignatureMethod",
					},
					Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
				},
				SamlReference: SamlReference{
					XMLName: xml.Name{
						Local: "Reference",
					},
					URI: "", // caller must populate "#" + ar.Id,
					Transforms: Transforms{
						XMLName: xml.Name{
							Local: "Transforms",
						},
						Transform: []Transform{{
							XMLName: xml.Name{
								Local: "Transform",
							},
							Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
						}, {
							XMLName: xml.Name{
								Local: "Transform",
							},
							Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
						}},
					},
					DigestMethod: DigestMethod{
						XMLName: xml.Name{
							Local: "DigestMethod",
						},
						Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
					},
					DigestValue: DigestValue{
						XMLName: xml.Name{
							Local: "DigestValue",
						},
					},
				},
			},
			SignatureValue: SignatureValue{
				XMLName: xml.Name{
					Local: "SignatureValue",
				},
			},
			KeyInfo: KeyInfo{
				XMLName: xml.Name{
					Local: "KeyInfo",
				},
				X509Data: X509Data{
					XMLName: xml.Name{
						Local: "X509Data",
					},
					X509Certificate: X509Certificate{
						XMLName: xml.Name{
							Local: "X509Certificate",
						},
						Cert: "", // caller must populate cert,
					},
				},
			},
		},
	}
}

func GetRequestSecurityTokenResponse(assertion string, context string) *RequestSecurityTokenResponse {
	return &RequestSecurityTokenResponse{
		XMLName: xml.Name{
			Local: "t:RequestSecurityTokenResponse",
		},
		Context: context,
		XMLNS:   "http://schemas.xmlsoap.org/ws/2005/02/trust",
		RequestedSecurityToken: RequestedSecurityToken{
			XMLName: xml.Name{
				Local: "t:RequestedSecurityToken",
			},
			Assertion: assertion,
		},
	}
}
