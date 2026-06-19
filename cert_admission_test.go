package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testTemplateOID = "1.3.6.1.4.1.311.21.8.1234567.7654321.1.2.3.4.5"
const testTemplateName = "ExampleClientTemplate"

// asn1ShortTLV encodes a single ASN.1 TLV with a short (<128 byte) definite length.
func asn1ShortTLV(tag byte, content []byte) []byte {
	out := []byte{tag, byte(len(content))}
	return append(out, content...)
}

// bmpStringExt builds an AD CS v1 template-name extension value as a BMPString TLV.
func bmpStringExt(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u16)*2)
	for _, r := range u16 {
		b = append(b, byte(r>>8), byte(r))
	}
	return asn1ShortTLV(0x1e, b) // 0x1e = BMPString
}

type certOpts struct {
	cn           string
	orgs         []string
	ous          []string
	dnsSANs      []string
	uriSANs      []string
	emailSANs    []string
	eku          []x509.ExtKeyUsage
	templateOID  string
	templateName string
}

// makeTestClientCert builds a CA and a leaf client cert per opts, returning the parsed leaf.
func makeTestClientCert(t *testing.T, opts certOpts) *x509.Certificate {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Issuing CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var extraExts []pkix.Extension
	if opts.templateOID != "" {
		oid, err := parseDottedOID(opts.templateOID)
		require.NoError(t, err)
		der, err := asn1.Marshal(msTemplateV2{TemplateID: oid, MajorVersion: 100, MinorVersion: 2})
		require.NoError(t, err)
		extraExts = append(extraExts, pkix.Extension{Id: oidMSTemplateV2, Value: der})
	}
	if opts.templateName != "" {
		extraExts = append(extraExts, pkix.Extension{Id: oidMSTemplateV1, Value: bmpStringExt(opts.templateName)})
	}

	var uris []*url.URL
	for _, u := range opts.uriSANs {
		parsed, err := url.Parse(u)
		require.NoError(t, err)
		uris = append(uris, parsed)
	}

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(20260619),
		Subject: pkix.Name{
			CommonName:         opts.cn,
			Organization:       opts.orgs,
			OrganizationalUnit: opts.ous,
		},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtKeyUsage:     opts.eku,
		DNSNames:        opts.dnsSANs,
		EmailAddresses:  opts.emailSANs,
		URIs:            uris,
		ExtraExtensions: extraExts,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return leaf
}

func defaultCephCert(t *testing.T) *x509.Certificate {
	return makeTestClientCert(t, certOpts{
		cn:           "svc-reader",
		orgs:         []string{"ExampleOrg"},
		ous:          []string{"Tenants"},
		dnsSANs:      []string{"svc-reader.example.com"},
		uriSANs:      []string{"spiffe://example.com/svc/reader"},
		eku:          []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		templateOID:  testTemplateOID,
		templateName: testTemplateName,
	})
}

func TestExtractCertClaims(t *testing.T) {
	claims := extractCertClaims(defaultCephCert(t))

	assert.Equal(t, "svc-reader", claims.CN)
	assert.Equal(t, "Example Issuing CA", claims.IssuerCN)
	assert.Equal(t, testTemplateOID, claims.TemplateOID)
	assert.Equal(t, testTemplateName, claims.TemplateName)
	assert.Contains(t, claims.EKUs, "clientAuth")
	assert.Contains(t, claims.SANDNS, "svc-reader.example.com")
	assert.Contains(t, claims.SANURI, "spiffe://example.com/svc/reader")
	assert.Contains(t, claims.Orgs, "ExampleOrg")
	assert.Contains(t, claims.OrgUnits, "Tenants")
	assert.NotEmpty(t, claims.Serial)
}

func TestAdmit_AND_AllPass(t *testing.T) {
	claims := extractCertClaims(defaultCephCert(t))
	policy := CertAdmissionPolicy{
		Logic: LogicAND,
		Rules: []CertMatchRule{
			{Field: CertFieldTemplateOID, Operator: OperatorEquals, Values: []string{testTemplateOID}},
			{Field: CertFieldIssuerCN, Operator: OperatorEquals, Values: []string{"Example Issuing CA"}},
			{Field: CertFieldEKU, Operator: OperatorEquals, Values: []string{"clientAuth"}},
		},
	}
	require.NoError(t, policy.Validate())
	assert.NoError(t, Admit(claims, policy))
}

func TestAdmit_AND_TemplateMismatchDenied(t *testing.T) {
	claims := extractCertClaims(defaultCephCert(t))
	policy := CertAdmissionPolicy{
		Logic: LogicAND,
		Rules: []CertMatchRule{
			{Field: CertFieldTemplateOID, Operator: OperatorEquals, Values: []string{"1.2.3.4.5"}},
		},
	}
	require.NoError(t, policy.Validate())
	assert.Error(t, Admit(claims, policy))
}

func TestAdmit_OR(t *testing.T) {
	claims := extractCertClaims(defaultCephCert(t))
	// Neither the wrong template nor wrong issuer matches, but the correct CN does.
	policy := CertAdmissionPolicy{
		Logic: LogicOR,
		Rules: []CertMatchRule{
			{Field: CertFieldTemplateOID, Operator: OperatorEquals, Values: []string{"1.2.3.4.5"}},
			{Field: CertFieldCN, Operator: OperatorEquals, Values: []string{"svc-reader"}},
		},
	}
	require.NoError(t, policy.Validate())
	assert.NoError(t, Admit(claims, policy))

	policy.Rules[1].Values = []string{"somebody-else"}
	assert.Error(t, Admit(claims, policy))
}

func TestAdmit_NegativeOperators(t *testing.T) {
	claims := extractCertClaims(defaultCephCert(t))
	policy := CertAdmissionPolicy{
		Logic: LogicAND,
		Rules: []CertMatchRule{
			// Cert has only clientAuth, so "must not be serverAuth" passes.
			{Field: CertFieldEKU, Operator: OperatorNotEquals, Values: []string{"serverAuth"}},
			// CN must not look like an admin identity.
			{Field: CertFieldCN, Operator: OperatorRegexNoMatch, Values: []string{"^admin"}},
		},
	}
	require.NoError(t, policy.Validate())
	assert.NoError(t, Admit(claims, policy))
}

func TestAdmit_GenericExtPresence(t *testing.T) {
	claims := extractCertClaims(defaultCephCert(t))
	policy := CertAdmissionPolicy{
		Rules: []CertMatchRule{
			{Field: CertFieldExtPrefix + "1.3.6.1.4.1.311.21.7", Operator: OperatorRegexMatch, Values: []string{".+"}},
		},
	}
	require.NoError(t, policy.Validate())
	assert.NoError(t, Admit(claims, policy))
}

func TestAdmit_NoRulesAdmitsAny(t *testing.T) {
	claims := extractCertClaims(defaultCephCert(t))
	assert.NoError(t, Admit(claims, CertAdmissionPolicy{}))
}

func TestIdentityFromClaims(t *testing.T) {
	claims := extractCertClaims(defaultCephCert(t))
	assert.Equal(t, "svc-reader", identityFromClaims(claims, CertFieldCN))
	assert.Equal(t, "svc-reader", identityFromClaims(claims, "")) // defaults to CN
	assert.Equal(t, "spiffe://example.com/svc/reader", identityFromClaims(claims, CertFieldSANURI))
}

func TestCertMatchRule_Validate(t *testing.T) {
	assert.Error(t, (&CertMatchRule{Field: "", Operator: "=", Values: []string{"x"}}).Validate())
	assert.Error(t, (&CertMatchRule{Field: "not_a_field", Operator: "=", Values: []string{"x"}}).Validate())
	assert.Error(t, (&CertMatchRule{Field: CertFieldCN, Operator: "??", Values: []string{"x"}}).Validate())
	assert.Error(t, (&CertMatchRule{Field: CertFieldCN, Operator: "="}).Validate())
	assert.Error(t, (&CertMatchRule{Field: CertFieldCN, Operator: "=~", Values: []string{"("}}).Validate())
	assert.Error(t, (&CertMatchRule{Field: "ext:not-an-oid", Operator: "=", Values: []string{"x"}}).Validate())
	assert.NoError(t, (&CertMatchRule{Field: CertFieldTemplateOID, Operator: "=", Values: []string{testTemplateOID}}).Validate())
	assert.NoError(t, (&CertMatchRule{Field: "ext:1.3.6.1.4.1.311.21.7", Operator: "=~", Values: []string{".+"}}).Validate())
}
