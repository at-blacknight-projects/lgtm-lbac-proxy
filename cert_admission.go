package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Client certificate admission.
//
// When mode B (proxy-terminated mTLS) is enabled, the verified peer certificate is
// the cryptographic root of admission: the proxy extracts a set of claims from the
// certificate (CertClaims), evaluates a fully operator-configurable admission policy
// against them (CertAdmissionPolicy), and only then derives the label-policy identity
// from a configured field. This lets operators trust whichever parts of the cert they
// want — Subject CN, issuer, the Microsoft AD CS certificate template, EKU, SANs, or
// any raw extension by OID — rather than a fixed, hard-coded check.

// Certificate claim field names usable in admission rules and identity_from.
const (
	CertFieldCN           = "cn"            // Subject Common Name (single)
	CertFieldSubjectDN    = "subject_dn"    // Full subject DN (single)
	CertFieldIssuerCN     = "issuer_cn"     // Issuer Common Name (single)
	CertFieldIssuerDN     = "issuer_dn"     // Full issuer DN (single)
	CertFieldTemplateOID  = "template_oid"  // AD CS v2 template OID, 1.3.6.1.4.1.311.21.7 (single)
	CertFieldTemplateName = "template_name" // AD CS v1 template name, 1.3.6.1.4.1.311.20.2 (single)
	CertFieldEKU          = "eku"           // Extended key usages, named + OID (multi)
	CertFieldSANDNS       = "san_dns"       // DNS SANs (multi)
	CertFieldSANURI       = "san_uri"       // URI SANs (multi)
	CertFieldSANEmail     = "san_email"     // email SANs (multi)
	CertFieldSANIP        = "san_ip"        // IP SANs (multi)
	CertFieldO            = "o"             // Subject Organizations (multi)
	CertFieldOU           = "ou"            // Subject Organizational Units (multi)
	CertFieldSerial       = "serial"        // Serial number, hex lower-case (single)
	// Prefix for matching an arbitrary extension by OID, value compared as lower-case hex,
	// e.g. field: "ext:1.3.6.1.4.1.311.21.7". Use operator "=~" with ".+" to assert presence.
	CertFieldExtPrefix = "ext:"
)

// Microsoft AD CS certificate template extension OIDs.
var (
	oidMSTemplateV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 7} // template info (OID + version)
	oidMSTemplateV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2} // enroll certtype (template name)
)

// ekuNames maps the named EKUs Go recognises to their conventional string form.
var ekuNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:             "any",
	x509.ExtKeyUsageServerAuth:      "serverAuth",
	x509.ExtKeyUsageClientAuth:      "clientAuth",
	x509.ExtKeyUsageCodeSigning:     "codeSigning",
	x509.ExtKeyUsageEmailProtection: "emailProtection",
	x509.ExtKeyUsageTimeStamping:    "timeStamping",
	x509.ExtKeyUsageOCSPSigning:     "OCSPSigning",
}

// CertClaims holds the subset of certificate attributes exposed to admission rules.
type CertClaims struct {
	CN           string
	SubjectDN    string
	IssuerCN     string
	IssuerDN     string
	TemplateOID  string
	TemplateName string
	EKUs         []string
	SANDNS       []string
	SANURI       []string
	SANEmail     []string
	SANIP        []string
	Orgs         []string
	OrgUnits     []string
	Serial       string
	// rawExts maps an extension OID (dotted string) to its lower-case hex-encoded value.
	rawExts map[string]string
}

// extractCertClaims pulls the admission-relevant attributes out of a verified certificate.
func extractCertClaims(cert *x509.Certificate) CertClaims {
	c := CertClaims{
		CN:        cert.Subject.CommonName,
		SubjectDN: cert.Subject.String(),
		IssuerCN:  cert.Issuer.CommonName,
		IssuerDN:  cert.Issuer.String(),
		SANDNS:    cert.DNSNames,
		SANEmail:  cert.EmailAddresses,
		Orgs:      cert.Subject.Organization,
		OrgUnits:  cert.Subject.OrganizationalUnit,
		Serial:    strings.ToLower(cert.SerialNumber.Text(16)),
		rawExts:   make(map[string]string, len(cert.Extensions)),
	}

	for _, u := range cert.URIs {
		c.SANURI = append(c.SANURI, u.String())
	}
	for _, ip := range cert.IPAddresses {
		c.SANIP = append(c.SANIP, ip.String())
	}

	// EKUs: both the named ones Go parsed and any unknown EKU OIDs.
	for _, eku := range cert.ExtKeyUsage {
		if name, ok := ekuNames[eku]; ok {
			c.EKUs = append(c.EKUs, name)
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		c.EKUs = append(c.EKUs, oid.String())
	}

	// Raw extensions (for ext:<oid> matching) and the MS template extensions.
	for _, ext := range cert.Extensions {
		c.rawExts[ext.Id.String()] = strings.ToLower(hex.EncodeToString(ext.Value))
		switch {
		case ext.Id.Equal(oidMSTemplateV2):
			if oid, err := parseMSTemplateV2(ext.Value); err == nil {
				c.TemplateOID = oid
			}
		case ext.Id.Equal(oidMSTemplateV1):
			if name, err := decodeDirectoryString(ext.Value); err == nil {
				c.TemplateName = name
			}
		}
	}

	return c
}

// msTemplateV2 mirrors the szOID_CERTIFICATE_TEMPLATE structure:
// SEQUENCE { templateID OBJECT IDENTIFIER, majorVersion INTEGER OPTIONAL, minorVersion INTEGER OPTIONAL }.
type msTemplateV2 struct {
	TemplateID   asn1.ObjectIdentifier
	MajorVersion int `asn1:"optional"`
	MinorVersion int `asn1:"optional"`
}

// parseMSTemplateV2 returns the dotted template OID from a v2 template extension value.
func parseMSTemplateV2(der []byte) (string, error) {
	var t msTemplateV2
	if _, err := asn1.Unmarshal(der, &t); err != nil {
		return "", err
	}
	return t.TemplateID.String(), nil
}

// decodeDirectoryString decodes an AD CS v1 template-name extension value, handling the
// BMPString (UTF-16BE) encoding AD CS commonly uses as well as plain UTF8/IA5/Printable.
func decodeDirectoryString(der []byte) (string, error) {
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rv); err != nil {
		return "", err
	}
	const tagBMPString = 30 // not exported by encoding/asn1
	if rv.Tag == tagBMPString {
		if len(rv.Bytes)%2 != 0 {
			return "", fmt.Errorf("invalid BMPString length %d", len(rv.Bytes))
		}
		u16 := make([]uint16, len(rv.Bytes)/2)
		for i := range u16 {
			u16[i] = uint16(rv.Bytes[2*i])<<8 | uint16(rv.Bytes[2*i+1])
		}
		return string(utf16.Decode(u16)), nil
	}
	return string(rv.Bytes), nil
}

// CertMatchRule is a single admission constraint against a certificate field.
// It mirrors LabelRule so admission config reads the same as label config.
type CertMatchRule struct {
	Field    string   `yaml:"field" mapstructure:"field"`       // e.g. "template_oid", "issuer_cn", "ext:<oid>"
	Operator string   `yaml:"operator" mapstructure:"operator"` // "=", "!=", "=~", "!~"
	Values   []string `yaml:"values" mapstructure:"values"`     // values / regex patterns
}

// CertAdmissionPolicy is the ordered set of admission rules and their combining logic.
type CertAdmissionPolicy struct {
	Logic string          `yaml:"logic" mapstructure:"logic"` // "AND" (default) or "OR"
	Rules []CertMatchRule `yaml:"rules" mapstructure:"rules"`
}

// Validate checks a single admission rule for a known field, valid operator, and values.
func (r *CertMatchRule) Validate() error {
	if r.Field == "" {
		return fmt.Errorf("admission rule field cannot be empty")
	}
	if !strings.HasPrefix(r.Field, CertFieldExtPrefix) && !knownCertField(r.Field) {
		return fmt.Errorf("unknown admission field %q", r.Field)
	}
	if strings.HasPrefix(r.Field, CertFieldExtPrefix) {
		if _, err := parseDottedOID(strings.TrimPrefix(r.Field, CertFieldExtPrefix)); err != nil {
			return fmt.Errorf("invalid ext OID in field %q: %w", r.Field, err)
		}
	}
	switch r.Operator {
	case OperatorEquals, OperatorNotEquals, OperatorRegexMatch, OperatorRegexNoMatch:
	default:
		return fmt.Errorf("invalid operator %q: must be one of =, !=, =~, !~", r.Operator)
	}
	if len(r.Values) == 0 {
		return fmt.Errorf("admission rule must have at least one value")
	}
	if r.Operator == OperatorRegexMatch || r.Operator == OperatorRegexNoMatch {
		for _, v := range r.Values {
			if _, err := regexp.Compile(v); err != nil {
				return fmt.Errorf("invalid regex pattern %q: %w", v, err)
			}
		}
	}
	return nil
}

// Validate checks the admission policy and defaults empty logic to AND.
func (p *CertAdmissionPolicy) Validate() error {
	if p.Logic == "" {
		p.Logic = LogicAND
	}
	if p.Logic != LogicAND && p.Logic != LogicOR {
		return fmt.Errorf("invalid admission logic %q: must be AND or OR", p.Logic)
	}
	for i := range p.Rules {
		if err := p.Rules[i].Validate(); err != nil {
			return fmt.Errorf("admission rule %d: %w", i, err)
		}
	}
	return nil
}

func knownCertField(field string) bool {
	switch field {
	case CertFieldCN, CertFieldSubjectDN, CertFieldIssuerCN, CertFieldIssuerDN,
		CertFieldTemplateOID, CertFieldTemplateName, CertFieldEKU,
		CertFieldSANDNS, CertFieldSANURI, CertFieldSANEmail, CertFieldSANIP,
		CertFieldO, CertFieldOU, CertFieldSerial:
		return true
	}
	return false
}

// claimValues returns the value(s) for a field. Single-valued fields return a one-element
// slice (possibly empty string). For ext:<oid> the value is the extension's hex, if present.
func (c CertClaims) claimValues(field string) []string {
	switch field {
	case CertFieldCN:
		return []string{c.CN}
	case CertFieldSubjectDN:
		return []string{c.SubjectDN}
	case CertFieldIssuerCN:
		return []string{c.IssuerCN}
	case CertFieldIssuerDN:
		return []string{c.IssuerDN}
	case CertFieldTemplateOID:
		return []string{c.TemplateOID}
	case CertFieldTemplateName:
		return []string{c.TemplateName}
	case CertFieldEKU:
		return c.EKUs
	case CertFieldSANDNS:
		return c.SANDNS
	case CertFieldSANURI:
		return c.SANURI
	case CertFieldSANEmail:
		return c.SANEmail
	case CertFieldSANIP:
		return c.SANIP
	case CertFieldO:
		return c.Orgs
	case CertFieldOU:
		return c.OrgUnits
	case CertFieldSerial:
		return []string{c.Serial}
	}
	if strings.HasPrefix(field, CertFieldExtPrefix) {
		oid := strings.TrimPrefix(field, CertFieldExtPrefix)
		if v, ok := c.rawExts[oid]; ok {
			return []string{v}
		}
		return nil
	}
	return nil
}

// evalRule reports whether the claims satisfy a single admission rule.
//
// Multi-valued fields (eku, san_*, o, ou) use any/none semantics:
//   - "=" / "=~": pass if ANY present value equals / matches a rule value
//   - "!=" / "!~": pass if NO present value equals / matches any rule value
//     (a field with no values trivially satisfies a negative rule)
func evalRule(rule CertMatchRule, claims CertClaims) bool {
	values := claims.claimValues(rule.Field)

	switch rule.Operator {
	case OperatorEquals:
		return anyMatch(values, rule.Values, exactMatcher)
	case OperatorRegexMatch:
		return anyMatch(values, rule.Values, regexMatcher)
	case OperatorNotEquals:
		return !anyMatch(values, rule.Values, exactMatcher)
	case OperatorRegexNoMatch:
		return !anyMatch(values, rule.Values, regexMatcher)
	}
	return false
}

func exactMatcher(certValue, ruleValue string) bool { return certValue == ruleValue }

func regexMatcher(certValue, ruleValue string) bool {
	re, err := regexp.Compile(ruleValue)
	if err != nil {
		return false
	}
	return re.MatchString(certValue)
}

// anyMatch reports whether any certValue matches any ruleValue under match.
func anyMatch(certValues, ruleValues []string, match func(certValue, ruleValue string) bool) bool {
	for _, cv := range certValues {
		for _, rv := range ruleValues {
			if match(cv, rv) {
				return true
			}
		}
	}
	return false
}

// Admit evaluates the admission policy against the certificate claims.
// Returns nil if admitted, or an error naming the first failing rule (AND) or
// reporting that no rule matched (OR).
func Admit(claims CertClaims, policy CertAdmissionPolicy) error {
	// No rules = admit any verified certificate (chain validity already enforced by the
	// TLS layer). Operators who want a deny-by-default posture configure at least one rule.
	if len(policy.Rules) == 0 {
		return nil
	}

	if policy.Logic == LogicOR {
		for _, rule := range policy.Rules {
			if evalRule(rule, claims) {
				return nil
			}
		}
		return fmt.Errorf("certificate admission denied: no admission rule matched")
	}

	// Default AND: every rule must pass.
	for i, rule := range policy.Rules {
		if !evalRule(rule, claims) {
			return fmt.Errorf("certificate admission denied: rule %d (%s %s %v) not satisfied",
				i, rule.Field, rule.Operator, rule.Values)
		}
	}
	return nil
}

// identityFromClaims returns the value of the configured identity field, used as the
// username for label-policy lookup. Defaults to CN when field is empty.
func identityFromClaims(claims CertClaims, field string) string {
	if field == "" {
		field = CertFieldCN
	}
	values := claims.claimValues(field)
	if len(values) == 0 {
		return ""
	}
	// For multi-valued fields the first value is used as the identity.
	return values[0]
}

// clientCertFromRequest returns the client certificate to evaluate, or (nil, nil) if
// none is present (so the caller can fall back to another auth method).
//
//   - Source "mtls": the verified peer certificate from the TLS handshake. Chain
//     validity is already guaranteed by the listener's RequireAndVerifyClientCert.
//   - Source "header": a PEM certificate forwarded by an mTLS-terminating ingress
//     (e.g. nginx $ssl_client_escaped_cert, which is URL-escaped). Trust here rests on
//     the ingress having verified the chain and on the proxy being reachable only via it.
func clientCertFromRequest(r *http.Request, cfg *ClientCertConfig) (*x509.Certificate, error) {
	switch cfg.Source {
	case "header":
		raw := r.Header.Get(cfg.CertHeader)
		if strings.TrimSpace(raw) == "" {
			return nil, nil
		}
		// nginx escapes the PEM; unescape if it was escaped (no-op for already-plain PEM).
		if unescaped, err := url.QueryUnescape(raw); err == nil {
			raw = unescaped
		}
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, fmt.Errorf("forwarded client cert header is not valid PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing forwarded client cert: %w", err)
		}
		return cert, nil
	default: // "mtls"
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return nil, nil
		}
		return r.TLS.PeerCertificates[0], nil
	}
}

// parseDottedOID parses a dotted OID string (e.g. "1.3.6.1.4.1.311.21.7").
func parseDottedOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("OID must have at least two arcs")
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid OID arc %q: %w", p, err)
		}
		oid[i] = n
	}
	return oid, nil
}
