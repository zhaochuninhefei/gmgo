// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

/*
x509/verify.go 实现证书信任链的验证:
c.Verify : 尝试构建证书c的有效信任链
*/

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	log "gitee.com/zhaochuninhefei/zcgolog/zclog"
)

type InvalidReason int

const (
	// NotAuthorizedToSign results when a certificate is signed by another
	// which isn't marked as a CA certificate.
	NotAuthorizedToSign InvalidReason = iota
	// Expired results when a certificate has expired, based on the time
	// given in the VerifyOptions.
	Expired
	// CANotAuthorizedForThisName results when an intermediate or root
	// certificate has a name constraint which doesn't permit a DNS or
	// other name (including IP address) in the leaf certificate.
	CANotAuthorizedForThisName
	// TooManyIntermediates results when a path length constraint is
	// violated.
	TooManyIntermediates
	// IncompatibleUsage results when the certificate's key usage indicates
	// that it may only be used for a different purpose.
	IncompatibleUsage
	// NameMismatch results when the subject name of a parent certificate
	// does not match the issuer name in the child.
	NameMismatch
	// NameConstraintsWithoutSANs is a legacy error and is no longer returned.
	NameConstraintsWithoutSANs
	// UnconstrainedName results when a CA certificate contains permitted
	// name constraints, but leaf certificate contains a name of an
	// unsupported or unconstrained type.
	UnconstrainedName
	// TooManyConstraints results when the number of comparison operations
	// needed to check a certificate exceeds the limit set by
	// VerifyOptions.MaxConstraintComparisions. This limit exists to
	// prevent pathological certificates can consuming excessive amounts of
	// CPU time to verify.
	TooManyConstraints
	// CANotAuthorizedForExtKeyUsage results when an intermediate or root
	// certificate does not permit a requested extended key usage.
	CANotAuthorizedForExtKeyUsage
)

// CertificateInvalidError results when an odd error occurs. Users of this
// library probably want to handle all these errors uniformly.
type CertificateInvalidError struct {
	Cert   *Certificate
	Reason InvalidReason
	Detail string
}

func (e CertificateInvalidError) Error() string {
	switch e.Reason {
	case NotAuthorizedToSign:
		return "x509: certificate is not authorized to sign other certificates"
	case Expired:
		return "x509: certificate has expired or is not yet valid: " + e.Detail
	case CANotAuthorizedForThisName:
		return "x509: a root or intermediate certificate is not authorized to sign for this name: " + e.Detail
	case CANotAuthorizedForExtKeyUsage:
		return "x509: a root or intermediate certificate is not authorized for an extended key usage: " + e.Detail
	case TooManyIntermediates:
		return "x509: too many intermediates for path length constraint"
	case IncompatibleUsage:
		return "x509: certificate specifies an incompatible key usage"
	case NameMismatch:
		return "x509: issuer name does not match subject from issuing certificate"
	case NameConstraintsWithoutSANs:
		return "x509: issuer has name constraints but leaf doesn't have a SAN extension"
	case UnconstrainedName:
		return "x509: issuer has name constraints but leaf contains unknown or unconstrained name: " + e.Detail
	}
	return "x509: unknown error"
}

// HostnameError results when the set of authorized names doesn't match the
// requested name.
type HostnameError struct {
	Certificate *Certificate
	Host        string
}

func (h HostnameError) Error() string {
	c := h.Certificate

	if !c.hasSANExtension() && matchHostnames(c.Subject.CommonName, h.Host) {
		return "x509: certificate relies on legacy Common Name field, use SANs instead"
	}

	var valid string
	if ip := net.ParseIP(h.Host); ip != nil {
		// Trying to validate an IP
		if len(c.IPAddresses) == 0 {
			return "x509: cannot validate certificate for " + h.Host + " because it doesn't contain any IP SANs"
		}
		for _, san := range c.IPAddresses {
			if len(valid) > 0 {
				valid += ", "
			}
			valid += san.String()
		}
	} else {
		valid = strings.Join(c.DNSNames, ", ")
	}

	if len(valid) == 0 {
		return "x509: certificate is not valid for any names, but wanted to match " + h.Host
	}
	return "x509: certificate is valid for " + valid + ", not " + h.Host
}

// UnknownAuthorityError results when the certificate issuer is unknown
type UnknownAuthorityError struct {
	Cert *Certificate
	// hintErr contains an error that may be helpful in determining why an
	// authority wasn't found.
	hintErr error
	// hintCert contains a possible authority certificate that was rejected
	// because of the error in hintErr.
	hintCert *Certificate
}

func (e UnknownAuthorityError) Error() string {
	s := "x509: certificate signed by unknown authority"
	if e.hintErr != nil {
		certName := e.hintCert.Subject.CommonName
		if len(certName) == 0 {
			if len(e.hintCert.Subject.Organization) > 0 {
				certName = e.hintCert.Subject.Organization[0]
			} else {
				certName = "serial:" + e.hintCert.SerialNumber.String()
			}
		}
		s += fmt.Sprintf(" (possibly because of %q while trying to verify candidate authority certificate %q)", e.hintErr, certName)
	}
	return s
}

// SystemRootsError results when we fail to load the system root certificates.
type SystemRootsError struct {
	Err error
}

func (se SystemRootsError) Error() string {
	msg := "x509: failed to load system roots and no roots provided"
	if se.Err != nil {
		return msg + "; " + se.Err.Error()
	}
	return msg
}

func (se SystemRootsError) Unwrap() error { return se.Err }

// errNotParsed is returned when a certificate without ASN.1 contents is
// verified. Platform-specific verification needs the ASN.1 contents.
var errNotParsed = errors.New("x509: missing ASN.1 contents; use ParseCertificate")

// VerifyOptions contains parameters for Certificate.Verify.
type VerifyOptions struct {
	// 如果设置了 DNSName，则使用 Certificate.VerifyHostname 或平台验证程序检查叶证书。
	// DNSName, if set, is checked against the leaf certificate with
	// Certificate.VerifyHostname or the platform verifier.
	DNSName string

	// 可选的中间证书池，它们不是信任锚，但可用于形成从叶证书到根证书的链。
	// Intermediates is an optional pool of certificates that are not trust
	// anchors, but can be used to form a chain from the leaf certificate to a
	// root certificate.
	Intermediates *CertPool

	// 根是叶证书需要链接到的一组受信任的根证书。 如果为零，则使用系统根或平台验证程序。
	// Roots is the set of trusted root certificates the leaf certificate needs
	// to chain up to. If nil, the system roots or the platform verifier are used.
	Roots *CertPool

	// CurrentTime 用于检查链中所有证书的有效性。 如果为零，则使用当前时间。
	// CurrentTime is used to check the validity of all certificates in the
	// chain. If zero, the current time is used.
	CurrentTime time.Time

	// KeyUsages 指定允许的扩展公钥用途。
	// 目标证书只要匹配上任意一个指定的用途即可通过该项检查。
	// 该字段默认值为 ExtKeyUsageServerAuth。
	// 如果允许任意一种扩展公钥用途，请在该字段列表中加入 ExtKeyUsageAny。
	// KeyUsages specifies which Extended Key Usage values are acceptable. A
	// chain is accepted if it allows any of the listed values. An empty list
	// means ExtKeyUsageServerAuth. To accept any key usage, include ExtKeyUsageAny.
	KeyUsages []ExtKeyUsage

	// MaxConstraintComparisions 是检查给定证书的名称约束时要执行的最大比较次数。
	// 如果为零，则使用合理的默认值。
	// 此限制可防止病态证书在验证时消耗过多的 CPU 时间。 它不适用于平台验证者。
	// MaxConstraintComparisions is the maximum number of comparisons to
	// perform when checking a given certificate's name constraints. If
	// zero, a sensible default is used. This limit prevents pathological
	// certificates from consuming excessive amounts of CPU time when
	// validating. It does not apply to the platform verifier.
	MaxConstraintComparisions int
}

const (
	// 子证书
	leafCertificate = iota
	// 中间证书
	intermediateCertificate
	// 根证书
	rootCertificate
)

// rfc2821Mailbox represents a “mailbox” (which is an email address to most
// people) by breaking it into the “local” (i.e. before the '@') and “domain”
// parts.
type rfc2821Mailbox struct {
	local, domain string
}

// parseRFC2821Mailbox parses an email address into local and domain parts,
// based on the ABNF for a “Mailbox” from RFC 2821. According to RFC 5280,
// Section 4.2.1.6 that's correct for an rfc822Name from a certificate: “The
// format of an rfc822Name is a "Mailbox" as defined in RFC 2821, Section 4.1.2”.
func parseRFC2821Mailbox(in string) (mailbox rfc2821Mailbox, ok bool) {
	if len(in) == 0 {
		return mailbox, false
	}

	localPartBytes := make([]byte, 0, len(in)/2)

	if in[0] == '"' {
		// Quoted-string = DQUOTE *qcontent DQUOTE
		// non-whitespace-control = %d1-8 / %d11 / %d12 / %d14-31 / %d127
		// qcontent = qtext / quoted-pair
		// qtext = non-whitespace-control /
		//         %d33 / %d35-91 / %d93-126
		// quoted-pair = ("\" text) / obs-qp
		// text = %d1-9 / %d11 / %d12 / %d14-127 / obs-text
		//
		// (Names beginning with “obs-” are the obsolete syntax from RFC 2822,
		// Section 4. Since it has been 16 years, we no longer accept that.)
		in = in[1:]
	QuotedString:
		for {
			if len(in) == 0 {
				return mailbox, false
			}
			c := in[0]
			in = in[1:]

			switch {
			case c == '"':
				break QuotedString

			case c == '\\':
				// quoted-pair
				if len(in) == 0 {
					return mailbox, false
				}
				if in[0] == 11 ||
					in[0] == 12 ||
					(1 <= in[0] && in[0] <= 9) ||
					(14 <= in[0] && in[0] <= 127) {
					localPartBytes = append(localPartBytes, in[0])
					in = in[1:]
				} else {
					return mailbox, false
				}

			case c == 11 ||
				c == 12 ||
				// Space (char 32) is not allowed based on the
				// BNF, but RFC 3696 gives an example that
				// assumes that it is. Several “verified”
				// errata continue to argue about this point.
				// We choose to accept it.
				c == 32 ||
				c == 33 ||
				c == 127 ||
				(1 <= c && c <= 8) ||
				(14 <= c && c <= 31) ||
				(35 <= c && c <= 91) ||
				(93 <= c && c <= 126):
				// qtext
				localPartBytes = append(localPartBytes, c)

			default:
				return mailbox, false
			}
		}
	} else {
		// Atom ("." Atom)*
	NextChar:
		for len(in) > 0 {
			// atext from RFC 2822, Section 3.2.4
			c := in[0]

			switch {
			case c == '\\':
				// Examples given in RFC 3696 suggest that
				// escaped characters can appear outside of a
				// quoted string. Several “verified” errata
				// continue to argue the point. We choose to
				// accept it.
				in = in[1:]
				if len(in) == 0 {
					return mailbox, false
				}
				fallthrough

			case ('0' <= c && c <= '9') ||
				('a' <= c && c <= 'z') ||
				('A' <= c && c <= 'Z') ||
				c == '!' || c == '#' || c == '$' || c == '%' ||
				c == '&' || c == '\'' || c == '*' || c == '+' ||
				c == '-' || c == '/' || c == '=' || c == '?' ||
				c == '^' || c == '_' || c == '`' || c == '{' ||
				c == '|' || c == '}' || c == '~' || c == '.':
				localPartBytes = append(localPartBytes, in[0])
				in = in[1:]

			default:
				break NextChar
			}
		}

		if len(localPartBytes) == 0 {
			return mailbox, false
		}

		// From RFC 3696, Section 3:
		// “period (".") may also appear, but may not be used to start
		// or end the local part, nor may two or more consecutive
		// periods appear.”
		twoDots := []byte{'.', '.'}
		if localPartBytes[0] == '.' ||
			localPartBytes[len(localPartBytes)-1] == '.' ||
			bytes.Contains(localPartBytes, twoDots) {
			return mailbox, false
		}
	}

	if len(in) == 0 || in[0] != '@' {
		return mailbox, false
	}
	in = in[1:]

	// The RFC species a format for domains, but that's known to be
	// violated in practice so we accept that anything after an '@' is the
	// domain part.
	if _, ok := domainToReverseLabels(in); !ok {
		return mailbox, false
	}

	mailbox.local = string(localPartBytes)
	mailbox.domain = in
	return mailbox, true
}

// domainToReverseLabels converts a textual domain name like foo.example.com to
// the list of labels in reverse order, e.g. ["com", "example", "foo"].
func domainToReverseLabels(domain string) (reverseLabels []string, ok bool) {
	for len(domain) > 0 {
		if i := strings.LastIndexByte(domain, '.'); i == -1 {
			reverseLabels = append(reverseLabels, domain)
			domain = ""
		} else {
			reverseLabels = append(reverseLabels, domain[i+1:])
			domain = domain[:i]
		}
	}

	if len(reverseLabels) > 0 && len(reverseLabels[0]) == 0 {
		// An empty label at the end indicates an absolute value.
		return nil, false
	}

	for _, label := range reverseLabels {
		if len(label) == 0 {
			// Empty labels are otherwise invalid.
			return nil, false
		}

		for _, c := range label {
			if c < 33 || c > 126 {
				// Invalid character.
				return nil, false
			}
		}
	}

	return reverseLabels, true
}

func matchEmailConstraint(mailbox rfc2821Mailbox, constraint string) (bool, error) {
	// If the constraint contains an @, then it specifies an exact mailbox
	// name.
	if strings.Contains(constraint, "@") {
		constraintMailbox, ok := parseRFC2821Mailbox(constraint)
		if !ok {
			return false, fmt.Errorf("x509: internal error: cannot parse constraint %q", constraint)
		}
		return mailbox.local == constraintMailbox.local && strings.EqualFold(mailbox.domain, constraintMailbox.domain), nil
	}

	// Otherwise the constraint is like a DNS constraint of the domain part
	// of the mailbox.
	return matchDomainConstraint(mailbox.domain, constraint)
}

func matchURIConstraint(uri *url.URL, constraint string) (bool, error) {
	// From RFC 5280, Section 4.2.1.10:
	// “a uniformResourceIdentifier that does not include an authority
	// component with a host name specified as a fully qualified domain
	// name (e.g., if the URI either does not include an authority
	// component or includes an authority component in which the host name
	// is specified as an IP address), then the application MUST reject the
	// certificate.”

	host := uri.Host
	if len(host) == 0 {
		return false, fmt.Errorf("URI with empty host (%q) cannot be matched against constraints", uri.String())
	}

	if strings.Contains(host, ":") && !strings.HasSuffix(host, "]") {
		var err error
		host, _, err = net.SplitHostPort(uri.Host)
		if err != nil {
			return false, err
		}
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") ||
		net.ParseIP(host) != nil {
		return false, fmt.Errorf("URI with IP (%q) cannot be matched against constraints", uri.String())
	}

	return matchDomainConstraint(host, constraint)
}

func matchIPConstraint(ip net.IP, constraint *net.IPNet) (bool, error) {
	if len(ip) != len(constraint.IP) {
		return false, nil
	}

	for i := range ip {
		if mask := constraint.Mask[i]; ip[i]&mask != constraint.IP[i]&mask {
			return false, nil
		}
	}

	return true, nil
}

func matchDomainConstraint(domain, constraint string) (bool, error) {
	// The meaning of zero length constraints is not specified, but this
	// code follows NSS and accepts them as matching everything.
	if len(constraint) == 0 {
		return true, nil
	}

	domainLabels, ok := domainToReverseLabels(domain)
	if !ok {
		return false, fmt.Errorf("x509: internal error: cannot parse domain %q", domain)
	}

	// RFC 5280 says that a leading period in a domain name means that at
	// least one label must be prepended, but only for URI and email
	// constraints, not DNS constraints. The code also supports that
	// behaviour for DNS constraints.

	mustHaveSubdomains := false
	if constraint[0] == '.' {
		mustHaveSubdomains = true
		constraint = constraint[1:]
	}

	constraintLabels, ok := domainToReverseLabels(constraint)
	if !ok {
		return false, fmt.Errorf("x509: internal error: cannot parse domain %q", constraint)
	}

	if len(domainLabels) < len(constraintLabels) ||
		(mustHaveSubdomains && len(domainLabels) == len(constraintLabels)) {
		return false, nil
	}

	for i, constraintLabel := range constraintLabels {
		if !strings.EqualFold(constraintLabel, domainLabels[i]) {
			return false, nil
		}
	}

	return true, nil
}

// checkNameConstraints checks that c permits a child certificate to claim the
// given name, of type nameType. The argument parsedName contains the parsed
// form of name, suitable for passing to the match function. The total number
// of comparisons is tracked in the given count and should not exceed the given
// limit.
func (c *Certificate) checkNameConstraints(count *int,
	maxConstraintComparisons int,
	nameType string,
	name string,
	parsedName interface{},
	match func(parsedName, constraint interface{}) (match bool, err error),
	permitted, excluded interface{}) error {

	excludedValue := reflect.ValueOf(excluded)

	*count += excludedValue.Len()
	if *count > maxConstraintComparisons {
		return CertificateInvalidError{c, TooManyConstraints, ""}
	}

	for i := 0; i < excludedValue.Len(); i++ {
		constraint := excludedValue.Index(i).Interface()
		match, err := match(parsedName, constraint)
		if err != nil {
			return CertificateInvalidError{c, CANotAuthorizedForThisName, err.Error()}
		}

		if match {
			return CertificateInvalidError{c, CANotAuthorizedForThisName, fmt.Sprintf("%s %q is excluded by constraint %q", nameType, name, constraint)}
		}
	}

	permittedValue := reflect.ValueOf(permitted)

	*count += permittedValue.Len()
	if *count > maxConstraintComparisons {
		return CertificateInvalidError{c, TooManyConstraints, ""}
	}

	ok := true
	for i := 0; i < permittedValue.Len(); i++ {
		constraint := permittedValue.Index(i).Interface()

		var err error
		if ok, err = match(parsedName, constraint); err != nil {
			return CertificateInvalidError{c, CANotAuthorizedForThisName, err.Error()}
		}

		if ok {
			break
		}
	}

	if !ok {
		return CertificateInvalidError{c, CANotAuthorizedForThisName, fmt.Sprintf("%s %q is not permitted by any constraint", nameType, name)}
	}

	return nil
}

// isValid 对 证书c 执行有效性检查，证书c是当前证书莲currentChain的候选者。
//  certType 证书c在证书链中的位置(0:子证书, 1:中间证书, 2:根证书)
//  currentChain 当前证书链
//  opts 校验参数
// isValid performs validity checks on c given that it is a candidate to append to the chain in currentChain.
func (c *Certificate) isValid(certType int, currentChain []*Certificate, opts *VerifyOptions) error {
	// log.Debugf("===== x509/verify.go isValid c.NotAfter 3: %s", c.NotAfter.Format(time.RFC3339))
	if len(c.UnhandledCriticalExtensions) > 0 {
		log.Debugf("===== x509/verify.go isValid 证书解析时有未完全处理的扩展ID: %#v", c.UnhandledCriticalExtensions)
		return UnhandledCriticalExtension{}
	}
	if len(currentChain) > 0 {
		// 检查当前证书链最后一个证书的签署者是否是证书c的拥有者
		child := currentChain[len(currentChain)-1]
		if !bytes.Equal(child.RawIssuer, c.RawSubject) {
			return CertificateInvalidError{c, NameMismatch, "===== x509/verify.go isValid 当前证书链最后一个证书的签署者不是证书c的拥有者"}
		}
	}
	// 获取当前时间并检查证书c是否已过期
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	// log.Debugf("===== x509/verify.go isValid c.NotAfter 4: %s , now: %s", c.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339))
	if now.Before(c.NotBefore) {
		return CertificateInvalidError{
			Cert:   c,
			Reason: Expired,
			Detail: fmt.Sprintf("current time %s is before %s", now.Format(time.RFC3339), c.NotBefore.Format(time.RFC3339)),
		}
	} else if now.After(c.NotAfter) {
		// log.Debugf("===== x509/verify.go isValid c.NotAfter 5: %s , now: %s", c.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339))
		return CertificateInvalidError{
			Cert:   c,
			Reason: Expired,
			Detail: fmt.Sprintf("current time %s is after %s", now.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339)),
		}
	}

	maxConstraintComparisons := opts.MaxConstraintComparisions
	if maxConstraintComparisons == 0 {
		maxConstraintComparisons = 250000
	}
	comparisonCount := 0

	var leaf *Certificate
	if certType == intermediateCertificate || certType == rootCertificate {
		// 如果证书c位置为中间证书或根证书，则当前证书链长度不可为0
		if len(currentChain) == 0 {
			return errors.New("===== x509/verify.go isValid 证书c位置为中间证书或根证书时当前证书链长度不可为0")
		}
		// 获取子证书:证书链的首个证书即子证书
		leaf = currentChain[0]
	}
	// 证书c是中间证书或根证书，且证书c有名称约束，且子证书有SAN扩展字段时，进行对SAN扩展字段检查
	if (certType == intermediateCertificate || certType == rootCertificate) &&
		c.hasNameConstraints() && leaf.hasSANExtension() {
		err := forEachSAN(leaf.getSANExtension(), func(tag int, data []byte) error {
			switch tag {
			case nameTypeEmail:
				name := string(data)
				mailbox, ok := parseRFC2821Mailbox(name)
				if !ok {
					return fmt.Errorf("x509: cannot parse rfc822Name %q", mailbox)
				}

				if err := c.checkNameConstraints(&comparisonCount, maxConstraintComparisons, "email address", name, mailbox,
					func(parsedName, constraint interface{}) (bool, error) {
						return matchEmailConstraint(parsedName.(rfc2821Mailbox), constraint.(string))
					}, c.PermittedEmailAddresses, c.ExcludedEmailAddresses); err != nil {
					return err
				}

			case nameTypeDNS:
				name := string(data)
				if _, ok := domainToReverseLabels(name); !ok {
					return fmt.Errorf("x509: cannot parse dnsName %q", name)
				}

				if err := c.checkNameConstraints(&comparisonCount, maxConstraintComparisons, "DNS name", name, name,
					func(parsedName, constraint interface{}) (bool, error) {
						return matchDomainConstraint(parsedName.(string), constraint.(string))
					}, c.PermittedDNSDomains, c.ExcludedDNSDomains); err != nil {
					return err
				}

			case nameTypeURI:
				name := string(data)
				uri, err := url.Parse(name)
				if err != nil {
					return fmt.Errorf("x509: internal error: URI SAN %q failed to parse", name)
				}

				if err := c.checkNameConstraints(&comparisonCount, maxConstraintComparisons, "URI", name, uri,
					func(parsedName, constraint interface{}) (bool, error) {
						return matchURIConstraint(parsedName.(*url.URL), constraint.(string))
					}, c.PermittedURIDomains, c.ExcludedURIDomains); err != nil {
					return err
				}

			case nameTypeIP:
				ip := net.IP(data)
				if l := len(ip); l != net.IPv4len && l != net.IPv6len {
					return fmt.Errorf("x509: internal error: IP SAN %x failed to parse", data)
				}

				if err := c.checkNameConstraints(&comparisonCount, maxConstraintComparisons, "IP address", ip.String(), ip,
					func(parsedName, constraint interface{}) (bool, error) {
						return matchIPConstraint(parsedName.(net.IP), constraint.(*net.IPNet))
					}, c.PermittedIPRanges, c.ExcludedIPRanges); err != nil {
					return err
				}

			default:
				// Unknown SAN types are ignored.
			}

			return nil
		})

		if err != nil {
			return err
		}
	}

	// KeyUsage status flags are ignored. From Engineering Security, Peter
	// Gutmann: A European government CA marked its signing certificates as
	// being valid for encryption only, but no-one noticed. Another
	// European CA marked its signature keys as not being valid for
	// signatures. A different CA marked its own trusted root certificate
	// as being invalid for certificate signing. Another national CA
	// distributed a certificate to be used to encrypt data for the
	// country’s tax authority that was marked as only being usable for
	// digital signatures but not for encryption. Yet another CA reversed
	// the order of the bit flags in the keyUsage due to confusion over
	// encoding endianness, essentially setting a random keyUsage in
	// certificates that it issued. Another CA created a self-invalidating
	// certificate by adding a certificate policy statement stipulating
	// that the certificate had to be used strictly as specified in the
	// keyUsage, and a keyUsage containing a flag indicating that the RSA
	// encryption key could only be used for Diffie-Hellman key agreement.

	// 证书c是中间证书时，其BasicConstraintsValid与IsCA必须为true
	if certType == intermediateCertificate && (!c.BasicConstraintsValid || !c.IsCA) {
		return CertificateInvalidError{c, NotAuthorizedToSign, ""}
	}
	// BasicConstraintsValid有效且设置了有效的MaxPathLen(大于0)时，做证书链长度检查。
	// 证书链长度不能超过ca证书设置的有效MaxPathLen。
	if c.BasicConstraintsValid && c.MaxPathLen >= 0 {
		numIntermediates := len(currentChain) - 1
		if numIntermediates > c.MaxPathLen {
			return CertificateInvalidError{c, TooManyIntermediates, ""}
		}
	}

	return nil
}

// Verify尝试构建证书c的有效信任链。
// 成功时将返回验证成功的证书链，其中第一个证书即c自身，最后一个是opts.Roots中的某个根证书。
// Verify attempts to verify c by building one or more chains from c to a
// certificate in opts.Roots, using certificates in opts.Intermediates if
// needed. If successful, it returns one or more chains where the first
// element of the chain is c and the last element is from opts.Roots.
//
// opts.Roots为空时，将使用系统平台的根证书验证。此时验证的详细信息与本方法的实现会有不同。
// 如果系统根证书不可用将返回SystemRootsError。
// If opts.Roots is nil, the platform verifier might be used, and
// verification details might differ from what is described below. If system
// roots are unavailable the returned error will be of type SystemRootsError.
//
// 信任链的中间证书的名称约束对整个信任链有效，不能只看传入的opts.DNSName。
// Name constraints in the intermediates will be applied to all names claimed
// in the chain, not just opts.DNSName. Thus it is invalid for a leaf to claim
// example.com if an intermediate doesn't permit it, even if example.com is not
// the name being validated. Note that DirectoryName constraints are not
// supported.
//
// 名称约束遵循RFC 5280标准，因此可以使用前导句点匹配。
// Name constraint validation follows the rules from RFC 5280, with the
// addition that DNS name constraints may use the leading period format
// defined for emails and URIs. When a constraint has a leading period
// it indicates that at least one additional label must be prepended to
// the constrained name to be considered valid.
//
// Extended Key Usage values are enforced nested down a chain, so an intermediate
// or root that enumerates EKUs prevents a leaf from asserting an EKU not in that
// list. (While this is not specified, it is common practice in order to limit
// the types of certificates a CA can issue.)
//
// WARNING: this function doesn't do any revocation checking.
func (c *Certificate) Verify(opts VerifyOptions) (chains [][]*Certificate, err error) {
	// Platform-specific verification needs the ASN.1 contents so
	// this makes the behavior consistent across platforms.
	// log.Debugf("===== x509/verify.go Verify c.NotAfter 1: %s", c.NotAfter.Format(time.RFC3339))
	if len(c.Raw) == 0 {
		return nil, errNotParsed
	}
	for i := 0; i < opts.Intermediates.len(); i++ {
		// 如果检查参数中包含可选的中间证书池，则先检查这些中间证书是否能够正常读取
		intermediatesCert, err := opts.Intermediates.cert(i)
		if err != nil {
			return nil, fmt.Errorf("gitee.com/zhaochuninhefei/gmgo/x509: error fetching intermediate: %w", err)
		}
		if len(intermediatesCert.Raw) == 0 {
			return nil, errNotParsed
		}
	}
	// 检查参数的根证书池为空，且平台为windows时，调用目标证书的系统校验，使用windows自己的校验与证书链构建。
	// Use Windows's own verification and chain building.
	if opts.Roots == nil && runtime.GOOS == "windows" {
		return c.systemVerify(&opts)
	}
	// 检查参数的根证书池为空，且平台不是windows时，获取系统的跟证书池
	if opts.Roots == nil {
		opts.Roots = systemRootsPool()
		if opts.Roots == nil {
			return nil, SystemRootsError{systemRootsErr}
		}
	}
	// log.Debugf("===== x509/verify.go Verify c.NotAfter 2: %s", c.NotAfter.Format(time.RFC3339))
	// 将目标证书作为叶证书进行有效性检查
	err = c.isValid(leafCertificate, nil, &opts)
	if err != nil {
		return
	}
	// 检查参数设置了DNSName时，对目标证书c做域名(或IP)检查
	if len(opts.DNSName) > 0 {
		err = c.VerifyHostname(opts.DNSName)
		if err != nil {
			return
		}
	}
	// 创建证书信任链
	var candidateChains [][]*Certificate
	if opts.Roots.contains(c) {
		// 如果检查参数的根证书池中包含目标证书c，则直接将其加入证书信任链，此时信任链只有这一个证书(叶证书)
		candidateChains = append(candidateChains, []*Certificate{c})
	} else {
		// 目标证书c不是检查参数的根证书池中的某一个，则将其作为第一个证书(叶证书)加入证书信任链
		if candidateChains, err = c.buildChains(nil, []*Certificate{c}, nil, &opts); err != nil {
			return nil, err
		}
	}
	// 获取检查参数的扩展公钥用途字段，未设置时默认值为 ExtKeyUsageServerAuth
	keyUsages := opts.KeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []ExtKeyUsage{ExtKeyUsageServerAuth}
	}
	// 如果扩展公钥用途包含 ExtKeyUsageAny , 则无需检查，直接返回证书信任链
	for _, usage := range keyUsages {
		if usage == ExtKeyUsageAny {
			return candidateChains, nil
		}
	}
	// 检查证书信任链中每个证书的扩展公钥用途是否能够匹配检查参数的扩展公钥用途。
	// 只保留匹配用途的证书留在证书链中。
	for _, candidate := range candidateChains {
		if checkChainForKeyUsage(candidate, keyUsages) {
			chains = append(chains, candidate)
		}
	}
	if len(chains) == 0 {
		return nil, CertificateInvalidError{c, IncompatibleUsage, ""}
	}
	return chains, nil
}

func appendToFreshChain(chain []*Certificate, cert *Certificate) []*Certificate {
	n := make([]*Certificate, len(chain)+1)
	copy(n, chain)
	n[len(chain)] = cert
	return n
}

// maxChainSignatureChecks is the maximum number of CheckSignatureFrom calls
// that an invocation of buildChains will (transitively) make. Most chains are
// less than 15 certificates long, so this leaves space for multiple chains and
// for failed checks due to different intermediates having the same Subject.
const maxChainSignatureChecks = 100

// 为证书c创建信任链
func (c *Certificate) buildChains(cache map[*Certificate][][]*Certificate, currentChain []*Certificate, sigChecks *int, opts *VerifyOptions) (chains [][]*Certificate, err error) {
	var (
		hintErr  error
		hintCert *Certificate
	)
	// 定义considerCandidate用于验证c并添加信任链
	considerCandidate := func(certType int, candidate *Certificate) {
		for _, cert := range currentChain {
			if cert.Equal(candidate) {
				return
			}
		}

		if sigChecks == nil {
			sigChecks = new(int)
		}
		*sigChecks++
		if *sigChecks > maxChainSignatureChecks {
			// 验签次数有限制，防止过多的验签
			err = errors.New("x509: signature check attempts limit reached while verifying certificate chain")
			return
		}
		// 使用当前证书candidate对c进行验签，即检查证书c是否由candidate拥有者签署。
		// 该步骤会最终调用到对应公钥的验签方法。
		if err := c.CheckSignatureFrom(candidate); err != nil {
			if hintErr == nil {
				hintErr = err
				hintCert = candidate
			}
			return
		}
		// 检查candidate的有效性
		err = candidate.isValid(certType, currentChain, opts)
		if err != nil {
			return
		}

		switch certType {
		case rootCertificate:
			// 如果candidate是根证书，则直接加入c的信任链
			chains = append(chains, appendToFreshChain(currentChain, candidate))
		case intermediateCertificate:
			if cache == nil {
				cache = make(map[*Certificate][][]*Certificate)
			}
			// 尝试从之前的遍历中缓存的信任链里找到candidate的信任链
			childChains, ok := cache[candidate]
			if !ok {
				// 如果candidate是中间证书且并未建立信任链，则为其建立信任链，此处是递归
				childChains, err = candidate.buildChains(cache, appendToFreshChain(currentChain, candidate), sigChecks, opts)
				cache[candidate] = childChains
			}
			// 将candidate的信任链加入c的信任链
			chains = append(chains, childChains...)
		}
	}
	// 遍历根证书，尝试验证c
	for _, root := range opts.Roots.findPotentialParents(c) {
		considerCandidate(rootCertificate, root)
	}
	// 遍历中间证书，尝试验证c
	for _, intermediate := range opts.Intermediates.findPotentialParents(c) {
		considerCandidate(intermediateCertificate, intermediate)
	}

	if len(chains) > 0 {
		err = nil
	}
	if len(chains) == 0 && err == nil {
		err = UnknownAuthorityError{c, hintErr, hintCert}
	}

	return
}

func validHostnamePattern(host string) bool { return validHostname(host, true) }
func validHostnameInput(host string) bool   { return validHostname(host, false) }

// validHostname reports whether host is a valid hostname that can be matched or
// matched against according to RFC 6125 2.2, with some leniency to accommodate
// legacy values.
func validHostname(host string, isPattern bool) bool {
	if !isPattern {
		host = strings.TrimSuffix(host, ".")
	}
	if len(host) == 0 {
		return false
	}

	for i, part := range strings.Split(host, ".") {
		if part == "" {
			// Empty label.
			return false
		}
		if isPattern && i == 0 && part == "*" {
			// Only allow full left-most wildcards, as those are the only ones
			// we match, and matching literal '*' characters is probably never
			// the expected behavior.
			continue
		}
		for j, c := range part {
			if 'a' <= c && c <= 'z' {
				continue
			}
			if '0' <= c && c <= '9' {
				continue
			}
			if 'A' <= c && c <= 'Z' {
				continue
			}
			if c == '-' && j != 0 {
				continue
			}
			if c == '_' {
				// Not a valid character in hostnames, but commonly
				// found in deployments outside the WebPKI.
				continue
			}
			return false
		}
	}

	return true
}

func matchExactly(hostA, hostB string) bool {
	if hostA == "" || hostA == "." || hostB == "" || hostB == "." {
		return false
	}
	return toLowerCaseASCII(hostA) == toLowerCaseASCII(hostB)
}

func matchHostnames(pattern, host string) bool {
	pattern = toLowerCaseASCII(pattern)
	host = toLowerCaseASCII(strings.TrimSuffix(host, "."))

	if len(pattern) == 0 || len(host) == 0 {
		return false
	}

	patternParts := strings.Split(pattern, ".")
	hostParts := strings.Split(host, ".")

	if len(patternParts) != len(hostParts) {
		return false
	}

	for i, patternPart := range patternParts {
		if i == 0 && patternPart == "*" {
			continue
		}
		if patternPart != hostParts[i] {
			return false
		}
	}

	return true
}

// toLowerCaseASCII returns a lower-case version of in. See RFC 6125 6.4.1. We use
// an explicitly ASCII function to avoid any sharp corners resulting from
// performing Unicode operations on DNS labels.
func toLowerCaseASCII(in string) string {
	// If the string is already lower-case then there's nothing to do.
	isAlreadyLowerCase := true
	for _, c := range in {
		if c == utf8.RuneError {
			// If we get a UTF-8 error then there might be
			// upper-case ASCII bytes in the invalid sequence.
			isAlreadyLowerCase = false
			break
		}
		if 'A' <= c && c <= 'Z' {
			isAlreadyLowerCase = false
			break
		}
	}

	if isAlreadyLowerCase {
		return in
	}

	out := []byte(in)
	for i, c := range out {
		if 'A' <= c && c <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

// 检查证书域名(或IP)
// VerifyHostname returns nil if c is a valid certificate for the named host.
// Otherwise it returns an error describing the mismatch.
//
// IP addresses can be optionally enclosed in square brackets and are checked
// against the IPAddresses field. Other names are checked case insensitively
// against the DNSNames field. If the names are valid hostnames, the certificate
// fields can have a wildcard as the left-most label.
//
// Note that the legacy Common Name field is ignored.
func (c *Certificate) VerifyHostname(h string) error {
	// IP addresses may be written in [ ].
	candidateIP := h
	if len(h) >= 3 && h[0] == '[' && h[len(h)-1] == ']' {
		candidateIP = h[1 : len(h)-1]
	}
	if ip := net.ParseIP(candidateIP); ip != nil {
		// We only match IP addresses against IP SANs.
		// See RFC 6125, Appendix B.2.
		for _, candidate := range c.IPAddresses {
			if ip.Equal(candidate) {
				return nil
			}
		}
		return HostnameError{c, candidateIP}
	}

	candidateName := toLowerCaseASCII(h) // Save allocations inside the loop.
	validCandidateName := validHostnameInput(candidateName)

	for _, match := range c.DNSNames {
		// Ideally, we'd only match valid hostnames according to RFC 6125 like
		// browsers (more or less) do, but in practice Go is used in a wider
		// array of contexts and can't even assume DNS resolution. Instead,
		// always allow perfect matches, and only apply wildcard and trailing
		// dot processing to valid hostnames.
		if validCandidateName && validHostnamePattern(match) {
			if matchHostnames(match, candidateName) {
				return nil
			}
		} else {
			if matchExactly(match, candidateName) {
				return nil
			}
		}
	}

	return HostnameError{c, h}
}

func checkChainForKeyUsage(chain []*Certificate, keyUsages []ExtKeyUsage) bool {
	usages := make([]ExtKeyUsage, len(keyUsages))
	copy(usages, keyUsages)

	if len(chain) == 0 {
		return false
	}

	usagesRemaining := len(usages)

	// We walk down the list and cross out any usages that aren't supported
	// by each certificate. If we cross out all the usages, then the chain
	// is unacceptable.

NextCert:
	for i := len(chain) - 1; i >= 0; i-- {
		cert := chain[i]
		if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
			// The certificate doesn't have any extended key usage specified.
			continue
		}

		for _, usage := range cert.ExtKeyUsage {
			if usage == ExtKeyUsageAny {
				// The certificate is explicitly good for any usage.
				continue NextCert
			}
		}

		const invalidUsage ExtKeyUsage = -1

	NextRequestedUsage:
		for i, requestedUsage := range usages {
			if requestedUsage == invalidUsage {
				continue
			}

			for _, usage := range cert.ExtKeyUsage {
				if requestedUsage == usage {
					continue NextRequestedUsage
				} else if requestedUsage == ExtKeyUsageServerAuth &&
					(usage == ExtKeyUsageNetscapeServerGatedCrypto ||
						usage == ExtKeyUsageMicrosoftServerGatedCrypto) {
					// In order to support COMODO
					// certificate chains, we have to
					// accept Netscape or Microsoft SGC
					// usages as equal to ServerAuth.
					continue NextRequestedUsage
				}
			}

			usages[i] = invalidUsage
			usagesRemaining--
			if usagesRemaining == 0 {
				return false
			}
		}
	}

	return true
}
