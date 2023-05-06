package x509_test

import (
	"fmt"
	"gitee.com/zhaochuninhefei/gmgo/x509"
	"testing"
)

func TestCertinfo(t *testing.T) {
	certPath := "testdata/sm2_sign_cert.cer"

	cert, _ := x509.ReadCertificateFromPemFile(certPath)

	certText, err := x509.CertificateText(cert)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(certText)
}

func TestCertificateText(t *testing.T) {
	type args struct {
		certPath string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "sm2 sign cert",
			args: args{
				certPath: "testdata/sm2_sign_cert.cer",
			},
		},
		{
			name: "ecdsa sign cert",
			args: args{
				certPath: "testdata/ecdsa_sign_cert.cer",
			},
		},
		{
			name: "ecdsaext sign cert",
			args: args{
				certPath: "testdata/ecdsaext_sign_cert.cer",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, _ := x509.ReadCertificateFromPemFile(tt.args.certPath)
			certText, err := x509.CertificateText(cert)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Println(certText)
		})
	}
}
