package CADDY_PFX_CERTIFICATES

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"log/slog"
	"os"
	"software.sslmate.com/src/go-pkcs12"
	"time"
)

func init() {
	caddy.RegisterModule(&PfxCertGetter{})
}

// PfxCertGetter allow user to set path to .pfx file to load TLS certificate
type PfxCertGetter struct {
	// Path to your .pfx file.
	Path string `json:"path,omitempty"`
	// Password used to decode pfx file. Required.
	Password string `json:"password,omitempty"`
	// FetchFullChain allows Caddy server to automatically download the certificate chain.
	FetchFullChain *bool `json:"fetch_full_chain,omitempty"`

	CacheCertName string

	ctx    caddy.Context
	logger *slog.Logger
}

func (*PfxCertGetter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.pfx",
		New: func() caddy.Module { return new(PfxCertGetter) },
	}
}

func (getter *PfxCertGetter) Provision(ctx caddy.Context) error {
	getter.ctx = ctx
	getter.logger = ctx.Slogger()

	if getter.Path == "" {
		return fmt.Errorf("path is required")
	}

	if getter.FetchFullChain == nil {
		tmp := true
		getter.FetchFullChain = &tmp
	}

	// Get the modification time of the file
	fileInfo, err := os.Stat(getter.Path)
	if err != nil {
		return err
	}
	modTime := fileInfo.ModTime()

	if *getter.FetchFullChain {
		getter.CacheCertName = getter.Path + "." + modTime.Format(time.RFC3339) + "-fullchain+pkey.pem"
	} else {
		getter.CacheCertName = getter.Path + "." + modTime.Format(time.RFC3339) + "-chain+pkey.pem"
	}

	return nil
}

func (getter *PfxCertGetter) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	storage := getter.ctx.Storage()

	if !storage.Exists(ctx, getter.CacheCertName) {
		err := getter.GenerateParsedKeys(ctx)
		if err != nil {
			getter.logger.Error("failed to decode pfx certificate", zap.Error(err))
			return nil, err
		}
	}

	var cert tls.Certificate

	pemData, err := storage.Load(ctx, getter.CacheCertName)
	if err != nil {
		return nil, err
	}

	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}

		switch block.Type {
		case "RSA PRIVATE KEY":
			if cert.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
				return nil, err
			}
			break
		case "CERTIFICATE":
			cert.Certificate = append(cert.Certificate, block.Bytes)
			break
		}

		pemData = rest
	}

	return &cert, nil

}

func (getter *PfxCertGetter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {

	for d.Next() {
		nested := false

		// Try to load nested as json
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			nested = true
			key := d.Val()
			if key == "path" {
				if !d.NextArg() {
					return d.ArgErr()
				}
				getter.Path = d.Val()
				continue
			}
			if key == "password" {
				if !d.NextArg() {
					return d.ArgErr()
				}
				getter.Password = d.Val()
				continue
			}
			if key == "fetch_full_chain" {
				if !d.NextArg() {
					return d.ArgErr()
				}

				if d.Val() == "true" {
					tmp := true
					getter.FetchFullChain = &tmp
				} else if d.Val() == "false" {
					tmp := false
					getter.FetchFullChain = &tmp
				} else {
					return d.Err(d.Val() + " is not a valid value for fetch_full_chain")
				}

				// Ensure no more arguments
				if d.NextArg() {
					return d.ArgErr()
				}
				continue
			} else {
				return d.Err(key + " not allowed here")
			}
		}

		// Else try to load from inline
		if !nested {
			if !d.NextArg() {
				return d.ArgErr()
			}
			getter.Path = d.Val()

			if d.NextArg() {
				getter.Password = d.Val()
			}
			if d.NextArg() {
				return d.ArgErr()
			}
		}
	}
	return nil
}

func (getter *PfxCertGetter) GenerateParsedKeys(ctx context.Context) error {
	storage := getter.ctx.Storage()

	// Read the PFX file
	pfxBytes, err := os.ReadFile(getter.Path)
	if err != nil {
		return err
	}

	// Decode the PFX file
	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(pfxBytes, getter.Password)
	if err != nil {
		return err
	}

	// Create single pem file with all data
	var pemData []byte

	// Append private key
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey.(*rsa.PrivateKey)),
	})...)

	// Combine leaf and intermediates from PFX and fetch the full chain automatically
	chain, err := getCertificateChain(append([]*x509.Certificate{certificate}, caCerts...))
	if err != nil {
		return err
	}

	// Append all certificates
	for _, caCert := range chain {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		})...)
	}

	// Cache single file in storage
	err = storage.Store(ctx, getter.CacheCertName, pemData)
	if err != nil {
		return err
	}

	return nil
}

// Interface guards
var (
	_ certmagic.Manager     = (*PfxCertGetter)(nil)
	_ caddy.Provisioner     = (*PfxCertGetter)(nil)
	_ caddyfile.Unmarshaler = (*PfxCertGetter)(nil)
)
