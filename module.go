package CADDY_PFX_CERTIFICATES

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"golang.org/x/crypto/pkcs12"
	"os"
	"time"
)

func init() {
	caddy.RegisterModule(PfxCertGetter{})
}

type PfxCertGetter struct {
	// The path to file with domain-certificate dictionary. Required.
	Path     string `json:"path,omitempty"`
	Password string `json:"password,omitempty"`

	CacheCertName string
	CachePkName   string

	ctx caddy.Context
}

func (PfxCertGetter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.pfx",
		New: func() caddy.Module { return new(PfxCertGetter) },
	}
}

func (getter *PfxCertGetter) Provision(ctx caddy.Context) error {
	getter.ctx = ctx
	if getter.Path == "" {
		return fmt.Errorf("path is required")
	}

	// Get the modification time of the file
	fileInfo, err := os.Stat(getter.Path)
	if err != nil {
		return err
	}
	modTime := fileInfo.ModTime()

	getter.CachePkName = getter.Path + "." + modTime.Format(time.RFC3339) + ".key"
	getter.CacheCertName = getter.Path + "." + modTime.Format(time.RFC3339) + ".crt"

	return nil
}

func (getter PfxCertGetter) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	storage := getter.ctx.Storage()

	if !storage.Exists(ctx, getter.CachePkName) || !storage.Exists(ctx, getter.CacheCertName) {
		err := getter.GenerateParsedKeys(ctx)
		if err != nil {
			return nil, err
		}
	}

	crtBytes, err := storage.Load(ctx, getter.CacheCertName)
	if err != nil {
		return nil, err
	}

	keyBytes, err := storage.Load(ctx, getter.CachePkName)
	if err != nil {
		return nil, err
	}

	crt, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}
	tlsCrt := &tls.Certificate{
		Certificate: [][]byte{crt.Raw},
		Leaf:        crt,
		PrivateKey:  key,
	}
	return tlsCrt, nil

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
			} else if key == "password" {
				if !d.NextArg() {
					return d.ArgErr()
				}
				getter.Password = d.Val()
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
	pk, crt, err := pkcs12.Decode(pfxBytes, getter.Password)
	if err != nil {
		return err
	}

	// Cache cert in storage
	err = storage.Store(ctx, getter.CacheCertName, crt.Raw)
	if err != nil {
		return err
	}

	//Cache pkey in storage
	err = storage.Store(ctx, getter.CachePkName, x509.MarshalPKCS1PrivateKey(pk.(*rsa.PrivateKey)))
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
