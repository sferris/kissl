package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
)

var (
	oidPKCS7Data       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional"`
}

type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms []asn1.RawValue `asn1:"set"`
	ContentInfo      pkcs7ContentInfo
	Certificates     asn1.RawValue
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

func encodeP7B(certificates [][]byte) ([]byte, error) {
	certificateDER := make([]byte, 0)
	for _, certificatePEM := range certificates {
		block, rest := pem.Decode(certificatePEM)
		if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
			return nil, errors.New("invalid certificate PEM")
		}
		certificateDER = append(certificateDER, block.Bytes...)
	}

	signedData, err := asn1.Marshal(pkcs7SignedData{
		Version:          1,
		DigestAlgorithms: []asn1.RawValue{},
		ContentInfo:      pkcs7ContentInfo{ContentType: oidPKCS7Data},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      certificateDER,
		},
		SignerInfos: []asn1.RawValue{},
	})
	if err != nil {
		return nil, err
	}
	contentInfo, err := asn1.Marshal(pkcs7ContentInfo{
		ContentType: oidPKCS7SignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedData,
		},
	})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: contentInfo}), nil
}

func serveCertificate(w http.ResponseWriter, r *http.Request, paths []string, pemFilename, p7bFilename string, pemChain bool) {
	format := r.URL.Query().Get("format")
	if format != "" && format != "pem" && format != "p7b" {
		fail(w, http.StatusBadRequest, "format must be pem or p7b")
		return
	}

	certificates := make([][]byte, 0, len(paths))
	for _, path := range paths {
		certificate, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			fail(w, http.StatusNotFound, "certificate not found")
			return
		}
		if err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		certificates = append(certificates, certificate)
		if format != "p7b" && !pemChain {
			break
		}
	}

	body := certificates[0]
	if pemChain {
		body = bytes.Join(certificates, []byte("\n"))
	}
	filename := pemFilename
	contentType := "application/x-pem-file"
	if format == "p7b" {
		var err error
		body, err = encodeP7B(certificates)
		if err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		filename = p7bFilename
		contentType = "application/pkcs7-mime"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
