package main

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/x509"
	"math/big"
)

func CheckIntegrity(seal SESeal) {
	//// 计算哈希值
	//hash := sha256.New()
	//hash.Write([]byte(eseal.ESealInfo.Header.ID))
	//hash.Write([]byte{byte(eseal.ESealInfo.Header.Version)})
	//hash.Write([]byte(eseal.ESealInfo.Header.Vid))
	//hash.Write([]byte(eseal.ESealInfo.EsID))
	//hash.Write([]byte{byte(eseal.ESealInfo.Property.Type)})
	//hash.Write([]byte(eseal.ESealInfo.Property.Name))
	//hash.Write([]byte{byte(eseal.ESealInfo.Property.CertListType)})
	//hash.Write(eseal.ESealInfo.Property.CertList.Certs)
	//hash.Write([]byte(eseal.ESealInfo.Property.CreateDate.String()))
	//hash.Write([]byte(eseal.ESealInfo.Property.ValidStart.String()))
	//hash.Write([]byte(eseal.ESealInfo.Property.ValidEnd.String()))
	//hash.Write(eseal.ESealInfo.Picture.Data)
	//for _, ext := range eseal.ESealInfo.ExtDatas {
	//	hash.Write([]byte(ext.ExtnID.String()))
	//	hash.Write(ext.ExtnValue)
	//}
	//digest := hash.Sum(nil)

	// 计算哈希值

	// 获取签名者的公钥（从证书中提取）
	cert1 := FilterCert(seal.Cert)
	block, _ := pem.Decode(cert1)
	if block == nil || block.Type != "CERTIFICATE" {
		fmt.Println("failed to decode PEM block containing certificate")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("failed to parse certificate:", err)
		return
	}
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("not ECDSA public key")
		return
	}

	// 提取签名
	var r, s big.Int
	signature := seal.SignedValue.Bytes
	r.SetBytes(signature[:len(signature)/2])
	s.SetBytes(signature[len(signature)/2:])

	// 验证签名
	valid := ecdsa.Verify(publicKey, seal.Cert, &r, &s)
	if valid {
		fmt.Println("Signature is valid")
	} else {
		fmt.Println("Signature is invalid")
	}
}

func FilterCert(rawCert []byte) []byte {
	temCert, err := x509.ParseCertificates(rawCert)
	if err != nil {
		fmt.Println(" FilterCert parse certificate:", err)
		return nil
	}
	for _, cert := range temCert {
		cert.PublicKey, err = x509.ParseSm2PublicKey(cert.RawSubjectPublicKeyInfo)
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		return certPEM
	}
	return nil
}

// VerifySignedValue verifies the SignedValue using the provided Cert and SignAlgID.
func VerifySignedValue(seal SESeal) error {
	// Decode the certificate
	tem := FilterCert(seal.Cert)
	block, _ := pem.Decode(tem)
	if block == nil {
		return errors.New("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Hash the data that was signed (this depends on the specific signing algorithm used)
	// For simplicity, we'll assume SHA256 was used
	hasher := crypto.SHA256.New()
	// Here we need to serialize ESealInfo and Cert, but for simplicity we'll use a placeholder function
	dataToVerify, err := asn1.Marshal(seal.ESealInfo) // Placeholder for the actual serialization process
	if err != nil {
		return fmt.Errorf("failed to marshal ESealInfo: %v", err)
	}
	hasher.Write(dataToVerify)

	// Verify the signature
	err = cert.CheckSignature(cert.SignatureAlgorithm, hasher.Sum(nil), seal.SignedValue.Bytes)
	if err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	return nil
}

//// VerifySignature verifies the signature value using the provided Cert and SignAlgID.
//func VerifySignature(seal SESeal) error {
//	// Decode the certificate
//	//block, _ := pem.Decode(seal.Cert)
//	tem := FilterCert(seal.Cert)
//	block, _ := pem.Decode(tem)
//	if block == nil {
//		return errors.New("failed to parse certificate PEM")
//	}
//
//	cert, err := x509.ParseCertificate(block.Bytes)
//	if err != nil {
//		return fmt.Errorf("failed to parse certificate: %v", err)
//	}
//
//	//// Hash the data that was signed (serialize ESealInfo)
//	//dataToVerify, err := asn1.Marshal(seal.ESealInfo)
//	//if err != nil {
//	//	return fmt.Errorf("failed to marshal ESealInfo: %v", err)
//	//}
//
//	//// Calculate the hash using SM3
//	//hashed := sm3.Sm3Sum(dataToVerify)
//	//ddd := seal.SignedValue.Bytes
//	//d := sm3.New()
//	//if string(hashed) == string(ddd) {
//	//	return nil
//	//}
//
//	// Verify the signature using SM2
//	sm2PubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
//	if !ok {
//		return errors.New("public key is not SM2")
//	}
//	// 提取签名
//	var r, s big.Int
//	signature := seal.SignedValue.Bytes
//	r.SetBytes(signature[:len(signature)/2])
//	s.SetBytes(signature[len(signature)/2:])
//	tem1 := sm2.PublicKey{
//		Curve: sm2PubKey.Curve,
//		X:     sm2PubKey.X,
//		Y:     sm2PubKey.Y,
//	}
//
//	// 验证签名
//	//valid := ecdsa.Verify(publicKey, seal.Cert, &r, &s)
//	if !sm2.Verify(&tem1, hashed, &r, &s) {
//		return errors.New("signature verification failed")
//	}
//
//	return nil
//}
