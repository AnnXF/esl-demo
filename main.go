package main

import (
	"encoding/asn1"
	"fmt"
	"io/ioutil"
)

// PKIMessage 定义
type PKIMessage struct {
	Header PKIHeader
	Body   asn1.RawValue
}

// PKIHeader 定义
type PKIHeader struct {
	Pvno      asn1.RawValue `asn1:"optional"`
	Sender    asn1.RawValue `asn1:"optional"`
	Recipient asn1.RawValue `asn1:"optional"`
}

//// PKIHeader 定义
//type PKIHeader struct {
//	Pvno      int         `asn1:"optional"`
//	Sender    GeneralName `asn1:"optional"`
//	Recipient GeneralName `asn1:"optional"`
//	MessageID string      `asn1:"ia5,optional"`
//	Time      time.Time   `asn1:"generalized,optional"`
//}

// GeneralName 定义
type GeneralName struct {
	DirectoryName DirectoryName `asn1:"tag:4"`
}

// DirectoryName 定义
type DirectoryName struct {
	CountryName      string `asn1:"printable,optional,tag:6"`
	CommonName       string `asn1:"utf8,optional,tag:3"`
	OrganizationName string `asn1:"utf8,optional,tag:10"`
	EmailAddress     string `asn1:"ia5,optional,tag:1"`
}

// PKIBody 定义
type PKIBody struct {
	Content asn1.RawValue `asn1:"tag:0"`
}

func main() {
	// 读取 Seal.esl 文件
	data, err := ioutil.ReadFile("/Users/ann-xf/Desktop/ann_work/ann-demo/esl/Seal.esl")
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// 解码 PKIMessage 的 Header
	var sESeal SESeal
	_, err = asn1.Unmarshal(data, &sESeal)
	if err != nil {
		fmt.Println("Error decoding PKIMessage ASN.1 data:", err)
		return
	}
	////输出解码后的 Header
	//fmt.Printf("Decoded PKIMessage Header: %+v\n", sESeal)

	var cert CertInfoList
	certByte := sESeal.ESealInfo.Property.CertList.Certs
	_, err = asn1.Unmarshal(certByte, &cert)
	if err != nil {
		fmt.Println("Error cert ASN.1 data:", err)
		return
	}
	// 输出解码后的 Header
	fmt.Printf("Decoded cert: %+v\n", cert.TBSCertificate.SubjectPublicKeyInfo.Algorithm.Algorithm.String())
	fmt.Printf("Decoded cert: %s\n", cert.TBSCertificate.SubjectPublicKeyInfo.SubjectPublicKey.Bytes)

}
