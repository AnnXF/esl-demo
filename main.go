package main

import (
	"encoding/asn1"
	"fmt"
	"github.com/tjfoc/gmsm/x509"
	"io/ioutil"
)

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

	certByte1 := sESeal.ESealInfo.Property.CertList.Certs
	certSign, err := x509.ParseCertificates(certByte1)
	if err != nil {
		fmt.Println("Error cert ASN.1 data:", err)
		return
	}
	// 输出解码后的 Header
	fmt.Printf(" x509.ParseCertificates certSign: %+v\n", certSign)

	certByte2 := sESeal.Cert
	certMake, err := x509.ParseCertificates(certByte2)
	if err != nil {
		fmt.Println("Error cert ASN.1 data:", err)
		return
	}
	fmt.Printf(" x509.ParseCertificates certMake: %+v\n", certMake)

}
