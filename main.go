package main

import (
	"encoding/asn1"
	"fmt"
	"github.com/itlabers/crypto/x509"
	"github.com/itlabers/ofd-go"
	"os"
)

func main() {
	// 读取 Seal.esl 文件
	data, err := os.ReadFile("./Seal.esl")
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
	certSign, err := x509.ParseCertificate(certByte1)
	if err != nil {
		fmt.Println("Error cert ASN.1 data:", err)
		return
	}
	// 输出解码后的 Header
	fmt.Printf(" x509.ParseCertificates certSign: %+v\n", certSign.Issuer.String())

	certByte2 := sESeal.Cert
	certMake, err := x509.ParseCertificates(certByte2)
	if err != nil {
		fmt.Println("Error cert ASN.1 data:", err)
		return
	}
	fmt.Printf(" x509.ParseCertificates certMake: %+v\n", certMake[0].Issuer.String())

	verify, err := OfdCheck()
	if err != nil {
		fmt.Println("Error cert ASN.1 data:", err)
		return
	}
	fmt.Println("verify:", verify)

}

func OfdCheck() (verify bool, err error) {
	//path := "many-ofd.ofd"
	//path := "./test-1.ofd"
	path := "./output.ofd"
	//path := "./test.ofd"
	ofdReader, err := ofd.NewOFDReader(path, ofd.WithValidator(&ofd.CommonValidator{}))
	if err != nil {
		return verify, err
	}
	defer ofdReader.Close()
	a, err := ofdReader.OFD()
	if err != nil {
		return verify, err
	}

	docIDList := []string{}
	for _, v := range a.DocBody {
		docIDList = append(docIDList, v.DocInfo.DocID.Text)
	}
	if len(docIDList) < 1 {
		err = fmt.Errorf(" file don't have eseal")
		return verify, err
	}
	flag := false
	for _, docID := range docIDList {
		signs, err := ofdReader.GetSignaturesById(docID)
		if err != nil {
			return verify, err
		}
		temFlag := false
		for _, v := range signs.Signature {
			sign, err := signs.GetSignatureById(v.ID)
			if err != nil {
				return verify, err
			}
			verify, err = sign.Verify()
			if err != nil {
				return verify, err
			}
			if !verify {
				flag = true
				temFlag = true
				break
			}
		}
		if temFlag {
			break
		}

	}
	if flag {
		verify = false
	} else {
		verify = true
	}
	return verify, nil
}
