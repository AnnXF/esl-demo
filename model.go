package main

import (
	"encoding/asn1"
	"time"
)

type SESeal struct {
	ESealInfo SES_SealInfo // 印章信息
}

type SES_SealInfo struct {
	Header   SES_Header         // 印章头
	EsID     string             // 印章表示
	Property SES_ESPropertyInfo // 印章属性
	Picture  SES_ESPictureInfo  // 印章图像数据
	ExtDatas []ExtensionDatas   // 自定义数据
}

// SES_Header 印章头
type SES_Header struct {
	ID      string
	Version int64
	Vid     string
}

// SES_ESPropertyInfo 印章属性
type SES_ESPropertyInfo struct {
	Type         int64        // 印章类型
	Name         string       // 印章名称
	CertListType int64        // 签证者证书信息类型
	CertList     SES_CertList // 签证者证书信息列表
	CreateDate   time.Time    // 印章制作时间
	ValidStart   time.Time    // 印章有效期起始时间
	ValidEnd     time.Time    // 印章有效期终止时间
}

// SES_CertList 签证者证书信息列表
type SES_CertList struct {
	Certs []byte // 签章者证书
	//Certs CertInfoList // 签章者证书
	//Certs CertInfoList // 签章者证书
	//CertDigestList CertDigestList // 签章者证书的杂凑值
}

// CertInfoList 签章者证书
type CertInfoList struct {
	TBSCertificate TBSCertificate
	//SignatureAlgorithm pkix.AlgorithmIdentifier
	//SignatureValue     asn1.BitString
}

type TBSCertificate struct {
	Version int64 `asn1:"explicit,tag:0"`
	//SerialNumber int64 `asn1:"explicit,tag:0"`
	//Signature    pkix.AlgorithmIdentifier
	//Issuer       pkix.Name
	//Validity     Validity
	//Subject      pkix.Name
	//SubjectPublicKeyInfo asn1.RawValue
	//IssuerUniqueID       asn1.RawValue
	//SubjectUniqueID      asn1.RawValue
	//Extensions           asn1.RawValue
}

type Validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// CertDigestList 签章者证书的杂凑值
type CertDigestList struct {
	Type  string //自定义类型
	Value []byte // 证书杂凑值
}

// SES_ESPictureInfo 印章图像数据
type SES_ESPictureInfo struct {
	Type   string // 图像类型
	Data   []byte // 图像数据
	Width  int64  // 图像显示宽度
	Height int64  // 图像显示高度
}

// ExtensionDatas 自定义数据
type ExtensionDatas struct {
	ExtnID    asn1.ObjectIdentifier // 自定义扩展字段标识
	Critical  bool                  // 自定义扩展字段是否关键
	ExtnValue []byte                // 自定义扩展字段数据值
}
