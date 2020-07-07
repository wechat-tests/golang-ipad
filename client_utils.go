package wxxx

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"math/rand"
	"strings"
	"time"
	"wxxx/mm_pb"
)

type protoEncodeType int

const (
	NoCompressRSA protoEncodeType = 7
	CompressRSA   protoEncodeType = 1
	CompressAES   protoEncodeType = 5
)

func (this *client) shortLinkExecute(hostUrl string,
	req proto.Message, cgi int, cgiPath mm_pb.CGI_URL,
	encodeType protoEncodeType, aesKey []byte, cookie []byte, muid int32,
	resp proto.Message) (*pkgInfo, error) {
	if hostUrl == "" {
		hostUrl = shortUrl
	}
	Log.Printf("aes key : len = %d >> %s", len(aesKey), ArrToHexStrWithSp(aesKey, " "))
	//pack
	src, err := this.pack(req, cgi, encodeType, aesKey, cookie, muid)
	if err != nil {
		return nil, errors.WithMessage(err, "marshall request failed")
	}
	reqCtx := &RequestCtx{
		HttpMethod:  POST,
		Url:         fmt.Sprintf("%s%s", hostUrl, cgiPath),
		ContentType: "application/octet-stream",
		UserAgent:   "MicroMessenger Client",
		BodyData:    src,
	}
	ret, err := this.shortLink.DO(reqCtx)
	if err != nil {
		return nil, errors.WithMessage(err, "short link execute failed ")
	}
	//un pack
	pkg, err := this.unpack(ret.BodyData, aesKey)
	if err != nil {
		return nil, errors.WithMessage(err, "unpack response data failed ")
	}
	//un marshall body
	err = proto.Unmarshal(pkg.body, resp)
	if err != nil {
		return nil, errors.WithMessage(err, "un marshall response data failed ")
	}
	return pkg, nil
}

func (this *client) newBasRequest(aesKey []byte, deviceId []byte, uin int32, scene int32) *mm_pb.BaseRequest {
	return &mm_pb.BaseRequest{
		SessionKey:    aesKey,
		Uin:           &uin,
		DeviceId:      deviceId,
		ClientVersion: &this.clientVersion,
		OsType:        &this.osType,
		Scene:         &scene,
	}
}

func (this *client) newRandomAesKey() *mm_pb.AesKey {
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	key := make([]byte, 16, 16)
	for i := 0; i < 16; i++ {
		key[i] = byte(random.Intn(0xff))
	}
	len := int32(16)
	return &mm_pb.AesKey{
		Len: &len,
		Key: key,
	}
}

func (this *client) newRandomDeviceId() string {
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	sb := strings.Builder{}
	for i := 0; i < 10; i++ {
		num := random.Intn(0x0F)
		sb.WriteString(fmt.Sprintf("%x", num))
	}
	return sb.String()
}

func (this *client) pack(pbMsg proto.Message, cgi int, encodeType protoEncodeType, aesKey []byte, cookie []byte, muid int32) ([]byte, error) {
	version := this.clientVersion
	loginRsaVersion := this.loginRsaVersion
	src, err := proto.Marshal(pbMsg)
	Log.Printf("pb msg raw pb : len = %d >> %s \n", len(src), ArrToHexStrWithSp(src, " "))
	if err != nil {
		return nil, errors.WithMessage(err, "marshall request failed")
	}
	pbData := src[:]
	rawMsgPbLen := len(src)
	lenAfterCompress := rawMsgPbLen
	if encodeType == CompressAES || encodeType == CompressRSA {
		//compress
		pbData, err = deflateZip(src)
		if err != nil {
			return nil, errors.WithMessage(err, "zip request failed")
		}
		lenAfterCompress = len(pbData)
	}
	var pbody []byte
	header := make([]byte, 0, 100)
	//byte 0, fix 0xbf,don't know what it is
	header = append(header, 0xbf)
	//byte 1,len << 2+2 or len<< 2 + 1, changed after make complete
	header = append(header, 2)
	//byte 2, encodeType << 4 & cookie len
	byte2 := (byte)(encodeType << 4 & 0xFF)
	if len(cookie) > 0 {
		byte2 = byte2 & 0x0f //add fix cookie len 15,
	}
	header = append(header, byte2)
	//version bytes, 4 bytes
	versionBytes := Int32ToArrBE(version)
	header = append(header, versionBytes...)
	//if encodeType == 1 || encodeType == 5 {
	//	versionBytes := UInt32ToArrBE(version)
	//	header = append(header, versionBytes...)
	//} else {
	//	header = append(header, []byte{0x16, 0x07, 0x03, 0x21}...)
	//}
	// uin bytes, 4 bytes
	uinBytes := Int32ToArrBE(muid)
	header = append(header, uinBytes...)
	//cookie bytes, 15 bytes for now, ATTENTION ! if not, means protocol changed
	if len(cookie) > 0 {
		//header = append(header, cookie...)
		header = append(header, cookie...)
	}
	//cgi type
	cgiBytes := VariantEncode(uint32(cgi))
	header = append(header, cgiBytes...)
	// len of raw pb msg
	lenOfRawPbBytes := VariantEncode(uint32(rawMsgPbLen))
	header = append(header, lenOfRawPbBytes...)
	// len of after compress
	lenOfCompressedPbBytes := VariantEncode(uint32(lenAfterCompress))
	header = append(header, lenOfCompressedPbBytes...)
	if encodeType == NoCompressRSA || encodeType == CompressRSA {
		//rsa version,
		header = append(header, VariantEncode(loginRsaVersion)...)
		//fix, don't know what it is
		header = append(header, []byte{0x0D, 0x00, 0x09}...)
		//rqt sign
		rqtSign, err := this.RQTSign(src)
		if err != nil {
			return nil, errors.WithMessage(err, "calc RQT sign failed ")
		}
		header = append(header, VariantEncode(rqtSign)...)
		//fix 0x00, don't know what it is
		header = append(header, 0x00)
		//change second byte with actual head length
		header[1] = (byte)(len(header)<<2 + 2)
		pbody = make([]byte, 0, len(header)+len(pbData))
		pbody = append(pbody, header...)
		encrypted, err := RsaEncrypt(pbData)
		if err != nil {
			return nil, errors.WithMessage(err, "rsa encrypt failed ")
		}
		pbody = append(pbody, encrypted...)
		//appedn
	} else {
		//don't know what it is
		header = append(header, VariantEncode(10000)...)
		//end tag , don't know what it is
		header = append(header, []byte{0x02}...)
		//check
		header = append(header, VariantEncode(0x00)...)
		//don't know what it is
		header = append(header, VariantEncode(uint32(0x01004567))...)
		//change second byte with actual head length
		header[1] = (byte)(len(header)<<2 + 2)
		//append aes data,TODO
		header = append(header, aesKey...)
	}
	return pbody, nil
}

//
//func (this *client) MakeHeader(version int32, loginRsaVersion int32, rawMsgPbLen int, lenAfterCompress int, cgi int, encodeType int, cookie []byte, muid int32) ([]byte, error) {
//	header := make([]byte, 0, 100)
//	//0 byte, fix 0xbf,don't know what it is
//	header = append(header, 0xbf)
//	//1 byte ,len << 2+2 or len<< 2 + 1, changed after make complete
//	header = append(header, 2)
//	//2 byte , encodeType << 4 & cookie len
//	byte2 := (byte)(encodeType << 4)
//	if len(cookie) > 0 {
//		byte2 = byte2 & 0x0f //add fix cookie len 15,
//	}
//	header = append(header, byte2)
//	//version bytes, 4 bytes
//	if encodeType == 1 || encodeType == 5 {
//		versionBytes := Int32ToArrBE(version)
//		header = append(header, versionBytes...)
//	} else {
//		header = append(header, []byte{0x16, 0x07, 0x03, 0x21}...)
//	}
//	// uin bytes, 4 bytes
//	uinBytes := Int32ToArrBE(muid)
//	header = append(header, uinBytes...)
//	//cookie bytes, 15 bytes for now, ATTENTION ! if not, means protocol changed
//	if len(cookie) == 15 {
//		header = append(header, cookie...)
//	} else {
//		cookieTmp := make([]byte, 15)
//		header = append(header, cookieTmp...)
//	}
//	//cgi type
//	cgiBytes := VariantEncode(uint32(cgi))
//	header = append(header, cgiBytes...)
//	// len of raw pb msg
//	lenOfRawPbBytes := VariantEncode(uint32(rawMsgPbLen))
//	header = append(header, lenOfRawPbBytes...)
//	// len of after compress
//	lenOfCompressedPbBytes := VariantEncode(uint32(lenAfterCompress))
//	header = append(header, lenOfCompressedPbBytes...)
//
//	if encodeType == 1 || encodeType == 5 {
//		//rsa version,
//		header = append(header, VariantEncode(uint32(loginRsaVersion))...)
//		//fix, don't know what it is
//		header = append(header, []byte{0x0D, 0x00, 0x09}...)
//		//rqt sign,TODO
//
//		//fix 0x00, don't know what it is
//		header = append(header, 0x00)
//		//change second byte with actual head length
//		header[1] = (byte)(len(header)<<2 + 2)
//	} else {
//		//don't know what it is
//		header = append(header, VariantEncode(10000)...)
//		//end tag , don't know what it is
//		header = append(header, []byte{0x02}...)
//		//check
//		header = append(header, VariantEncode(0x00)...)
//		//don't know what it is
//		header = append(header, VariantEncode(uint32(0x01004567))...)
//		//change second byte with actual head length
//		header[1] = (byte)(len(header)<<2 + 1)
//		//append aes data,TODO
//	}
//	return header, nil
//}

type pkgInfo struct {
	isCompressed    bool
	uin             uint32
	cookie          []byte
	encryptAlg      int
	version         uint32
	cgi             uint32
	rawPbLen        uint32
	compressedPbLen uint32
	body            []byte
	encryptedBody   []byte
}

//un pack header & body
func (this *client) unpack(raw []byte, aesKey []byte) (pkg *pkgInfo, err error) {
	if len(raw) < 0x20 {
		return nil, errors.New("data len too short")
	}
	if raw[0] != 0xbf {
		return nil, errors.New("invalid data header")
	}
	byte1 := int(raw[1] & 0xff)
	//header len first 6 bits of byte1
	headerLen := byte1 >> 2
	// is body compressed , last 2 bits of byte1
	isCompressed := byte1&0x03 == 0x01
	byte2 := int(raw[2] & 0xff)
	//encryption algorithm , first 4 bit of byte2
	//05 :aes ; 07 :rsa
	encryptAlg := byte2 >> 4 & 0xff
	//cookie len , last 4 bit of byte2
	cookieLen := byte2 & 0x0F
	//server version ,byte 3 - 6 ,ignore
	serverVersion := ArrToUint32BE(raw[3:7])
	//uin byte 7 - 10,
	uin := ArrToUint32BE(raw[7:11])
	//cookie , normally cookie len = 0x0f, cookie len > 0x0f means protocol header changed
	if cookieLen > 0x0f {
		return nil, errors.New("un supported protocol header")
	}
	cookie := raw[11 : 11+cookieLen]
	currentIdx := 11 + cookieLen
	// cgi type ,variant
	n, cgi := VariantDecode(raw[currentIdx:currentIdx+5], 0)
	currentIdx += n
	// length of raw protobuf data
	n, rawPbLen := VariantDecode(raw[currentIdx:currentIdx+5], 0)
	currentIdx += n
	// length of compressed protobuf data
	n, compressedPbLen := VariantDecode(raw[currentIdx:currentIdx+5], 0)
	currentIdx += n
	//ignore
	//body
	if headerLen > len(raw) {
		return nil, errors.New("bad package")
	}
	encryptedBodyBytes := make([]byte, len(raw)-headerLen)
	//encryptedBodyBytes = append(encryptedBodyBytes, raw[headerLen:]...)
	copy(encryptedBodyBytes, raw[headerLen:])
	Log.Printf("encryptedBodyBytes : len =%d >> %s\n", len(encryptedBodyBytes), ArrToHexStrWithSp(encryptedBodyBytes, " "))
	//aes decrypt
	body := AESCbcDecrypt(encryptedBodyBytes, aesKey)
	Log.Printf("decryptedBodyBytes : len =%d >> %s\n", len(body), ArrToHexStrWithSp(body, " "))
	if isCompressed {
		//unzip
		body, err = deflateUnZip(body)
		if err != nil {
			return nil, errors.WithMessage(err, "un zip resp body failed")
		}
		Log.Printf("unziped body : len =%d >> %s\n", len(body), ArrToHexStrWithSp(body, " "))
	}
	return &pkgInfo{
		isCompressed:    isCompressed,
		uin:             uin,
		cookie:          cookie,
		encryptAlg:      encryptAlg,
		version:         serverVersion,
		cgi:             cgi,
		rawPbLen:        rawPbLen,
		compressedPbLen: compressedPbLen,
		body:            body,
		//encryptedBody:   encryptedBodyBytes,
	}, nil
}

// RQT sign
func (this *client) RQTSign(data []byte) (uint32, error) {
	pixels, err := hex.DecodeString("6a664d5d537c253f736e48273a295e4f") //TODO fix hardcode
	if err != nil {
		return 0, err
	}
	md5Bytes := []byte(GetMd5Hex(data))
	block1 := make([]byte, 48+len(pixels))
	copy(block1, pixels)
	for i := 0; i < len(block1); i++ {
		block1[i] = block1[i] ^ 0x36
	}
	bf1 := bytes.Buffer{}
	bf1.Write(block1)
	bf1.Write(md5Bytes[:])
	r1Sha1Bytes := sha1.Sum(bf1.Bytes())
	block2 := make([]byte, 48+len(pixels))
	copy(block2, pixels)
	for i := 0; i < len(block2); i++ {
		block2[i] = block2[i] ^ 0x5c
	}
	bf2 := bytes.Buffer{}
	bf2.Write(block2)
	bf2.Write(r1Sha1Bytes[:])
	r2Sha1Bytes := sha1.Sum(bf2.Bytes())
	var t1 = 0
	var t2 = 0
	var t3 = 0
	for i := 2; i < len(r2Sha1Bytes); i++ {
		v1 := int(r2Sha1Bytes[i-2] & 0xff)
		v2 := int(r2Sha1Bytes[i-1] & 0xff)
		v3 := int(r2Sha1Bytes[i] & 0xff)
		t1 = 0x83*t1 + v1
		t2 = 0x83*t2 + v2
		t3 = 0x83*t3 + v3
	}
	r1 := 1  //TODO fix hardcode
	key := 1 //TODO fix hardcode
	r3 := t1 & 0x00007f
	r4 := (t3 << 16) & 0x7f0000
	r5 := (t2 << 8) & 0x007f00
	return uint32(r3 | r4 | r5 | ((r1<<5 | key&0x1f) << 24)), nil
}
