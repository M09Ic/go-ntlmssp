package ntlmssp

import (
	"fmt"
	"unsafe"
)

type LMResponse struct {
	Response [24]byte
}

type LMv2Response struct {
	Response            [16]byte
	ChallengeFromClient [8]byte
}

type NTLMResponse struct {
	Response [24]byte
}

type NTLMv2Response struct {
	Response        [16]byte
	ClientChallenge NTLMv2ClientChallenge
}

type NTLMv2ClientChallenge struct {
	RespType            byte
	HiRespType          byte
	Reserved1           uint16
	Reserved2           uint32
	TimeStamp           uint64
	ChallengeFromClient [8]byte
	Reserved3           uint32
	AVPair              map[string]interface{}
}

type NTLMv2SessionResponse struct {
	Response [24]byte
}

type AnonymousResponse struct {
}

func (cc NTLMv2ClientChallenge) Marshal() []byte {
	output := []byte{cc.RespType, cc.HiRespType}
	output = append(output, []byte{0, 0}...)
	output = append(output, []byte{0, 0, 0, 0}...)
	output = append(output, (*(*[8]byte)(unsafe.Pointer(&cc.TimeStamp)))[:]...)
	output = append(output, cc.ChallengeFromClient[:]...)
	output = append(output, []byte{0, 0, 0, 0}...)

	for k, v := range cc.AVPair {
		if avIdsRev[k] == 0 {
			continue
		}
		output = append(output, avIdsRev[k], 0)

		if avIdsRev[k] != 6 && avIdsRev[k] != 7 && avIdsRev[k] != 8 && avIdsRev[k] != 10 {
			length := len(v.(string)) * 2
			output = append(output, byte(length&0xff), byte((length&0xff00)>>8))
			output = append(output, encodeUTF16LE([]byte(v.(string)))...)
		} else {
			length := len(v.([]byte))
			output = append(output, byte(length&0xff), byte((length&0xff00)>>8))
			output = append(output, v.([]byte)...)
		}
	}
	output = append(output, []byte{0, 0, 0, 0}...)
	return output
}

func ParseNTLMv2Response(bs []byte) *NTLMv2Response {
	ntv2r := NTLMv2Response{}
	copy(ntv2r.Response[:], bs[:16])

	ntv2r.ClientChallenge.RespType = bs[16]
	ntv2r.ClientChallenge.HiRespType = bs[17]
	// skip 6
	ntv2r.ClientChallenge.TimeStamp = bytes2Uint(bs[24:32], '<')
	copy(ntv2r.ClientChallenge.ChallengeFromClient[:], bs[32:40])
	// skip 4
	ntv2r.ClientChallenge.AVPair = ParseAVPair(bs[44:])

	return &ntv2r
}

var windowsVer = map[string]string{
	"5.0.2195": "2000",
	"5.1.2600": "XP",
	//"5.1.2600.1105": "XP SP1",
	//"5.1.2600.1106": "XP SP1",
	//"5.1.2600.2180": "XP SP2",
	"5.2.3790": "Server 2003/Server 2003 R2",
	//"5.2.3790.1180": "Server 2003 SP1",
	"6.0.6000":   "Vista",
	"6.0.6001":   "Vista SP1/Server2008",
	"6.0.6002":   "Vista SP2/Server2008 SP2",
	"6.1.0":      "7/Server2008 R2",
	"6.1.7600":   "7/Server2008 R2",
	"6.1.7601":   "7 SP1/Server2008 R2 SP1",
	"6.2.9200":   "8/Server2012",
	"6.3.9600":   "8.1/Server2012 R2",
	"10.0.10240": "10 1507",
	"10.0.10586": "10 1511",
	"10.0.14393": "10 1607/Server2016",
	"10.0.15063": "10 1703",
	"10.0.16299": "10 1709",
	"10.0.17134": "10 1803",
	"10.0.17763": "10 1809/Server2019",
	"10.0.18362": "10 1903",
	"10.0.18363": "10 1909",
	"10.0.19041": "10 2004/Server2004",
	"10.0.19042": "10 20H2/Server20H2",
	"10.0.19043": "10 21H2",
	"10.0.20348": "Server2022",
	"11.0.22000": "11",
}

func NTLMInfo(ret []byte) map[string]interface{} {
	flags := NewChallengeMsg(ret)
	tinfo := ParseAVPair(flags.TargetInfo())
	delete(tinfo, "MsvAvTimestamp")
	offset_version := 48
	version := ret[offset_version : offset_version+8]
	ver, _ := ReadVersionStruct(version)
	build := fmt.Sprintf("%d.%d.%d", ver.ProductMajorVersion, ver.ProductMinorVersion, ver.ProductBuild)
	tinfo["Version"] = fmt.Sprintf("Windows %s_(%s)", windowsVer[build], build)
	return tinfo
}
