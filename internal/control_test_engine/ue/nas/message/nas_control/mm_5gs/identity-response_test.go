package mm_5gs

import (
	"bytes"
	"testing"

	"github.com/free5gc/nas/ie"
	nas "github.com/free5gc/nas/message"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"my5G-RANTester/internal/common/auth"
	"my5G-RANTester/internal/control_test_engine/ue/context"
)

func TestLuhnCheckDigit(t *testing.T) {
	// TS 23.003 Annex B example.
	assert.Equal(t, uint8(8), luhnCheckDigit("49015420323751"))
	assert.Equal(t, uint8(0), luhnCheckDigit("00000000000000"))
}

func TestImeiFromMsinMatchesImeisv(t *testing.T) {
	imei := imeiFromMsin("0000000120")
	require.Len(t, imei, 15)
	assert.Equal(t, imeisvFromMsin("0000000120")[:14], imei[:14])
	assert.Equal(t, "000000000001206", imei)
}

// rawIdentity returns the 5GS mobile identity value of a plain Identity Response.
func rawIdentity(t *testing.T, pdu []byte) ([]byte, *ie.MobileId5GS) {
	t.Helper()
	m, err := nas.Parse(pdu, nil)
	require.NoError(t, err)
	rsp, ok := m.(*nas.IdRsp)
	require.True(t, ok)
	require.NotNil(t, rsp.MobileId)
	// EPD, security header, message type, 2-byte length.
	length := int(pdu[3])<<8 | int(pdu[4])
	require.Len(t, pdu, 5+length)
	return pdu[5:], rsp.MobileId
}

func TestIdentityResponseImei(t *testing.T) {
	for _, digits := range []string{"490154203237518", "000000000000000"} {
		pdu := encodePlain(&nas.IdRsp{MobileId: imeiIdentity(digits)})
		raw, id := rawIdentity(t, pdu)
		require.Len(t, raw, 8)
		assert.Equal(t, ie.IdType_5GS_IMEI, raw[0]&7)
		assert.NotZero(t, raw[0]&8, "a 15-digit IMEI must set the odd indicator, even with check digit 0")
		assert.Equal(t, digits[14]-'0', raw[7]>>4, "15th digit sits in the high nibble of the last octet")
		assert.Equal(t, "imei-"+digits, id.PEIStr())
	}
}

func TestIdentityResponseImeisv(t *testing.T) {
	digits := imeisvFromMsin("0000000120")
	pdu := encodePlain(&nas.IdRsp{MobileId: imeisvIdentity(digits)})
	raw, id := rawIdentity(t, pdu)
	require.Len(t, raw, 9)
	assert.Equal(t, ie.IdType_5GS_IMEISV, raw[0]&7)
	assert.Zero(t, raw[0]&8)
	assert.Equal(t, uint8(0xf), raw[8]>>4)
	assert.Equal(t, "imeisv-"+digits, id.PEIStr())
}

func TestIdentityResponseForProtectedImei(t *testing.T) {
	ue := &context.UEContext{}
	ue.UeSecurity.Kamf = bytes.Repeat([]byte{0x42}, 32)
	ue.UeSecurity.CipheringAlg, ue.UeSecurity.IntegrityAlg = 2, 2
	require.NoError(t, auth.AlgorithmKeyDerivation(2, ue.UeSecurity.Kamf, &ue.UeSecurity.KnasEnc, 2, &ue.UeSecurity.KnasInt))
	ue.UeSecurity.ULCount.Set(0, 3)

	// The network side decodes with its own view of the same context, before the UE counter moves.
	network := ue.NASSecurityContext().Clone()
	network.Side = nas.CoreNetworkSide

	pdu, err := IdentityResponseFor(ue, ie.IdType_5GS_IMEI, true)
	require.NoError(t, err)
	assert.Equal(t, byte(nas.SecHdrTypeIntegrityProtectedAndCiphered), pdu[1])
	assert.Equal(t, uint32(4), ue.UeSecurity.ULCount.Get(), "uplink NAS COUNT advances")

	m, err := nas.Parse(pdu, network)
	require.NoError(t, err)
	rsp, ok := m.(*nas.IdRsp)
	require.True(t, ok)
	assert.Equal(t, "imei-"+imeiFromMsin(ue.GetMsin()), rsp.MobileId.PEIStr())

	_, err = IdentityResponseFor(ue, ie.IdType_5GS_GUTI, true)
	assert.Error(t, err, "5G-GUTI is not answered")
}

func TestIdentityResponseForPlainSuciUnchanged(t *testing.T) {
	ue := &context.UEContext{}
	pdu, err := IdentityResponseFor(ue, ie.IdType_5GS_SUCI, false)
	require.NoError(t, err)
	assert.Equal(t, IdentityResponse(ue), pdu)
}
