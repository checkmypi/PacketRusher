/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package mm_5gs

import (
	"fmt"

	"github.com/free5gc/nas/ie"
	nas "github.com/free5gc/nas/message"
	"my5G-RANTester/internal/control_test_engine/ue/context"
	"my5G-RANTester/internal/control_test_engine/ue/nas/message/nas_control"
)

// IdentityResponse builds a plain Identity Response carrying the SUCI.
func IdentityResponse(ue *context.UEContext) []byte {
	identity := ue.GetSuci()
	return encodePlain(&nas.IdRsp{MobileId: &identity})
}

// IdentityResponseFor answers an Identity Request for the given 5GS identity type
// (SUCI, IMEI or IMEISV). When the request arrived under a NAS security context the
// response is integrity protected and ciphered with it (TS 24.501 4.4.4.3).
func IdentityResponseFor(ue *context.UEContext, idType uint8, protected bool) ([]byte, error) {
	var identity *ie.MobileId5GS
	switch idType {
	case ie.IdType_5GS_SUCI:
		suci := ue.GetSuci()
		identity = &suci
	case ie.IdType_5GS_IMEI:
		identity = imeiIdentity(imeiFromMsin(ue.GetMsin()))
	case ie.IdType_5GS_IMEISV:
		identity = imeisvIdentity(imeisvFromMsin(ue.GetMsin()))
	default:
		return nil, fmt.Errorf("identity type %s is not supported", ie.IdType5GSStr(idType))
	}
	pdu := encodePlain(&nas.IdRsp{MobileId: identity})
	if pdu == nil {
		return nil, fmt.Errorf("encoding Identity Response (%s) failed", ie.IdType5GSStr(idType))
	}
	if !protected {
		return pdu, nil
	}
	return nas_control.EncodeNasPduWithSecurity(ue, pdu, nas.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
}

// imeiFromMsin returns the 15-digit IMEI matching the IMEISV sent in Security Mode
// Complete: the same 14-digit TAC+SNR followed by the Luhn check digit (TS 23.003 6.2.1).
func imeiFromMsin(msin string) string {
	body := imeisvFromMsin(msin)[:14]
	return body + string(rune('0'+luhnCheckDigit(body)))
}

// luhnCheckDigit computes the check digit of TS 23.003 Annex B for the given digits.
func luhnCheckDigit(digits string) uint8 {
	sum := 0
	for i := 0; i < len(digits); i++ {
		d := int(digits[len(digits)-1-i] - '0')
		if i%2 == 0 { // the rightmost payload digit and every second one left of it are doubled
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return uint8((10 - sum%10) % 10)
}

func imeiIdentity(digits string) *ie.MobileId5GS {
	// A 15-digit IMEI always has an odd number of digits, even when the check digit is 0.
	identity := &ie.MobileId5GS{TypeOfId: ie.IdType_5GS_IMEI, OddEvenIndic: ie.OddNumOfIdDigit}
	for i := range identity.IMEI {
		identity.IMEI[i] = digits[i] - '0'
	}
	return identity
}

func imeisvIdentity(digits string) *ie.MobileId5GS {
	identity := &ie.MobileId5GS{TypeOfId: ie.IdType_5GS_IMEISV}
	for i := range identity.IMEISV {
		identity.IMEISV[i] = digits[i] - '0'
	}
	return identity
}
