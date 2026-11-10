/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 * © Copyright 2026 Valentin D'Emmanuele
 */
package handler

import (
	"github.com/free5gc/nas/ie"
	nas "github.com/free5gc/nas/message"
	"my5G-RANTester/internal/control_test_engine/ue/context"
	"my5G-RANTester/internal/control_test_engine/ue/nas/message/nas_control"
	"my5G-RANTester/internal/control_test_engine/ue/nas/message/nas_control/mm_5gs"
	"my5G-RANTester/internal/control_test_engine/ue/nas/message/sender"
	"my5G-RANTester/internal/control_test_engine/ue/nas/trigger"
	log "my5G-RANTester/internal/log"
	"net/netip"
)

func HandlerAuthenticationReject(ue *context.UEContext, msg *nas.AuthRej) {
	ue.RegistrationFailed()
	log.Info(ue.LogTag()+"[NAS] Authentication of UE ", ue.GetUeId(), " failed")
	ue.SetStateMM_DEREGISTERED()
}

func HandlerAuthenticationRequest(ue *context.UEContext, msg *nas.AuthReq) {
	if msg.Ngksi == nil || msg.Ngksi.Ksi == ie.NASKeyNA || msg.AuthParamRAND5GAuthChlg == nil || msg.AuthParamAUTN5GAuthChlg == nil || msg.ABBA == nil {
		log.Error(ue.LogTag() + "[NAS] Authentication Request missing mandatory AKA parameters")
		return
	}
	param, result := ue.DeriveRESstarAndSetKey(ue.UeSecurity.AuthenticationSubs, msg.AuthParamRAND5GAuthChlg.Rand, ue.UeSecurity.Snn, msg.AuthParamAUTN5GAuthChlg.Autn)
	var response []byte
	switch result {
	case "MAC failure", "SQN failure":
		response = mm_5gs.AuthenticationFailure(result, "", param)
	case "successful":
		response = mm_5gs.AuthenticationResponse(param, "")
		ue.SetStateMM_REGISTERED_INITIATED()
	default:
		log.Errorf(ue.LogTag()+"[NAS] Authentication failed: %s", result)
		return
	}
	sender.SendToGnb(ue, response)
}

func HandlerSecurityModeCommand(ue *context.UEContext, msg *nas.SecModeCmd) {
	if msg.Ngksi == nil || msg.Ngksi.Ksi == ie.NASKeyNA || msg.SelectedNASSecAlgos == nil || msg.ReplayedUESecCapabilities == nil {
		log.Error(ue.LogTag() + "[NAS] Invalid Security Mode Command")
		return
	}
	ue.UeSecurity.NgKsi = *msg.Ngksi
	rinmr := uint8(0)
	if msg.Additional5GSecInfo != nil && msg.Additional5GSecInfo.RINMR {
		rinmr = 1
	}
	pdu, err := mm_5gs.SecurityModeComplete(ue, rinmr)
	if err != nil {
		log.Errorf(ue.LogTag()+"[NAS] Security Mode Complete: %v", err)
		return
	}
	sender.SendToGnb(ue, pdu)
}

func HandlerRegistrationAccept(ue *context.UEContext, msg *nas.RegAccept) {
	if msg.RegResult5GS == nil || msg.RegResult5GS.Value != ie.RegResult_3gpp {
		log.Error(ue.LogTag() + "[NAS] Registration Accept does not register 3GPP access")
		return
	}
	ue.SetStateMM_REGISTERED()
	if msg.GUTI5G != nil {
		ue.Set5gGuti(msg.GUTI5G)
	} else {
		log.Warn(ue.LogTag() + "[NAS] AMF did not assign a 5G-GUTI")
	}
	if ue.Snssai.Sst == 0 && msg.AllowedNSSAI != nil && len(msg.AllowedNSSAI.SNSSAIs) > 0 {
		allowed := msg.AllowedNSSAI.SNSSAIs[0]
		ue.Snssai.Sst, ue.Snssai.Sd = int32(allowed.SST), allowed.SD
	}
	pdu, err := mm_5gs.RegistrationComplete(ue)
	if err != nil {
		log.Errorf(ue.LogTag()+"[NAS] Registration Complete: %v", err)
		return
	}
	sender.SendToGnb(ue, pdu)
}

func HandlerServiceAccept(ue *context.UEContext, msg *nas.SvcAccept) { ue.SetStateMM_REGISTERED() }

func HandlerDlNasTransportPduaccept(ue *context.UEContext, msg *nas.DLNASTransport) {
	if msg.PayloadCntrType == nil || msg.PayloadCntrType.Value != ie.PayloadCntrType_N1SMInfo || msg.PayloadCntr == nil || msg.PDUSessID == nil {
		log.Error(ue.LogTag() + "[NAS] Invalid DL NAS Transport")
		return
	}
	payload := nas_control.GetNasPduFromPduAccept(msg)
	if payload == nil {
		log.Error(ue.LogTag() + "[NAS] Invalid N1 SM payload")
		return
	}
	switch m := payload.(type) {
	case *nas.PDUSessEstReq:
		// An AMF that cannot forward the establishment request returns it with a
		// 5GMM cause, instead of a 5GSM reject: the attempt failed, and is not retried.
		if session, err := ue.GetPduSession(m.PDUSessId); err == nil && msg.Cause5GMM != nil {
			session.EstablishmentFailed()
		}
	case *nas.PDUSessEstAccept:
		// TS 24.501 §9.11.4.10: an IPv4 address, an IPv6 interface identifier, or both.
		if m.PDUAddr == nil || (len(m.PDUAddr.IPv4) != 4 && len(m.PDUAddr.IPv6IfId) != 8) {
			log.Error(ue.LogTag() + "[NAS] PDU session requires an IPv4 address or an IPv6 interface identifier")
			return
		}
		session, err := ue.GetPduSession(m.PDUSessId)
		if err != nil {
			log.Errorf(ue.LogTag()+"[NAS] Unknown PDU session %d: %v", m.PDUSessId, err)
			return
		}
		if len(m.PDUAddr.IPv4) == 4 {
			var ip [12]uint8
			copy(ip[:], m.PDUAddr.IPv4)
			session.SetIp(ip)
			log.Infof(ue.LogTag()+"[NAS] PDU session %d address: %s", m.PDUSessId, session.GetIp())
		}
		if len(m.PDUAddr.IPv6IfId) == 8 {
			linkLocal := [16]byte{0xfe, 0x80}
			copy(linkLocal[8:], m.PDUAddr.IPv6IfId)
			session.SetIPv6(netip.AddrFrom16(linkLocal))
			log.Infof(ue.LogTag()+"[NAS] PDU session %d IPv6 link-local address: %s", m.PDUSessId, session.GetIPv6())
		}
		session.SetStateSM_PDU_SESSION_ACTIVE()
		if m.DNN != nil {
			log.Infof(ue.LogTag()+"[NAS] PDU session DNN: %s", m.DNN.Value)
		}
		if m.SNSSAI != nil {
			log.Infof(ue.LogTag()+"[NAS] PDU session NSSAI: SST %d, SD %s", m.SNSSAI.SST, m.SNSSAI.SD)
		}
		log.Infof(ue.LogTag()+"[NAS] PDU session QoS rules: %+v", m.AuthoQosRules)
	case *nas.PDUSessRelCmd:
		session, err := ue.GetPduSession(m.PDUSessId)
		if err != nil || session == nil {
			log.Errorf(ue.LogTag()+"[NAS] Unknown PDU session %d", m.PDUSessId)
			return
		}
		ue.DeletePduSession(m.PDUSessId)
		trigger.InitPduSessionReleaseComplete(ue, session)
	case *nas.PDUSessEstRej:
		log.Errorf(ue.LogTag()+"[NAS] PDU session %d rejected: %s", m.PDUSessId, m.Cause5GSM)
		handleEstablishmentReject(ue, m)
	default:
		log.Errorf(ue.LogTag()+"[NAS] Unsupported N1 SM payload: %s", payload.MsgType())
	}
}

// HandlerIdentityRequest answers SUCI, IMEI and IMEISV requests; protected tells whether the
// request arrived under a NAS security context, so the response is protected the same way.
func HandlerIdentityRequest(ue *context.UEContext, msg *nas.IdReq, protected bool) {
	if msg.IdType == nil {
		log.Error(ue.LogTag() + "[NAS] Identity Request without identity type")
		return
	}
	switch msg.IdType.IdType {
	case ie.IdType_5GS_SUCI, ie.IdType_5GS_IMEI, ie.IdType_5GS_IMEISV:
		trigger.InitIdentifyResponse(ue, msg.IdType.IdType, protected)
	default:
		log.Error(ue.LogTag() + "[NAS] Only SUCI, IMEI and IMEISV identity requests are supported, got " + ie.IdType5GSStr(msg.IdType.IdType))
	}
}
func HandlerConfigurationUpdateCommand(ue *context.UEContext, msg *nas.CfgUpdateCmd) {
	trigger.InitConfigurationUpdateComplete(ue)
}
