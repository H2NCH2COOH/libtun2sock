#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#define PROTO_HOPOPT 0
#define PROTO_ICMP 1
#define PROTO_IGMP 2
#define PROTO_GGP 3
#define PROTO_IPv4 4
#define PROTO_ST 5
#define PROTO_TCP 6
#define PROTO_CBT 7
#define PROTO_EGP 8
#define PROTO_IGP 9
#define PROTO_BBN_RCC_MON 10
#define PROTO_NVP_II 11
#define PROTO_PUP 12
#define PROTO_EMCON 14
#define PROTO_XNET 15
#define PROTO_CHAOS 16
#define PROTO_UDP 17
#define PROTO_MUX 18
#define PROTO_DCN_MEAS 19
#define PROTO_HMP 20
#define PROTO_PRM 21
#define PROTO_XNS_IDP 22
#define PROTO_TRUNK_1 23
#define PROTO_TRUNK_2 24
#define PROTO_LEAF_1 25
#define PROTO_LEAF_2 26
#define PROTO_RDP 27
#define PROTO_IRTP 28
#define PROTO_ISO_TP4 29
#define PROTO_NETBLT 30
#define PROTO_MFE_NSP 31
#define PROTO_MERIT_INP 32
#define PROTO_DCCP 33
#define PROTO_3PC 34
#define PROTO_IDPR 35
#define PROTO_XTP 36
#define PROTO_DDP 37
#define PROTO_IDPR_CMTP 38
#define PROTO_TP_Plus_Plus 39
#define PROTO_IL 40
#define PROTO_IPv6 41
#define PROTO_SDRP 42
#define PROTO_IPv6_Route 43
#define PROTO_IPv6_Frag 44
#define PROTO_IDRP 45
#define PROTO_RSVP 46
#define PROTO_GRE 47
#define PROTO_DSR 48
#define PROTO_BNA 49
#define PROTO_ESP 50
#define PROTO_AH 51
#define PROTO_I_NLSP 52
#define PROTO_NARP 54
#define PROTO_MOBILE 55
#define PROTO_TLSP 56
#define PROTO_SKIP 57
#define PROTO_IPv6_ICMP 58
#define PROTO_IPv6_NoNxt 59
#define PROTO_IPv6_Opts 60
#define PROTO_CFTP 62
#define PROTO_SAT_EXPAK 64
#define PROTO_KRYPTOLAN 65
#define PROTO_RVD 66
#define PROTO_IPPC 67
#define PROTO_SAT_MON 69
#define PROTO_VISA 70
#define PROTO_IPCV 71
#define PROTO_CPNX 72
#define PROTO_CPHB 73
#define PROTO_WSN 74
#define PROTO_PVP 75
#define PROTO_BR_SAT_MON 76
#define PROTO_SUN_ND 77
#define PROTO_WB_MON 78
#define PROTO_WB_EXPAK 79
#define PROTO_ISO_IP 80
#define PROTO_VMTP 81
#define PROTO_SECURE_VMTP 82
#define PROTO_VINES 83
#define PROTO_TTP 84
#define PROTO_IPTM 84
#define PROTO_NSFNET_IGP 85
#define PROTO_DGP 86
#define PROTO_TCF 87
#define PROTO_EIGRP 88
#define PROTO_OSPFIGP 89
#define PROTO_Sprite_RPC 90
#define PROTO_LARP 91
#define PROTO_MTP 92
#define PROTO_AX_25 93
#define PROTO_IPIP 94
#define PROTO_SCC_SP 96
#define PROTO_ETHERIP 97
#define PROTO_ENCAP 98
#define PROTO_GMTP 100
#define PROTO_IFMP 101
#define PROTO_PNNI 102
#define PROTO_PIM 103
#define PROTO_ARIS 104
#define PROTO_SCPS 105
#define PROTO_QNX 106
#define PROTO_A_or_N 107
#define PROTO_IPComp 108
#define PROTO_SNP 109
#define PROTO_Compaq_Peer 110
#define PROTO_IPX_in_IP 111
#define PROTO_VRRP 112
#define PROTO_PGM 113
#define PROTO_L2TP 115
#define PROTO_DDX 116
#define PROTO_IATP 117
#define PROTO_STP 118
#define PROTO_SRP 119
#define PROTO_UTI 120
#define PROTO_SMP 121
#define PROTO_PTP 123
#define PROTO_ISIS_over_IPv4 124
#define PROTO_FIRE 125
#define PROTO_CRTP 126
#define PROTO_CRUDP 127
#define PROTO_SSCOPMCE 128
#define PROTO_IPLT 129
#define PROTO_SPS 130
#define PROTO_PIPE 131
#define PROTO_SCTP 132
#define PROTO_FC 133
#define PROTO_RSVP_E2E_IGNORE 134
#define PROTO_Mobility_Header 135
#define PROTO_UDPLite 136
#define PROTO_MPLS_in_IP 137
#define PROTO_manet 138
#define PROTO_HIP 139
#define PROTO_Shim6 140
#define PROTO_WESP 141
#define PROTO_ROHC 142
#define PROTO_Experimentation_and_Testing_1 253
#define PROTO_Experimentation_and_Testing_2 254
#define PROTO_Reserved 255

static inline int proto_is_ipv6_hdr_ext(int proto)
{
    switch(proto)
    {
        case PROTO_HOPOPT:
        case PROTO_IPv6_Route:
        case PROTO_IPv6_Frag:
        case PROTO_ESP:
        case PROTO_AH:
        case PROTO_IPv6_Opts:
        case PROTO_Mobility_Header:
        case PROTO_HIP:
        case PROTO_Shim6:
        case PROTO_Experimentation_and_Testing_1:
        case PROTO_Experimentation_and_Testing_2:
            return 1;
        default:
            return 0;
    }
}

#endif /* _PROTOCOL_H_ */
