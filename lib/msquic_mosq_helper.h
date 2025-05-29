#ifndef MSQUIC_MOSQ_HELPER_H
#define MSQUIC_MOSQ_HELPER_H

#ifdef WITH_QUIC

#include "msquic.h"

const char* 
quic_status_to_string(
    QUIC_STATUS status
    );

uint32_t
decode_hex_buffer(
    _In_z_ const char* HexBuffer,
    _In_ uint32_t OutBufferLen,
    _Out_writes_to_(OutBufferLen, return)
        uint8_t* OutBuffer
    );

BOOLEAN
convert_arg_to_address(
    _In_z_ const char* Arg,
    _In_ uint16_t Port,
    _Out_ QUIC_ADDR* Address
    );

#endif

#endif