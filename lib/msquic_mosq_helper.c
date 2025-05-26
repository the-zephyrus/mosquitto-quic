#include "msquic_mosq_helper.h"
#include "msquic.h"
#include "quic_platform.h"

const char* 
quic_status_to_string(QUIC_STATUS status)
{
    switch (status) {
        case QUIC_STATUS_SUCCESS:
            return "The operation completed successfully.";
            
        case QUIC_STATUS_PENDING:
            return "The operation is pending.";
            
        case QUIC_STATUS_CONTINUE:
            return "The operation will continue.";
            
        case QUIC_STATUS_OUT_OF_MEMORY:
            return "Allocation of memory failed.";
            
        case QUIC_STATUS_INVALID_PARAMETER:
            return "An invalid parameter was encountered.";
            
        case QUIC_STATUS_INVALID_STATE:
            return "The current state was not valid for this operation.";
            
        case QUIC_STATUS_NOT_SUPPORTED:
            return "The operation was not supported.";
            
        case QUIC_STATUS_NOT_FOUND:
            return "The object was not found.";
            
        case QUIC_STATUS_BUFFER_TOO_SMALL:
            return "The buffer was too small for the operation.";
            
        case QUIC_STATUS_HANDSHAKE_FAILURE:
            return "The connection handshake failed.";
            
        case QUIC_STATUS_ABORTED:
            return "The connection or stream was aborted.";
            
        case QUIC_STATUS_ADDRESS_IN_USE:
            return "The local address is already in use.";
            
        case QUIC_STATUS_INVALID_ADDRESS:
            return "Binding to socket failed, likely caused by a family mismatch between local and remote address.";
            
        case QUIC_STATUS_CONNECTION_TIMEOUT:
            return "The connection timed out waiting for a response from the peer.";
            
        case QUIC_STATUS_CONNECTION_IDLE:
            return "The connection timed out from inactivity.";
            
        case QUIC_STATUS_INTERNAL_ERROR:
            return "An internal error was encountered.";
            
        case QUIC_STATUS_UNREACHABLE:
            return "The server is currently unreachable.";
            
        case QUIC_STATUS_CONNECTION_REFUSED:
            return "The server refused the connection.";
            
        case QUIC_STATUS_PROTOCOL_ERROR:
            return "A protocol error was encountered.";
            
        case QUIC_STATUS_VER_NEG_ERROR:
            return "A version negotiation error was encountered.";
            
        case QUIC_STATUS_USER_CANCELED:
            return "The peer app/user canceled the connection during the handshake.";
            
        case QUIC_STATUS_ALPN_NEG_FAILURE:
            return "The connection handshake failed to negotiate a common ALPN.";
            
        case QUIC_STATUS_STREAM_LIMIT_REACHED:
            return "A stream failed to start because the peer doesn't allow any more to be open at this time.";
            
        default:
            return "Unknown status code.";
    }
}

static uint8_t 
decode_hex_char(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return 0; // 或者其他错误指示
}

uint32_t
decode_hex_buffer(
    _In_z_ const char* HexBuffer,
    _In_ uint32_t OutBufferLen,
    _Out_writes_to_(OutBufferLen, return)
        uint8_t* OutBuffer
    )
{
    uint32_t HexBufferLen = (uint32_t)strlen(HexBuffer) / 2;
    if (HexBufferLen > OutBufferLen) {
        return 0;
    }

    for (uint32_t i = 0; i < HexBufferLen; i++) {
        OutBuffer[i] =
            (decode_hex_char(HexBuffer[i * 2]) << 4) |
            decode_hex_char(HexBuffer[i * 2 + 1]);
    }

    return HexBufferLen;
}

BOOLEAN
convert_arg_to_address(
    _In_z_ const char* Arg,
    _In_ uint16_t Port,   
    _Out_ QUIC_ADDR* Address
    )
{
    if (strcmp("*", Arg) == 0) {
        CxPlatZeroMemory(Address, sizeof(*Address));
        QuicAddrSetFamily(Address, QUIC_ADDRESS_FAMILY_UNSPEC);
        QuicAddrSetPort(Address, Port);
        return TRUE;
    }
    return QuicAddrFromString(Arg, Port, Address);
}


