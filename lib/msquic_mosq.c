#ifdef WITH_QUIC
#include "msquic_mosq.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "mosquitto_internal.h"
#include "msquic.h"
#include "msquic_mosq_helper.h"
#include "net_mosq.h"
#include "packet_mosq.h"

#include "util_mosq.h"

#define DEFAULT_SEND_BUFFER_SIZE       0x20000 // 128 KiB
const QUIC_API_TABLE* msquic = NULL;
HQUIC registration = NULL;
HQUIC configuration = NULL;

/*=============================================================================
 * MsQuic Library Initialization and Configuration
 *=============================================================================*/

int msquic_init(void)
{
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (msquic == NULL) {
        if (QUIC_FAILED(status = MsQuicOpen2(&msquic))) {
            msquic = NULL;
            return MOSQ_ERR_QUIC_API;
        }
    }
    return MOSQ_ERR_SUCCESS;
}

void msquic_cleanup(void)
{
    if (msquic != NULL) {
        if (configuration != NULL) {
            msquic->ConfigurationClose(configuration);
            configuration = NULL;
        }
        if (registration != NULL) {
            msquic->RegistrationClose(registration);
            registration = NULL;
        }
        MsQuicClose(msquic);
        msquic = NULL;
    }
}

int msquic_init_client(struct mosquitto *mosq)
{
    if(!msquic) {
        return MOSQ_ERR_QUIC_NOT_INIT;
    }

    QUIC_STATUS status = QUIC_STATUS_SUCCESS;

    if (registration == NULL) {
        const char* app_name = mosq->quic_app_name ? mosq->quic_app_name : "mosquitto-quic-client";
        
        const QUIC_REGISTRATION_CONFIG reg_config = { app_name, mosq->quic_execution_profile };
        
        if (QUIC_FAILED(status = msquic->RegistrationOpen(
            &reg_config, 
            &registration))) {
            log__printf(mosq, MOSQ_LOG_ERR, "Client %s RegistrationOpen failed [QUIC] (0x%x - %s)",
                            SAFE_PRINT(mosq->id), status, quic_status_to_string(status));
            return MOSQ_ERR_QUIC_API;
        }
    }

    if(configuration == NULL){
        const char* alpn_name = mosq->quic_alpn ? mosq->quic_alpn : "mqtt";
        const QUIC_BUFFER alpn = { 
            (uint32_t)strlen(alpn_name), 
            (uint8_t*)alpn_name 
        };

        QUIC_SETTINGS settings = {0};
        
        settings.IdleTimeoutMs = 0;
        settings.IsSet.IdleTimeoutMs = TRUE;
        settings.SendBufferingEnabled = mosq->quic_use_send_buffering != 0;
        settings.IsSet.SendBufferingEnabled = TRUE;

        if (QUIC_FAILED(status = msquic->ConfigurationOpen(
                registration,
                &alpn,
                1,
                &settings,
                sizeof(settings),
                NULL,
                &configuration))) {
            log__printf(mosq, MOSQ_LOG_ERR, "Client %s ConfigurationOpen failed [QUIC] (0x%x - %s)",
                            SAFE_PRINT(mosq->id), status, quic_status_to_string(status));
            return MOSQ_ERR_QUIC_API;
        }

        QUIC_CREDENTIAL_CONFIG credconfig = {0};
        credconfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
        credconfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;

        if (!mosq->quic_insecure) {
            credconfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
            log__printf(mosq, MOSQ_LOG_WARNING, "Client %s Certificate validation disabled [QUIC]",
                SAFE_PRINT(mosq->id));
        }
        
        if (QUIC_FAILED(status = msquic->ConfigurationLoadCredential(
                configuration,
                &credconfig))) {
            log__printf(mosq, MOSQ_LOG_ERR, "Client %s ConfigurationLoadCredential failed [QUIC] (0x%x - %s)",
                            SAFE_PRINT(mosq->id), status, quic_status_to_string(status));
            return MOSQ_ERR_QUIC_API;
        }
    }
    return MOSQ_ERR_SUCCESS;
}

/*=============================================================================
 * MsQuic Stream Management and Event Handling
 *=============================================================================*/

static QUIC_STATUS 
msquic_handle_stream_event(
    struct mosquitto *mosq,
    struct mosq_quic_stream *stream,
    QUIC_STREAM_EVENT *event
)
{
    switch (event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        struct mosquitto__packet * packet = (struct mosquitto__packet *)event->SEND_COMPLETE.ClientContext;
        uint32_t bytes_send = packet->to_process;
        packet->pos += bytes_send;
        packet->to_process -= bytes_send;
        stream->bytes_outstanding -= bytes_send ;
        packet__process_send(mosq, packet);
        int rc = packet__write_quic_stream(mosq, stream);
        if(rc){
            net__wakeup_loop(mosq, rc);
        }
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        const uint8_t* current_buf = NULL;
        uint32_t current_buf_len = 0;
        uint32_t bytes_consumed = 0;
        for (uint32_t i = 0; i < event->RECEIVE.BufferCount; ++i) {
            current_buf = event->RECEIVE.Buffers[i].Buffer;
            current_buf_len = event->RECEIVE.Buffers[i].Length;
            while (current_buf_len > 0) {
                bytes_consumed = 0;
                int rc = packet__read_quic(mosq, current_buf, current_buf_len, &bytes_consumed);
                if (rc) {
                    net__wakeup_loop(mosq, rc);
                }
                current_buf += bytes_consumed;
                current_buf_len -= bytes_consumed;
            }
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            CxPlatListEntryRemove(&stream->list_entry);
            msquic->StreamClose(stream->handle);
            mosquitto__free(stream);
        }
        break;
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
        struct mosquitto *mosq = stream->connection->mosq;
        if (!mosq->quic_use_send_buffering && stream->ideal_sendbuffer != event->IDEAL_SEND_BUFFER_SIZE.ByteCount) {
            stream->ideal_sendbuffer = event->IDEAL_SEND_BUFFER_SIZE.ByteCount;
            int rc = packet__write_quic_stream(mosq, stream);
            if (rc) {
                net__wakeup_loop(mosq, rc);
            }
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
msquic_client_stream_callback(
    _In_ HQUIC handle,
    _In_opt_ void* context,
    _Inout_ QUIC_STREAM_EVENT* event
    )
{
    UNUSED(handle);
    struct mosq_quic_stream *stream = (struct mosq_quic_stream *)context;
    struct mosquitto *mosq = stream->connection->mosq;
    return msquic_handle_stream_event(mosq, stream, event);
}

static int msquic_start_new_stream(struct mosq_quic_connection *connection)
{
    if (!connection) {
        return MOSQ_ERR_INVAL;
    }

    if (!msquic) {
        return MOSQ_ERR_QUIC_NOT_INIT;
    }

    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    struct mosquitto *mosq = connection->mosq;

    struct mosq_quic_stream *newstream;
    newstream = mosquitto__calloc(1, sizeof(struct mosq_quic_stream));
    if (!newstream) {
        return MOSQ_ERR_NOMEM;
    }

    newstream->handle = NULL; 
    newstream->connection = connection;
    newstream->bytes_outstanding = 0;
    newstream->ideal_sendbuffer = mosq->quic_use_send_buffering ? 
                                  1 : DEFAULT_SEND_BUFFER_SIZE;

    if (QUIC_FAILED(status = msquic->StreamOpen(
            connection->handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            msquic_client_stream_callback,
            newstream,
            &newstream->handle))) {
        log__printf(mosq, MOSQ_LOG_ERR, "Client %s StreamOpen failed [QUIC] (0x%x - %s)",
            SAFE_PRINT(mosq->id),status,quic_status_to_string(status));
        goto cleanup_stream;
    }

    if (QUIC_FAILED(status = msquic->StreamStart(
            newstream->handle,
            QUIC_STREAM_START_FLAG_NONE))) { 
        log__printf(mosq, MOSQ_LOG_ERR, "Client %s StreamStart failed [QUIC] (0x%x - %s)",
            SAFE_PRINT(mosq->id),status,quic_status_to_string(status));
        goto cleanup_stream;
    }

    CxPlatListInsertTail(&connection->stream_list_head, &newstream->list_entry);
    return MOSQ_ERR_SUCCESS;

cleanup_stream:
    if(newstream->handle) {
        msquic->StreamClose(newstream->handle);
    }
    mosquitto__free(newstream);
    return MOSQ_ERR_QUIC_API;
}

int msquic_send(const struct mosq_quic_stream *stream, const void *buf, uint32_t count, void* client_context)
{
    if(!msquic) {
        return MOSQ_ERR_QUIC_NOT_INIT;
    }
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    struct mosquitto *mosq = stream->connection->mosq;
    QUIC_BUFFER quic_buffer;
    quic_buffer.Buffer = (uint8_t*)buf;
    quic_buffer.Length = count;

    if(QUIC_FAILED(status = msquic->StreamSend(
            stream->handle,
            &quic_buffer,
            1,
            QUIC_SEND_FLAG_NONE,
            client_context))) {
        log__printf(mosq, MOSQ_LOG_ERR, "Client %s StreamSend failed [QUIC] (0x%x - %s)",
            SAFE_PRINT(mosq->id), status, quic_status_to_string(status));
        return MOSQ_ERR_QUIC_API;
    }
    return MOSQ_ERR_SUCCESS;
}

/*=============================================================================
 * MsQuic Connection Management and Event Handling
 *=============================================================================*/
static QUIC_STATUS 
msquic_handle_connection_event(
    struct mosquitto *mosq,
    struct mosq_quic_connection *connection,
    QUIC_CONNECTION_EVENT *event
)
{
    switch (event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        int rc = 0;
        for (int i = 0; i < mosq->quic_stream_count; ++i) {
            rc = msquic_start_new_stream(connection);
            if(rc){ 
                break;
            }
        }
        if(!rc){
            mosquitto__set_state(mosq, mosq_cs_connected);
        }
        net__wakeup_loop(mosq, rc);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        QUIC_STATUS status = event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
        log__printf(mosq, MOSQ_LOG_ERR, "Client %s Connection shutdown by transport [QUIC] (0x%x - %s)",
            SAFE_PRINT(mosq->id), status, quic_status_to_string(status));
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        if(!event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            msquic->ConnectionClose(connection->handle);
            connection->handle = NULL;
        }
        if(event->SHUTDOWN_COMPLETE.HandshakeCompleted) {
            log__printf(mosq, MOSQ_LOG_INFO, "Client %s Connection shutdown complete [QUIC]",
                SAFE_PRINT(mosq->id));
        }else{
            log__printf(mosq, MOSQ_LOG_ERR, "Client %s Handshake failed [QUIC]",
                SAFE_PRINT(mosq->id));
        }
        net__wakeup_loop(mosq, MOSQ_ERR_QUIC_CONNECTION_SHUTDOWN);
        break;

    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        uint32_t ticket_length = event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
        const uint8_t* ticket_data = event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket;
        mosquitto__free(mosq->quic_resumption_ticket);
        mosq->quic_resumption_ticket = (QUIC_BUFFER*)mosquitto__malloc(sizeof(QUIC_BUFFER) + ticket_length);
        if(mosq->quic_resumption_ticket) {
            mosq->quic_resumption_ticket->Buffer = (uint8_t*)(mosq->quic_resumption_ticket + 1);
            mosq->quic_resumption_ticket->Length = ticket_length;
            memcpy(mosq->quic_resumption_ticket->Buffer, ticket_data, ticket_length);
        }else{
            log__printf(mosq, MOSQ_LOG_ERR, "Client %s Failed to allocate memory for resumption ticket [QUIC]",
                SAFE_PRINT(mosq->id));
            net__wakeup_loop(mosq, MOSQ_ERR_NOMEM);
        }
        break;
    default:
        break;
    }
    
    return QUIC_STATUS_SUCCESS;
}
 
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
msquic_client_connection_callback(
    _In_ HQUIC handle,
    _In_opt_ void* context,
    _Inout_ QUIC_CONNECTION_EVENT* event
)
{
    UNUSED(handle);
    struct mosq_quic_connection *connection = (struct mosq_quic_connection *)context;
    struct mosquitto *mosq = connection->mosq;
    return msquic_handle_connection_event(mosq, connection, event);
}

int msquic_start_connection(struct mosq_quic_connection *connection, const char *host, uint16_t port, const char *bind_address)
{
    if(!msquic) {
        return MOSQ_ERR_QUIC_NOT_INIT;
    }

    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    struct mosquitto *mosq = connection->mosq;
    HQUIC connection_handle = NULL;
    
    if(QUIC_FAILED(status = msquic->ConnectionOpen(
            registration,
            msquic_client_connection_callback,
            connection,
            &connection_handle))) {
        log__printf(mosq, MOSQ_LOG_ERR, "Client %s ConnectionOpen failed [QUIC] (0x%x - %s)",
            SAFE_PRINT(mosq->id), status, quic_status_to_string(status));
        goto Error;
    }

    if(bind_address) {
        QUIC_ADDR local_addr = {0};
        if(!convert_arg_to_address(bind_address, 0, &local_addr)){
            log__printf(mosq, MOSQ_LOG_WARNING, "Client %s Invalid bind address format [QUIC] (%s)",
                SAFE_PRINT(mosq->id), bind_address);
        }else{
            BOOLEAN share_enabled = TRUE;
            if (QUIC_FAILED(status = msquic->SetParam(
                    connection_handle,
                    QUIC_PARAM_CONN_SHARE_UDP_BINDING,
                    sizeof(share_enabled),
                    &share_enabled))) {
                log__printf(mosq, MOSQ_LOG_ERR, "Client %s SetParam failed [QUIC] (0x%x - %s)",
                    SAFE_PRINT(mosq->id), status, quic_status_to_string(status));
                goto Error;
            }
            if (QUIC_FAILED(status = msquic->SetParam(
                    connection_handle,
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    sizeof(local_addr),
                    &local_addr))) {
                log__printf(mosq, MOSQ_LOG_ERR, "Client %s SetParam failed [QUIC] (0x%x - %s)",
                    SAFE_PRINT(mosq->id), status, quic_status_to_string(status));
                goto Error;
            }
        }
    }

    if(mosq->quic_resumption_ticket) {
        if(QUIC_FAILED(status = msquic->SetParam(
                connection_handle,
                QUIC_PARAM_CONN_RESUMPTION_TICKET,
                mosq->quic_resumption_ticket->Length,
                mosq->quic_resumption_ticket->Buffer))) {
            log__printf(mosq, MOSQ_LOG_WARNING, "Client %s Failed to set resumption ticket [QUIC] (0x%x - %s)",
                SAFE_PRINT(mosq->id), status, quic_status_to_string(status));
        }
    }

    if(QUIC_FAILED(status = msquic->ConnectionStart(
            connection_handle,
            configuration,
            QUIC_ADDRESS_FAMILY_UNSPEC,
            host,
            port))) {
        log__printf(mosq, MOSQ_LOG_ERR, "Client %s ConnectionStart failed [QUIC] (0x%x - %s)",
                    SAFE_PRINT(mosq->id), status, quic_status_to_string(status));
        goto Error;
    }

    connection->handle = connection_handle;

    return MOSQ_ERR_SUCCESS;

Error:
    if(connection_handle != NULL) {
        msquic->ConnectionClose(connection_handle);
    }
    return MOSQ_ERR_QUIC_API;
}

int msquic_shutdown_connection(const struct mosq_quic_connection *connection)
{
    if(!msquic) {
        return MOSQ_ERR_QUIC_NOT_INIT;
    }

    if(connection->handle) {
        msquic->ConnectionShutdown(
            connection->handle, 
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 
            0);
    }
    return MOSQ_ERR_SUCCESS;
}
#endif
