#ifdef WITH_QUIC
#include "msquic_mosq.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "net_mosq.h"
#include "packet_mosq.h"
#include "util_mosq.h"

typedef struct {
    void* original_client_context;
    uint32_t bytes_in_send;       
} msquic_send_context;

static const QUIC_API_TABLE* msquic = NULL;
static HQUIC registration = NULL;

static const char* quic_status_to_string(QUIC_STATUS status)
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

int msquic_init(const char *appname, QUIC_EXECUTION_PROFILE execution_profile)
{
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;

    if (msquic != NULL && registration != NULL) {
        return MOSQ_ERR_SUCCESS;
    }

    if (msquic == NULL) {
        if (QUIC_FAILED(status = MsQuicOpen2(&msquic))) {
            msquic = NULL;
            return MOSQ_ERR_QUIC_API;
        }
    }

    if (registration == NULL) {
         const QUIC_REGISTRATION_CONFIG regconfig = { appname, execution_profile };
         if (QUIC_FAILED(status = msquic->RegistrationOpen(&regconfig, &registration))) {
            registration = NULL;
            MsQuicClose(msquic);
            msquic = NULL;
            return MOSQ_ERR_QUIC_API;
         }
    }
    return MOSQ_ERR_SUCCESS;
}

void msquic_cleanup(void)
{
    if (msquic != NULL) {
        if (registration != NULL) {
            msquic->RegistrationClose(registration);
            registration = NULL;
        }
        MsQuicClose(msquic);
        msquic = NULL;
    }
}

int msquic_setup_client_configuration(struct mosquitto *mosq)
{
    if(!mosq) {
        return MOSQ_ERR_INVAL;
    }
    
    if(!msquic || !registration) {
        return MOSQ_ERR_QUIC_UNINITIALIZED;
    }

    if (mosq->quic_config.handle) {
        return MOSQ_ERR_SUCCESS;
    }

    QUIC_STATUS status = QUIC_STATUS_SUCCESS;

    const char* alpn_name = mosq->quic_config.alpn ? mosq->quic_config.alpn : "mqtt";
    size_t alpn_length = strlen(alpn_name);
    if (alpn_length > UINT32_MAX) {
        log__printf(mosq, MOSQ_LOG_ERR, "QUIC: ALPN string too long");
        return MOSQ_ERR_INVAL;
    }
    const QUIC_BUFFER alpn = {(uint32_t)alpn_length, (uint8_t*)alpn_name};

    QUIC_SETTINGS settings = {0};

    settings.IdleTimeoutMs = 0;
    settings.IsSet.IdleTimeoutMs = TRUE;

    settings.SendBufferingEnabled = mosq->quic_connection_params.use_send_buffering;
    settings.IsSet.SendBufferingEnabled = TRUE;

    settings.PacingEnabled = mosq->quic_connection_params.use_pacing;
    settings.IsSet.PacingEnabled = TRUE;


    if (QUIC_FAILED(status = msquic->ConfigurationOpen(
            registration,
            &alpn,
            1,
            &settings,
            sizeof(settings),
            NULL,
            &mosq->quic_config.handle))) {
        log__printf(mosq, MOSQ_LOG_ERR, "QUIC: ConfigurationOpen failed, status 0x%x - %s", 
            status, quic_status_to_string(status));
        mosq->quic_config.handle = NULL;
        return MOSQ_ERR_QUIC_API;
    }

    QUIC_CREDENTIAL_CONFIG credconfig;
    memset(&credconfig, 0, sizeof(credconfig));
    credconfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    credconfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (!mosq->quic_config.insecure) {
        credconfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        log__printf(mosq, MOSQ_LOG_WARNING, "QUIC: Certificate validation disabled - connection is insecure");
    }
    
    if (QUIC_FAILED(status = msquic->ConfigurationLoadCredential(
            mosq->quic_config.handle,
            &credconfig))) {
        log__printf(mosq, MOSQ_LOG_ERR, "QUIC: ConfigurationLoadCredential failed, status 0x%x - %s", 
            status, quic_status_to_string(status));
        msquic->ConfigurationClose(mosq->quic_config.handle);
        mosq->quic_config.handle = NULL;
        return MOSQ_ERR_QUIC_API;
    }
    return MOSQ_ERR_SUCCESS;
}

void msquic_close_client_configuration(struct mosquitto *mosq)
{
    if (msquic != NULL && mosq != NULL) {
        if (mosq->quic_config.handle) {
            msquic->ConfigurationClose(mosq->quic_config.handle);
            mosq->quic_config.handle = NULL;
        }
    }
}

static void
msquic_stream_on_send_complete(
    struct mosq_quic_stream *stream,
    struct mosquitto__packet *packet
    )
{
    int rc;
    uint32_t bytes_send = packet->to_process;
    packet->pos += bytes_send;
    packet->to_process -= bytes_send;
    stream->bytes_outstanding -= bytes_send ;
    packet__process_sent(stream, packet);
    rc = packet__write(stream->connection->client_ctx);
    if(rc){
        net__loop_wakeup(stream->connection->client_ctx, rc);
    }
}
static void
msquic_stream_on_receive(
    struct mosq_quic_stream *stream, 
    const QUIC_BUFFER* buffers, 
    uint32_t buffer_count
)
{
    const uint8_t* current_buf = NULL;
    uint32_t current_buf_len = 0;
    uint32_t bytes_consumed = 0;
    int rc;

    for (uint32_t i = 0; i < buffer_count; ++i) {
        current_buf = buffers[i].Buffer;
        current_buf_len = buffers[i].Length;

        while (current_buf_len > 0) {
            bytes_consumed = 0;
            rc = packet__read(stream, current_buf, current_buf_len, &bytes_consumed);
            if (rc) {
                net__loop_wakeup(stream->connection->client_ctx, rc);
            }
            current_buf += bytes_consumed;
            current_buf_len -= bytes_consumed;
        }
    }
}

static QUIC_STATUS 
msquic_handle_stream_event(
    struct mosq_quic_stream *stream,
    QUIC_STREAM_EVENT *event
)
{
    switch (event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        struct mosquitto__packet * packet = (struct mosquitto__packet *)event->SEND_COMPLETE.ClientContext;
        msquic_stream_on_send_complete(stream, packet);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        msquic_stream_on_receive(stream, event->RECEIVE.Buffers, event->RECEIVE.BufferCount);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            msquic->StreamClose(stream->handle);
            struct mosq_quic_stream *stream_cleanup = stream;
            stream = NULL;
            mosquitto__free(stream_cleanup);
        }
        break;
    case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:
        struct mosquitto *mosq = stream->connection->client_ctx;
        if (!mosq->quic_connection_params.use_send_buffering && stream->ideal_sendbuffer != event->IDEAL_SEND_BUFFER_SIZE.ByteCount) {
            stream->ideal_sendbuffer = event->IDEAL_SEND_BUFFER_SIZE.ByteCount;
            int rc = packet__write(stream->connection->client_ctx);
            if (rc) {
                net__loop_wakeup(stream->connection->client_ctx, rc);
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
quic_client_stream_callback(
    _In_ HQUIC handle,
    _In_opt_ void* context,
    _Inout_ QUIC_STREAM_EVENT* event
    )
{
    UNUSED(handle);
    struct mosq_quic_stream *stream = (struct mosq_quic_stream *)context;
    log__printf(stream->connection->client_ctx, MOSQ_LOG_DEBUG, "QUIC: Stream event %d", event->Type);
    return msquic_handle_stream_event(stream, event);
}


static int quic_start_new_stream(struct mosq_quic_connection *connection)
{
    if (!connection) {
        return MOSQ_ERR_INVAL;
    }

    if (!msquic) {
        return MOSQ_ERR_QUIC_UNINITIALIZED;
    }

    QUIC_STATUS status;
    struct mosquitto *mosq = connection->client_ctx;
    struct mosq_quic_stream *newstream;

    if (!mosq) {
        return MOSQ_ERR_INVAL;
    }
    if(!connection->handle) {
        return MOSQ_ERR_NO_CONN;
    }


   if (connection->stream == NULL) {
        newstream = mosquitto__calloc(1, sizeof(struct mosq_quic_stream));
        if (!newstream) {
            return MOSQ_ERR_NOMEM;
        }
    }else {
        return MOSQ_ERR_SUCCESS;
    }

    newstream->handle = NULL; 
    newstream->connection = connection;
    newstream->bytes_outstanding = 0;
    newstream->ideal_sendbuffer = PERF_DEFAULT_SEND_BUFFER_SIZE; 


    if (QUIC_FAILED(status = msquic->StreamOpen(
            connection->handle,
            QUIC_STREAM_OPEN_FLAG_NONE,
            quic_client_stream_callback,
            newstream,
            &newstream->handle))) {
        log__printf(mosq, MOSQ_LOG_ERR, "QUIC: StreamOpen failed, 0x%x - %s", status, quic_status_to_string(status));
        mosquitto__free(newstream);
        return MOSQ_ERR_QUIC_API;
    }

    if (QUIC_FAILED(status = msquic->StreamStart(
            newstream->handle,
            QUIC_STREAM_START_FLAG_NONE))) { 
        log__printf(mosq, MOSQ_LOG_ERR, "QUIC: StreamStart failed, 0x%x - %s", status, quic_status_to_string(status));
        msquic->StreamClose(newstream->handle);
        mosquitto__free(newstream);
        return MOSQ_ERR_QUIC_API;
    }

    connection->stream = newstream;
    return MOSQ_ERR_SUCCESS;
}

static QUIC_STATUS 
msquic_handle_connection_event(
    struct mosq_quic_connection *connection,
    QUIC_CONNECTION_EVENT *event
)
{
    struct mosquitto *mosq = connection->client_ctx;
    switch (event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        mosquitto__set_state(mosq, mosq_cs_connected);
        int rc = quic_start_new_stream(connection);
        net__loop_wakeup(mosq, rc);
        log__printf(mosq, MOSQ_LOG_DEBUG, "QUIC: Connection established");
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
    log__printf(mosq, MOSQ_LOG_ERR, "QUIC: Connection shutdown by transport, 0x%x", 
        event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        break;
        
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        if (event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            msquic->ConnectionClose(connection->handle);
            connection->handle = NULL;
        }
        if(event->SHUTDOWN_COMPLETE.HandshakeCompleted) {
            net__loop_wakeup(mosq, MOSQ_ERR_CONN_LOST);
        }else{
            log__printf(mosq, MOSQ_LOG_DEBUG, "QUIC: Connection handshake failed");
            net__loop_wakeup(mosq, MOSQ_ERR_QUIC_HANDSHAKE);
        }
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        uint32_t ticket_len = event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
        uint8_t *new_ticket_data = mosquitto__malloc(ticket_len);

        if (new_ticket_data) {
            memcpy(new_ticket_data,
                   event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket,
                   ticket_len);

            mosq->quic_connection_params.resumption_ticket_data = new_ticket_data;
            mosq->quic_connection_params.resumption_ticket_length = ticket_len;
            mosq->quic_connection_params.use_resumption_ticket = true; // Mark that we have a valid ticket
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
    log__printf(connection->client_ctx, MOSQ_LOG_DEBUG, "QUIC: Connection event %d", event->Type);
    return msquic_handle_connection_event(connection, event);
}

int msquic_start_connection(struct mosq_quic_connection *connection, const char *host, uint16_t port, const char *bind_address)
{
    if(!msquic || !registration) {
        return MOSQ_ERR_QUIC_UNINITIALIZED;
    }

    QUIC_STATUS status;
    struct mosquitto *mosq = connection->client_ctx;
    HQUIC connection_handle = NULL;
    
    if (QUIC_FAILED(status = msquic->ConnectionOpen(
            registration,
            msquic_client_connection_callback,
            connection,
            &connection_handle))) {
        log__printf(mosq, MOSQ_LOG_ERR, "QUIC: ConnectionOpen failed, 0x%x - %s", 
            status, quic_status_to_string(status));
        goto Error;
    }

    if (mosq->quic_connection_params.use_resumption_ticket) {
        if (QUIC_FAILED(status = msquic->SetParam(
                connection_handle,
                QUIC_PARAM_CONN_RESUMPTION_TICKET,
                mosq->quic_connection_params.resumption_ticket_length,
                mosq->quic_connection_params.resumption_ticket_data))) {
        log__printf(mosq, MOSQ_LOG_WARNING, "QUIC: Failed to set resumption ticket, 0x%x - %s", 
            status, quic_status_to_string(status));
        }
    }
    
    
    if(bind_address) {
        QUIC_ADDR localAddr = {0};
        if(QuicAddrFromString(bind_address, 0, &localAddr)) {
            if(QUIC_FAILED(status = msquic->SetParam(
                    connection_handle,
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    sizeof(localAddr),
                    &localAddr))) {
                log__printf(mosq, MOSQ_LOG_WARNING, "QUIC: Unable to set local address, 0x%x - %s", 
                    status, quic_status_to_string(status));
            }
        } else {
            log__printf(mosq, MOSQ_LOG_WARNING, "QUIC: Invalid bind address format: %s", bind_address);
        }
    }

    if(QUIC_FAILED(status = msquic->ConnectionStart(
            connection_handle,
            mosq->quic_config.handle,
            QUIC_ADDRESS_FAMILY_UNSPEC,
            host,
            port))) {
        log__printf(mosq, MOSQ_LOG_ERR, "QUIC: ConnectionStart failed, 0x%x - %s", 
            status, quic_status_to_string(status));
        goto Error;
    }

    connection->handle = connection_handle;

    mosquitto__set_state(mosq, mosq_cs_connect_pending);

    return MOSQ_ERR_SUCCESS;
    
Error:
    if (connection_handle != NULL) {
        msquic->ConnectionClose(connection_handle);
    }
    return MOSQ_ERR_QUIC_API;
}


int msquic_shutdown_connection(const struct mosq_quic_connection *connection)
{
    if(!msquic || !registration) {
        return MOSQ_ERR_QUIC_UNINITIALIZED;
    }

    if(connection->handle) {
        msquic->ConnectionShutdown(
            connection->handle, 
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 
            0);
    }
    return MOSQ_ERR_SUCCESS;
}


int msquic_send(const struct mosq_quic_stream * stream, const void *buf, uint32_t count, void* client_context)
{
    if(!msquic || !registration) {
        return MOSQ_ERR_QUIC_UNINITIALIZED;
    }


    struct mosquitto *mosq = stream->connection->client_ctx;
    
    QUIC_BUFFER quic_buffer;
    quic_buffer.Buffer = (uint8_t*)buf;
    quic_buffer.Length = count;

    QUIC_STATUS status = msquic->StreamSend(
        stream->handle,
        &quic_buffer,              
        1,                 
        QUIC_SEND_FLAG_NONE, 
        client_context       
    );

    if (QUIC_FAILED(status)) {
        log__printf(mosq, MOSQ_LOG_ERR, "QUIC: StreamSend failed, 0x%x - %s",
            status, quic_status_to_string(status));
        return MOSQ_ERR_QUIC_API;
    }

    return MOSQ_ERR_SUCCESS;
}
#endif
