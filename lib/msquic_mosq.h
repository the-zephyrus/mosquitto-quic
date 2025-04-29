#ifndef MSQUIC_MOSQ_H
#define MSQUIC_MOSQ_H

#ifdef WITH_QUIC
#include "mosquitto_internal.h"
#include "msquic.h"

int msquic_init(const char *appname, QUIC_EXECUTION_PROFILE execution_profile);
void msquic_cleanup(void);

int msquic_setup_client_configuration(struct mosquitto *mosq);
void msquic_close_client_configuration(struct mosquitto *mosq);

int msquic_start_connection(struct mosq_quic_connection *connection, const char *host, uint16_t port, const char *bind_address);
int msquic_shutdown_connection(const struct mosq_quic_connection *connection);

int msquic_send(const struct mosq_quic_stream * stream, const void *buf, uint32_t count, void* client_context);

#endif

#endif