/**
 * @file libnicetunnel.c
 * @brief Program file that is supposed to contain functions covered by cc-compiled unit tests.
 */
#include "nicetunnel.h"
#include <agent.h>
#include <gio/gnetworking.h>
#include <stdlib.h> /* for abort(3) */
#include <stddef.h> /* for offsetof */

#define OK my_goto_if_fail
#define OK2 my_goto_if_fail2
#define FA my_abort_if_fail

#define MILLION (1000*1000L)

#define TUNNEL_BUFSIZE (2*MILLION)

#define DATAGRAM_TTL_USEC (2 * MILLION)

#define D64 G_GINT64_FORMAT
#define DZ G_GSSIZE_FORMAT
#define UZ G_GSIZE_FORMAT

const char my_log_domain[] = "nicetunnel";

const char my_log_domain_debug[] = "nicetunnel-d";

GCancellable *my_cancellable = NULL;

gboolean my_is_exiting = FALSE;

GMainLoop *my_gloop;

GNetworkAddress *my_stun_connectable = NULL;

gboolean my_is_client;

gchar *my_bind_addr = NULL;

gchar *my_peer_addr = NULL;

gchar *my_control_addr = NULL;

gchar *my_control_peer = NULL;

gint my_timeout_sec = 120;

static const gchar *state_name[] = { "disconnected", "gathering", "connecting", "connected", "ready", "failed" };

static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, my_nice_t *data);
static void cb_component_state_changed(NiceAgent *agent, guint stream_id, guint component_id, guint state,
		my_nice_t *data);
static void cb_nice_recv(NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer _data);

static void my_append_sockaddr(gchar *buf, gsize sz, GInetSocketAddress *sa) {
	GInetAddress *tmp_host_struct = g_inet_socket_address_get_address(sa);
	guint16 port;
	port = g_inet_socket_address_get_port(sa);
	gchar *host;

	host = g_inet_address_to_string(tmp_host_struct);
	/* Disambiguate ports from IPv6 addresses using square brackets. */
	const gchar *fmt = g_inet_address_get_family(tmp_host_struct) == G_SOCKET_FAMILY_IPV6 ? "[%s]:%u" : "%s:%u";
	size_t len = strlen(buf);
	g_snprintf(buf + len, sz - len, fmt, host, port);
	g_clear_pointer(&host, g_free);
}

static GInetSocketAddress* my_get_ipv4_addr(GSocketAddressEnumerator *enumerator, GError **err) {
	gboolean x = FALSE;
	GSocketAddress *sockaddr;
	for (;;) {
		sockaddr = g_socket_address_enumerator_next(enumerator, NULL, err);
		if (!sockaddr) {
			if (x) {
				g_set_error(err, MY_CUSTOM_ERROR, 0, "Not found any ipv4 addresses");
			}
			return NULL;
		}
		x = TRUE;
		if (G_SOCKET_FAMILY_IPV4 == g_socket_address_get_family(sockaddr)) {
			return G_INET_SOCKET_ADDRESS(sockaddr);
		}
		g_object_unref(sockaddr);
	}
	g_assert_not_reached();
	abort(); // make CDT happy
}

static gint64 _my_advance_deadline(my_nice_t *data, gint64 now_usec) {
	data->deadline_usec = now_usec + (my_timeout_sec * MILLION);
	my_debug("Will expire at: %'" D64, data->deadline_usec);
	return data->deadline_usec;
}

gint64 my_advance_deadline(my_nice_t *data, gint64 now_usec) {
	g_mutex_lock(&data->mutex);
	gint64 deadline_usec = _my_advance_deadline(data, now_usec);
	g_mutex_unlock(&data->mutex);
	return deadline_usec;
}

// !!!
// in server mode we want to validate remote candidates string before sending local candidate
// in client mode we want to send local candidates before receiving remote candidates
// in client mode the string parameter will be NULL
gboolean my_nice_negotiate(my_nice_t *data, gchar *remote_sdp_early, GError **err) {
	gboolean res = FALSE;

	gchar *remote_sdp_late = NULL;
	NiceAgent *agent = NULL;
	GInetSocketAddress *stun_sockaddr = NULL;
	GSocketAddressEnumerator *enumerator = NULL;
	gchar *local_sdp = NULL;

	guint stream_id;

	if (my_stun_connectable) {
		enumerator = g_socket_connectable_enumerate((GSocketConnectable*) my_stun_connectable);
		OK(stun_sockaddr = my_get_ipv4_addr(enumerator, err));
	}

	agent = nice_agent_new(g_main_loop_get_context(my_gloop), NICE_COMPATIBILITY_RFC5245);

	if (stun_sockaddr) {
		guint stun_port;
		stun_port = g_inet_socket_address_get_port(stun_sockaddr);
		GInetAddress *tmp_stun_addr;
		tmp_stun_addr = g_inet_socket_address_get_address(stun_sockaddr);
		gchar *stun_addr = g_inet_address_to_string(tmp_stun_addr);
		g_object_set(agent, "stun-server", stun_addr, NULL);
		g_clear_pointer(&stun_addr, g_free);
		g_object_set(agent, "stun-server-port", stun_port, NULL);
	}

	g_object_set(agent, "controlling-mode", my_is_client, NULL);

	g_signal_connect(agent, "candidate-gathering-done", G_CALLBACK(cb_candidate_gathering_done), data);
	g_signal_connect(agent, "component-state-changed", G_CALLBACK(cb_component_state_changed), data);

	// Create a new stream with one component
	FA(0 != (stream_id = nice_agent_add_stream(agent, 1)));
	data->stream_id = stream_id;

	FA(nice_agent_set_stream_name (agent, stream_id, "text"));

	// Attach to the component to receive the data
	// Without this call, candidates cannot be gathered
	FA(nice_agent_attach_recv(agent, stream_id, 1, g_main_loop_get_context (my_gloop), cb_nice_recv, data));

	// Start gathering local candidates
	FA(nice_agent_gather_candidates(agent, stream_id));

	g_mutex_lock(&data->mutex);
	while (!data->candidate_gathering_done) {
		g_info("Waiting for candidate_gathering_done");
		g_cond_wait(&data->cond, &data->mutex);
	}
	g_mutex_unlock(&data->mutex);

	if (my_is_exiting) {
		g_set_error(err, MY_CUSTOM_ERROR, 0, "Cancelled");
		goto done;
	}

	// Candidate gathering is done. Send our local candidates

	local_sdp = nice_agent_generate_local_sdp(agent);

	if (remote_sdp_early) {
		OK(0 <= nice_agent_parse_remote_sdp (agent, remote_sdp_early));
	}

	my_print("Generated SDP from agent :\n%s\n\n", local_sdp);
	OK(my_send_string(data->control_conn, local_sdp, err));

	if (!remote_sdp_early) {
		OK(remote_sdp_late = my_read_bstr(data->control_conn, err));
		OK(0 <= nice_agent_parse_remote_sdp (agent, remote_sdp_late));
	}
	data->agent = agent;
	agent = NULL;
	res = TRUE;
	done:
	g_clear_pointer(&remote_sdp_late, g_free);
	g_clear_pointer(&local_sdp, g_free);
	g_clear_object(&stun_sockaddr);
	g_clear_object(&enumerator);
	g_clear_object(&agent);
	return res;
}

static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, my_nice_t *data) {
	g_info("SIGNAL candidate gathering done");

	g_mutex_lock(&data->mutex);
	data->candidate_gathering_done = TRUE;
	g_cond_signal(&data->cond);
	g_mutex_unlock(&data->mutex);
}

static void cb_component_state_changed(NiceAgent *agent, guint stream_id, guint component_id, guint state,
		my_nice_t *data) {
	g_info("SIGNAL: state changed %d %d %s[%d]", stream_id, component_id, state_name[state], state);

	if (state >= NICE_COMPONENT_STATE_READY) {
		g_mutex_lock(&data->mutex);
		data->negotiate_outcome = state;
		g_cond_signal(&data->cond);
		g_mutex_unlock(&data->mutex);
	}
}

static void cb_nice_recv(NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer _data) {
	my_nice_t *data = _data;

	GError *_error = NULL;
	GError **err = &_error;

	gssize bytes_sent;

	my_debug("From Nice received: %'u bytes", len);
	my_advance_deadline(data, g_get_monotonic_time());
	bytes_sent = g_socket_send_to(data->gsocket, G_SOCKET_ADDRESS(data->peer_sa), buf, len, my_cancellable, err);
	if (bytes_sent == -1) {
		if (!(*err)) {
			g_set_error_literal(err, MY_CUSTOM_ERROR, 0, "The library did not provide failure details");
		}
		my_printerr("g_socket_send_to() failed: %s\n", _error->message);
		g_clear_error(err);
	}
}

#define MAX_BSTR_SIZE (1024*1024)

GQuark my_custom_error_quark() {
	return g_quark_from_static_string("g-custom-error-quark");
}

static GSocketAddress* my_parse_host_and_port(const gchar *host_and_port, gboolean allow_zero_port, GError **err) {
	GSocketAddress *sockaddr = NULL;

	GNetworkAddress *connectable = NULL;
	GSocketAddressEnumerator *enumerator = NULL;

	OK(connectable = (GNetworkAddress* )g_network_address_parse(host_and_port, 0, err));

	if (!allow_zero_port) {
		guint16 port;
		OK2(0 != (port = g_network_address_get_port(connectable)), "a non-zero port was not specified in: %s", host_and_port);
	}

	enumerator = g_socket_connectable_enumerate((GSocketConnectable*) connectable);

	OK(sockaddr = g_socket_address_enumerator_next(enumerator, NULL, err));
	done:
	g_clear_object(&enumerator);
	g_clear_object(&connectable);
	return sockaddr;
}

gchar* my_read_bstr(GSocketConnection *connection, GError **err) {
	gsize bytes_read;

	GInputStream *istream = g_io_stream_get_input_stream(G_IO_STREAM(connection));

	guint32 bstrlen;

	g_return_val_if_fail(g_input_stream_read_all(istream, &bstrlen, 4, &bytes_read, my_cancellable, err), (NULL));
	g_return_val_if_fail(4 == bytes_read, (g_set_error(err, MY_CUSTOM_ERROR, 0, "message truncated"),NULL));

	bstrlen = g_ntohl(bstrlen);
	g_return_val_if_fail(bstrlen <= MAX_BSTR_SIZE,
			(g_set_error(err, MY_CUSTOM_ERROR, 0, "message too big: %u", bstrlen), NULL));

	gchar *res = (gchar*) g_malloc(bstrlen + 1);

	g_return_val_if_fail(g_input_stream_read_all(istream, res, bstrlen, &bytes_read, my_cancellable, err),
			(g_free(res), NULL));
	g_return_val_if_fail(bytes_read == bstrlen,
			(g_set_error(err, MY_CUSTOM_ERROR, 0, "message truncated: bytes_read:%" UZ ",bstrlen:%d", bytes_read,bstrlen),g_free(res), NULL));

	res[bstrlen] = '\0';

	done:

	return res;
}

my_nice_t* my_nice_t_new(gint64 now_usec, GSocket *gsocket) {
	my_nice_t *res = g_malloc0(sizeof(my_nice_t));
	g_mutex_init(&res->mutex);
	g_cond_init(&res->cond);
	g_queue_init(&res->payload_queue);
	_my_advance_deadline(res, now_usec);
	res->gsocket = gsocket;
	return res;
}

void my_nice_t_free(my_nice_t *data) {
	g_mutex_lock(&data->mutex);
	data->candidate_gathering_done = TRUE;
	if (NICE_COMPONENT_STATE_FAILED != data->negotiate_outcome) {
		data->negotiate_outcome = data->negotiate_outcome == NICE_COMPONENT_STATE_LAST;
	}
	g_cond_signal(&data->cond);
	g_mutex_unlock(&data->mutex);
	if (data->nice_send_thread) {
		g_info("Waiting for Nice Send Thread");
		g_clear_pointer(&data->nice_send_thread, g_thread_join);
	}
	g_clear_object(&data->agent);

	g_mutex_clear(&data->mutex);
	g_cond_clear(&data->cond);

	// owned by client main or server accept handler
	//g_clear_object(&data->gsocket);
	// owned by server accept handler or client connect thread
	//g_clear_object(&data->control_conn);
	g_queue_clear_full(&data->payload_queue, g_free);
	g_clear_object(&data->peer_sa);
	g_free(data);
	g_info("Freed");
}

gboolean my_graceful_close(GSocketConnection *connection, GError **err) {
	gboolean res = FALSE;
	GIOStream *io_stream = G_IO_STREAM(connection);
	OK(g_output_stream_close(g_io_stream_get_output_stream(io_stream), my_cancellable, err));
	GSocket *tmp_gsocket = g_socket_connection_get_socket(connection);
	OK(g_socket_shutdown(tmp_gsocket, FALSE, TRUE, err));
	tmp_gsocket = NULL;

	gchar c;
	gssize sz;
	OK(-1 != (sz = g_input_stream_read(g_io_stream_get_input_stream(G_IO_STREAM(connection)), &c, 1, my_cancellable, err)));
	if (0 != sz) {
		g_set_error(err, MY_CUSTOM_ERROR, 0, "Unexpected extra byte on control socket: %02x", (c & 0xFF));
		goto done;
	}
	OK(g_io_stream_close(io_stream, NULL, err));
	res = TRUE;
	done:

	return res;
}

// their nice_ equivalents not exported in .so for some reason
static const gchar*
my_candidate_type_to_string(NiceCandidateType type) {
	switch (type) {
	case NICE_CANDIDATE_TYPE_HOST:
		return "host";
	case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
		return "srflx";
	case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
		return "prflx";
	case NICE_CANDIDATE_TYPE_RELAYED:
		return "relay";
	default:
		g_assert_not_reached();
		abort(); // make CDT happy
	}
}

static const gchar*
my_candidate_transport_to_string(NiceCandidateTransport transport) {
	switch (transport) {
	case NICE_CANDIDATE_TRANSPORT_UDP:
		return "udp";
	case NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
		return "tcp-act";
	case NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
		return "tcp-pass";
	case NICE_CANDIDATE_TRANSPORT_TCP_SO:
		return "tcp-so";
	default:
		g_assert_not_reached();
		abort(); // make CDT happy
	}
}

static void my_niceaddr_tostring(gchar *buf, gsize bufsz, NiceAddress *nicea) {
	GSocketAddress *gsockaddr = NULL;
	if (bufsz <= 0) {
		return;
	}
	buf[0] = '\0';
	if (nicea && nicea->s.addr.sa_family != AF_UNSPEC
			&& NULL != (gsockaddr = g_socket_address_new_from_native(&nicea->s, sizeof(nicea->s)))) {
		my_append_sockaddr(buf, bufsz, G_INET_SOCKET_ADDRESS(gsockaddr));
	} else {
		g_snprintf(buf, bufsz, "(null)");
	}
	g_clear_object(&gsockaddr);
}

static
void my_print_candidate(const char *prefix, NiceCandidate *candidate) {

	gchar addr_str[100];
	gchar base_addr_str[100];
	my_niceaddr_tostring(addr_str, sizeof(addr_str), &candidate->addr);
	my_niceaddr_tostring(base_addr_str, sizeof(base_addr_str), &candidate->base_addr);
	my_print("%s: %s %s %s (public: %s)\n", prefix, my_candidate_type_to_string(candidate->type),
			my_candidate_transport_to_string(candidate->transport), base_addr_str, addr_str);
}

// like nice_agent_send, but allows distinguishing EWOULDBLOCK
static gint my_agent_send(NiceAgent *agent, guint stream_id, guint component_id, guint len, const gchar *buf,
		GError **error) {
	GOutputVector local_buf = { buf, len };
	NiceOutputMessage local_message = { &local_buf, 1 };
	gint n_sent_bytes;

	g_return_val_if_fail(NICE_IS_AGENT (agent), -1);
	g_return_val_if_fail(stream_id >= 1, -1);
	g_return_val_if_fail(component_id >= 1, -1);
	g_return_val_if_fail(buf != NULL, -1);

	n_sent_bytes = nice_agent_send_messages_nonblocking(agent, stream_id, component_id, &local_message, 1, NULL, error);

	return n_sent_bytes;
}

static gboolean my_nice_send_loop(my_nice_t *data, GError **err) {
	gboolean res = FALSE;

	my_datagram_t *datagram = NULL;

	guint negotiate_outcome;
	gint64 now;
	gint bytes_sent = -1;

	g_mutex_lock(&data->mutex);
	for (;;) {
		negotiate_outcome = data->negotiate_outcome;
		if (negotiate_outcome >= NICE_COMPONENT_STATE_READY) {
			break;
		}
		g_info("Waiting for Negotiation Outcome");
		g_cond_wait(&data->cond, &data->mutex);
	}
	g_mutex_unlock(&data->mutex);

	if (negotiate_outcome >= NICE_COMPONENT_STATE_FAILED) {
		g_set_error(err, MY_CUSTOM_ERROR, 0, "Negotiation failed");
		goto done;
	}

	NiceCandidate *local, *remote;
	if (nice_agent_get_selected_pair(data->agent, data->stream_id, 1, &local, &remote)) {
		my_print_candidate("Selected Local  Candidate", local);
		my_print_candidate("Selected Remote Candidate", remote);
	}

	for (;;) {
		g_mutex_lock(&data->mutex);
		now = g_get_monotonic_time();
		if (bytes_sent >= 0) {
			_my_advance_deadline(data, now);
		}
		for (;;) {
			negotiate_outcome = data->negotiate_outcome;
			if (NICE_COMPONENT_STATE_READY != negotiate_outcome) {
				break;
			}
			while (NULL != (datagram = g_queue_pop_head(&data->payload_queue))) {
				data->payload_total -= datagram->size;
				if (now - datagram->expiry_usec < 0) {
					goto waited_enough;
				}
				g_info("Discarding an expired datagram");
				g_free(datagram);
			}
			my_debug("Waiting for Datagrams...");
			g_cond_wait(&data->cond, &data->mutex);
			now = g_get_monotonic_time();
		}
		waited_enough: g_mutex_unlock(&data->mutex);

		if (NICE_COMPONENT_STATE_READY != negotiate_outcome) {
			break;
		}

		GError *send_error = NULL;
		bytes_sent = my_agent_send(data->agent, data->stream_id, 1, datagram->size, datagram->buf, &send_error);
		g_clear_pointer(&datagram, g_free);
		if (bytes_sent < 0) {
			if (!send_error) {
				g_set_error(&send_error, MY_CUSTOM_ERROR, 0, "Unknown Error");
			} else if (send_error->domain == G_IO_ERROR && send_error->code == G_IO_ERROR_WOULD_BLOCK) {
				g_info("Nice Agent Send failed with: %s", send_error->message);
				g_clear_error(&send_error);
				continue;
			}

			g_warning("Nice Agent Send failed with: %s", send_error->message);
			g_clear_error(&send_error);
		}

	}

	if (NICE_COMPONENT_STATE_LAST == negotiate_outcome) {
		res = TRUE;
	} else {
		g_set_error(err, MY_CUSTOM_ERROR, 0, "Nice communication failed");
	}
	done:
	g_clear_pointer(&datagram, g_free);

	// nice_agent_close_async(data->agent, callback, callback_data);

	return res;
}

static void* nice_send_thread(gpointer param) {
	my_nice_t *data = param;

	GError *_error = NULL;
	GError **err = &_error;

	if (!my_nice_send_loop(data, err)) {
		my_printerr("Nice Send loop failed: %s\n", _error->message);
		goto done;
	}
	done:

	g_clear_error(&_error);
	return NULL;
}

static gboolean accept_tcp_callback(GThreadedSocketService *service, GSocketConnection *connection,
		GObject *source_object, gpointer user_data) {
	GError *_error = NULL;
	GError **err = &_error;

	gchar *remote_sdp = NULL;
	my_nice_t *data = NULL;
	GSocket *gsocket = NULL;
	GHashTable *tunnels_by_peer = NULL;

	GSocketAddress *sa = NULL;
	OK(sa = g_socket_connection_get_remote_address(connection, err));

	gchar buf[100] = "";
	my_append_sockaddr(buf, sizeof(buf), G_INET_SOCKET_ADDRESS(sa));
	my_print("Reading a command from: %s\n", buf);

	GSocket *tmp_gsocket = g_socket_connection_get_socket(connection);
	g_socket_set_timeout(tmp_gsocket, my_timeout_sec);
	tmp_gsocket = NULL;

	remote_sdp = my_read_bstr(connection, &_error);
	if (!remote_sdp) {
		my_printerr("my_read_bstr failed: %s\n", _error->message);
		g_clear_error(&_error);
		if (!g_io_stream_close((GIOStream*) connection, NULL, &_error)) {
			my_printerr("g_io_stream_close failed: %s\n", _error->message);
			g_clear_error(&_error);
		}
		goto done;
	}
	my_print("message: %s\n", remote_sdp);

	gsocket = my_udp_socket_bind(my_bind_addr, my_peer_addr, &_error);
	if (!gsocket) {
		my_printerr("bind failed: %s\n", _error->message);
		goto done;
	}
	data = my_nice_t_new(g_get_monotonic_time(), gsocket);
	data->control_conn = connection;
	data->peer_sa = G_INET_SOCKET_ADDRESS(g_socket_get_remote_address(gsocket, NULL));

	if (!my_nice_negotiate(data, remote_sdp, &_error)) {
		my_printerr("bind failed: %s\n", _error->message);
		goto done;
	}

	// flush and shutdown
	if (!my_graceful_close(connection, err)) {
		my_printerr("Graceful shutdown failed: %s\n", _error->message);
		goto done;
	}

	gchar thread_name[100] = "Sendto ";
	my_append_sockaddr(thread_name, sizeof(thread_name), data->peer_sa);
	g_info("Starting thread: %s", thread_name);
	data->nice_send_thread = g_thread_new(g_strdup(thread_name), nice_send_thread, data);

	tunnels_by_peer = my_tunnels_by_peer_new();
	// TODO: what if peer_sa NULL?
	g_hash_table_insert(tunnels_by_peer, data->peer_sa, data);
	data = NULL; // now owned by hashtable

	OK(my_recv_loop(gsocket, tunnels_by_peer, err));

	done: if (_error) {
		my_printerr("%s\n", _error->message);
		g_clear_error(&_error);
	}

	g_clear_object(&gsocket);
	g_clear_pointer(&tunnels_by_peer, g_hash_table_destroy);
	g_clear_pointer(&data, my_nice_t_free);
	g_clear_pointer(&remote_sdp, g_free);
	g_clear_object(&sa);
	return TRUE;
}

GSocketConnection* my_messenger_connect(GError **err) {
	GSocketConnection *connection = NULL;
	GSocketClient *client = NULL;
	if (!my_control_peer) {
		g_error("Control peer was not configured!");
	}
	client = g_socket_client_new();
	OK(connection = g_socket_client_connect_to_host(client, my_control_peer, 0, NULL, err));

	GSocket *tmp_gsocket = g_socket_connection_get_socket(connection);
	g_socket_set_timeout(tmp_gsocket, my_timeout_sec);
	tmp_gsocket = NULL;

	done:
	g_clear_object(&client);
	return connection;
}

gboolean my_send_string(GSocketConnection *connection, const gchar *str, GError **err) {
	gboolean res = FALSE;
	GOutputStream *ostream = g_io_stream_get_output_stream(G_IO_STREAM(connection));
	guint32 len = strlen(str);
	guint32 len2 = g_htonl(len);
	OK(-1 != g_output_stream_write(ostream, &len2, 4, NULL, err));
	OK(-1 != g_output_stream_write(ostream, str, len, NULL, err));
	OK(g_output_stream_flush(ostream, NULL, err));
	res = TRUE;
	done: return res;
}

GSocket* my_udp_socket_bind(const gchar *bind_addr, const gchar *peer_addr, GError **err) {
	GSocket *res = NULL;

	GSocket *gsocket = NULL;
	GSocketAddress *bind_sockaddr = NULL;
	GSocketAddress *peer_sockaddr = NULL;
	gboolean implicit_bind = FALSE;

	GSocketFamily family = G_SOCKET_FAMILY_IPV4;

	if (!bind_addr && !peer_addr) {
		implicit_bind = TRUE;
		bind_addr = "localhost:0";
	}

	if (bind_addr) {
		OK(bind_sockaddr = my_parse_host_and_port(bind_addr, TRUE, err));
		family = g_socket_address_get_family(bind_sockaddr);
	}

	if (peer_addr) {
		OK(peer_sockaddr = my_parse_host_and_port(peer_addr, FALSE, err));
		family = g_socket_address_get_family(peer_sockaddr);
	}

	OK(gsocket = g_socket_new(family, G_SOCKET_TYPE_DATAGRAM, G_SOCKET_PROTOCOL_UDP, err));

	g_socket_set_timeout(gsocket, my_timeout_sec);

	if (bind_sockaddr) {
		OK(g_socket_bind(gsocket, bind_sockaddr, TRUE, err));
	}

	if (peer_sockaddr) {
		OK(g_socket_connect(gsocket, peer_sockaddr, NULL, err));
	}

	res = gsocket;
	gsocket = NULL;

	done:
	g_clear_object(&gsocket);
	g_clear_object(&bind_sockaddr);
	g_clear_object(&peer_sockaddr);

	return res;
}

GSocketService* my_nice_server_start(GError **err) {

	GSocketService *res = NULL;

	GSocketAddress *sockaddr = NULL;
	GSocketService *service = NULL;

	OK(sockaddr = my_parse_host_and_port(my_control_addr, TRUE, err));

	service = g_threaded_socket_service_new(10);

	OK(g_socket_listener_add_address((GSocketListener*) service, sockaddr, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, NULL, NULL, err));

	g_signal_connect(service, "run", G_CALLBACK (accept_tcp_callback), NULL);

	/* start the socket service */
	g_socket_service_start(service);

	gchar buf[100] = "";
	my_append_sockaddr(buf, sizeof(buf), G_INET_SOCKET_ADDRESS(sockaddr));
	my_print("Waiting for commands on TCP address: %s\n", buf);
	res = service;
	service = NULL;
	done:
	g_clear_object(&service);
	g_clear_object(&sockaddr);

	return res;
}

void* my_client_thread(GSocket *gsocket) {
	GError *_error = NULL;
	GError **err = &_error;

	GHashTable *tunnels_by_peer = NULL;

	tunnels_by_peer = my_tunnels_by_peer_new();
	OK(my_recv_loop(gsocket, tunnels_by_peer, err));
	done:

	if (_error) {
		my_printerr("%s\n", _error->message);
		g_clear_error(&_error);
	}

	g_clear_pointer(&tunnels_by_peer, g_hash_table_destroy);
	g_main_loop_quit(my_gloop);
	return NULL;
}

/* See glib/gbytes.c */
#define MY_HASH_SEED 5381
guint my_bytes_hash(gconstpointer data, gsize size, guint32 h) {
	const signed char *p, *e;
	for (p = (signed char*) data, e = (signed char*) data + size; p != e; p++) {
		h = (h << 5) + h + *p;
	}
	return h;
}

guint my_inet_socket_address_hash(gconstpointer _sa) {
	if (!_sa) {
		return 0;
	}
	GInetSocketAddress *sa = (void*) _sa;
	guint16 port;
	port = g_inet_socket_address_get_port(sa);
	GInetAddress *tmp_host_struct = g_inet_socket_address_get_address(sa);
	gsize sz = g_inet_address_get_native_size(tmp_host_struct);
	const guint8 *bytes = g_inet_address_to_bytes(tmp_host_struct);
	return my_bytes_hash(&port, sizeof(port), my_bytes_hash(bytes, sz, MY_HASH_SEED));
}

gboolean my_inet_socket_address_equal(gconstpointer _sa1, gconstpointer _sa2) {
	if (_sa1 == _sa2) {
		return TRUE;
	}
	if (!_sa1) {
		return FALSE;
	}
	GInetSocketAddress *sa1 = (void*) _sa1;
	GInetSocketAddress *sa2 = (void*) _sa2;
	return g_inet_socket_address_get_port(sa1) == g_inet_socket_address_get_port(sa2)
			&& g_inet_address_equal(g_inet_socket_address_get_address(sa1), g_inet_socket_address_get_address(sa2));
}

static void* connect_thread(gpointer param) {
	my_nice_t *data = param;

	GError *_error = NULL;
	GError **err = &_error;

	data->control_conn = my_messenger_connect(err);
	if (!data->control_conn) {
		my_printerr("connect failed: %s\n", _error->message);
		goto done;
	}
	if (!my_nice_negotiate(data, NULL, err)) {
		my_printerr("negotiation failed: %s\n", _error->message);
		goto done;
	}
	if (!my_graceful_close(data->control_conn, err)) {
		my_printerr("Graceful shutdown failed: %s\n", _error->message);
		goto done;
	}
	if (!my_nice_send_loop(data, err)) {
		my_printerr("Nice Send loop failed: %s\n", _error->message);
		goto done;
	}
	done:

	if (!data->agent) {
		g_mutex_lock(&data->mutex);
		data->negotiate_outcome = NICE_COMPONENT_STATE_FAILED;
		g_cond_signal(&data->cond);
		g_mutex_unlock(&data->mutex);
	}
	g_clear_object(&data->control_conn);
	g_clear_error(&_error);
	return NULL;
}

static my_datagram_t* my_datagram_realloc(my_datagram_t *datagram, gsize new_size) {
	datagram = g_realloc(datagram, new_size + offsetof(my_datagram_t, buf));
	datagram->size = new_size;
	return datagram;
}

static my_datagram_t* my_datagram_new() {
	// hope that's enough for the huge loopback datagrams
	return my_datagram_realloc(NULL, 60000);
}

typedef struct {
	gint64 now;
	gint64 nearest_deadline;
} tunnels_GHRFunc_param;

static void set_nearest_deadline(tunnels_GHRFunc_param *param, gint64 candidate_deadline) {
	if (candidate_deadline - param->nearest_deadline < 0) {
		param->nearest_deadline = candidate_deadline;
	}
}

static gboolean tunnels_GHRFunc(gpointer key, gpointer _value, gpointer user_data) {
	tunnels_GHRFunc_param *param = user_data;
	my_nice_t *data = _value;

	g_mutex_lock(&data->mutex);
	guint negotiate_outcome = data->negotiate_outcome;
	gint64 deadline = data->deadline_usec;
	g_mutex_unlock(&data->mutex);

	if (negotiate_outcome >= NICE_COMPONENT_STATE_FAILED) {
		my_printerr("Negotiation failed in spawned thread; removing...\n");
	} else if (param->now - deadline >= 0) {
		g_info("Expired at: %'" D64, param->now);
		my_printerr("Tunnel expired; removing...\n");
	} else {
		set_nearest_deadline(param, deadline);
		return FALSE;
	}
	g_clear_pointer(&data, my_nice_t_free);
	return TRUE;
}

static gboolean tunnels_cleanup_func(gpointer _key, gpointer _value, gpointer user_data) {
	my_nice_t *data = _value;
	my_nice_t_free(data);
	return TRUE;
}

GHashTable* my_tunnels_by_peer_new() {
	return g_hash_table_new(my_inet_socket_address_hash, my_inet_socket_address_equal);
}

static gboolean print_local_addr(GSocket *gsocket, GError **err) {
	gboolean res = FALSE;
	GSocketAddress *sa = NULL;
	OK(sa = g_socket_get_local_address(gsocket, err));
	gchar buf[100] = "";
	my_append_sockaddr(buf, sizeof(buf), G_INET_SOCKET_ADDRESS(sa));
	my_print("Waiting for datagrams on address: %s\n", buf);
	res = TRUE;
	done:
	g_clear_object(&sa);
	return res;
}

gboolean my_recv_loop(GSocket *gsocket, GHashTable *tunnels_by_peer, GError **err) {
	gboolean res = FALSE;

	GError *_error = NULL;
	my_datagram_t *datagram = NULL;
	GSocketAddress *_sa = NULL;
	gssize bytes_received;

	tunnels_GHRFunc_param param;

	if (!err) {
		err = &_error;
	}

	OK(print_local_addr(gsocket, err));
	param.now = g_get_monotonic_time();
	// in case hashtable not empty
	param.nearest_deadline = param.now;

	for (; !my_is_exiting;) {
		if (!my_is_client && 0 == g_hash_table_size(tunnels_by_peer)) {
			g_info("Current UDP socket no longer has peers");
			break;
		}
		if (param.now - param.nearest_deadline >= 0) {
			param.nearest_deadline = param.now + G_MAXINT64;
			g_hash_table_foreach_remove(tunnels_by_peer, tunnels_GHRFunc, &param);
		}

		if (!datagram) {
			// previous failed recv may have left an allocated datagram
			datagram = my_datagram_new();
		}
		bytes_received = g_socket_receive_from(gsocket, &_sa, datagram->buf, datagram->size, my_cancellable, err);
		if (bytes_received == -1) {
			if (!(*err)) {
				g_set_error_literal(err, MY_CUSTOM_ERROR, 0, "The library did not provide failure details");
			}
			my_printerr("g_socket_receive_from() failed: %s\n", (*err)->message);
			if ((*err)->domain == G_IO_ERROR && (*err)->code == G_IO_ERROR_TIMED_OUT) {
				my_printerr("socket read timeout\n");
			}
			g_clear_error(err);
		} else {
			my_debug("From UDP peer received: %'" DZ " bytes", bytes_received);
			my_nice_t *data;
			data = g_hash_table_lookup(tunnels_by_peer, _sa);
			param.now = g_get_monotonic_time();
			if (!data && my_is_client) {
				data = my_nice_t_new(param.now, gsocket);
				set_nearest_deadline(&param, data->deadline_usec);
				data->peer_sa = G_INET_SOCKET_ADDRESS(_sa);
				_sa = NULL;
				gchar thread_name[100] = "Sendto ";
				my_append_sockaddr(thread_name, sizeof(thread_name), data->peer_sa);
				g_info("Starting thread: %s", thread_name);
				data->nice_send_thread = g_thread_new(g_strdup(thread_name), connect_thread, data);
				g_hash_table_insert(tunnels_by_peer, data->peer_sa, data);
			}

			if (data) {
				datagram = my_datagram_realloc(datagram, bytes_received);
				datagram->expiry_usec = param.now + DATAGRAM_TTL_USEC;

				// keep only sz latest payload
				g_mutex_lock(&data->mutex);
				data->payload_total += datagram->size;
				for (my_datagram_t *victim;
						data->payload_total > TUNNEL_BUFSIZE
								&& NULL != (victim = g_queue_pop_head(&data->payload_queue));) {
					g_info("Buffer full; discarding previous datagram");
					data->payload_total -= victim->size;
					g_free(victim);
				}
				g_queue_push_tail(&data->payload_queue, datagram);
				datagram = NULL;
				g_cond_signal(&data->cond);
				g_mutex_unlock(&data->mutex);

			} else {
				g_clear_pointer(&data, g_free);
			}

			g_clear_object(&_sa);
		}
		param.now = g_get_monotonic_time();
	}
	res = TRUE;
	done:

	g_hash_table_foreach_remove(tunnels_by_peer, tunnels_cleanup_func, NULL);
	g_clear_pointer(&datagram, g_free);
	g_clear_error(&_error);
	return res;
}

