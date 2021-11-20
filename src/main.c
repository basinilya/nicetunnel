/**
 * @file main.c
 * @brief Program file containing the main() function and functions not covered by cc-compiled unit tests.
 */

#include "nicetunnel.h"

#include <gio/gnetworking.h>
#include <gio/gsocketclient.h>

#ifndef G_OS_WIN32
#include <glib-unix.h>
#include <signal.h>
#endif

#include <locale.h>
#include <stdlib.h> /* for EXIT_FAILURE */
#include <unistd.h> /* for usleep */

#define D64 G_GINT64_FORMAT

static gchar *stun_addr = NULL;

static GOptionEntry entries[] = { //
		{ "bind-sdp", 'b', 0, G_OPTION_ARG_STRING, &my_control_addr, "Local Signaling Address to listen for commands",
		NULL }, //
		{ "connect-sdp", 'c', 0, G_OPTION_ARG_STRING, &my_control_peer,
			"Remote Peer Signaling Address to send commands",
			NULL }, //
		{ "bind-udp", 'B', 0, G_OPTION_ARG_STRING, &my_bind_addr, "Local Datagram Bind Address",
		NULL }, //
		{ "peer-udp", 'P', 0, G_OPTION_ARG_STRING, &my_peer_addr, "Datagram Peer Address",
		NULL }, //
		{ "stun-addr", 's', 0, G_OPTION_ARG_STRING, &stun_addr, "Stun server address and port", NULL }, //
		{ NULL } };

static int suicide_signal = 0;

#ifndef G_OS_WIN32
static gboolean my_signal_handler(gpointer user_data) {
	my_print("signal\n");
	suicide_signal = SIGINT;
	g_main_loop_quit(my_gloop);
	return FALSE;
}
#endif

int main(int argc, char *argv[]) {

	int res = EXIT_FAILURE;

	GSocket *gsocket = NULL;
	GError *_error = NULL;
	GError **err = &_error;
	GOptionContext *context = NULL;
	GThread *clientthread = NULL;
	GSocketService *service = NULL;
	GObjectClass *socketClientClass = NULL;

	// this is supposed to add thousand separator to printf %d;
	// works when LANG is en_US.UTF-8
	setlocale(LC_NUMERIC, "");

	g_log_set_writer_func(my_log_writer, NULL, NULL);

	/* initialize glib */
#ifndef GLIB_VERSION_2_36
	  g_type_init ();
#endif

	g_networking_init();

	g_info("Nice Tunnel is starting at %'" D64 "...", g_get_monotonic_time());

#ifdef USE_MSAN
	// libproxy is written in c++ and we don't have instrumented libstdc++
	socketClientClass = g_type_class_ref(G_TYPE_SOCKET_CLIENT);
	GParamSpec *pspec = g_object_class_find_property(socketClientClass, "enable-proxy");
	G_PARAM_SPEC_BOOLEAN(pspec)->default_value = FALSE;
#endif

	context = g_option_context_new(" - Create a tunnel between two peers");
	g_option_context_add_main_entries(context, entries, NULL);
	if (!g_option_context_parse(context, &argc, &argv, &_error)) {
		my_printerr("option parsing failed: %s\n", _error->message);
		goto done;
	}
	if (my_control_peer && my_control_addr) {
		my_printerr("Both local and remote addr cannot be used at the same time\n");
		goto done;
	}
	my_is_client = !!my_control_peer;

	if (!my_is_client) {
		if (my_bind_addr) {
			my_printerr("bind-addr is meaningless in server mode\n");
			goto done;
		}
	}

	if (!my_control_peer && !my_control_addr) {
		my_control_addr = g_strdup("[::]:1500");
	}

	if (stun_addr) {
		if (!(my_stun_connectable = (GNetworkAddress*) g_network_address_parse(stun_addr, 3478, err))) {
			my_printerr("Failed to parse STUN address: %s\n", _error->message);
			goto done;
		}
	}

	my_gloop = g_main_loop_new(NULL, FALSE);

#ifndef G_OS_WIN32
	g_unix_signal_add(SIGINT, my_signal_handler, NULL);
#endif

	my_cancellable = g_cancellable_new();

	if (my_is_client) {
		gsocket = my_udp_socket_bind(my_bind_addr, my_peer_addr, err);
		if (!gsocket) {
			my_printerr("Bind failed: %s\n", _error->message);
			goto done;
		}

		clientthread = g_thread_new("client thread", (GThreadFunc) my_client_thread, gsocket);
	} else {
		service = my_nice_server_start(&_error);
		if (!service) {
			my_printerr("Nice Server start failed: %s\n", _error->message);
			goto done;
		}
	}

	g_main_loop_run(my_gloop);
	my_is_exiting = TRUE;
	g_cancellable_cancel(my_cancellable);

	my_print("exiting\n");

	res = EXIT_SUCCESS;
	done:

	g_clear_object(&service);
	usleep(200000);
	if (clientthread) {
		g_info("Joining clientthread...");
		g_clear_pointer(&clientthread, g_thread_join);
	}
	g_clear_object(&my_cancellable);
	g_clear_object(&gsocket);
	g_clear_pointer(&my_gloop, g_main_loop_unref);
	g_clear_object(&my_stun_connectable);
	g_clear_pointer(&stun_addr, g_free);
	g_clear_pointer(&my_control_addr, g_free);
	g_clear_pointer(&context, g_option_context_free);
	g_clear_pointer(&socketClientClass, g_type_class_unref);
	g_clear_error(&_error);
	if (suicide_signal != 0) {
		res = EXIT_FAILURE;
		// kill(getpid(), suicide_signal);
	}
	return res;
}
