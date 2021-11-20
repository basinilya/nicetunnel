#pragma once

extern const char my_log_domain[];
#define G_LOG_DOMAIN my_log_domain

extern const char my_log_domain_debug[];
#define MY_LOG_DOMAIN_DEBUG my_log_domain_debug

#define my_debug(...)    g_log_structured_standard (MY_LOG_DOMAIN_DEBUG, G_LOG_LEVEL_DEBUG, \
                                                   __FILE__, G_STRINGIFY (__LINE__), \
                                                   G_STRFUNC, __VA_ARGS__)

#define G_LOG_USE_STRUCTURED 1

#include <glib.h>
#include <gio/gio.h>
#include <agent.h>

#define my_abort_if_fail(expr) \
  G_STMT_START { \
    if (G_LIKELY (expr)) \
      { } \
    else \
      { \
        g_error ("%s", #expr); \
        goto done; \
      } \
  } G_STMT_END

#define my_goto_if_fail(expr) \
  G_STMT_START { \
    if (G_LIKELY (expr)) \
      { } \
    else \
      { \
        g_warning ("%s", #expr); \
        goto done; \
      } \
  } G_STMT_END

#define my_goto_if_fail2(expr, ...) \
  G_STMT_START { \
    if (G_LIKELY (expr)) \
      { } \
    else \
      { \
        g_warning ("%s", #expr); \
        g_set_error(err, MY_CUSTOM_ERROR, 0, __VA_ARGS__); \
        goto done; \
      } \
  } G_STMT_END

// like g_print, but in debug mode also prints the regular g_debug line with a timestamp
#define my_print( ...) \
  G_STMT_START { \
      { \
        g_info(":"); \
        g_print (__VA_ARGS__); \
      } \
  } G_STMT_END

#define my_printerr(...) \
  G_STMT_START { \
      { \
        g_info(":"); \
        g_printerr (__VA_ARGS__); \
      } \
  } G_STMT_END

typedef struct _my_datagram my_datagram_t;

struct _my_datagram {
	gint64 expiry_usec;
	gsize size;
	gchar buf[];
};

typedef struct _my_nice {
	gboolean candidate_gathering_done;
	guint negotiate_outcome;
	GMutex mutex;
	GCond cond;
	GSocket *gsocket;
	GSocketConnection *control_conn;
	gint64 deadline_usec;

	GQueue payload_queue;
	gsize payload_total;

	NiceAgent *agent;
	gint stream_id;
	GInetSocketAddress *peer_sa;
	GThread *nice_send_thread;
} my_nice_t;

extern 	GCancellable *my_cancellable;

extern gboolean my_is_exiting;

extern gint my_timeout_sec;

extern gchar *my_bind_addr;

extern gchar *my_peer_addr;

void my_force_use_journal();

GLogWriterOutput
my_log_writer(GLogLevelFlags   log_level,
                      const GLogField *fields,
                      gsize            n_fields,
                      gpointer         user_data);

gint64 my_advance_deadline(my_nice_t *data, gint64 now_usec);

GHashTable* my_tunnels_by_peer_new();

my_nice_t *my_nice_t_new(gint64 now_usec, GSocket *gsocket);

void my_nice_t_free(my_nice_t *data);

gboolean my_recv_loop(GSocket *gsocket, GHashTable *tunnels_by_peer, GError **err);

gboolean my_send_string(GSocketConnection *control_conn, const gchar *str, GError **err) G_GNUC_WARN_UNUSED_RESULT;

GSocketConnection *my_messenger_connect(GError **err) G_GNUC_WARN_UNUSED_RESULT;

gboolean my_graceful_close(GSocketConnection *connection, GError **err);

extern GMainLoop *my_gloop;

extern GNetworkAddress *my_stun_connectable;

extern gchar *my_control_addr;

extern gchar *my_control_peer;

extern gboolean my_is_client;

GQuark my_custom_error_quark();

#define MY_CUSTOM_ERROR my_custom_error_quark()

void* my_client_thread(GSocket *gsocket);

gchar* my_read_bstr(GSocketConnection *control_conn, GError **err);

GSocketService *my_nice_server_start(GError **err);

gboolean my_nice_negotiate(my_nice_t *data, gchar *remote_sdp_early, GError **err);

GSocket * my_udp_socket_bind(const gchar *bind_addr, const gchar *peer_addr, GError **err);

