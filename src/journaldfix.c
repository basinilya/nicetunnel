#include "nicetunnel.h"
#include <glib/gmessages.h>
#include <stdio.h>
#include <sys/types.h>

#ifndef G_OS_WIN32
#include <sys/socket.h>
#include <sys/un.h>
#endif

#define DEFAULT_LEVELS (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING | G_LOG_LEVEL_MESSAGE)
#define INFO_LEVELS (G_LOG_LEVEL_INFO | G_LOG_LEVEL_DEBUG)

static gsize my_use_journal_initialized = 0;

static gboolean my_use_journal = FALSE;

#ifdef G_OS_WIN32
static gchar  fatal_msg_buf[1000] = "Unspecified fatal error encountered, aborting.";
#endif

void my_force_use_journal() {
	  if (g_once_init_enter (&my_use_journal_initialized))
	    {
	      my_use_journal = TRUE;
	      g_once_init_leave (&my_use_journal_initialized, TRUE);
	    }

}

static void
_g_log_abort (gboolean breakpoint)
{
  gboolean debugger_present;

  if (g_test_subprocess ())
    {
      /* If this is a test case subprocess then it probably caused
       * this error message on purpose, so just exit() rather than
       * abort()ing, to avoid triggering any system crash-reporting
       * daemon.
       */
      _exit (1);
    }

#ifdef G_OS_WIN32
  debugger_present = IsDebuggerPresent ();
#else
  /* Assume GDB is attached. */
  debugger_present = TRUE;
#endif /* !G_OS_WIN32 */

  if (debugger_present && breakpoint)
    G_BREAKPOINT ();
  else
    g_abort ();
}

static gboolean
should_drop_message (GLogLevelFlags   log_level,
                     const char      *log_domain,
                     const GLogField *fields,
                     gsize            n_fields)
{
  /* Disable debug message output unless specified in G_MESSAGES_DEBUG. */
  if (!(log_level & DEFAULT_LEVELS) && !(log_level >> G_LOG_LEVEL_USER_SHIFT))
    {
      const gchar *domains;
      gsize i;

      domains = g_getenv ("G_MESSAGES_DEBUG");

      if ((log_level & INFO_LEVELS) == 0 ||
          domains == NULL)
        return TRUE;

      if (log_domain == NULL)
        {
          for (i = 0; i < n_fields; i++)
            {
              if (g_strcmp0 (fields[i].key, "GLIB_DOMAIN") == 0)
                {
                  log_domain = fields[i].value;
                  break;
                }
            }
        }

      if (strcmp (domains, "all") != 0 &&
          (log_domain == NULL || !strstr (domains, log_domain)))
        return TRUE;
    }

  return FALSE;
}

static
gboolean
my_log_writer_is_journald (gint output_fd)
{
#if defined(__linux__) && !defined(__BIONIC__)
  /* FIXME: Use the new journal API for detecting whether we’re writing to the
   * journal. See: https://github.com/systemd/systemd/issues/2473
   */
  union {
    struct sockaddr_storage storage;
    struct sockaddr sa;
    struct sockaddr_un un;
  } addr;
  socklen_t addr_len;
  int err;

  if (output_fd < 0)
    return FALSE;

  addr_len = sizeof(addr);
  err = getpeername (output_fd, &addr.sa, &addr_len);
  if (err == 0 && addr.storage.ss_family == AF_UNIX)
    return g_str_has_prefix (addr.un.sun_path, "/run/systemd/journal");
#endif

  return FALSE;
}


GLogWriterOutput
my_log_writer(GLogLevelFlags   log_level,
                      const GLogField *fields,
                      gsize            n_fields,
                      gpointer         user_data)
{
  g_return_val_if_fail (fields != NULL, G_LOG_WRITER_UNHANDLED);
  g_return_val_if_fail (n_fields > 0, G_LOG_WRITER_UNHANDLED);

  if (should_drop_message (log_level, NULL, fields, n_fields))
    return G_LOG_WRITER_HANDLED;

#if 0
  /* Mark messages as fatal if they have a level set in
   * g_log_set_always_fatal().
   */
  if ((log_level & my_log_always_fatal) && !log_is_old_api (fields, n_fields))
    log_level |= G_LOG_FLAG_FATAL;
#endif

  /* Try logging to the systemd journal as first choice. */
  if (g_once_init_enter (&my_use_journal_initialized))
    {
      my_use_journal = my_log_writer_is_journald (fileno (stderr));
      g_once_init_leave (&my_use_journal_initialized, TRUE);
    }

  if (my_use_journal &&
      g_log_writer_journald (log_level, fields, n_fields, user_data) ==
      G_LOG_WRITER_HANDLED)
    goto handled;

  /* FIXME: Add support for the Windows log. */

  if (g_log_writer_standard_streams (log_level, fields, n_fields, user_data) ==
      G_LOG_WRITER_HANDLED)
    goto handled;

  return G_LOG_WRITER_UNHANDLED;

handled:
  /* Abort if the message was fatal. */
  if (log_level & G_LOG_FLAG_FATAL)
    {
      /* MessageBox is allowed on UWP apps only when building against
       * the debug CRT, which will set -D_DEBUG */
#if defined(G_OS_WIN32) && (defined(_DEBUG) || !defined(G_WINAPI_ONLY_APP))
      if (!g_test_initialized ())
        {
          WCHAR *wide_msg;

          wide_msg = g_utf8_to_utf16 (fatal_msg_buf, -1, NULL, NULL, NULL);

          MessageBoxW (NULL, wide_msg, NULL, MB_ICONERROR | MB_SETFOREGROUND);

          g_free (wide_msg);
        }
#endif /* !G_OS_WIN32 */

      _g_log_abort (!(log_level & G_LOG_FLAG_RECURSION));
    }

  return G_LOG_WRITER_HANDLED;
}
