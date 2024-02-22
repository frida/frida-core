#ifdef HAVE_NICE

#define OPENSSL_SUPPRESS_DEPRECATED

#include "frida-base.h"

#include <errno.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <usrsctp.h>

static gchar * frida_steal_bio_to_string (BIO ** bio);

static int frida_on_connection_output (void * addr, void * buffer, size_t length, uint8_t tos, uint8_t set_df);
static void frida_on_debug_printf (const char * format, ...);

static void frida_on_upcall (struct socket * sock, void * user_data, int flags);

void
_frida_generate_certificate (guint8 ** cert_der, gint * cert_der_length, gchar ** cert_pem, gchar ** key_pem)
{
  X509 * x509;
  X509_NAME * name;
  EVP_PKEY * pkey;
  BIGNUM * e;
  RSA * rsa;
  BIO * bio;
  guint8 * der;
  long n;

  x509 = X509_new ();

  ASN1_INTEGER_set (X509_get_serialNumber (x509), 1);
  X509_gmtime_adj (X509_get_notBefore (x509), 0);
  X509_gmtime_adj (X509_get_notAfter (x509), 15780000);

  name = X509_get_subject_name (x509);
  X509_NAME_add_entry_by_txt (name, "C", MBSTRING_ASC, (const unsigned char *) "CA", -1, -1, 0);
  X509_NAME_add_entry_by_txt (name, "O", MBSTRING_ASC, (const unsigned char *) "Frida", -1, -1, 0);
  X509_NAME_add_entry_by_txt (name, "CN", MBSTRING_ASC, (const unsigned char *) "lolcathost", -1, -1, 0);
  X509_set_issuer_name (x509, name);

  pkey = EVP_PKEY_new ();
  e = BN_new ();
  BN_set_word (e, RSA_F4);
  rsa = RSA_new ();
  RSA_generate_key_ex (rsa, 2048, e, NULL);
  EVP_PKEY_set1_RSA (pkey, g_steal_pointer (&rsa));
  BN_free (e);
  X509_set_pubkey (x509, pkey);

  X509_sign (x509, pkey, EVP_sha256 ());

  bio = BIO_new (BIO_s_mem ());
  i2d_X509_bio (bio, x509);
  n = BIO_get_mem_data (bio, (guint8 **) &der);
  *cert_der = g_memdup2 (der, n);
  *cert_der_length = n;
  BIO_free (g_steal_pointer (&bio));

  bio = BIO_new (BIO_s_mem ());
  PEM_write_bio_X509 (bio, x509);
  *cert_pem = frida_steal_bio_to_string (&bio);

  bio = BIO_new (BIO_s_mem ());
  PEM_write_bio_PrivateKey (bio, pkey, NULL, NULL, 0, NULL, NULL);
  *key_pem = frida_steal_bio_to_string (&bio);

  EVP_PKEY_free (pkey);
  X509_free (x509);
}

static gchar *
frida_steal_bio_to_string (BIO ** bio)
{
  gchar * result;
  long n;
  char * str;

  n = BIO_get_mem_data (*bio, &str);
  result = g_strndup (str, n);

  BIO_free (g_steal_pointer (bio));

  return result;
}

void
_frida_sctp_connection_initialize_sctp_backend (void)
{
  const int msec_per_sec = 1000;

  usrsctp_init_nothreads (0, frida_on_connection_output, frida_on_debug_printf);

  usrsctp_sysctl_set_sctp_sendspace (256 * 1024);
  usrsctp_sysctl_set_sctp_recvspace (256 * 1024);

  usrsctp_sysctl_set_sctp_ecn_enable (FALSE);
  usrsctp_sysctl_set_sctp_pr_enable (TRUE);
  usrsctp_sysctl_set_sctp_auth_enable (FALSE);
  usrsctp_sysctl_set_sctp_asconf_enable (FALSE);

  usrsctp_sysctl_set_sctp_max_burst_default (10);

  usrsctp_sysctl_set_sctp_max_chunks_on_queue (10 * 1024);

  usrsctp_sysctl_set_sctp_delayed_sack_time_default (20);

  usrsctp_sysctl_set_sctp_heartbeat_interval_default (10 * msec_per_sec);

  usrsctp_sysctl_set_sctp_rto_max_default (10 * msec_per_sec);
  usrsctp_sysctl_set_sctp_rto_min_default (1 * msec_per_sec);
  usrsctp_sysctl_set_sctp_rto_initial_default (1 * msec_per_sec);
  usrsctp_sysctl_set_sctp_init_rto_max_default (10 * msec_per_sec);

  usrsctp_sysctl_set_sctp_init_rtx_max_default (5);
  usrsctp_sysctl_set_sctp_assoc_rtx_max_default (5);
  usrsctp_sysctl_set_sctp_path_rtx_max_default (5);

  usrsctp_sysctl_set_sctp_nr_outgoing_streams_default (1024);

  usrsctp_sysctl_set_sctp_initial_cwnd (10);
}

static int
frida_on_connection_output (void * addr, void * buffer, size_t length, uint8_t tos, uint8_t set_df)
{
  FridaSctpConnection * connection = addr;

  _frida_sctp_connection_emit_transport_packet (connection, buffer, (gint) length);

  return 0;
}

static void
frida_on_debug_printf (const char * format, ...)
{
  g_printerr ("[SCTP] %s\n", format);
}

void *
_frida_sctp_connection_create_sctp_socket (FridaSctpConnection * self)
{
  struct socket * sock;
  struct linger linger;
  int nodelay;
  struct sctp_event ev;
  const uint16_t event_types[] = {
    SCTP_ASSOC_CHANGE,
    SCTP_PEER_ADDR_CHANGE,
    SCTP_REMOTE_ERROR,
    SCTP_SHUTDOWN_EVENT,
    SCTP_ADAPTATION_INDICATION,
    SCTP_STREAM_RESET_EVENT,
    SCTP_SENDER_DRY_EVENT,
    SCTP_STREAM_CHANGE_EVENT,
    SCTP_SEND_FAILED_EVENT,
  };
  guint i;
  int recv_rcvinfo;
  struct sctp_assoc_value assoc;

  usrsctp_register_address (self);

  sock = usrsctp_socket (AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL);
  usrsctp_set_upcall (sock, frida_on_upcall, self);
  usrsctp_set_non_blocking (sock, TRUE);

  linger.l_onoff = TRUE;
  linger.l_linger = 0;
  usrsctp_setsockopt (sock, SOL_SOCKET, SO_LINGER, &linger, sizeof (linger));

  nodelay = TRUE;
  usrsctp_setsockopt (sock, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof (nodelay));

  ev.se_assoc_id = SCTP_ALL_ASSOC;
  ev.se_on = TRUE;
  for (i = 0; i != G_N_ELEMENTS (event_types); i++)
  {
    ev.se_type = event_types[i];
    usrsctp_setsockopt (sock, IPPROTO_SCTP, SCTP_EVENT, &ev, sizeof (ev));
  }

  recv_rcvinfo = TRUE;
  usrsctp_setsockopt (sock, IPPROTO_SCTP, SCTP_RECVRCVINFO, &recv_rcvinfo, sizeof (recv_rcvinfo));

  assoc.assoc_id = SCTP_ALL_ASSOC;
  assoc.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_CHANGE_ASSOC_REQ;
  usrsctp_setsockopt (sock, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &assoc, sizeof (assoc));

  return sock;
}

void
_frida_sctp_connection_connect_sctp_socket (FridaSctpConnection * self, void * sock, guint16 port)
{
  struct sockaddr_conn addr;

#ifdef HAVE_SCONN_LEN
  addr.sconn_len = sizeof (addr);
#endif
  addr.sconn_family = AF_CONN;
  addr.sconn_port = htons (port);
  addr.sconn_addr = self;

  usrsctp_bind (sock, (struct sockaddr *) &addr, sizeof (addr));

  usrsctp_connect (sock, (struct sockaddr *) &addr, sizeof (addr));
}

static void
frida_on_upcall (struct socket * sock, void * user_data, int flags)
{
  FridaSctpConnection * connection = user_data;

  _frida_sctp_connection_on_sctp_socket_events_changed (connection);
}

void
_frida_sctp_connection_close (void * sock)
{
  usrsctp_close (sock);
}

void
_frida_sctp_connection_shutdown (void * sock, FridaSctpShutdownType type, GError ** error)
{
  if (usrsctp_shutdown (sock, type) == -1)
  {
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno), "%s", g_strerror (errno));
  }
}

GIOCondition
_frida_sctp_connection_query_sctp_socket_events (void * sock)
{
  GIOCondition condition = 0;
  int events;

  events = usrsctp_get_events (sock);

  if ((events & SCTP_EVENT_READ) != 0)
    condition |= G_IO_IN;

  if ((events & SCTP_EVENT_WRITE) != 0)
    condition |= G_IO_OUT;

  if ((events & SCTP_EVENT_ERROR) != 0)
    condition |= G_IO_ERR;

  return condition;
}

void
_frida_sctp_connection_handle_transport_packet (FridaSctpConnection * self, guint8 * data, gint data_length)
{
  usrsctp_conninput (self, data, data_length, 0);
}

gssize
_frida_sctp_connection_recv (void * sock, guint8 * buffer, gint buffer_length, guint16 * stream_id, FridaPayloadProtocolId * protocol_id,
    FridaSctpMessageFlags * message_flags, GError ** error)
{
  gssize n;
  struct sockaddr_conn from;
  socklen_t from_length;
  struct sctp_rcvinfo info;
  socklen_t info_length;
  unsigned int info_type;
  int msg_flags;

  from_length = sizeof (from);
  info_length = sizeof (info);
  info_type = SCTP_RECVV_NOINFO;
  msg_flags = 0;

  n = usrsctp_recvv (sock, buffer, buffer_length, (struct sockaddr *) &from, &from_length, &info, &info_length, &info_type, &msg_flags);
  if (n == -1)
    goto propagate_usrsctp_error;

  if (info_type == SCTP_RECVV_RCVINFO)
  {
    *stream_id = info.rcv_sid;
    *protocol_id = ntohl (info.rcv_ppid);
  }
  else
  {
    *stream_id = 0;
    *protocol_id = FRIDA_PAYLOAD_PROTOCOL_ID_NONE;
  }

  *message_flags = 0;

  if ((msg_flags & MSG_EOR) != 0)
    *message_flags |= FRIDA_SCTP_MESSAGE_FLAGS_END_OF_RECORD;

  if ((msg_flags & MSG_NOTIFICATION) != 0)
    *message_flags |= FRIDA_SCTP_MESSAGE_FLAGS_NOTIFICATION;

  return n;

propagate_usrsctp_error:
  {
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno), "%s", g_strerror (errno));
    return -1;
  }
}

gssize
_frida_sctp_connection_send (void * sock, guint16 stream_id, FridaPayloadProtocolId protocol_id, guint8 * data, gint data_length,
      GError ** error)
{
  gssize n;
  struct sctp_sendv_spa spa;
  struct sctp_sndinfo * si;

  spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;

  si = &spa.sendv_sndinfo;
  si->snd_sid = stream_id;
  si->snd_flags = SCTP_EOR;
  si->snd_ppid = htonl (protocol_id);
  si->snd_context = 0;
  si->snd_assoc_id = 0;

  n = usrsctp_sendv (sock, data, data_length, NULL, 0, &spa, sizeof (spa), SCTP_SENDV_SPA, 0);
  if (n == -1)
    goto propagate_usrsctp_error;

  return n;

propagate_usrsctp_error:
  {
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno), "%s", g_strerror (errno));
    return -1;
  }
}

gint
_frida_sctp_timer_source_get_timeout (void)
{
  return usrsctp_get_timeout ();
}

void
_frida_sctp_timer_source_process_timers (guint32 elapsed_msec)
{
  usrsctp_handle_timers (elapsed_msec);
}

#endif /* HAVE_NICE */
