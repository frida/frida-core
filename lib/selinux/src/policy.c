#include <fcntl.h>
#include <gio/gio.h>
#include <glib.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>

#define FRIDA_SELINUX_ERROR frida_selinux_error_quark ()

typedef struct _FridaSELinuxRule FridaSELinuxRule;
typedef enum _FridaSELinuxErrorEnum FridaSELinuxErrorEnum;

struct _FridaSELinuxRule
{
  const gchar * sources[4];
  const gchar * target;
  const gchar * klass;
  const gchar * permissions[16];
};

enum _FridaSELinuxErrorEnum
{
  FRIDA_SELINUX_ERROR_POLICY_FORMAT_NOT_SUPPORTED,
  FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND,
  FRIDA_SELINUX_ERROR_CLASS_NOT_FOUND,
  FRIDA_SELINUX_ERROR_PERMISSION_NOT_FOUND
};

static gboolean frida_load_policy (const gchar * filename, policydb_t * db, gchar ** data, GError ** error);
static gboolean frida_save_policy (const gchar * filename, policydb_t * db, GError ** error);
static type_datum_t * frida_ensure_type (policydb_t * db, const gchar * type_name, guint num_attributes, ...);
static avtab_datum_t * frida_ensure_rule (policydb_t * db, const gchar * s, const gchar * t, const gchar * c, const gchar * p, GError ** error);

static const FridaSELinuxRule frida_selinux_rules[] =
{
  { { "untrusted_app", "zygote", NULL }, "frida_file", "fifo_file", { "open", "write", NULL } },
  { { "untrusted_app", "zygote", NULL }, "frida_file", "file", { "open", "read", "getattr", "execute", NULL } },
  { { "untrusted_app", "zygote", NULL }, "frida_file", "sock_file", { "write", NULL } },
};

G_DEFINE_QUARK (frida-selinux-error-quark, frida_selinux_error)

void
frida_selinux_patch_policy (void)
{
  const gchar * system_policy = "/sys/fs/selinux/policy";
  policydb_t db;
  gchar * db_data;
  sidtab_t sidtab;
  GError * error = NULL;
  int res;
  guint rule_index;

  sepol_set_policydb (&db);
  sepol_set_sidtab (&sidtab);

  if (!g_file_test (system_policy, G_FILE_TEST_EXISTS))
    return;

  if (!frida_load_policy (system_policy, &db, &db_data, &error))
  {
    g_warning ("Unable to load SELinux policy from the kernel: %s", error->message);
    g_error_free (error);
    return;
  }

  res = policydb_load_isids (&db, &sidtab);
  g_assert_cmpint (res, ==, 0);

  if (frida_ensure_type (&db, "frida_file", 1, "file_type", &error) == NULL)
  {
    g_warning ("Unable to add SELinux type: %s", error->message);
    g_clear_error (&error);
    goto beach;
  }

  for (rule_index = 0; rule_index != G_N_ELEMENTS (frida_selinux_rules); rule_index++)
  {
    const FridaSELinuxRule * rule = &frida_selinux_rules[rule_index];
    const gchar * const * source;
    const gchar * const * perm;

    for (source = rule->sources; *source != NULL; source++)
    {
      for (perm = rule->permissions; *perm != NULL; perm++)
      {
        if (frida_ensure_rule (&db, *source, rule->target, rule->klass, *perm, &error) == NULL)
        {
          g_warning ("Unable to add SELinux rule: %s", error->message);
          g_clear_error (&error);
        }
      }
    }
  }

  if (!frida_save_policy ("/sys/fs/selinux/load", &db, &error))
  {
    g_warning ("Unable to save SELinux policy to the kernel: %s", error->message);
    g_clear_error (&error);
  }

beach:
  policydb_destroy (&db);
  g_free (db_data);
}

static gboolean
frida_load_policy (const gchar * filename, policydb_t * db, gchar ** data, GError ** error)
{
  policy_file_t file;
  int res;

  policy_file_init (&file);
  file.type = PF_USE_MEMORY;
  if (!g_file_get_contents (filename, &file.data, &file.len, error))
    return FALSE;

  *data = file.data;

  policydb_init (db);

  res = policydb_read (db, &file, FALSE);
  if (res != 0)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_POLICY_FORMAT_NOT_SUPPORTED, "unsupported policy database format");
    policydb_destroy (db);
    g_free (*data);
    return FALSE;
  }

  return TRUE;
}

static gboolean
frida_save_policy (const gchar * filename, policydb_t * db, GError ** error)
{
  void * data;
  size_t size;
  int res, fd;

  res = policydb_to_image (NULL, db, &data, &size);
  g_assert_cmpint (res, ==, 0);

  fd = open (filename, O_RDWR);
  if (fd == -1)
    goto error;

  res = write (fd, data, size);
  if (res == -1)
    goto error;

  close (fd);

  return TRUE;

error:
  {
    int e;

    e = errno;
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (e), "%s", strerror (e));

    if (fd != -1)
      close (fd);

    return FALSE;
  }
}

static type_datum_t *
frida_ensure_type (policydb_t * db, const gchar * type_name, guint n_attributes, ...)
{
  type_datum_t * type;
  ebitmap_t * attr_map;
  va_list vl;
  guint i;
  GError * pending_error, ** error;

  type = hashtab_search (db->p_types.table, (char *) type_name);
  if (type == NULL)
  {
    uint32_t id, i, n;
    gchar * name;

    id = ++db->p_types.nprim;
    name = strdup (type_name);

    type = malloc (sizeof (type_datum_t));

    type_datum_init (type);
    type->s.value = id;
    type->primary = TRUE;
    type->flavor = TYPE_TYPE;

    hashtab_insert (db->p_types.table, name, type);

    policydb_index_others (NULL, db, FALSE);

    i = id - 1;
    n = db->p_types.nprim;
    db->type_attr_map = realloc (db->type_attr_map, n * sizeof (ebitmap_t));
    db->attr_type_map = realloc (db->attr_type_map, n * sizeof (ebitmap_t));
    ebitmap_init (&db->type_attr_map[i]);
    ebitmap_init (&db->attr_type_map[i]);

    attr_map = &db->type_attr_map[i];

    /* We also need to add the type itself as the degenerate case. */
    ebitmap_set_bit (attr_map, i, 1);
  }
  else
  {
    attr_map = &db->type_attr_map[type->s.value - 1];
  }

  va_start (vl, n_attributes);

  pending_error = NULL;
  for (i = 0; i != n_attributes; i++)
  {
    const gchar * attribute_name;
    type_datum_t * attribute_type;

    attribute_name = va_arg (vl, const gchar *);
    attribute_type = hashtab_search (db->p_types.table, (char *) attribute_name);
    if (attribute_type != NULL)
    {
      uint32_t attribute_id = attribute_type->s.value;
      ebitmap_set_bit (attr_map, attribute_id - 1, 1);
    }
    else if (pending_error == NULL)
    {
      g_set_error (&pending_error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND, "attribute type %s does not exist", attribute_name);
    }
  }

  error = va_arg (vl, GError **);
  if (pending_error != NULL)
    g_propagate_error (error, pending_error);

  va_end (vl);

  return (pending_error == NULL) ? type : NULL;
}

static avtab_datum_t *
frida_ensure_rule (policydb_t * db, const gchar * s, const gchar * t, const gchar * c, const gchar * p, GError ** error)
{
  type_datum_t * source, * target;
  class_datum_t * klass;
  perm_datum_t * perm;
  avtab_key_t key;
  avtab_datum_t * av;

  source = hashtab_search (db->p_types.table, (char *) s);
  if (source == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND, "source type %s does not exist", s);
    return NULL;
  }

  target = hashtab_search (db->p_types.table, (char *) t);
  if (target == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND, "target type %s does not exist", t);
    return NULL;
  }

  klass = hashtab_search (db->p_classes.table, (char *) c);
  if (klass == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_CLASS_NOT_FOUND, "class %s does not exist", c);
    return NULL;
  }

  perm = hashtab_search (klass->permissions.table, (char *) p);
  if (perm == NULL && klass->comdatum != NULL)
    perm = hashtab_search (klass->comdatum->permissions.table, (char *) p);
  if (perm == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_PERMISSION_NOT_FOUND, "perm %s does not exist in class %s", p, c);
    return NULL;
  }

  key.source_type = source->s.value;
  key.target_type = target->s.value;
  key.target_class = klass->s.value;
  key.specified = AVTAB_ALLOWED;

  av = avtab_search (&db->te_avtab, &key);
  if (av == NULL)
  {
    int res;

    av = malloc (sizeof (avtab_datum_t));
    av->data = 1U << (perm->s.value - 1);

    res = avtab_insert (&db->te_avtab, &key, av);
    g_assert_cmpint (res, ==, 0);
  }

  av->data |= 1U << (perm->s.value - 1);

  return av;
}

