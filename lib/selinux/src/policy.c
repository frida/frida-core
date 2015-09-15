#include <fcntl.h>
#include <gio/gio.h>
#include <glib.h>
#include <selinux/selinux.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>

#define FRIDA_SELINUX_ERROR frida_selinux_error_quark ()

typedef struct _FridaSELinuxRule FridaSELinuxRule;
typedef enum _FridaSELinuxErrorEnum FridaSELinuxErrorEnum;

struct _FridaSELinuxRule
{
  const guint16 fields;
  const gchar * sources[4];
  const gchar * target;
  const gchar * klass;
  const gchar * details[16];
};

enum _FridaSELinuxErrorEnum
{
  FRIDA_SELINUX_ERROR_POLICY_FORMAT_NOT_SUPPORTED,
  FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND,
  FRIDA_SELINUX_ERROR_CLASS_NOT_FOUND,
  FRIDA_SELINUX_ERROR_ROLE_NOT_FOUND,
  FRIDA_SELINUX_ERROR_PERMISSION_NOT_FOUND
};

static gboolean frida_load_policy (const gchar * filename, policydb_t * db, gchar ** data, GError ** error);
static gboolean frida_save_policy (const gchar * filename, policydb_t * db, GError ** error);
static type_datum_t * frida_ensure_type (policydb_t * db, const gchar * type_name, guint num_attributes, ...);
static void frida_add_type_to_class_constraints_referencing_attribute (policydb_t * db, uint32_t type_id, uint32_t attribute_id);
static gboolean frida_ensure_role_is_authorized (policydb_t * db, const gchar * role_name, const gchar * type_name, GError ** error);
static gboolean frida_ensure_permissive (policydb_t * db, const gchar * type_name, GError ** error);
static avtab_datum_t * frida_ensure_rule (policydb_t * db, guint16 fields, const gchar * s, const gchar * t, const gchar * c, const gchar * detail, GError ** error);

static gboolean frida_set_file_contents (const gchar * filename, const gchar * contents, gssize length, GError ** error);

static const FridaSELinuxRule frida_selinux_rules[] =
{
  /*
   * init -> frida transition
   */

  /* Old domain may exec the file and transition to the new domain. */
  { AVTAB_ALLOWED, { "init", NULL }, "frida_exec", "file", { "getattr", "open", "read", "execute", NULL } },
  { AVTAB_ALLOWED, { "init", NULL }, "frida", "process", { "transition", NULL } },
  /* New domain is entered by executing the file. */
  { AVTAB_ALLOWED, { "frida", NULL }, "frida_exec", "file", { "entrypoint", "getattr", "open", "read", "execute", NULL } },
  /* New domain can send SIGCHLD to its caller. */
  { AVTAB_ALLOWED, { "frida", NULL }, "init", "process", { "sigchld", NULL } },
  /* Enable AT_SECURE, i.e. libc secure mode. (XXX: we use allow instead of dontaudit) */
  { AVTAB_ALLOWED, { "init", NULL }, "frida", "process", { "noatsecure", NULL } },
  /* XXX dontaudit candidate but requires further study. */
  { AVTAB_ALLOWED, { "init", NULL }, "frida", "process", { "siginh", "rlimitinh", NULL } },
  /* Make the transition occur by default. */
  { AVTAB_TRANSITION, { "init", NULL }, "frida_exec", "process", { "frida", NULL } },

  /*
   * World permissions
   */
  { AVTAB_ALLOWED, { "domain", NULL }, "frida_file", "dir", { "search", NULL } },
  { AVTAB_ALLOWED, { "domain", NULL }, "frida_file", "fifo_file", { "open", "write", NULL } },
  { AVTAB_ALLOWED, { "domain", NULL }, "frida_file", "file", { "open", "read", "getattr", "execute", NULL } },
  { AVTAB_ALLOWED, { "domain", NULL }, "frida_file", "sock_file", { "write", NULL } },
  { AVTAB_ALLOWED, { "domain", NULL }, "shell_data_file", "dir", { "search", NULL } },
  { AVTAB_ALLOWED, { "zygote", NULL }, "zygote", "capability", { "sys_ptrace", NULL } },
  { AVTAB_ALLOWED, { "zygote", NULL }, "zygote", "process", { "execmem", NULL } },
  { AVTAB_ALLOWED, { "zygote", NULL }, "shell", "process", { "sigchld", NULL } },
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
  gboolean success;
  guint rule_index;

  sepol_set_policydb (&db);
  sepol_set_sidtab (&sidtab);

  if (!g_file_test (system_policy, G_FILE_TEST_EXISTS))
    return;

  if (!frida_load_policy (system_policy, &db, &db_data, &error))
  {
    g_printerr ("Unable to load SELinux policy from the kernel: %s\n", error->message);
    g_error_free (error);
    return;
  }

  res = policydb_load_isids (&db, &sidtab);
  g_assert_cmpint (res, ==, 0);

  if (frida_ensure_type (&db, "frida", 4, "domain", "mlstrustedsubject", "netdomain", "appdomain", &error) == NULL)
  {
    g_printerr ("Unable to add SELinux type: %s\n", error->message);
    g_clear_error (&error);
    goto beach;
  }

  if (!frida_ensure_role_is_authorized (&db, "r", "frida", &error))
  {
    g_printerr ("Unable to add SELinux role authorization: %s\n", error->message);
    g_clear_error (&error);
    goto beach;
  }

  success = frida_ensure_permissive (&db, "frida", &error);
  g_assert (success);

  if (frida_ensure_type (&db, "frida_exec", 2, "exec_type", "file_type", &error) == NULL)
  {
    g_printerr ("Unable to add SELinux type: %s\n", error->message);
    g_clear_error (&error);
    goto beach;
  }

  if (frida_ensure_type (&db, "frida_file", 2, "file_type", "mlstrustedobject", &error) == NULL)
  {
    g_printerr ("Unable to add SELinux type: %s\n", error->message);
    g_clear_error (&error);
    goto beach;
  }

  for (rule_index = 0; rule_index != G_N_ELEMENTS (frida_selinux_rules); rule_index++)
  {
    const FridaSELinuxRule * rule = &frida_selinux_rules[rule_index];
    const gchar * const * source;
    const gchar * const * detail;

    for (source = rule->sources; *source != NULL; source++)
    {
      for (detail = rule->details; *detail != NULL; detail++)
      {
        if (frida_ensure_rule (&db, rule->fields, *source, rule->target, rule->klass, *detail, &error) == NULL)
        {
          g_printerr ("Unable to add SELinux rule: %s\n", error->message);
          g_clear_error (&error);
        }
      }
    }
  }

  if (!frida_save_policy ("/sys/fs/selinux/load", &db, &error))
  {
    gboolean success = FALSE, probably_in_emulator;

    probably_in_emulator = security_getenforce () == 1 && security_setenforce (0) == 0;
    if (probably_in_emulator)
    {
      g_clear_error (&error);

      success = frida_ensure_permissive (&db, "shell", &error);
      if (success)
        success = frida_save_policy ("/sys/fs/selinux/load", &db, &error);

      security_setenforce (1);
    }

    if (!success)
    {
      g_printerr ("Unable to save SELinux policy to the kernel: %s\n", error->message);
      g_clear_error (&error);
    }
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
  int res;

  res = policydb_to_image (NULL, db, &data, &size);
  g_assert_cmpint (res, ==, 0);

  return frida_set_file_contents (filename, data, size, error);
}

static type_datum_t *
frida_ensure_type (policydb_t * db, const gchar * type_name, guint n_attributes, ...)
{
  type_datum_t * type;
  uint32_t type_id;
  va_list vl;
  guint i;
  GError * pending_error, ** error;

  type = hashtab_search (db->p_types.table, (char *) type_name);
  if (type == NULL)
  {
    uint32_t i, n;
    gchar * name;

    type_id = ++db->p_types.nprim;
    name = strdup (type_name);

    type = malloc (sizeof (type_datum_t));

    type_datum_init (type);
    type->s.value = type_id;
    type->primary = TRUE;
    type->flavor = TYPE_TYPE;

    hashtab_insert (db->p_types.table, name, type);

    policydb_index_others (NULL, db, FALSE);

    i = type_id - 1;
    n = db->p_types.nprim;
    db->type_attr_map = realloc (db->type_attr_map, n * sizeof (ebitmap_t));
    db->attr_type_map = realloc (db->attr_type_map, n * sizeof (ebitmap_t));
    ebitmap_init (&db->type_attr_map[i]);
    ebitmap_init (&db->attr_type_map[i]);

    /* We also need to add the type itself as the degenerate case. */
    ebitmap_set_bit (&db->type_attr_map[i], i, 1);
  }
  else
  {
    type_id = type->s.value;
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
      ebitmap_set_bit (&attribute_type->types, type_id - 1, 1);
      ebitmap_set_bit (&db->type_attr_map[type_id - 1], attribute_id - 1, 1);
      ebitmap_set_bit (&db->attr_type_map[attribute_id - 1], type_id - 1, 1);

      frida_add_type_to_class_constraints_referencing_attribute (db, type_id, attribute_id);
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

static void
frida_add_type_to_class_constraints_referencing_attribute (policydb_t * db, uint32_t type_id, uint32_t attribute_id)
{
  uint32_t class_index;

  for (class_index = 0; class_index != db->p_classes.nprim; class_index++)
  {
    class_datum_t * klass = db->class_val_to_struct[class_index];
    constraint_node_t * node;

    for (node = klass->constraints; node != NULL; node = node->next)
    {
      constraint_expr_t * expr;

      for (expr = node->expr; expr != NULL; expr = expr->next)
      {
        ebitmap_node_t * tnode;
        guint i;

        ebitmap_for_each_bit (&expr->type_names->types, tnode, i)
        {
          if (ebitmap_node_get_bit (tnode, i) && i == attribute_id - 1)
            ebitmap_set_bit (&expr->names, type_id - 1, 1);
        }
      }
    }
  }
}

static gboolean
frida_ensure_role_is_authorized (policydb_t * db, const gchar * role_name, const gchar * type_name, GError ** error)
{
  role_datum_t * role;
  type_datum_t * type;

  role = hashtab_search (db->p_roles.table, (char *) role_name);
  if (role == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_ROLE_NOT_FOUND, "role %s does not exist", role_name);
    return FALSE;
  }

  type = hashtab_search (db->p_types.table, (char *) type_name);
  if (type == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND, "type %s does not exist", type_name);
    return FALSE;
  }

  ebitmap_set_bit (&role->types.types, type->s.value - 1, 1);

  return TRUE;
}

static gboolean
frida_ensure_permissive (policydb_t * db, const gchar * type_name, GError ** error)
{
  type_datum_t * type;
  int res;

  type = hashtab_search (db->p_types.table, (char *) type_name);
  if (type == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND, "type %s does not exist", type_name);
    return FALSE;
  }

  res = ebitmap_set_bit (&db->permissive_map, type->s.value, 1);
  g_assert_cmpint (res, ==, 0);

  return TRUE;
}

static avtab_datum_t *
frida_ensure_rule (policydb_t * db, guint16 fields, const gchar * s, const gchar * t, const gchar * c, const gchar * detail, GError ** error)
{
  type_datum_t * source, * target;
  class_datum_t * klass;
  perm_datum_t * perm = NULL;
  type_datum_t * transition_to = NULL;
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

  if ((fields & AVTAB_TRANSITION) != AVTAB_TRANSITION)
  {
    perm = hashtab_search (klass->permissions.table, (char *) detail);
    if (perm == NULL && klass->comdatum != NULL)
      perm = hashtab_search (klass->comdatum->permissions.table, (char *) detail);
    if (perm == NULL)
    {
      g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_PERMISSION_NOT_FOUND, "perm %s does not exist in class %s", detail, c);
      return NULL;
    }
  }
  else
  {
    transition_to = hashtab_search (db->p_types.table, (char *) detail);
    if (transition_to == NULL)
    {
      g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND, "transition target type %s does not exist", detail);
      return NULL;
    }
  }

  key.source_type = source->s.value;
  key.target_type = target->s.value;
  key.target_class = klass->s.value;
  key.specified = fields;

  av = avtab_search (&db->te_avtab, &key);
  if (av != NULL)
  {
    if (perm != NULL)
      av->data |= 1U << (perm->s.value - 1);
    else
      av->data = transition_to->s.value;
  }
  else
  {
    int res;

    av = malloc (sizeof (avtab_datum_t));
    if (perm != NULL)
      av->data = 1U << (perm->s.value - 1);
    else
      av->data = transition_to->s.value;
    av->ops = NULL;

    res = avtab_insert (&db->te_avtab, &key, av);
    g_assert_cmpint (res, ==, 0);
  }

  return av;
}

/* Just like g_file_set_contents() except there's no temporary file involved. */

static gboolean
frida_set_file_contents (const gchar * filename, const gchar * contents, gssize length, GError ** error)
{
  int fd, res;
  gsize offset, size;

  fd = open (filename, O_RDWR);
  if (fd == -1)
    goto error;

  offset = 0;
  size = (length == -1) ? strlen (contents) : length;

  while (offset != size)
  {
    res = write (fd, contents + offset, size - offset);
    if (res != -1)
      offset += res;
    else if (errno != EINTR)
      goto error;
  }

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

