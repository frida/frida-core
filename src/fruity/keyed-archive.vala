namespace Frida.Fruity {
	public class NSObject {
		public virtual uint hash () {
			return (uint) this;
		}

		public virtual bool is_equal_to (NSObject other) {
			return other == this;
		}

		public virtual string to_string () {
			return "NSObject";
		}

		public static uint hash_func (NSObject val) {
			return val.hash ();
		}

		public static bool equal_func (NSObject a, NSObject b) {
			return a.is_equal_to (b);
		}
	}

	public class NSNumber : NSObject {
		public bool boolean {
			get;
			private set;
		}

		public int64 integer {
			get;
			private set;
		}

		public NSNumber.from_boolean (bool val) {
			boolean = val;
			integer = val ? 1 : 0;
		}

		public NSNumber.from_integer (int64 val) {
			boolean = (val != 0) ? true : false;
			integer = val;
		}

		public override uint hash () {
			return (uint) integer;
		}

		public override bool is_equal_to (NSObject other) {
			var other_number = other as NSNumber;
			if (other_number == null)
				return false;
			return other_number.integer == integer;
		}

		public override string to_string () {
			return integer.to_string ();
		}
	}

	public class NSString : NSObject {
		public string str {
			get;
			private set;
		}

		public NSString (string str) {
			this.str = str;
		}

		public override uint hash () {
			return str.hash ();
		}

		public override bool is_equal_to (NSObject other) {
			var other_string = other as NSString;
			if (other_string == null)
				return false;
			return other_string.str == str;
		}

		public override string to_string () {
			return str;
		}
	}

	public class NSDictionary : NSObject {
		public int size {
			get {
				return storage.size;
			}
		}

		public Gee.Set<Gee.Map.Entry<string, NSObject>> entries {
			owned get {
				return storage.entries;
			}
		}

		public Gee.Iterable<string> keys {
			owned get {
				return storage.keys;
			}
		}

		public Gee.Iterable<NSObject> values {
			owned get {
				return storage.values;
			}
		}

		private Gee.HashMap<string, NSObject> storage;

		public NSDictionary (Gee.HashMap<string, NSObject>? storage = null) {
			this.storage = (storage != null) ? storage : new Gee.HashMap<string, NSObject> ();
		}

		public unowned T get_value<T> (string key) throws Error {
			unowned T? val;
			if (!get_optional_value<T> (key, out val))
				throw new Error.PROTOCOL ("Expected dictionary to contain “%s”", key);
			return val;
		}

		public bool get_optional_value<T> (string key, out unowned T? val) throws Error {
			val = null;

			NSObject? opaque_obj = storage[key];
			if (opaque_obj == null)
				return false;

			Type expected_type = typeof (T);
			Type actual_type = Type.from_instance (opaque_obj);
			if (!actual_type.is_a (expected_type)) {
				throw new Error.PROTOCOL ("Expected “%s” to be a %s but got %s",
					key, expected_type.name (), actual_type.name ());
			}

			val = (T) opaque_obj;
			return true;
		}

		public void set_value (string key, NSObject val) {
			storage[key] = val;
		}
	}

	public class NSDictionaryRaw : NSObject {
		public int size {
			get {
				return storage.size;
			}
		}

		public Gee.Set<Gee.Map.Entry<NSObject, NSObject>> entries {
			owned get {
				return storage.entries;
			}
		}

		public Gee.Iterable<NSObject> keys {
			owned get {
				return storage.keys;
			}
		}

		public Gee.Iterable<NSObject> values {
			owned get {
				return storage.values;
			}
		}

		private Gee.HashMap<NSObject, NSObject> storage;

		public NSDictionaryRaw (Gee.HashMap<NSObject, NSObject>? storage = null) {
			this.storage = (storage != null)
				? storage
				: new Gee.HashMap<NSObject, NSObject> (NSObject.hash_func, NSObject.equal_func);
		}
	}

	public class NSArray : NSObject {
		public int length {
			get {
				return storage.size;
			}
		}

		public Gee.Iterable<NSObject> elements {
			owned get {
				return storage;
			}
		}

		private Gee.ArrayList<NSObject> storage;

		public NSArray (Gee.ArrayList<NSObject>? storage = null) {
			this.storage = (storage != null) ? storage : new Gee.ArrayList<NSObject> (NSObject.equal_func);
		}
	}

	public class NSDate : NSObject {
		public double time {
			get;
			private set;
		}

		private const int64 MAC_EPOCH_DELTA_FROM_UNIX = 978307200LL;

		public NSDate (double time) {
			this.time = time;
		}

		public DateTime to_date_time () {
			int64 whole_seconds = (int64) time;
			return new DateTime.from_unix_utc (MAC_EPOCH_DELTA_FROM_UNIX + whole_seconds)
				.add_seconds (time - (double) whole_seconds);
		}
	}

	public class NSError : NSObject {
		public NSString domain {
			get;
			private set;
		}

		public int64 code {
			get;
			private set;
		}

		public NSDictionary user_info {
			get;
			private set;
		}

		public NSError (NSString domain, int64 code, NSDictionary user_info) {
			this.domain = domain;
			this.code = code;
			this.user_info = user_info;
		}
	}

	namespace NSKeyedArchive {
		private Gee.HashMap<Type, EncodeFunc> encoders;
		private Gee.HashMap<string, DecodeFunc> decoders;

		private const string[] DICTIONARY_CLASS = { "NSDictionary", "NSObject" };

		[CCode (has_target = false)]
		private delegate PlistUid EncodeFunc (NSObject instance, EncodingContext ctx);

		[CCode (has_target = false)]
		private delegate NSObject DecodeFunc (PlistDict instance, DecodingContext ctx) throws Error, PlistError;

		public static uint8[] encode (NSObject? obj) {
			if (obj == null)
				return new uint8[0];

			ensure_encoders_registered ();

			var objects = new PlistArray ();
			objects.add_string ("$null");

			var ctx = new EncodingContext (objects);

			var top = new PlistDict ();
			top.set_uid ("root", encode_value (obj, ctx));

			var plist = new Plist ();
			plist.set_integer ("$version", 100000);
			plist.set_array ("$objects", objects);
			plist.set_string ("$archiver", "NSKeyedArchiver");
			plist.set_dict ("$top", top);

			return plist.to_binary ();
		}

		private static PlistUid encode_value (NSObject? obj, EncodingContext ctx) {
			if (obj == null)
				return new PlistUid (0);

			var type = Type.from_instance (obj);
			var encode_object = encoders[type];
			if (encode_object == null)
				critical ("Missing NSKeyedArchive encoder for type “%s”", type.name ());

			return encode_object (obj, ctx);
		}

		public static NSObject? decode (uint8[] data) throws Error {
			ensure_decoders_registered ();

			try {
				var plist = new Plist.from_binary (data);

				var ctx = new DecodingContext (plist.get_array ("$objects"));

				return decode_value (plist.get_dict ("$top").get_uid ("root"), ctx);
			} catch (PlistError e) {
				throw new Error.PROTOCOL ("%s", e.message);
			}
		}

		private static NSObject? decode_value (PlistUid index, DecodingContext ctx) throws Error, PlistError {
			var uid = index.uid;
			if (uid == 0)
				return null;

			var objects = ctx.objects;

			Value * val = objects.get_value ((int) uid);
			Type t = val.type ();

			if (t == typeof (bool))
				return new NSNumber.from_boolean (val.get_boolean ());

			if (t == typeof (int64))
				return new NSNumber.from_integer (val.get_int64 ());

			if (t == typeof (string))
				return new NSString (val.get_string ());

			if (t == typeof (PlistDict)) {
				var instance = (PlistDict) val.get_object ();
				var klass = objects.get_dict ((int) instance.get_uid ("$class").uid);
				var decode = get_decoder (klass);
				return decode (instance, ctx);
			}

			throw new Error.NOT_SUPPORTED ("Unsupported NSKeyedArchive type: %s", val.type_name ());
		}

		private static DecodeFunc get_decoder (PlistDict klass) throws Error, PlistError {
			var hierarchy = klass.get_array ("$classes");

			int n = hierarchy.length;
			for (int i = 0; i != n; i++) {
				var name = hierarchy.get_string (i);
				var decoder = decoders[name];
				if (decoder != null)
					return decoder;
			}

			throw new Error.NOT_SUPPORTED ("Missing NSKeyedArchive decoder for type “%s”", klass.get_string ("$classname"));
		}

		private static void ensure_encoders_registered () {
			if (encoders != null)
				return;

			encoders = new Gee.HashMap<Type, EncodeFunc> ();
			encoders[typeof (NSNumber)] = encode_number;
			encoders[typeof (NSString)] = encode_string;
			encoders[typeof (NSDictionary)] = encode_dictionary;
		}

		private static void ensure_decoders_registered () {
			if (decoders != null)
				return;

			decoders = new Gee.HashMap<string, DecodeFunc> ();
			decoders["NSDictionary"] = decode_dictionary;
			decoders["NSArray"] = decode_array;
			decoders["NSDate"] = decode_date;
			decoders["NSError"] = decode_error;
		}

		private static PlistUid encode_number (NSObject instance, EncodingContext ctx) {
			int64 val = ((NSNumber) instance).integer;

			var uid = ctx.find_existing_object (e => e.holds (typeof (int64)) && e.get_int64 () == val);
			if (uid != null)
				return uid;

			var objects = ctx.objects;
			uid = new PlistUid (objects.length);
			objects.add_integer (val);
			return uid;
		}

		private static PlistUid encode_string (NSObject instance, EncodingContext ctx) {
			string str = ((NSString) instance).str;

			var uid = ctx.find_existing_object (e => e.holds (typeof (string)) && e.get_string () == str);
			if (uid != null)
				return uid;

			var objects = ctx.objects;
			uid = new PlistUid (objects.length);
			objects.add_string (str);
			return uid;
		}

		private static PlistUid encode_dictionary (NSObject instance, EncodingContext ctx) {
			NSDictionary dict = (NSDictionary) instance;

			var object = new PlistDict ();
			var uid = ctx.add_object (object);

			var keys = new PlistArray ();
			var objs = new PlistArray ();
			foreach (var entry in dict.entries) {
				var key = encode_value (new NSString (entry.key), ctx);
				var obj = encode_value (entry.value, ctx);

				keys.add_uid (key);
				objs.add_uid (obj);
			}
			object.set_array ("NS.keys", keys);
			object.set_array ("NS.objects", objs);
			object.set_uid ("$class", ctx.get_class (DICTIONARY_CLASS));

			return uid;
		}

		private static NSObject decode_dictionary (PlistDict instance, DecodingContext ctx) throws Error, PlistError {
			var keys = instance.get_array ("NS.keys");
			var objs = instance.get_array ("NS.objects");

			int n = keys.length;

			var string_keys = new Gee.ArrayList<string> ();
			for (int i = 0; i != n; i++) {
				var key = decode_value (keys.get_uid (i), ctx) as NSString;
				if (key is NSString)
					string_keys.add (key.str);
				else
					break;
			}

			if (string_keys.size == n) {
				var storage = new Gee.HashMap<string, NSObject> ();

				for (int i = 0; i != n; i++)
					storage[string_keys[i]] = decode_value (objs.get_uid (i), ctx);

				return new NSDictionary (storage);
			} else {
				var storage = new Gee.HashMap<NSObject, NSObject> (NSObject.hash_func, NSObject.equal_func);

				for (int i = 0; i != n; i++) {
					var key = decode_value (keys.get_uid (i), ctx);
					var obj = decode_value (objs.get_uid (i), ctx);

					storage[key] = obj;
				}

				return new NSDictionaryRaw (storage);
			}
		}

		private static NSObject decode_array (PlistDict instance, DecodingContext ctx) throws Error, PlistError {
			var objs = instance.get_array ("NS.objects");

			var storage = new Gee.ArrayList<NSObject> (NSObject.equal_func);

			var n = objs.length;
			for (int i = 0; i != n; i++) {
				var obj = decode_value (objs.get_uid (i), ctx);

				storage.add (obj);
			}

			return new NSArray (storage);
		}

		private static NSObject decode_date (PlistDict instance, DecodingContext ctx) throws Error, PlistError {
			var time = instance.get_double ("NS.time");

			return new NSDate (time);
		}

		private static NSObject decode_error (PlistDict instance, DecodingContext ctx) throws Error, PlistError {
			NSString? domain = decode_value (instance.get_uid ("NSDomain"), ctx) as NSString;
			if (domain == null)
				throw new Error.PROTOCOL ("Malformed NSError");

			int64 code = instance.get_integer ("NSCode");

			NSObject? user_info = decode_value (instance.get_uid ("NSUserInfo"), ctx);
			if (user_info != null && !(user_info is NSDictionary))
				throw new Error.PROTOCOL ("Malformed NSError");

			return new NSError (domain, code, (NSDictionary) user_info);
		}

		private class EncodingContext {
			public PlistArray objects;

			private Gee.HashMap<string, PlistUid> classes = new Gee.HashMap<string, PlistUid> ();

			public delegate void AddObjectFunc (PlistArray objects);

			public EncodingContext (PlistArray objects) {
				this.objects = objects;
			}

			public PlistUid? find_existing_object (Gee.Predicate<Value *> predicate) {
				int64 uid = 0;
				foreach (var e in objects.elements) {
					if (uid > 0 && predicate (e))
						return new PlistUid (uid);
					uid++;
				}

				return null;
			}

			public PlistUid add_object (PlistDict obj) {
				var uid = new PlistUid (objects.length);
				objects.add_dict (obj);
				return uid;
			}

			public PlistUid get_class (string[] description) {
				var canonical_name = description[0];

				var uid = classes[canonical_name];
				if (uid != null)
					return uid;

				var spec = new PlistDict ();

				var hierarchy = new PlistArray ();
				foreach (var name in description)
					hierarchy.add_string (name);
				spec.set_array ("$classes", hierarchy);

				spec.set_string ("$classname", canonical_name);

				uid = add_object (spec);
				classes[canonical_name] = uid;

				return uid;
			}
		}

		private class DecodingContext {
			public PlistArray objects;

			public DecodingContext (PlistArray objects) {
				this.objects = objects;
			}
		}
	}
}
