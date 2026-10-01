package patterns

var standardHelperDependencies = map[string][]string{
	"$std_mem_eof":                     {"$offset"},
	"$std_mem_reached":                 {"$offset"},
	"$std_mem_read_unsigned":           {"$readUint", "$readBigUint", "$sectionOf", "$SectionPointer"},
	"$std_mem_read_signed":             {"$readInt", "$readBigInt", "$sectionOf", "$SectionPointer"},
	"$std_mem_create_section":          {"$Section"},
	"$std_mem_delete_section":          {"$sectionOf"},
	"$std_mem_get_section_size":        {"$sectionOf"},
	"$std_mem_set_section_size":        {"$sectionOf"},
	"$std_mem_copy_section_to_section": {"$sectionOf"},
	"$std_mem_copy_value_to_section":   {"$sectionOf"},
	"$std_mem_read_string":             {"$readString"},
	"$std_mem_find_sequence":           {"$std_mem_find"},
	"$std_mem_find_sequence_in_range":  {"$std_mem_find"},
	"$std_mem_find_string":             {"$std_mem_find"},
	"$std_mem_find_string_in_range":    {"$std_mem_find"},
	"$std_mem_find":                    {"$offset"},
	"$std_format":                      {"$format"},
	"$std_time_format_dos_date":        {"$format"},
	"$std_time_format_dos_time":        {"$format"},
	"$std_print":                       {"$format"},
	"$std_assert":                      {"$truthy"},
	"$std_assert_warn":                 {"$truthy"},
	"$std_core_formatted_value":        {"$display"},
	"$std_string_to_string":            {"$display"},
	"$std_time_format":                 {"$std_time_of"},
	"$std_time_to_utc":                 {"$std_time_value"},
	"$std_time_to_local":               {"$std_time_value"},
	"$std_hash_crc32":                  {"$std_hash_crc"},
	"$std_hash_crc16":                  {"$std_hash_crc"},
	"$std_hash_crc8":                   {"$std_hash_crc"},
}

var standardHelperSources = map[string]string{
	"$std_mem_eof": `function $std_mem_eof(env) { return $offset(env.base, env.cursor) >= env.limit; }
`,
	"$std_mem_size": `function $std_mem_size(env) { return env.limit; }
`,
	"$std_mem_base_address": `function $std_mem_base_address(env) { return 0; }
`,
	"$std_mem_reached": `function $std_mem_reached(env, address) { return $offset(env.base, env.cursor) >= Number(address); }
`,
	"$std_mem_align_to": `function $std_mem_align_to(env, alignment, value) { return alignment > 0 ? Math.ceil(Number(value) / Number(alignment)) * Number(alignment) : Number(value); }
`,
	"$std_mem_read_unsigned": `function $std_mem_read_unsigned(env, address, size, endian = 0, section = undefined) {
    const littleEndian = endian === 0 ? (env.littleEndian ?? true) : endian === 2;
    const base = section === undefined ? env.base : new $SectionPointer($sectionOf(env, section), 0);
    return size > 6 ? $readBigUint(base.add(address), size, littleEndian) : $readUint(base.add(address), size, littleEndian);
}
`,
	"$std_mem_read_signed": `function $std_mem_read_signed(env, address, size, endian = 0, section = undefined) {
    const littleEndian = endian === 0 ? (env.littleEndian ?? true) : endian === 2;
    const base = section === undefined ? env.base : new $SectionPointer($sectionOf(env, section), 0);
    return size > 6 ? $readBigInt(base.add(address), size, littleEndian) : $readInt(base.add(address), size, littleEndian);
}
`,
	"$std_mem_create_section": `function $std_mem_create_section(env, name) {
    const section = new $Section(env.sections.length, String(name));
    env.sections.push(section);
    return section.id;
}
`,
	"$std_mem_delete_section": `function $std_mem_delete_section(env, id) { $sectionOf(env, id); env.sections[Number(id)] = null; }
`,
	"$std_mem_get_section_size": `function $std_mem_get_section_size(env, id) { return $sectionOf(env, id).size; }
`,
	"$std_mem_set_section_size": `function $std_mem_set_section_size(env, id, size) { $sectionOf(env, id).resize(Number(size)); }
`,
	"$std_mem_copy_section_to_section": `function $std_mem_copy_section_to_section(env, from, fromAddress, to, toAddress, size) {
    const bytes = new Uint8Array($sectionOf(env, from).slice(Number(fromAddress), Number(size)));
    $sectionOf(env, to).write(Number(toAddress), bytes);
}
`,
	"$std_mem_copy_value_to_section": `function $std_mem_copy_value_to_section(env, value, to, toAddress) {
    $sectionOf(env, to).write(Number(toAddress), new Uint8Array(value.address.readByteArray(value.size)));
}
`,
	"$std_mem_read_string": `function $std_mem_read_string(env, address, size) { return $readString(env.base.add(address), size); }
`,
	"$std_mem_find": `function $std_mem_find(env, occurrence, from, to, needle) {
    const start = Math.max(0, Math.min(from, env.limit));
    const end = Math.max(start, Math.min(to, env.limit));
    if (!Number.isFinite(end))
        throw new Error("searching needs a bounded size");
    const haystack = new Uint8Array(env.base.add(start).readByteArray(end - start));
    let remaining = Number(occurrence);
    outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
        for (let j = 0; j !== needle.length; j++) {
            if (haystack[i + j] !== needle[j])
                continue outer;
        }
        if (remaining === 0)
            return start + i;
        remaining--;
    }
    return -1;
}
`,
	"$std_mem_find_sequence": `function $std_mem_find_sequence(env, occurrence, ...bytes) { return $std_mem_find(env, occurrence, 0, env.limit, bytes.map(Number)); }
`,
	"$std_mem_find_sequence_in_range": `function $std_mem_find_sequence_in_range(env, occurrence, from, to, ...bytes) { return $std_mem_find(env, occurrence, Number(from), Number(to), bytes.map(Number)); }
`,
	"$std_mem_find_string": `function $std_mem_find_string(env, occurrence, text) { return $std_mem_find(env, occurrence, 0, env.limit, Array.from(String(text), (c) => c.charCodeAt(0) & 0xff)); }
`,
	"$std_mem_find_string_in_range": `function $std_mem_find_string_in_range(env, occurrence, from, to, text) { return $std_mem_find(env, occurrence, Number(from), Number(to), Array.from(String(text), (c) => c.charCodeAt(0) & 0xff)); }
`,
	"$std_core_array_index": `function $std_core_array_index(env) { return env.arrayIndex ?? 0; }
`,
	"$std_core_member_count": `function $std_core_member_count(env, pattern) { return Array.isArray(pattern) ? pattern.length : Object.keys(pattern.$fields ?? {}).length; }
`,
	"$std_core_has_member": `function $std_core_has_member(env, pattern, name) { return Object.prototype.hasOwnProperty.call(pattern, String(name)); }
`,
	"$std_core_set_display_name": `function $std_core_set_display_name(env, pattern, name) { if (pattern !== null && typeof pattern === "object") Object.defineProperty(pattern, "$displayName", { value: String(name), configurable: true }); }
`,
	"$std_core_formatted_value": `function $std_core_formatted_value(env, pattern) { return (pattern !== null && typeof pattern === "object" && pattern.$formatted !== undefined) ? pattern.$formatted : $display(pattern); }
`,
	"$std_core_set_endian": `function $std_core_set_endian(env, endian) { env.littleEndian = Number(endian) !== 1; }
`,
	"$std_format": `function $std_format(env, text, ...args) { return $format(String(text), ...args); }
`,
	"$std_print": `function $std_print(env, text, ...args) { console.log($format(String(text), ...args)); }
`,
	"$std_assert": `function $std_assert(env, condition, message) {
    if (!$truthy(condition))
        throw new Error("assertion failed: " + message);
}
`,
	"$std_error": `function $std_error(env, message) { throw new Error(String(message)); }
`,
	"$std_warning": `function $std_warning(env, message) { console.warn(String(message)); }
`,
	"$std_string_length": `function $std_string_length(env, text) { return Array.from(String(text)).length; }
`,
	"$std_string_at": `function $std_string_at(env, text, index) {
    const characters = Array.from(String(text));
    if (index < 0 || index >= characters.length)
        throw new Error("index " + index + " is out of range");
    return characters[index];
}
`,
	"$std_string_substr": `function $std_string_substr(env, text, start, count) { return Array.from(String(text)).slice(Math.max(0, start), Math.max(0, start) + Math.max(0, count)).join(""); }
`,
	"$std_string_contains": `function $std_string_contains(env, text, part) { return String(text).includes(String(part)); }
`,
	"$std_string_starts_with": `function $std_string_starts_with(env, text, part) { return String(text).startsWith(String(part)); }
`,
	"$std_string_ends_with": `function $std_string_ends_with(env, text, part) { return String(text).endsWith(String(part)); }
`,
	"$std_string_to_string": `function $std_string_to_string(env, value) { return $display(value); }
`,
	"$std_string_to_upper": `function $std_string_to_upper(env, text) { return String(text).toUpperCase(); }
`,
	"$std_string_to_lower": `function $std_string_to_lower(env, text) { return String(text).toLowerCase(); }
`,
	"$std_string_reverse": `function $std_string_reverse(env, text) { return Array.from(String(text)).reverse().join(""); }
`,
	"$std_string_replace": `function $std_string_replace(env, text, from, to) { return String(text).split(String(from)).join(String(to)); }
`,
	"$std_string_parse_int": `function $std_string_parse_int(env, text, base) {
    const number = parseInt(String(text).trim(), Number(base) === 0 ? undefined : Number(base));
    if (Number.isNaN(number))
        throw new Error(JSON.stringify(String(text)) + " is not a number");
    return number;
}
`,
	"$std_string_parse_float": `function $std_string_parse_float(env, text) {
    const number = parseFloat(String(text).trim());
    if (Number.isNaN(number))
        throw new Error(JSON.stringify(String(text)) + " is not a number");
    return number;
}
`,
	"$std_ctype_isprint":  "function $std_ctype_isprint(env, c) { const code = $codeOf(c); return code >= 0x20 && code !== 0x7f; }\n",
	"$std_ctype_isgraph":  "function $std_ctype_isgraph(env, c) { const code = $codeOf(c); return code > 0x20 && code !== 0x7f; }\n",
	"$std_ctype_isdigit":  "function $std_ctype_isdigit(env, c) { return /^[0-9]$/.test($charOf(c)); }\n",
	"$std_ctype_isalpha":  "function $std_ctype_isalpha(env, c) { return /^\\p{L}$/u.test($charOf(c)); }\n",
	"$std_ctype_isalnum":  "function $std_ctype_isalnum(env, c) { return /^[\\p{L}0-9]$/u.test($charOf(c)); }\n",
	"$std_ctype_isspace":  "function $std_ctype_isspace(env, c) { return /^\\s$/.test($charOf(c)); }\n",
	"$std_ctype_isupper":  "function $std_ctype_isupper(env, c) { return /^\\p{Lu}$/u.test($charOf(c)); }\n",
	"$std_ctype_islower":  "function $std_ctype_islower(env, c) { return /^\\p{Ll}$/u.test($charOf(c)); }\n",
	"$std_ctype_iscntrl":  "function $std_ctype_iscntrl(env, c) { const code = $codeOf(c); return code < 0x20 || code === 0x7f; }\n",
	"$std_ctype_ispunct":  "function $std_ctype_ispunct(env, c) { return /^\\p{P}$/u.test($charOf(c)); }\n",
	"$std_ctype_isxdigit": "function $std_ctype_isxdigit(env, c) { return /^[0-9a-fA-F]$/.test($charOf(c)); }\n",
	"$charOf": `function $charOf(c) { return typeof c === "string" ? c.charAt(0) : String.fromCharCode(Number(c)); }
`,
	"$codeOf": `function $codeOf(c) { return typeof c === "string" ? c.charCodeAt(0) : Number(c); }
`,
	"$std_math_floor": "function $std_math_floor(env, x) { return Math.floor(Number(x)); }\n",
	"$std_math_ceil":  "function $std_math_ceil(env, x) { return Math.ceil(Number(x)); }\n",
	"$std_math_round": "function $std_math_round(env, x) { return Math.round(Number(x)); }\n",
	"$std_math_sqrt":  "function $std_math_sqrt(env, x) { return Math.sqrt(Number(x)); }\n",
	"$std_math_sin":   "function $std_math_sin(env, x) { return Math.sin(Number(x)); }\n",
	"$std_math_cos":   "function $std_math_cos(env, x) { return Math.cos(Number(x)); }\n",
	"$std_math_tan":   "function $std_math_tan(env, x) { return Math.tan(Number(x)); }\n",
	"$std_math_exp":   "function $std_math_exp(env, x) { return Math.exp(Number(x)); }\n",
	"$std_math_log":   "function $std_math_log(env, x) { return Math.log(Number(x)); }\n",
	"$std_math_log2":  "function $std_math_log2(env, x) { return Math.log2(Number(x)); }\n",
	"$std_math_log10": "function $std_math_log10(env, x) { return Math.log10(Number(x)); }\n",
	"$std_math_pow":   "function $std_math_pow(env, x, y) { return Math.pow(Number(x), Number(y)); }\n",
	"$std_math_min":   "function $std_math_min(env, x, y) { return Math.min(Number(x), Number(y)); }\n",
	"$std_math_max":   "function $std_math_max(env, x, y) { return Math.max(Number(x), Number(y)); }\n",
	"$std_math_abs":   "function $std_math_abs(env, x) { return Math.abs(Number(x)); }\n",
	"$std_math_factorial": `function $std_math_factorial(env, n) { let result = 1; for (let i = 2; i <= Number(n); i++) result *= i; return result; }
`,
	"$std_math_accumulate": `function $std_math_accumulate(env, start, end, width) {
    const size = Number(width);
    let sum = 0n;
    for (let address = Number(start); address + size <= Number(end); address += size) {
        const bytes = new Uint8Array(env.base.add(address).readByteArray(size));
        let value = 0n;
        for (let i = size - 1; i >= 0; i--)
            value = (value << 8n) | BigInt(bytes[env.littleEndian ? i : size - 1 - i]);
        sum = BigInt.asUintN(64, sum + value);
    }
    return sum;
}
`,
	"$std_time_epoch": `function $std_time_epoch(env) { return Math.floor(Date.now() / 1000); }
`,
	"$std_time_value": `function $std_time_value(date, utc) {
    const get = (local, universal) => utc ? universal.call(date) : local.call(date);
    const start = utc ? Date.UTC(date.getUTCFullYear(), 0, 1) : new Date(date.getFullYear(), 0, 1).getTime();
    return {
        year: get(Date.prototype.getFullYear, Date.prototype.getUTCFullYear),
        month: get(Date.prototype.getMonth, Date.prototype.getUTCMonth) + 1,
        day: get(Date.prototype.getDate, Date.prototype.getUTCDate),
        hours: get(Date.prototype.getHours, Date.prototype.getUTCHours),
        minutes: get(Date.prototype.getMinutes, Date.prototype.getUTCMinutes),
        seconds: get(Date.prototype.getSeconds, Date.prototype.getUTCSeconds),
        weekDay: get(Date.prototype.getDay, Date.prototype.getUTCDay),
        yearDay: Math.floor((date.getTime() - start) / 86400000) + 1,
    };
}
`,
	"$std_time_to_utc": `function $std_time_to_utc(env, seconds) { return $std_time_value(new Date(Number(seconds) * 1000), true); }
`,
	"$std_time_to_local": `function $std_time_to_local(env, seconds) { return $std_time_value(new Date(Number(seconds) * 1000), false); }
`,
	"$std_time_of": `function $std_time_of(value) {
    if (typeof value === "object" && value !== null && value.year !== undefined)
        return value;
    return $std_time_value(new Date(Number(value) * 1000), true);
}
`,
	"$std_time_format": `function $std_time_format(env, value, layout = "%Y-%m-%d %H:%M:%S") {
    const t = $std_time_of(value);
    const pad = (n, width) => String(n).padStart(width, "0");
    const days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
    const months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
    return String(layout).replace(/%([YymdHMSjaAbBFT%])/g, (match, verb) => {
        switch (verb) {
            case "Y": return pad(t.year, 4);
            case "y": return pad(t.year % 100, 2);
            case "m": return pad(t.month, 2);
            case "d": return pad(t.day, 2);
            case "H": return pad(t.hours, 2);
            case "M": return pad(t.minutes, 2);
            case "S": return pad(t.seconds, 2);
            case "j": return pad(t.yearDay, 3);
            case "a": return days[t.weekDay].slice(0, 3);
            case "A": return days[t.weekDay];
            case "b": return months[t.month - 1].slice(0, 3);
            case "B": return months[t.month - 1];
            case "F": return pad(t.year, 4) + "-" + pad(t.month, 2) + "-" + pad(t.day, 2);
            case "T": return pad(t.hours, 2) + ":" + pad(t.minutes, 2) + ":" + pad(t.seconds, 2);
            default: return "%";
        }
    });
}
`,
	"$std_time_format_dos_date": `function $std_time_format_dos_date(env, value, template = "{:04}-{:02}-{:02}") {
    const date = Number(typeof value === "object" && value !== null ? value.$value : value);
    return $format(String(template), 1980 + (date >> 9), (date >> 5) & 0xf, date & 0x1f);
}
`,
	"$std_time_format_dos_time": `function $std_time_format_dos_time(env, value, template = "{:02}:{:02}:{:02}") {
    const time = Number(typeof value === "object" && value !== null ? value.$value : value);
    return $format(String(template), time >> 11, (time >> 5) & 0x3f, (time & 0x1f) * 2);
}
`,
	"$std_time_to_dos_date": `function $std_time_to_dos_date(env, value) {
    const date = Number(typeof value === "object" && value !== null ? value.$value : value);
    return { day: date & 0x1f, month: (date >> 5) & 0xf, year: date >> 9 };
}
`,
	"$std_time_to_dos_time": `function $std_time_to_dos_time(env, value) {
    const time = Number(typeof value === "object" && value !== null ? value.$value : value);
    return { seconds: time & 0x1f, minutes: (time >> 5) & 0x3f, hours: time >> 11 };
}
`,
	"$std_assert_warn": `function $std_assert_warn(env, condition, message) {
    if (!$truthy(condition))
        console.warn(String(message));
}
`,
	"$std_time_filetime_to_unix": `function $std_time_filetime_to_unix(env, filetime) { return Math.floor(Number(filetime) / 10000000) - 11644473600; }
`,
	"$std_limits_u8_min":   "function $std_limits_u8_min(env) { return 0; }\n",
	"$std_limits_u8_max":   "function $std_limits_u8_max(env) { return 0xff; }\n",
	"$std_limits_u16_min":  "function $std_limits_u16_min(env) { return 0; }\n",
	"$std_limits_u16_max":  "function $std_limits_u16_max(env) { return 0xffff; }\n",
	"$std_limits_u32_min":  "function $std_limits_u32_min(env) { return 0; }\n",
	"$std_limits_u32_max":  "function $std_limits_u32_max(env) { return 0xffffffff; }\n",
	"$std_limits_u64_min":  "function $std_limits_u64_min(env) { return 0; }\n",
	"$std_limits_u64_max":  "function $std_limits_u64_max(env) { return 0xffffffffffffffffn; }\n",
	"$std_limits_u128_min": "function $std_limits_u128_min(env) { return 0; }\n",
	"$std_limits_u128_max": "function $std_limits_u128_max(env) { return 0xffffffffffffffffffffffffffffffffn; }\n",
	"$std_limits_s8_min":   "function $std_limits_s8_min(env) { return -0x80; }\n",
	"$std_limits_s8_max":   "function $std_limits_s8_max(env) { return 0x7f; }\n",
	"$std_limits_s16_min":  "function $std_limits_s16_min(env) { return -0x8000; }\n",
	"$std_limits_s16_max":  "function $std_limits_s16_max(env) { return 0x7fff; }\n",
	"$std_limits_s32_min":  "function $std_limits_s32_min(env) { return -0x80000000; }\n",
	"$std_limits_s32_max":  "function $std_limits_s32_max(env) { return 0x7fffffff; }\n",
	"$std_limits_s64_min":  "function $std_limits_s64_min(env) { return -0x8000000000000000n; }\n",
	"$std_limits_s64_max":  "function $std_limits_s64_max(env) { return 0x7fffffffffffffffn; }\n",
	"$std_limits_s128_min": "function $std_limits_s128_min(env) { return -0x80000000000000000000000000000000n; }\n",
	"$std_limits_s128_max": "function $std_limits_s128_max(env) { return 0x7fffffffffffffffffffffffffffffffn; }\n",
	"$std_hash_crc": `function $std_hash_crc(env, width, pattern, init, poly, xorOut, reflectIn, reflectOut) {
    const bytes = new Uint8Array(pattern.$address.readByteArray(pattern.$size));
    const mask = (1n << BigInt(width)) - 1n;
    const top = 1n << BigInt(width - 1);
    const reflect = (value, bits) => { let r = 0n; for (let i = 0; i < bits; i++) if (value & (1n << BigInt(i))) r |= 1n << BigInt(bits - 1 - i); return r; };
    let remainder = BigInt(init) & mask;
    for (let b of bytes) {
        let value = BigInt(b);
        if (reflectIn)
            value = reflect(value, 8);
        remainder ^= value << BigInt(width - 8);
        for (let bit = 0; bit < 8; bit++) {
            remainder = (remainder & top) ? ((remainder << 1n) ^ BigInt(poly)) : (remainder << 1n);
            remainder &= mask;
        }
    }
    if (reflectOut)
        remainder = reflect(remainder, width);
    return Number((remainder ^ BigInt(xorOut)) & mask);
}
`,
	"$std_hash_crc32": "function $std_hash_crc32(env, ...args) { return $std_hash_crc(env, 32, ...args); }\n",
	"$std_hash_crc16": "function $std_hash_crc16(env, ...args) { return $std_hash_crc(env, 16, ...args); }\n",
	"$std_hash_crc8":  "function $std_hash_crc8(env, ...args) { return $std_hash_crc(env, 8, ...args); }\n",
}
