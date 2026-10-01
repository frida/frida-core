export function $environment(base, limit, sections = [$mainSection(base, limit)], inputs = {}) { return { base, limit, cursor: base, root: null, globals: {}, littleEndian: true, arrayIndex: 0, breaks: false, continues: false, sections, inputs }; }

export function $heapEnvironment(env, size) {
    const section = new $Section(env.sections.length, "heap", true);
    env.sections.push(section);
    section.resize(size);
    return $sectionEnvironment(env, section.id);
}

export function $cloneLocal(env, value) {
    if (value === null || typeof value !== "object" || value.$type === undefined)
        return value;
    const section = new $Section(env.sections.length, "heap", true);
    env.sections.push(section);
    section.write(0, new Uint8Array(value.$address.readByteArray(value.$size)));
    const henv = $sectionEnvironment(env, section.id);
    let clone = null;
    $placeInSection(section, () => { clone = value.$type.$parse(henv.base, henv, null, value.$args); });
    return clone;
}

export function $sectionEnvironment(env, id) {
    const section = $sectionOf(env, id);
    const base = new $SectionPointer(section, 0);
    return { base, get limit() { return section.size; }, cursor: base, root: env.root, globals: env.globals, littleEndian: env.littleEndian, arrayIndex: env.arrayIndex, breaks: false, continues: false, sections: env.sections };
}

export function $check(env, address, size) {
    if ($offset(env.base, address) + size > env.limit)
        throw new Error("the data ended before the value could be read");
}

export function $alignCursor(base, cursor, alignment) { return base.add(Math.ceil($offset(base, cursor) / alignment) * alignment); }

export function $cursorOffset(base, cursor) {
    const offset = $offset(base, cursor);
    return offset < 0 ? BigInt.asUintN(64, BigInt(offset)) : offset;
}

export function $snapshot(object, env) { return { cursor: env.cursor, fields: Object.keys(object.$fields) }; }

export function $restore(object, env, saved) {
    env.cursor = saved.cursor;
    for (const name of Object.keys(object.$fields)) {
        if (!saved.fields.includes(name)) {
            delete object.$fields[name];
            delete object[name];
        }
    }
}

export function $matchCase(conditions) {
    const matched = conditions.indexOf(true);
    if (matched !== -1 && conditions.indexOf(true, matched + 1) !== -1)
        throw new Error("ambiguous match: several cases apply");
    return matched;
}

export function $scoped(object, name) {
    for (let scope = object; scope !== null && scope !== undefined; scope = scope.$parent) {
        if (name in scope)
            return scope[name];
    }
    throw new Error("unknown identifier " + name);
}

export function $unknown(name) { throw new Error("unknown identifier " + name); }

export function $callNamed(named, env, $this, name, value) {
    const callee = named[String(name)];
    if (callee === undefined)
        throw new Error("unknown function " + name);
    return callee(env, $this, value);
}

export function $parsed(value) { return [value, value.$size]; }

export function $patternReading([value, size]) { return [$patternInteger(value), size]; }

export function $patternInteger(value) {
    if (value !== null && typeof value === "object" && value.$transformed !== undefined)
        return value.$transformed;
    if (value === null || typeof value !== "object" || value.$address === undefined || value.$size > 8)
        return value;
    const bytes = new Uint8Array(value.$address.readByteArray(value.$size));
    let number = 0;
    for (let i = bytes.length - 1; i >= 0; i--)
        number = number * 256 + bytes[i];
    return number;
}

export function $pointee(metadata) {
    if (metadata.pointee === undefined) {
        if (metadata.address.readPointer === undefined || metadata.target === undefined)
            throw new Error("pointer cannot be dereferenced here");
        metadata.pointee = metadata.target()[0];
    }
    return metadata.pointee;
}

export function $deref(pointer, type) { return pointer.isNull() ? null : new type(pointer); }

export function $pointerOf(value) { return (value === null) ? NULL : (value.$address !== undefined) ? value.$address : ptr(value); }

export function $std_mem_create_section(env, name) {
    const section = new $Section(env.sections.length, String(name));
    env.sections.push(section);
    return section.id;
}

export function $std_mem_delete_section(env, id) { $sectionOf(env, id); env.sections[Number(id)] = null; }

export function $std_mem_get_section_size(env, id) { return $sectionOf(env, id).size; }

export function $std_mem_set_section_size(env, id, size) { $sectionOf(env, id).resize(Number(size)); }

export function $std_mem_copy_value_to_section(env, value, to, toAddress) {
    $sectionOf(env, to).write(Number(toAddress), new Uint8Array(value.address.readByteArray(value.size)));
}

export function $std_mem_copy_section_to_section(env, from, fromAddress, to, toAddress, size) {
    const bytes = new Uint8Array($sectionOf(env, from).slice(Number(fromAddress), Number(size)));
    $sectionOf(env, to).write(Number(toAddress), bytes);
}

export function $std_mem_eof(env) { return $offset(env.base, env.cursor) >= env.limit; }

export function $std_mem_size(env) { return env.limit; }

export function $std_mem_base_address(env) { return 0; }

export function $std_mem_reached(env, address) { return $offset(env.base, env.cursor) >= Number(address); }

export function $std_mem_align_to(env, alignment, value) { return alignment > 0 ? Math.ceil(Number(value) / Number(alignment)) * Number(alignment) : Number(value); }

export function $std_mem_read_unsigned(env, address, size, endian = 0, section = undefined) {
    const littleEndian = endian === 0 ? (env.littleEndian ?? true) : endian === 2;
    const base = section === undefined ? env.base : new $SectionPointer($sectionOf(env, section), 0);
    return size > 6 ? $readBigUint(base.add(address), size, littleEndian) : $readUint(base.add(address), size, littleEndian);
}

export function $std_mem_read_signed(env, address, size, endian = 0, section = undefined) {
    const littleEndian = endian === 0 ? (env.littleEndian ?? true) : endian === 2;
    const base = section === undefined ? env.base : new $SectionPointer($sectionOf(env, section), 0);
    return size > 6 ? $readBigInt(base.add(address), size, littleEndian) : $readInt(base.add(address), size, littleEndian);
}

export function $std_mem_read_string(env, address, size) { return $readString(env.base.add(address), size); }

export function $std_mem_find_sequence(env, occurrence, ...bytes) { return $std_mem_find(env, occurrence, 0, env.limit, bytes.map(Number)); }

export function $std_mem_find_sequence_in_range(env, occurrence, from, to, ...bytes) { return $std_mem_find(env, occurrence, Number(from), Number(to), bytes.map(Number)); }

export function $std_mem_find_string(env, occurrence, text) { return $std_mem_find(env, occurrence, 0, env.limit, Array.from(String(text), (c) => c.charCodeAt(0) & 0xff)); }

export function $std_mem_find_string_in_range(env, occurrence, from, to, text) { return $std_mem_find(env, occurrence, Number(from), Number(to), Array.from(String(text), (c) => c.charCodeAt(0) & 0xff)); }

function $std_mem_find(env, occurrence, from, to, needle) {
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

export function $std_core_array_index(env) { return env.arrayIndex ?? 0; }

export function $std_core_member_count(env, pattern) { return Array.isArray(pattern) ? pattern.length : Object.keys(pattern.$fields ?? {}).length; }

export function $std_core_has_member(env, pattern, name) { return Object.prototype.hasOwnProperty.call(pattern, String(name)); }

export function $std_core_set_display_name(env, pattern, name) { if (pattern !== null && typeof pattern === "object") Object.defineProperty(pattern, "$displayName", { value: String(name), configurable: true }); }

export function $std_core_formatted_value(env, pattern) { return (pattern !== null && typeof pattern === "object" && pattern.$formatted !== undefined) ? pattern.$formatted : $display(pattern); }

export function $std_core_set_endian(env, endian) { env.littleEndian = Number(endian) !== 1; }

export function $std_format(env, text, ...args) { return $format(String(text), ...args); }

export function $std_print(env, text, ...args) { console.log($format(String(text), ...args)); }

export function $std_assert(env, condition, message) {
    if (!$truthy(condition))
        throw new Error("assertion failed: " + message);
}

export function $std_error(env, message) { throw new Error(String(message)); }

export function $std_warning(env, message) { console.warn(String(message)); }

export function $std_assert_warn(env, condition, message) {
    if (!$truthy(condition))
        console.warn(String(message));
}

export function $std_string_length(env, text) { return Array.from(String(text)).length; }

export function $std_string_at(env, text, index) {
    const characters = Array.from(String(text));
    if (index < 0 || index >= characters.length)
        throw new Error("index " + index + " is out of range");
    return characters[index];
}

export function $std_string_substr(env, text, start, count) { return Array.from(String(text)).slice(Math.max(0, start), Math.max(0, start) + Math.max(0, count)).join(""); }

export function $std_string_contains(env, text, part) { return String(text).includes(String(part)); }

export function $std_string_starts_with(env, text, part) { return String(text).startsWith(String(part)); }

export function $std_string_ends_with(env, text, part) { return String(text).endsWith(String(part)); }

export function $std_string_to_string(env, value) { return $display(value); }

export function $std_string_to_upper(env, text) { return String(text).toUpperCase(); }

export function $std_string_to_lower(env, text) { return String(text).toLowerCase(); }

export function $std_string_reverse(env, text) { return Array.from(String(text)).reverse().join(""); }

export function $std_string_replace(env, text, from, to) { return String(text).split(String(from)).join(String(to)); }

export function $std_string_parse_int(env, text, base) {
    const number = parseInt(String(text).trim(), Number(base) === 0 ? undefined : Number(base));
    if (Number.isNaN(number))
        throw new Error(JSON.stringify(String(text)) + " is not a number");
    return number;
}

export function $std_string_parse_float(env, text) {
    const number = parseFloat(String(text).trim());
    if (Number.isNaN(number))
        throw new Error(JSON.stringify(String(text)) + " is not a number");
    return number;
}

export function $std_ctype_isdigit(env, c) { return /^[0-9]$/.test($charOf(c)); }

export function $std_ctype_isxdigit(env, c) { return /^[0-9a-fA-F]$/.test($charOf(c)); }

export function $std_ctype_isupper(env, c) { return /^\p{Lu}$/u.test($charOf(c)); }

export function $std_ctype_islower(env, c) { return /^\p{Ll}$/u.test($charOf(c)); }

export function $std_ctype_isalpha(env, c) { return /^\p{L}$/u.test($charOf(c)); }

export function $std_ctype_isalnum(env, c) { return /^[\p{L}0-9]$/u.test($charOf(c)); }

export function $std_ctype_isspace(env, c) { return /^\s$/.test($charOf(c)); }

export function $std_ctype_ispunct(env, c) { return /^\p{P}$/u.test($charOf(c)); }

export function $std_ctype_iscntrl(env, c) { const code = $codeOf(c); return code < 0x20 || code === 0x7f; }

export function $std_ctype_isprint(env, c) { const code = $codeOf(c); return code >= 0x20 && code !== 0x7f; }

export function $std_ctype_isgraph(env, c) { const code = $codeOf(c); return code > 0x20 && code !== 0x7f; }

export function $std_math_floor(env, x) { return Math.floor(Number(x)); }

export function $std_math_ceil(env, x) { return Math.ceil(Number(x)); }

export function $std_math_round(env, x) { return Math.round(Number(x)); }

export function $std_math_sqrt(env, x) { return Math.sqrt(Number(x)); }

export function $std_math_exp(env, x) { return Math.exp(Number(x)); }

export function $std_math_log(env, x) { return Math.log(Number(x)); }

export function $std_math_log2(env, x) { return Math.log2(Number(x)); }

export function $std_math_log10(env, x) { return Math.log10(Number(x)); }

export function $std_math_sin(env, x) { return Math.sin(Number(x)); }

export function $std_math_cos(env, x) { return Math.cos(Number(x)); }

export function $std_math_tan(env, x) { return Math.tan(Number(x)); }

export function $std_math_pow(env, x, y) { return Math.pow(Number(x), Number(y)); }

export function $std_math_min(env, x, y) { return Math.min(Number(x), Number(y)); }

export function $std_math_max(env, x, y) { return Math.max(Number(x), Number(y)); }

export function $std_math_abs(env, x) { return Math.abs(Number(x)); }

export function $std_math_factorial(env, n) { let result = 1; for (let i = 2; i <= Number(n); i++) result *= i; return result; }

export function $std_math_accumulate(env, start, end, width) {
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

export function $std_time_epoch(env) { return Math.floor(Date.now() / 1000); }

export function $std_time_to_utc(env, seconds) { return $std_time_value(new Date(Number(seconds) * 1000), true); }

export function $std_time_to_local(env, seconds) { return $std_time_value(new Date(Number(seconds) * 1000), false); }

export function $std_time_format(env, value, layout = "%Y-%m-%d %H:%M:%S") {
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

function $std_time_of(value) {
    if (typeof value === "object" && value !== null && value.year !== undefined)
        return value;
    return $std_time_value(new Date(Number(value) * 1000), true);
}

function $std_time_value(date, utc) {
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

export function $std_time_format_dos_date(env, value, template = "{:04}-{:02}-{:02}") {
    const date = Number(typeof value === "object" && value !== null ? value.$value : value);
    return $format(String(template), 1980 + (date >> 9), (date >> 5) & 0xf, date & 0x1f);
}

export function $std_time_format_dos_time(env, value, template = "{:02}:{:02}:{:02}") {
    const time = Number(typeof value === "object" && value !== null ? value.$value : value);
    return $format(String(template), time >> 11, (time >> 5) & 0x3f, (time & 0x1f) * 2);
}

export function $std_time_to_dos_date(env, value) {
    const date = Number(typeof value === "object" && value !== null ? value.$value : value);
    return { day: date & 0x1f, month: (date >> 5) & 0xf, year: date >> 9 };
}

export function $std_time_to_dos_time(env, value) {
    const time = Number(typeof value === "object" && value !== null ? value.$value : value);
    return { seconds: time & 0x1f, minutes: (time >> 5) & 0x3f, hours: time >> 11 };
}

export function $std_time_filetime_to_unix(env, filetime) { return Math.floor(Number(filetime) / 10000000) - 11644473600; }

export function $std_limits_u8_min(env) { return 0; }

export function $std_limits_u8_max(env) { return 0xff; }

export function $std_limits_s8_min(env) { return -0x80; }

export function $std_limits_s8_max(env) { return 0x7f; }

export function $std_limits_u16_min(env) { return 0; }

export function $std_limits_u16_max(env) { return 0xffff; }

export function $std_limits_s16_min(env) { return -0x8000; }

export function $std_limits_s16_max(env) { return 0x7fff; }

export function $std_limits_u32_min(env) { return 0; }

export function $std_limits_u32_max(env) { return 0xffffffff; }

export function $std_limits_s32_min(env) { return -0x80000000; }

export function $std_limits_s32_max(env) { return 0x7fffffff; }

export function $std_limits_u64_min(env) { return 0; }

export function $std_limits_u64_max(env) { return 0xffffffffffffffffn; }

export function $std_limits_s64_min(env) { return -0x8000000000000000n; }

export function $std_limits_s64_max(env) { return 0x7fffffffffffffffn; }

export function $std_limits_u128_min(env) { return 0; }

export function $std_limits_u128_max(env) { return 0xffffffffffffffffffffffffffffffffn; }

export function $std_limits_s128_min(env) { return -0x80000000000000000000000000000000n; }

export function $std_limits_s128_max(env) { return 0x7fffffffffffffffffffffffffffffffn; }

export function $std_hash_crc32(env, ...args) { return $std_hash_crc(env, 32, ...args); }

export function $std_hash_crc16(env, ...args) { return $std_hash_crc(env, 16, ...args); }

export function $std_hash_crc8(env, ...args) { return $std_hash_crc(env, 8, ...args); }

function $std_hash_crc(env, width, pattern, init, poly, xorOut, reflectIn, reflectOut) {
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

export function $parseArray(env, address, length, read) {
    const result = [];
    let cursor = address;
    const outerIndex = env.arrayIndex;
    for (let i = 0; i !== length; i++) {
        env.arrayIndex = i;
        const [value, size] = read(cursor);
        cursor = cursor.add(size);
        if (env.continues) {
            env.continues = false;
            continue;
        }
        result.push(value);
        if (env.breaks) {
            env.breaks = false;
            break;
        }
    }
    env.arrayIndex = outerIndex;
    return [result, $offset(address, cursor)];
}

export function $parseWhile(env, address, proceed, read) {
    const result = [];
    let cursor = address;
    const saved = env.cursor;
    const outerIndex = env.arrayIndex;
    for (;;) {
        env.cursor = cursor;
        env.arrayIndex = result.length;
        const more = proceed(cursor);
        env.cursor = saved;
        if (!more)
            break;
        const [value, size] = read(cursor);
        cursor = cursor.add(size);
        if (env.continues) {
            env.continues = false;
            continue;
        }
        result.push(value);
        if (env.breaks) {
            env.breaks = false;
            break;
        }
    }
    env.arrayIndex = outerIndex;
    return [result, $offset(address, cursor)];
}

export function $padWhile(env, address, proceed) {
    let size = 0;
    const saved = env.cursor;
    while ($offset(env.base, address) + size < env.limit) {
        env.cursor = address.add(size);
        const more = proceed(env.cursor);
        env.cursor = saved;
        if (!more)
            break;
        size++;
    }
    return size;
}

export function $readArray(address, length, stride, read) {
    const result = new Array(length);
    for (let i = 0; i !== length; i++)
        result[i] = read(address.add(i * stride));
    return result;
}

export function $padArray(elements, length) {
    while (elements.length < length)
        elements.push(0);
    return elements;
}

export function $parseCString(address) {
    const value = address.readUtf8String();
    return [value, $cStringSize(address)];
}

export function $parseCString16(address) {
    const value = address.readUtf16String();
    return [value, $cString16Size(address)];
}

export function $cStringSize(address) {
    let length = 0;
    while (address.add(length).readU8() !== 0)
        length++;
    return length + 1;
}

export function $cString16Size(address) {
    let length = 0;
    while (address.add(length).readU16() !== 0)
        length += 2;
    return length + 2;
}

export function $readString(address, size) {
    const bytes = new Uint8Array(address.readByteArray(size));
    let length = bytes.indexOf(0);
    if (length === -1)
        length = size;
    return address.readUtf8String(length);
}

export function $readString16(address, count) {
    const units = new Uint16Array(address.readByteArray(count * 2));
    let length = units.indexOf(0);
    if (length === -1)
        length = count;
    return address.readUtf16String(length);
}

export function $readBitRange(address, bitOffset, width, bigEndian = false) {
    const first = Math.floor(bitOffset / 8);
    const last = Math.floor((bitOffset + width - 1) / 8);
    const bytes = new Uint8Array(address.add(first).readByteArray(last - first + 1));
    let bits = 0n;
    if (bigEndian) {
        for (let i = 0; i !== width; i++) {
            const index = bitOffset % 8 + i;
            bits = (bits << 1n) | BigInt((bytes[index >> 3] >> (7 - (index & 7))) & 1);
        }
    } else {
        for (let i = 0; i !== bytes.length; i++)
            bits |= BigInt(bytes[i]) << BigInt(8 * i);
        bits = (bits >> BigInt(bitOffset % 8)) & ((1n << BigInt(width)) - 1n);
    }
    return width > 53 ? bits : Number(bits);
}

export function $add(left, right) {
    if (typeof left === "string" || typeof right === "string")
        return $display(left) + $display(right);
    if ($wide(left, right) || (Number.isInteger(left) && Number.isInteger(right) && !Number.isSafeInteger(left + right)))
        return $fit($big(left) + $big(right));
    return left + right;
}

export function $sub(left, right) {
    $number(left); $number(right);
    if ($wide(left, right) || (Number.isInteger(left) && Number.isInteger(right) && !Number.isSafeInteger(left - right)))
        return $fit($big(left) - $big(right));
    return left - right;
}

export function $mul(left, right) {
    if (typeof left === "string") {
        const count = Number(right);
        if (count < 0)
            throw new Error("a string cannot be repeated a negative number of times");
        return left.repeat(count);
    }
    $number(right);
    if ($wide(left, right) || (Number.isInteger(left) && Number.isInteger(right) && !Number.isSafeInteger(left * right)))
        return $fit($big(left) * $big(right));
    return left * right;
}

export function $divide(left, right) {
    $number(left); $number(right);
    if (Number(right) === 0)
        throw new Error("division by zero");
    if ($wide(left, right))
        return $fit($big(left) / $big(right));
    return Number.isInteger(left) && Number.isInteger(right) ? Math.trunc(left / right) : left / right;
}

export function $modulo(left, right) {
    $number(left); $number(right);
    if (Number(right) === 0)
        throw new Error("division by zero");
    if ($wide(left, right))
        return $fit($big(left) % $big(right));
    return left % right;
}

export function $shl(left, right) { $number(left); $number(right); return $fit($big(left) << $big(right)); }

export function $shr(left, right) { $number(left); $number(right); return $fit($big(left) >> $big(right)); }

export function $band(left, right) { $number(left); $number(right); return $fit($big(left) & $big(right)); }

export function $bor(left, right) { $number(left); $number(right); return $fit($big(left) | $big(right)); }

export function $bxor(left, right) { $number(left); $number(right); return $fit($big(left) ^ $big(right)); }

export function $bnot(value) { $number(value); return typeof value === "bigint" ? BigInt.asUintN(128, ~value) : $fit(~$big(value)); }

export function $charAdd(left, right, leftIsChar, rightIsChar) {
    if (typeof left === "string" && rightIsChar)
        return left + String.fromCharCode(Number(right));
    if (typeof right === "string" && leftIsChar)
        return String.fromCharCode(Number(left)) + right;
    return left + right;
}

export function $eq(left, right) {
    if (typeof left === "string" && left.length === 1 && typeof right !== "string")
        return left.charCodeAt(0) == right;
    if (typeof right === "string" && right.length === 1 && typeof left !== "string")
        return left == right.charCodeAt(0);
    return left == right;
}

export function $truthy(value) { return typeof value === "string" ? value !== "" : Boolean(Number(value)); }

export function $index(object, index) {
    const i = Number(index);
    if (object === null || object === undefined || i < 0 || i >= object.length)
        throw new RangeError("index " + i + " is out of range");
    return object[i];
}

export function $packedString(value) {
    if (typeof value !== "string")
        return value;
    let packed = 0n;
    for (let i = value.length - 1; i >= 0; i--)
        packed = (packed << 8n) | BigInt(value.charCodeAt(i) & 0xff);
    return $fit(packed);
}

export function $stringRef(text) {
    const bytes = new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff));
    return { address: { readByteArray() { return bytes.buffer; } }, size: bytes.length };
}

export function $labelled(members, name, value) {
    const number = typeof value === "bigint" ? value : Number(value);
    let label = members[String(number)];
    if (label === undefined)
        label = (members.$ranges ?? []).find(([first, last]) => first <= number && number <= last)?.[2] ?? number;
    return { $label: name + "::" + label, valueOf() { return number; }, toString() { return this.$label; } };
}

export function $templateArgument(value) {
    if (typeof value === "string") {
        const text = value.length > 32 ? "..." : value;
        const escapes = { 7: "\\a", 8: "\\b", 9: "\\t", 10: "\\n", 11: "\\v", 12: "\\f", 13: "\\r" };
        let encoded = "";
        for (const character of text) {
            const code = character.charCodeAt(0) & 0xff;
            encoded += (code >= 0x20 && code < 0x7f) ? character : (escapes[code] ?? "\\x" + code.toString(16).toUpperCase().padStart(2, "0"));
        }
        return '"' + encoded + '"';
    }
    if (value !== null && typeof value === "object" && value.$type !== undefined)
        return (value.$typeName ?? value.$type.name) + "{ }";
    return String(value);
}

function $format(text, ...args) {
    let next = 0;
    return text.replace(/\{\{|\}\}|\{([^{}:]*)(?::([^{}]*))?\}/g, (match, index, spec) => {
        if (match === "{{")
            return "{";
        if (match === "}}")
            return "}";
        const position = index === "" ? next++ : Number(index);
        if (position >= args.length)
            return match;
        return $formatValue(args[position], spec ?? "");
    });
}

function $formatValue(value, spec) {
    const m = /^(#)?(0)?(\d+)?(?:\.(\d+))?([xXbocd])?$/.exec(spec) ?? [];
    const [, alternate, zero, width, precision, verb] = m;
    let text;
    switch (verb) {
        case "x":
        case "X":
        case "b":
        case "o": {
            const base = { x: 16, X: 16, b: 2, o: 8 }[verb];
            const number = typeof value === "bigint" ? value : BigInt(Math.trunc(Number(value)));
            text = BigInt.asUintN(64, number).toString(base);
            if (verb === "X")
                text = text.toUpperCase();
            if (alternate)
                text = { x: "0x", X: "0x", b: "0b", o: "0o" }[verb] + text;
            break;
        }
        case "c":
            text = String.fromCharCode(Number(value));
            break;
        default:
            text = (typeof value === "number" && precision !== undefined) ? value.toFixed(Number(precision)) : $display(value);
    }
    const target = Number(width ?? 0);
    if (text.length >= target)
        return text;
    const padding = (zero ? "0" : " ").repeat(target - text.length);
    if (zero && /^0[xbo]/.test(text))
        return text.slice(0, 2) + padding + text.slice(2);
    if (zero && text.startsWith("-"))
        return "-" + padding + text.slice(1);
    return padding + text;
}

export function $display(value) {
    if (value === null || value === undefined)
        return "";
    if (typeof value === "object" && value.$label !== undefined)
        return value.$label;
    if (typeof value === "object" && value.$address !== undefined)
        return "<pattern>";
    return String(value);
}

export function $matchPattern(bytes) { return bytes.map((b) => (b === null) ? "??" : b.toString(16).padStart(2, "0")).join(" "); }

export function $putFloat(bytes, offset, size, value, littleEndian) {
    const buffer = new ArrayBuffer(size);
    const view = new DataView(buffer);
    if (size === 4)
        view.setFloat32(0, value, littleEndian);
    else
        view.setFloat64(0, value, littleEndian);
    new Uint8Array(buffer).forEach((b, i) => { bytes[offset + i] = b; });
}

export function $putString(bytes, offset, size, value) {
    for (let i = 0; i !== value.length; i++)
        bytes[offset + i] = value.charCodeAt(i) & 0xff;
    if (value.length < size)
        bytes[offset + value.length] = 0;
}

export function $putString16(bytes, offset, count, value) {
    for (let i = 0; i !== value.length; i++)
        $putInteger(bytes, offset + i * 2, 2, value.charCodeAt(i), true);
    if (value.length < count)
        $putInteger(bytes, offset + value.length * 2, 2, 0, true);
}

export function $putInteger(bytes, offset, size, value, littleEndian) {
    let v = BigInt.asUintN(size * 8, BigInt(value.toString()));
    for (let i = 0; i !== size; i++) {
        bytes[littleEndian ? offset + i : offset + size - 1 - i] = Number(v & 0xffn);
        v >>= 8n;
    }
}

export function $readU16LE(address) { return $readScalar(address, 2, "getUint16", true); }

export function $readU16BE(address) { return $readScalar(address, 2, "getUint16", false); }

export function $readS16LE(address) { return $readScalar(address, 2, "getInt16", true); }

export function $readS16BE(address) { return $readScalar(address, 2, "getInt16", false); }

export function $readU32LE(address) { return $readScalar(address, 4, "getUint32", true); }

export function $readU32BE(address) { return $readScalar(address, 4, "getUint32", false); }

export function $readS32LE(address) { return $readScalar(address, 4, "getInt32", true); }

export function $readS32BE(address) { return $readScalar(address, 4, "getInt32", false); }

export function $readU64LE(address) { return uint64($readScalar(address, 8, "getBigUint64", true).toString()); }

export function $readU64BE(address) { return uint64($readScalar(address, 8, "getBigUint64", false).toString()); }

export function $readS64LE(address) { return int64($readScalar(address, 8, "getBigInt64", true).toString()); }

export function $readS64BE(address) { return int64($readScalar(address, 8, "getBigInt64", false).toString()); }

export function $readFloatLE(address) { return $readScalar(address, 4, "getFloat32", true); }

export function $readFloatBE(address) { return $readScalar(address, 4, "getFloat32", false); }

export function $readDoubleLE(address) { return $readScalar(address, 8, "getFloat64", true); }

export function $readDoubleBE(address) { return $readScalar(address, 8, "getFloat64", false); }

export function $readScalar(address, size, method, littleEndian) { return new DataView(address.readByteArray(size))[method](0, littleEndian); }

export function $readInt(address, size, littleEndian) { return $signExtend($readUint(address, size, littleEndian), size * 8); }

export function $readUint(address, size, littleEndian) {
    const bytes = new Uint8Array(address.readByteArray(size));
    let value = 0;
    for (let i = 0; i !== size; i++)
        value = value * 256 + bytes[littleEndian ? size - 1 - i : i];
    return value;
}

export function $signExtend(value, bits) { return (value >= 2 ** (bits - 1)) ? value - 2 ** bits : value; }

export function $readBigInt(address, size, littleEndian) { return BigInt.asIntN(size * 8, $readBigUint(address, size, littleEndian)); }

export function $readBigUint(address, size, littleEndian) {
    const bytes = new Uint8Array(address.readByteArray(size));
    let value = 0n;
    for (let i = 0; i !== size; i++)
        value = (value << 8n) | BigInt(bytes[littleEndian ? size - 1 - i : i]);
    return value;
}

export function $writeU16LE(address, value) { $writeScalar(address, 2, "setUint16", value, true); }

export function $writeU16BE(address, value) { $writeScalar(address, 2, "setUint16", value, false); }

export function $writeS16LE(address, value) { $writeScalar(address, 2, "setInt16", value, true); }

export function $writeS16BE(address, value) { $writeScalar(address, 2, "setInt16", value, false); }

export function $writeU32LE(address, value) { $writeScalar(address, 4, "setUint32", value, true); }

export function $writeU32BE(address, value) { $writeScalar(address, 4, "setUint32", value, false); }

export function $writeS32LE(address, value) { $writeScalar(address, 4, "setInt32", value, true); }

export function $writeS32BE(address, value) { $writeScalar(address, 4, "setInt32", value, false); }

export function $writeU64LE(address, value) { $writeScalar(address, 8, "setBigUint64", BigInt(value.toString()), true); }

export function $writeU64BE(address, value) { $writeScalar(address, 8, "setBigUint64", BigInt(value.toString()), false); }

export function $writeS64LE(address, value) { $writeScalar(address, 8, "setBigInt64", BigInt(value.toString()), true); }

export function $writeS64BE(address, value) { $writeScalar(address, 8, "setBigInt64", BigInt(value.toString()), false); }

export function $writeFloatLE(address, value) { $writeScalar(address, 4, "setFloat32", value, true); }

export function $writeFloatBE(address, value) { $writeScalar(address, 4, "setFloat32", value, false); }

export function $writeDoubleLE(address, value) { $writeScalar(address, 8, "setFloat64", value, true); }

export function $writeDoubleBE(address, value) { $writeScalar(address, 8, "setFloat64", value, false); }

export function $writeScalar(address, size, method, value, littleEndian) {
    const buffer = new ArrayBuffer(size);
    new DataView(buffer)[method](0, value, littleEndian);
    address.writeByteArray(buffer);
}

export function $writeUint(address, size, value, littleEndian) {
    const bytes = new Uint8Array(size);
    let v = BigInt.asUintN(size * 8, BigInt(value));
    for (let i = 0; i !== size; i++) {
        bytes[littleEndian ? i : size - 1 - i] = Number(v & 0xffn);
        v >>= 8n;
    }
    address.writeByteArray(bytes.buffer);
}

export function $extractBits(value, offset, bits) { return Math.floor(value / 2 ** offset) % 2 ** bits; }

export function $insertBits(value, offset, bits, field) {
    const current = Math.floor(value / 2 ** offset) % 2 ** bits;
    return value + (field % 2 ** bits - current) * 2 ** offset;
}

export function $extractBigBits(value, offset, bits) { return (value >> BigInt(offset)) & ((1n << BigInt(bits)) - 1n); }

export function $insertBigBits(value, offset, bits, field) {
    const mask = ((1n << BigInt(bits)) - 1n) << BigInt(offset);
    return (value & ~mask) | ((field << BigInt(offset)) & mask);
}

function $mainSection(base, limit) {
    return {
        id: 0,
        name: "main",
        get size() { return limit; },
        slice(offset, size) { return base.add(offset).readByteArray(size); },
        write() { throw new Error("the main section is read-only"); },
    };
}

function $sectionOf(env, id) {
    if (typeof id === "bigint" && id === 0xffffffffffffffffn)
        return env.base.section ?? env.sections[0];
    if (typeof id === "bigint" && id === 0xfffffffffffffffen)
        throw new Error("the pattern-local section cannot be accessed");
    const section = env.sections[Number(id)];
    if (section === undefined || section === null)
        throw new Error("section " + id + " does not exist");
    return section;
}

export function $placeInSection(section, refresh) {
    if (section.placements !== undefined)
        section.placements.push(refresh);
    refresh();
}

class $Section {
    constructor(id, name, growable = false) {
        this.id = id;
        this.name = name;
        this.growable = growable;
        this.bytes = new Uint8Array(0);
        this.placements = [];
        this.refreshing = false;
    }
    get size() { return this.bytes.length; }
    resize(size) {
        const next = new Uint8Array(size);
        next.set(this.bytes.subarray(0, Math.min(size, this.bytes.length)));
        this.bytes = next;
        this.refresh();
    }
    slice(offset, size) {
        if (this.growable && offset >= 0)
            this.extend(offset + size);
        if (offset < 0 || offset + size > this.bytes.length)
            throw new Error("access violation reading section " + this.name);
        return this.bytes.slice(offset, offset + size).buffer;
    }
    write(offset, bytes) {
        this.extend(offset + bytes.length);
        this.bytes.set(bytes, offset);
        this.refresh();
    }
    extend(size) {
        if (size <= this.bytes.length)
            return;
        const next = new Uint8Array(size);
        next.set(this.bytes);
        this.bytes = next;
    }
    refresh() {
        if (this.refreshing)
            return;
        this.refreshing = true;
        try {
            for (const placement of this.placements)
                placement();
        } finally {
            this.refreshing = false;
        }
    }
}

class $SectionPointer {
    constructor(section, offset) {
        this.section = section;
        this.offset = offset;
    }
    add(delta) { return new $SectionPointer(this.section, this.offset + $pointerDelta(delta)); }
    sub(delta) { return new $SectionPointer(this.section, this.offset - $pointerDelta(delta)); }
    compare(other) { const d = this.offset - $pointerDelta(other); return d < 0 ? -1 : (d > 0 ? 1 : 0); }
    equals(other) { return this.compare(other) === 0; }
    isNull() { return false; }
    toString(radix = 16) { return radix === 16 ? "0x" + this.offset.toString(16) : this.offset.toString(radix); }
    toJSON() { return this.toString(); }
    toUInt32() { return this.offset >>> 0; }
    readByteArray(size) { return this.section.slice(this.offset, size); }
    view(size) { return new DataView(this.readByteArray(size)); }
    readU8() { return this.view(1).getUint8(0); }
    readS8() { return this.view(1).getInt8(0); }
    readU16() { return this.view(2).getUint16(0, true); }
    readS16() { return this.view(2).getInt16(0, true); }
    readU32() { return this.view(4).getUint32(0, true); }
    readS32() { return this.view(4).getInt32(0, true); }
    readU64() { return uint64(this.view(8).getBigUint64(0, true).toString()); }
    readS64() { return int64(this.view(8).getBigInt64(0, true).toString()); }
    readFloat() { return this.view(4).getFloat32(0, true); }
    readDouble() { return this.view(8).getFloat64(0, true); }
    readPointer() { return ptr("0x" + this.view(Process.pointerSize)[Process.pointerSize === 8 ? "getBigUint64" : "getUint32"](0, true).toString(16)); }
    readUtf8String(length = -1) {
        const bytes = new Uint8Array(this.section.bytes.buffer, this.offset, length === -1 ? this.section.size - this.offset : length);
        const end = length === -1 ? bytes.indexOf(0) : -1;
        let text = "";
        for (const byte of end === -1 ? bytes : bytes.subarray(0, end))
            text += String.fromCharCode(byte);
        return decodeURIComponent(escape(text));
    }
    readUtf16String(length = -1) {
        const units = length === -1 ? (this.section.size - this.offset) >>> 1 : length;
        const view = this.view(units * 2);
        let text = "";
        for (let i = 0; i !== units; i++) {
            const unit = view.getUint16(i * 2, true);
            if (length === -1 && unit === 0)
                break;
            text += String.fromCharCode(unit);
        }
        return text;
    }
    writeU8(value) { this.section.write(this.offset, new Uint8Array([Number(value) & 0xff])); return this; }
    writeByteArray(bytes) { this.section.write(this.offset, new Uint8Array(bytes)); return this; }
    writePointer(value) {
        const buffer = new ArrayBuffer(Process.pointerSize);
        new DataView(buffer)[Process.pointerSize === 8 ? "setBigUint64" : "setUint32"](0, Process.pointerSize === 8 ? BigInt(value.toString()) : Number(value), true);
        return this.writeByteArray(buffer);
    }
}

function $pointerDelta(value) {
    if (typeof value === "object" && value !== null)
        return value.offset;
    return typeof value === "bigint" ? Number(BigInt.asIntN(64, value)) : Number(value);
}

export function $offset(base, pointer) { return parseInt(pointer.sub(base).toString(10), 10); }

export function $align(value, alignment) { return Math.ceil(value / alignment) * alignment; }

function $wide(left, right) { return typeof left === "bigint" || typeof right === "bigint" || !Number.isSafeInteger(left) || !Number.isSafeInteger(right); }

function $fit(value) { return (value >= -9007199254740991n && value <= 9007199254740991n) ? Number(value) : value; }

function $big(value) { return typeof value === "bigint" ? value : BigInt(Math.trunc(Number(value))); }

function $number(value) {
    if (typeof value === "string")
        throw new TypeError("cannot use a string as a number");
    return value;
}

function $charOf(c) { return typeof c === "string" ? c.charAt(0) : String.fromCharCode(Number(c)); }

function $codeOf(c) { return typeof c === "string" ? c.charCodeAt(0) : Number(c); }
