package patterns

const standardLibraryPath = "<std>"

const standardLibrarySource = `
namespace std::mem {
	using Section = u64;

	enum Endian : u8 {
		Native,
		Big,
		Little,
	};

	union Reinterpreter<From, To> {
		From from_value;
		To to_value;
	};

	struct Bytes<auto Size> {
		u8 data[Size] [[inline]];
	};

	struct AlignTo<auto Alignment> {
		padding[(Alignment - ($ % Alignment)) % Alignment];
	};
};

namespace std::mem::impl {
	struct MagicSearchImpl<auto Magic, T> {
		s128 address = std::mem::find_string_in_range(0, $, std::mem::size(), Magic);
		if (address < 0)
			break;
		$ = address;
		try {
			T data [[inline]];
		} catch {
			T data;
		}
	};
};

namespace std::mem {
	struct MagicSearch<auto Magic, T> {
		std::mem::impl::MagicSearchImpl<Magic, T> impl[while(!std::mem::eof())] [[inline]];
	};
};

namespace std::core {
	enum BitfieldOrder : u8 {
		LeftToRight = 0,
		RightToLeft = 1,
		MostToLeastSignificant = 0,
		LeastToMostSignificant = 1,
	};
};

namespace std {
	struct Array<T, auto Size> {
		T data[Size] [[inline]];
	};

	struct ByteSizedArray<T, auto NumBytes> {
		u64 startAddress = $;
		T array[while($ - startAddress < NumBytes)] [[inline]];
		std::assert($ - startAddress == NumBytes, "Not enough bytes available to fit a whole number of types");
	};

	fn unimplemented() {
		std::error("Unimplemented code path reached!");
	};
};

namespace std::math {
	fn clamp(auto x, auto min, auto max) {
		if (x < min)
			return min;
		else if (x > max)
			return max;
		else
			return x;
	};
};

namespace std::string::impl {
	fn format_string(ref auto string) {
		return string.data;
	};
};

namespace std::string {
	struct NullString {
		char data[] [[inline]];
	};

	struct NullString16 {
		char16 data[] [[inline]];
	};

	struct SizedString<SizeType> {
		SizeType size;
		char data[size] [[inline]];
	};

	struct SizedString16<SizeType> {
		SizeType size;
		char16 data[size] [[inline]];
	};
};

namespace std::time {
	using EpochTime = u32;

	bitfield DOSTime {
		seconds : 5;
		minutes : 6;
		hours : 5;
	};

	bitfield DOSDate {
		day : 5;
		month : 4;
		year : 7;
	};

	struct Time {
		u8 sec;
		u8 min;
		u8 hour;
		u8 mday;
		u8 mon;
		s16 year;
		u8 wday;
		u16 yday;
		bool isdst;
	} [[sealed]];

	union TimeConverter {
		Time time;
		u128 value;
	};

	enum TimeZone : u8 {
		Local,
		UTC,
	};

	fn epoch() {
		return builtin::std::time::epoch();
	};

	fn to_local(auto epoch_time) {
		TimeConverter converter;
		converter.value = builtin::std::time::to_local(epoch_time);
		return converter.time;
	};

	fn to_utc(auto epoch_time) {
		TimeConverter converter;
		converter.value = builtin::std::time::to_utc(epoch_time);
		return converter.time;
	};

	fn now(TimeZone time_zone = TimeZone::Local) {
		if (time_zone == TimeZone::UTC)
			return std::time::to_utc(std::time::epoch());
		return std::time::to_local(std::time::epoch());
	};

	fn to_epoch(Time time) {
		TimeConverter converter;
		converter.time = time;
		return builtin::std::time::to_epoch(converter.value);
	};

	fn format(Time time, str format_string = "%c") {
		TimeConverter converter;
		converter.time = time;
		return builtin::std::time::format(format_string, converter.value);
	};
};

namespace std::ptr {
	struct NullablePtr<PointeeType, PointerType> {
		PointerType pointerValue [[hidden]];
		if (pointerValue != 0) {
			PointeeType data @ pointerValue [[inline]];
		}
	};
};
`
