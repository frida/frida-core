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
		u16 year;
		u8 month;
		u8 day;
		u8 hours;
		u8 minutes;
		u8 seconds;
		u8 weekDay;
		u16 yearDay;
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
