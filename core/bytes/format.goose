// Zero-allocation decimal and hexadecimal integer formatting into appendable buffers.
namespace core;

import std;

// Formats an unsigned 64-bit integer in decimal notation into appendable buffer out.
fn format_u64_dec<B>(val: u64, out: B&) {
    guard val > 0 else {
        out.push('0');
        return;
    }
    var digits: u8[20] = [0; 20];
    var count = 0;
    var v = val;
    while v > 0 {
        digits[count] = ('0' + ((v % 10) as! u8));
        v = v / 10;
        count++;
    }
    for i in count {
        out.push(digits[count - 1 - i]);
    }
}

// Formats a signed 64-bit integer in decimal notation into appendable buffer out.
fn format_i64_dec<B>(val: i64, out: B&) {
    if val < 0 {
        out.push('-');
        if val == -9223372036854775807 - 1 {
            out.append("9223372036854775808");
            return;
        }
        format_u64_dec((-val) as! u64, out);
        return;
    }
    format_u64_dec(val as! u64, out);
}

// Formats an unsigned 64-bit integer in hexadecimal notation into appendable buffer out.
// If uppercase is true, uses '0'..'9','A'..'F'; otherwise '0'..'9','a'..'f'.
fn format_u64_hex<B>(val: u64, out: B&, uppercase: bool = false) {
    guard val > 0 else {
        out.push('0');
        return;
    }
    let hex_chars: const u8[16] = if uppercase {
        ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']
    } else {
        ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
    };
    var digits: u8[16] = [0; 16];
    var count = 0;
    var v = val;
    while v > 0 {
        digits[count] = hex_chars[(v & 0x0F) as! i64];
        v = v >> 4;
        count++;
    }
    for i in count {
        out.push(digits[count - 1 - i]);
    }
}

// Formats an unsigned 32-bit integer in hexadecimal notation into appendable buffer out.
fn format_u32_hex<B>(val: u32, out: B&, uppercase: bool = false) {
    format_u64_hex(val as! u64, out, uppercase);
}

// Formats an unsigned byte as exactly two hexadecimal characters into appendable buffer out.
fn format_u8_hex<B>(val: u8, out: B&, uppercase: bool = false) {
    let hex_chars: const u8[16] = if uppercase {
        ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']
    } else {
        ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
    };
    out.push(hex_chars[((val >> 4) & 0x0F) as! i64]);
    out.push(hex_chars[(val & 0x0F) as! i64]);
}

// Formats an unsigned 64-bit integer with leading zero padding to fixed width.
fn format_u64_hex_fixed<B>(val: u64, width: i64, out: B&, uppercase: bool = false) {
    guard width > 0 else { return; }
    let hex_chars: const u8[16] = if uppercase {
        ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']
    } else {
        ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
    };
    var digits: u8[16] = [0; 16];
    var count = 0;
    var v = val;
    while v > 0 && count < 16 {
        digits[count] = hex_chars[(v & 0x0F) as! i64];
        v = v >> 4;
        count++;
    }
    let pad_count = if width > count { width - count } else { 0 };
    for _ in pad_count {
        out.push('0');
    }
    let take = if count > width { width } else { count };
    for i in take {
        out.push(digits[take - 1 - i]);
    }
}
