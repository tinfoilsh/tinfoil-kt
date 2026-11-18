package sh.tinfoil.internal.transport

import java.util.BitSet

/**
 * Where a member can be added to, or replaced in, the text of a JSON object
 * without touching any other byte of it.
 *
 * The text is read by a scanner that accepts exactly the JSON grammar of RFC
 * 8259 in well-formed UTF-8, and nothing else: no byte order mark, comments,
 * trailing commas, unquoted names, control characters in strings or data
 * after the object. A text that it refuses is one that a strict parser
 * refuses too, or that this code does not need to understand, and is left
 * alone. A text that it accepts has the structure that the scanner found,
 * for any conforming parser, so an edit at the positions that it reports
 * cannot be read differently by the server.
 */
internal class JsonObjectText private constructor(
    /** How many members the object has, repeats included. */
    val memberCount: Int,
    /** The index of the brace that closes the object. */
    val closingBrace: Int,
    /** How many members have the name that was asked about, in any spelling. */
    val occurrences: Int,
    /** Where the value of the last such member starts, or -1. */
    val valueStart: Int,
    /** The index after that value, or -1. */
    val valueEnd: Int,
) {
    /** Told of each member of an object, in order, by where its name and its value are in the text. */
    internal fun interface MemberVisitor {
        /**
         * [nameStart] is the index of the quote that opens the member's
         * name and [nameEnd] the index after the quote that closes it;
         * the value is the text from [valueStart] to [valueEnd], without
         * whitespace around it.
         */
        fun member(nameStart: Int, nameEnd: Int, valueStart: Int, valueEnd: Int)
    }

    /** Told of each element of an array, in order: the text from [start] to [end]. */
    internal fun interface ElementVisitor {
        fun element(start: Int, end: Int)
    }

    internal companion object {
        /**
         * The deepest nesting that is read, the object itself included.
         * Deeper texts are refused, as common server-side parsers do.
         */
        const val MAX_DEPTH: Int = 10_000

        /**
         * The layout of [text] if it is one JSON object with nothing but
         * whitespace around it, counting the top-level members named
         * [name]; otherwise null. Names are compared after their escapes
         * are decoded, so that `"\u0061"` names the member `a`. Members of
         * nested objects are not counted.
         */
        fun scan(text: ByteArray, name: String): JsonObjectText? {
            var members = 0
            var occurrences = 0
            var start = -1
            var end = -1
            val closingBrace = members(text) { nameStart, nameEnd, valueStart, valueEnd ->
                members++
                if (isName(text, nameStart, nameEnd, name)) {
                    occurrences++
                    start = valueStart
                    end = valueEnd
                }
            }
            return if (closingBrace < 0) null else JsonObjectText(members, closingBrace, occurrences, start, end)
        }

        /**
         * Tells [visitor] of each top-level member of the text between
         * [from] and [to] if that is one JSON object with nothing but
         * whitespace around it, and returns the index of the brace that
         * closes it; otherwise returns -1, in which case what [visitor] was
         * told means nothing. Members of nested objects are not visited.
         */
        fun members(text: ByteArray, from: Int = 0, to: Int = text.size, visitor: MemberVisitor): Int =
            Scanner(text, from, to).scanObject(visitor)

        /**
         * Tells [visitor] of each element of the text between [from] and
         * [to] if that is one JSON array with nothing but whitespace around
         * it, and returns true; otherwise returns false, in which case what
         * [visitor] was told means nothing. Elements of nested arrays are
         * not visited.
         */
        fun elements(text: ByteArray, from: Int, to: Int, visitor: ElementVisitor): Boolean =
            Scanner(text, from, to).scanArray(visitor)

        /**
         * Whether the name between [nameStart] and [nameEnd], as a
         * [MemberVisitor] is given them, spells [name] once its escapes are
         * decoded. [name] is ASCII.
         */
        fun isName(text: ByteArray, nameStart: Int, nameEnd: Int, name: String): Boolean =
            Scanner(text, 0, text.size).isName(nameStart + 1, nameEnd - 1, name)

        /**
         * Whether [text] is exactly one JSON value, of any kind, with
         * nothing but whitespace around it.
         */
        fun isValue(text: ByteArray): Boolean = Scanner(text, 0, text.size).scanValue()

        /**
         * The string that the text between [from] and [to] spells, if that
         * is exactly one JSON string; otherwise null. An escape for half of
         * a surrogate pair that has no other half decodes to U+FFFD, the
         * replacement character.
         */
        fun string(text: ByteArray, from: Int, to: Int): String? = Scanner(text, from, to).decodeString()
    }

    /** Reads the text from [from] up to [size], and nothing outside it. */
    private class Scanner(private val text: ByteArray, from: Int, private val size: Int) {
        private var index = from

        /** The index of the closing brace, or -1. */
        fun scanObject(visitor: MemberVisitor): Int {
            skipWhitespace()
            if (!take('{')) {
                return -1
            }
            skipWhitespace()
            val closingBrace: Int
            if (peek() == '}'.code) {
                closingBrace = index
                index++
            } else {
                while (true) {
                    skipWhitespace()
                    val nameStart = index
                    if (!skipString()) {
                        return -1
                    }
                    val nameEnd = index
                    skipWhitespace()
                    if (!take(':')) {
                        return -1
                    }
                    skipWhitespace()
                    val start = index
                    if (!skipValue()) {
                        return -1
                    }
                    visitor.member(nameStart, nameEnd, start, index)
                    skipWhitespace()
                    if (take(',')) {
                        continue
                    }
                    closingBrace = index
                    if (!take('}')) {
                        return -1
                    }
                    break
                }
            }
            skipWhitespace()
            return if (index == size) closingBrace else -1
        }

        fun scanValue(): Boolean {
            skipWhitespace()
            if (!skipValue()) {
                return false
            }
            skipWhitespace()
            return index == size
        }

        fun scanArray(visitor: ElementVisitor): Boolean {
            skipWhitespace()
            if (!take('[')) {
                return false
            }
            skipWhitespace()
            if (!take(']')) {
                while (true) {
                    skipWhitespace()
                    val start = index
                    if (!skipValue()) {
                        return false
                    }
                    visitor.element(start, index)
                    skipWhitespace()
                    if (take(',')) {
                        continue
                    }
                    if (!take(']')) {
                        return false
                    }
                    break
                }
            }
            skipWhitespace()
            return index == size
        }

        /** The string that the whole text spells, or null if it is not one string. */
        fun decodeString(): String? {
            val start = index
            if (!skipString() || index != size) {
                return null
            }
            val decoded = StringBuilder(size - start)
            var at = start + 1
            val end = size - 1
            while (at < end) {
                val b = text[at].toInt() and 0xff
                if (b != '\\'.code) {
                    // The text is well-formed UTF-8, so its characters can
                    // be copied a run at a time.
                    var runEnd = at
                    while (runEnd < end && text[runEnd].toInt() != '\\'.code) {
                        runEnd++
                    }
                    decoded.append(String(text, at, runEnd - at, Charsets.UTF_8))
                    at = runEnd
                    continue
                }
                val escape = text[at + 1].toInt().toChar()
                at += 2
                when (escape) {
                    'b' -> decoded.append('\b')
                    'f' -> decoded.append('\u000c')
                    'n' -> decoded.append('\n')
                    'r' -> decoded.append('\r')
                    't' -> decoded.append('\t')
                    'u' -> {
                        val unit = hex4(at).toChar()
                        at += 4
                        when {
                            !unit.isSurrogate() -> decoded.append(unit)
                            unit.isHighSurrogate() && at + 6 <= end && text[at].toInt() == '\\'.code &&
                                text[at + 1].toInt() == 'u'.code && hex4(at + 2).toChar().isLowSurrogate() -> {
                                decoded.append(unit).append(hex4(at + 2).toChar())
                                at += 6
                            }
                            else -> decoded.append(REPLACEMENT)
                        }
                    }
                    // A quote, a backslash or a slash, as itself.
                    else -> decoded.append(escape)
                }
            }
            return decoded.toString()
        }

        private fun hex4(at: Int): Int {
            var value = 0
            for (i in 0 until 4) {
                value = value * 16 + hexValue(text[at + i].toInt())
            }
            return value
        }

        private fun peek(): Int = if (index < size) text[index].toInt() and 0xff else -1

        private fun take(c: Char): Boolean {
            if (peek() != c.code) {
                return false
            }
            index++
            return true
        }

        private fun skipWhitespace() {
            while (index < size) {
                when (text[index].toInt()) {
                    0x20, 0x09, 0x0a, 0x0d -> index++
                    else -> return
                }
            }
        }

        /**
         * Moves past the value at the index, which is a member or an
         * element of the container that is being read. Nesting is followed
         * with a stack of its own rather than the thread's, so that no text
         * can exhaust it.
         */
        private fun skipValue(): Boolean {
            // One bit for each open container: set for an object.
            val objects = BitSet()
            var depth = 0
            while (true) {
                // A value starts here.
                skipWhitespace()
                var opened = false
                when (peek()) {
                    '{'.code, '['.code -> {
                        val isObject = peek() == '{'.code
                        // The container that is being read is the first level.
                        if (depth + 2 > MAX_DEPTH) {
                            return false
                        }
                        index++
                        skipWhitespace()
                        if (peek() == (if (isObject) '}' else ']').code) {
                            index++
                        } else {
                            objects.set(depth, isObject)
                            depth++
                            if (isObject && !skipName()) {
                                return false
                            }
                            opened = true
                        }
                    }
                    '"'.code -> if (!skipString()) return false
                    't'.code -> if (!skipLiteral("true")) return false
                    'f'.code -> if (!skipLiteral("false")) return false
                    'n'.code -> if (!skipLiteral("null")) return false
                    else -> if (!skipNumber()) return false
                }
                if (opened) {
                    continue
                }
                // A value has ended: close containers until one continues.
                while (true) {
                    if (depth == 0) {
                        return true
                    }
                    skipWhitespace()
                    val inObject = objects.get(depth - 1)
                    if (take(',')) {
                        if (inObject && !skipName()) {
                            return false
                        }
                        break
                    }
                    if (!take(if (inObject) '}' else ']')) {
                        return false
                    }
                    depth--
                }
            }
        }

        /** Moves past a member's name and its colon. */
        private fun skipName(): Boolean {
            skipWhitespace()
            if (!skipString()) {
                return false
            }
            skipWhitespace()
            return take(':')
        }

        private fun skipLiteral(literal: String): Boolean {
            if (index + literal.length > size) {
                return false
            }
            for (i in literal.indices) {
                if (text[index + i].toInt() != literal[i].code) {
                    return false
                }
            }
            index += literal.length
            return true
        }

        private fun skipDigits(): Boolean {
            val start = index
            while (peek() in '0'.code..'9'.code) {
                index++
            }
            return index > start
        }

        private fun skipNumber(): Boolean {
            take('-')
            if (!take('0')) {
                if (peek() !in '1'.code..'9'.code) {
                    return false
                }
                skipDigits()
            }
            if (take('.') && !skipDigits()) {
                return false
            }
            if (peek() == 'e'.code || peek() == 'E'.code) {
                index++
                if (!take('+')) {
                    take('-')
                }
                if (!skipDigits()) {
                    return false
                }
            }
            return true
        }

        /** Moves past the string at the index, which must be well-formed UTF-8 with valid escapes. */
        private fun skipString(): Boolean {
            if (!take('"')) {
                return false
            }
            while (index < size) {
                val b = text[index].toInt() and 0xff
                when {
                    b == '"'.code -> {
                        index++
                        return true
                    }
                    b == '\\'.code -> {
                        index++
                        when (peek()) {
                            '"'.code, '\\'.code, '/'.code, 'b'.code, 'f'.code, 'n'.code, 'r'.code, 't'.code -> index++
                            'u'.code -> {
                                index++
                                repeat(4) {
                                    if (hexValue(peek()) < 0) {
                                        return false
                                    }
                                    index++
                                }
                            }
                            else -> return false
                        }
                    }
                    b < 0x20 -> return false
                    b < 0x80 -> index++
                    else -> if (!skipMultibyte(b)) return false
                }
            }
            return false
        }

        /**
         * Moves past one character of two to four bytes that starts with
         * [lead], refusing what is not UTF-8: a stray continuation byte, an
         * overlong form, a surrogate, or a value past U+10FFFF.
         */
        private fun skipMultibyte(lead: Int): Boolean {
            val length: Int
            // The range that the second byte must be in.
            var low = 0x80
            var high = 0xbf
            when (lead) {
                in 0xc2..0xdf -> length = 2
                0xe0 -> {
                    length = 3
                    low = 0xa0
                }
                0xed -> {
                    length = 3
                    high = 0x9f
                }
                in 0xe1..0xef -> length = 3
                0xf0 -> {
                    length = 4
                    low = 0x90
                }
                in 0xf1..0xf3 -> length = 4
                0xf4 -> {
                    length = 4
                    high = 0x8f
                }
                else -> return false
            }
            if (index + length > size) {
                return false
            }
            if ((text[index + 1].toInt() and 0xff) !in low..high) {
                return false
            }
            for (i in 2 until length) {
                if ((text[index + i].toInt() and 0xc0) != 0x80) {
                    return false
                }
            }
            index += length
            return true
        }

        private fun hexValue(c: Int): Int = when (c) {
            in '0'.code..'9'.code -> c - '0'.code
            in 'a'.code..'f'.code -> c - 'a'.code + 10
            in 'A'.code..'F'.code -> c - 'A'.code + 10
            else -> -1
        }

        /**
         * Whether the string whose contents are the bytes from [start] to
         * [end], already checked, spells [name] once its escapes are
         * decoded. [name] is ASCII, so any other character settles it.
         */
        fun isName(start: Int, end: Int, name: String): Boolean {
            var at = start
            var matched = 0
            while (at < end) {
                var c = text[at].toInt() and 0xff
                at++
                if (c == '\\'.code) {
                    val escape = text[at].toInt().toChar()
                    at++
                    c = when (escape) {
                        'b' -> 0x08
                        'f' -> 0x0c
                        'n' -> 0x0a
                        'r' -> 0x0d
                        't' -> 0x09
                        'u' -> {
                            var value = 0
                            repeat(4) {
                                value = value * 16 + hexValue(text[at].toInt())
                                at++
                            }
                            value
                        }
                        // A quote, a backslash or a slash, as itself.
                        else -> escape.code
                    }
                }
                if (matched >= name.length || name[matched].code != c) {
                    return false
                }
                matched++
            }
            return matched == name.length
        }
    }
}

/** What an escape for an unpaired surrogate decodes to. */
private const val REPLACEMENT = '\ufffd'
