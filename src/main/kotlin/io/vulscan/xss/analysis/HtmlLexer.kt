package io.vulscan.xss.analysis

/**
 * Конечный автомат по токенизации HTML5. DOM не строит: определяет только состояние в позиции [stateAt].
 * Всё, что автомат не может истолковать уверенно, возвращается как [ReflectionContext.UNKNOWN].
 */
object HtmlLexer {
    private enum class S {
        DATA, TAG_OPEN, END_TAG_OPEN, TAG_NAME, END_TAG_NAME, BEFORE_ATTR_NAME, ATTR_NAME, AFTER_ATTR_NAME,
        BEFORE_ATTR_VALUE, ATTR_DQ, ATTR_SQ, ATTR_UNQ, COMMENT, BOGUS, RAW,
    }

    private val RAW_TEXT_TAGS = setOf("script", "style", "textarea", "title")
    private val URL_ATTRS = setOf("href", "src", "action", "formaction")

    private fun isAsciiLetter(c: Char) = c in 'a'..'z' || c in 'A'..'Z'
    private fun isSpace(c: Char) = c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\u000c'

    fun stateAt(body: String, offset: Int): LexState {
        val end = offset.coerceIn(0, body.length)
        var s = S.DATA
        val tag = StringBuilder()
        val attr = StringBuilder()
        var isEndTag = false
        var rawTag = ""
        var rawStart = -1
        var commentStart = 0
        var i = 0

        fun emit(at: Int) {
            if (!isEndTag && tag.toString() in RAW_TEXT_TAGS) {
                s = S.RAW
                rawTag = tag.toString()
                rawStart = at + 1
            } else {
                s = S.DATA
            }
        }

        while (i < end) {
            val c = body[i]
            var consume = true
            when (s) {
                S.DATA -> if (c == '<') s = S.TAG_OPEN
                S.TAG_OPEN -> when {
                    isAsciiLetter(c) -> {
                        tag.setLength(0)
                        tag.append(c.lowercaseChar())
                        isEndTag = false
                        s = S.TAG_NAME
                    }
                    c == '/' -> s = S.END_TAG_OPEN
                    c == '!' -> {
                        if (body.startsWith("--", i + 1)) {
                            s = S.COMMENT
                            commentStart = i + 3
                            i += 3
                            consume = false
                        } else {
                            s = S.BOGUS
                        }
                    }
                    c == '?' -> s = S.BOGUS
                    c == '<' -> Unit
                    else -> s = S.DATA
                }
                S.END_TAG_OPEN -> when {
                    isAsciiLetter(c) -> {
                        tag.setLength(0)
                        tag.append(c.lowercaseChar())
                        isEndTag = true
                        s = S.END_TAG_NAME
                    }
                    c == '>' -> s = S.DATA
                    else -> s = S.BOGUS
                }
                S.TAG_NAME, S.END_TAG_NAME -> when {
                    isSpace(c) || c == '/' -> s = S.BEFORE_ATTR_NAME
                    c == '>' -> emit(i)
                    else -> tag.append(c.lowercaseChar())
                }
                S.BEFORE_ATTR_NAME -> when {
                    isSpace(c) || c == '/' -> Unit
                    c == '>' -> emit(i)
                    else -> {
                        attr.setLength(0)
                        attr.append(c.lowercaseChar())
                        s = S.ATTR_NAME
                    }
                }
                S.ATTR_NAME -> when {
                    isSpace(c) -> s = S.AFTER_ATTR_NAME
                    c == '/' -> s = S.BEFORE_ATTR_NAME
                    c == '=' -> s = S.BEFORE_ATTR_VALUE
                    c == '>' -> emit(i)
                    else -> attr.append(c.lowercaseChar())
                }
                S.AFTER_ATTR_NAME -> when {
                    isSpace(c) -> Unit
                    c == '/' -> s = S.BEFORE_ATTR_NAME
                    c == '=' -> s = S.BEFORE_ATTR_VALUE
                    c == '>' -> emit(i)
                    else -> {
                        attr.setLength(0)
                        attr.append(c.lowercaseChar())
                        s = S.ATTR_NAME
                    }
                }
                S.BEFORE_ATTR_VALUE -> when {
                    isSpace(c) -> Unit
                    c == '"' -> s = S.ATTR_DQ
                    c == '\'' -> s = S.ATTR_SQ
                    c == '>' -> emit(i)
                    else -> {
                        s = S.ATTR_UNQ
                        consume = false
                    }
                }
                S.ATTR_DQ -> if (c == '"') s = S.BEFORE_ATTR_NAME
                S.ATTR_SQ -> if (c == '\'') s = S.BEFORE_ATTR_NAME
                S.ATTR_UNQ -> when {
                    isSpace(c) -> s = S.BEFORE_ATTR_NAME
                    c == '>' -> emit(i)
                }
                S.COMMENT -> if (c == '>') {
                    val dashes = i - 2 >= commentStart && body[i - 1] == '-' && body[i - 2] == '-'
                    val bang = i - 3 >= commentStart && body[i - 1] == '!' && body[i - 2] == '-' && body[i - 3] == '-'
                    val abrupt = i == commentStart || (i == commentStart + 1 && body[i - 1] == '-')
                    if (dashes || bang || abrupt) s = S.DATA
                }
                S.BOGUS -> if (c == '>') s = S.DATA
                S.RAW -> if (c == '<' && closesRawText(body, i, rawTag)) {
                    tag.setLength(0)
                    tag.append(rawTag)
                    isEndTag = true
                    s = S.END_TAG_NAME
                    i += 2 + rawTag.length
                    consume = false
                }
            }
            if (consume) i++
        }
        return result(s, tag.toString(), attr.toString(), isEndTag, rawTag, rawStart)
    }

    /** `</tag` и после него пробел, `/` или `>` (без учёта регистра). */
    private fun closesRawText(body: String, at: Int, tag: String): Boolean {
        if (!body.startsWith("</", at)) return false
        if (!body.regionMatches(at + 2, tag, 0, tag.length, ignoreCase = true)) return false
        val next = body.getOrNull(at + 2 + tag.length) ?: return true
        return isSpace(next) || next == '/' || next == '>'
    }

    private fun result(s: S, tag: String, attr: String, isEndTag: Boolean, rawTag: String, rawStart: Int): LexState {
        fun attribute(quote: Char?, quoted: ReflectionContext): LexState {
            val ctx = if (attr in URL_ATTRS) ReflectionContext.ATTR_URL else quoted
            return LexState(ctx, tag, attr, quote)
        }
        return when (s) {
            S.DATA -> LexState(ReflectionContext.HTML_TEXT)
            S.TAG_OPEN -> LexState(ReflectionContext.TAG_NAME_OR_ATTR_NAME)
            S.TAG_NAME, S.BEFORE_ATTR_NAME, S.ATTR_NAME, S.AFTER_ATTR_NAME ->
                if (isEndTag) LexState(ReflectionContext.UNKNOWN) else LexState(ReflectionContext.TAG_NAME_OR_ATTR_NAME, tag)
            S.BEFORE_ATTR_VALUE, S.ATTR_UNQ -> attribute(null, ReflectionContext.ATTR_UNQUOTED)
            S.ATTR_DQ -> attribute('"', ReflectionContext.ATTR_DOUBLE_QUOTED)
            S.ATTR_SQ -> attribute('\'', ReflectionContext.ATTR_SINGLE_QUOTED)
            S.COMMENT -> LexState(ReflectionContext.HTML_COMMENT)
            S.RAW -> when (rawTag) {
                "script" -> LexState(ReflectionContext.SCRIPT_CODE, rawTag, rawStart = rawStart)
                "style" -> LexState(ReflectionContext.STYLE, rawTag)
                else -> LexState(ReflectionContext.RCDATA, rawTag)
            }
            S.END_TAG_OPEN, S.END_TAG_NAME, S.BOGUS -> LexState(ReflectionContext.UNKNOWN)
        }
    }
}
