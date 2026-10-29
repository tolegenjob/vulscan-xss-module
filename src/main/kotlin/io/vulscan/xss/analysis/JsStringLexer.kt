package io.vulscan.xss.analysis

enum class JsState { CODE, STRING_DQ, STRING_SQ, TEMPLATE, LINE_COMMENT, BLOCK_COMMENT, UNKNOWN }

/**
 * Упрощённый лексер JavaScript: различает код, строки `'…'`, `"…"`, шаблоны, комментарии.
 * Регулярные литералы и вложенные `${}` не разбираются — при их появлении результат [JsState.UNKNOWN].
 */
object JsStringLexer {
    private const val REGEX_PRECEDING = "(,=:[!&|?{};+-*%<>~^"
    private val REGEX_KEYWORDS = setOf("return", "typeof", "case", "do", "else", "in", "instanceof", "new", "delete", "void", "throw", "of", "yield", "await")

    fun stateAt(script: String, offset: Int): JsState = scan(script, offset.coerceIn(0, script.length), null)

    /** Идентификаторы, встреченные в состоянии CODE (строки и комментарии пропускаются). Пусто при неоднозначности разбора. */
    fun identifiersInCode(script: String): Set<String> {
        val found = LinkedHashSet<String>()
        val result = scan(script, script.length, found)
        return if (result == JsState.UNKNOWN) emptySet() else found
    }

    private fun identStart(c: Char) = c.isLetter() || c == '_' || c == '$'
    private fun identPart(c: Char) = c.isLetterOrDigit() || c == '_' || c == '$'

    private fun scan(script: String, limit: Int, collect: MutableSet<String>?): JsState {
        var state = JsState.CODE
        var previous = '\u0000'
        var i = 0
        while (i < limit) {
            val c = script[i]
            when (state) {
                JsState.CODE -> when {
                    c == '"' -> state = JsState.STRING_DQ
                    c == '\'' -> state = JsState.STRING_SQ
                    c == '`' -> state = JsState.TEMPLATE
                    c == '/' && script.getOrNull(i + 1) == '/' -> {
                        state = JsState.LINE_COMMENT
                        i++
                    }
                    c == '/' && script.getOrNull(i + 1) == '*' -> {
                        state = JsState.BLOCK_COMMENT
                        i++
                    }
                    c == '/' -> {
                        if (previous == '\u0000' || previous in REGEX_PRECEDING) return JsState.UNKNOWN
                        previous = c
                    }
                    identStart(c) -> {
                        var j = i
                        while (j < script.length && identPart(script[j])) j++
                        val ident = script.substring(i, j)
                        collect?.add(ident)
                        previous = if (ident in REGEX_KEYWORDS) '(' else 'a'
                        i = j - 1
                    }
                    c.isDigit() -> {
                        var j = i
                        while (j < script.length && (script[j].isLetterOrDigit() || script[j] == '.')) j++
                        previous = '0'
                        i = j - 1
                    }
                    c.isWhitespace() -> Unit
                    else -> previous = c
                }
                JsState.STRING_DQ -> when (c) {
                    '\\' -> i++
                    '"' -> {
                        state = JsState.CODE
                        previous = '"'
                    }
                    '\n', '\r' -> return JsState.UNKNOWN
                    else -> Unit
                }
                JsState.STRING_SQ -> when (c) {
                    '\\' -> i++
                    '\'' -> {
                        state = JsState.CODE
                        previous = '\''
                    }
                    '\n', '\r' -> return JsState.UNKNOWN
                    else -> Unit
                }
                JsState.TEMPLATE -> when {
                    c == '\\' -> i++
                    c == '`' -> {
                        state = JsState.CODE
                        previous = '`'
                    }
                    c == '$' && script.getOrNull(i + 1) == '{' -> return JsState.UNKNOWN
                }
                JsState.LINE_COMMENT -> if (c == '\n' || c == '\r') state = JsState.CODE
                JsState.BLOCK_COMMENT -> if (c == '*' && script.getOrNull(i + 1) == '/') {
                    state = JsState.CODE
                    i++
                }
                JsState.UNKNOWN -> return JsState.UNKNOWN
            }
            i++
        }
        return state
    }
}
