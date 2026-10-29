package io.vulscan.xss.analysis

/** Синтаксический контекст, в котором в ответе оказалась канарейка. */
enum class ReflectionContext {
    HTML_TEXT,
    HTML_COMMENT,
    ATTR_DOUBLE_QUOTED,
    ATTR_SINGLE_QUOTED,
    ATTR_UNQUOTED,

    /** Значение `href|src|action|formaction`; тип кавычек см. [LexState.quote]. */
    ATTR_URL,
    SCRIPT_CODE,
    SCRIPT_STRING_DQ,
    SCRIPT_STRING_SQ,
    SCRIPT_STRING_TEMPLATE,
    STYLE,

    /** Содержимое `<textarea>` и `<title>`: теги внутри не создают элементов. */
    RCDATA,
    TAG_NAME_OR_ATTR_NAME,

    /** Контекст определить нельзя; такое отражение никогда не даёт finding. */
    UNKNOWN,
}

/** Состояние токенизатора в заданной позиции. [rawStart] — начало содержимого `<script>` (для SCRIPT_CODE). */
data class LexState(
    val context: ReflectionContext,
    val tagName: String? = null,
    val attrName: String? = null,
    val quote: Char? = null,
    val rawStart: Int = -1,
)

/** Отражение с уточнённым контекстом (после анализа JS внутри `<script>`). */
data class ReflectionPoint(
    val offset: Int,
    val context: ReflectionContext,
    val quote: Char?,
    val tagName: String?,
    val attrName: String?,
)
