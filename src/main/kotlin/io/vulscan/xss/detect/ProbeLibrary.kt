package io.vulscan.xss.detect

import io.vulscan.xss.analysis.ReflectionContext
import io.vulscan.xss.analysis.ReflectionPoint

enum class ProofKind { DOM_TAG, DOM_ATTRIBUTE, JS_IDENTIFIER }

/**
 * Безвредная проба: не содержит обработчиков событий, `javascript:`, `<script`, `<svg`, `<img`.
 * [required] — символы, без которых проба в данном контексте не сработает.
 */
class Probe(
    val id: String,
    val required: Set<Char>,
    val proofKind: ProofKind,
    val build: (canary: String) -> String,
) {
    val injectionProof: String get() = if (proofKind == ProofKind.JS_IDENTIFIER) "JS_STRING_BREAK" else "DOM_STRUCTURE"

    fun verify(body: String, canary: String): Boolean = when (proofKind) {
        ProofKind.DOM_TAG -> DomProof.tagInjected(body, canary)
        ProofKind.DOM_ATTRIBUTE -> DomProof.attributeInjected(body, canary)
        ProofKind.JS_IDENTIFIER -> JsProof.identifierInjected(body, canary)
    }
}

object ProbeLibrary {
    const val TAG_NAME = "vsxtag"
    const val ATTR_NAME = "vsxattr"
    const val VAR_PREFIX = "vsxv"

    private val FORBIDDEN = Regex("(?i)(\\bon[a-z]+\\s*=|javascript:|<script|<svg|<img|<iframe|<object|<embed)")
    private val RAW_TEXT_TAGS = listOf("script", "style", "textarea", "title")

    private fun tag(c: String) = "<$TAG_NAME id=$c>"

    val TAG = Probe("tag", setOf('<', '>'), ProofKind.DOM_TAG) { c -> c + tag(c) }
    val ATTR_DQ = Probe("attr-dq", setOf('"', ' '), ProofKind.DOM_ATTRIBUTE) { c -> c + "\" $ATTR_NAME=\"" + c }
    val ATTR_SQ = Probe("attr-sq", setOf('\'', ' '), ProofKind.DOM_ATTRIBUTE) { c -> c + "' $ATTR_NAME='" + c }
    val ATTR_UNQ = Probe("attr-unq", setOf(' '), ProofKind.DOM_ATTRIBUTE) { c -> c + " $ATTR_NAME=" + c }
    val JS_DQ = Probe("js-dq", setOf('"', ';'), ProofKind.JS_IDENTIFIER) { c -> c + "\";$VAR_PREFIX$c=1;//" }
    val JS_SQ = Probe("js-sq", setOf('\'', ';'), ProofKind.JS_IDENTIFIER) { c -> c + "';$VAR_PREFIX$c=1;//" }
    val JS_TEMPLATE = Probe("js-template", setOf('`', ';'), ProofKind.JS_IDENTIFIER) { c -> c + "`;$VAR_PREFIX$c=1;//" }
    val JS_CODE = Probe("js-code", setOf(';'), ProofKind.JS_IDENTIFIER) { c -> c + ";$VAR_PREFIX$c=1;//" }
    val COMMENT_CLOSE = Probe("comment-close", setOf('-', '>', '<'), ProofKind.DOM_TAG) { c -> c + "-->" + tag(c) }

    fun closeTag(name: String) = Probe("close:$name", setOf('<', '/', '>'), ProofKind.DOM_TAG) { c -> c + "</$name>" + tag(c) }

    fun all(): List<Probe> =
        listOf(TAG, ATTR_DQ, ATTR_SQ, ATTR_UNQ, JS_DQ, JS_SQ, JS_TEMPLATE, JS_CODE, COMMENT_CLOSE) + RAW_TEXT_TAGS.map(::closeTag)

    /** Пробы для контекста в порядке предпочтения (сначала с меньшими требованиями к символам). */
    fun candidates(point: ReflectionPoint): List<Probe> = when (point.context) {
        ReflectionContext.HTML_TEXT -> listOf(TAG)
        ReflectionContext.ATTR_DOUBLE_QUOTED -> listOf(ATTR_DQ)
        ReflectionContext.ATTR_SINGLE_QUOTED -> listOf(ATTR_SQ)
        ReflectionContext.ATTR_UNQUOTED, ReflectionContext.TAG_NAME_OR_ATTR_NAME -> listOf(ATTR_UNQ)
        ReflectionContext.ATTR_URL -> when (point.quote) {
            '"' -> listOf(ATTR_DQ)
            '\'' -> listOf(ATTR_SQ)
            else -> listOf(ATTR_UNQ)
        }
        ReflectionContext.SCRIPT_STRING_DQ -> listOf(JS_DQ, closeTag("script"))
        ReflectionContext.SCRIPT_STRING_SQ -> listOf(JS_SQ, closeTag("script"))
        ReflectionContext.SCRIPT_STRING_TEMPLATE -> listOf(JS_TEMPLATE, closeTag("script"))
        ReflectionContext.SCRIPT_CODE -> listOf(JS_CODE, closeTag("script"))
        ReflectionContext.STYLE -> listOf(closeTag("style"))
        ReflectionContext.RCDATA -> listOf(closeTag(if (point.tagName == "title") "title" else "textarea"))
        ReflectionContext.HTML_COMMENT -> listOf(COMMENT_CLOSE)
        ReflectionContext.UNKNOWN -> emptyList()
    }

    /** Чем меньше, тем опаснее отражение и тем раньше оно проверяется. */
    fun danger(context: ReflectionContext): Int = when (context) {
        ReflectionContext.SCRIPT_STRING_DQ, ReflectionContext.SCRIPT_STRING_SQ,
        ReflectionContext.SCRIPT_STRING_TEMPLATE, ReflectionContext.SCRIPT_CODE -> 0
        ReflectionContext.ATTR_DOUBLE_QUOTED, ReflectionContext.ATTR_SINGLE_QUOTED,
        ReflectionContext.ATTR_UNQUOTED, ReflectionContext.ATTR_URL -> 1
        ReflectionContext.HTML_TEXT -> 2
        ReflectionContext.TAG_NAME_OR_ATTR_NAME -> 3
        ReflectionContext.STYLE, ReflectionContext.RCDATA -> 4
        ReflectionContext.HTML_COMMENT -> 5
        ReflectionContext.UNKNOWN -> 9
    }

    /** Проверка при старте: пробы безвредны, содержат канарейку и опираются только на проверяемые символы. */
    fun validate() {
        val sample = "vsxabcdefghij"
        val payloads = all().map { it.id to it.build(sample) } + ("survival" to CharacterSurvival.payload(sample))
        payloads.forEach { (id, value) ->
            check(sample in value) { "Probe $id does not contain the canary" }
            check(!FORBIDDEN.containsMatchIn(value)) { "Probe $id contains a forbidden construct: $value" }
        }
        all().forEach { check(CharacterSurvival.CHARS.containsAll(it.required)) { "Probe ${it.id} requires an unchecked character" } }
    }
}
