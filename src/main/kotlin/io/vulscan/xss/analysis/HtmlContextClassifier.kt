package io.vulscan.xss.analysis

/** Определяет контекст отражения: HTML-автомат, а внутри `<script>` ещё и лексер JavaScript. */
object HtmlContextClassifier {
    fun classify(body: String, offset: Int): ReflectionPoint {
        val state = HtmlLexer.stateAt(body, offset)
        if (state.context != ReflectionContext.SCRIPT_CODE) {
            return ReflectionPoint(offset, state.context, state.quote, state.tagName, state.attrName)
        }
        val script = body.substring(state.rawStart.coerceAtLeast(0), offset.coerceIn(0, body.length).coerceAtLeast(state.rawStart.coerceAtLeast(0)))
        val context = when (JsStringLexer.stateAt(script, script.length)) {
            JsState.CODE -> ReflectionContext.SCRIPT_CODE
            JsState.STRING_DQ -> ReflectionContext.SCRIPT_STRING_DQ
            JsState.STRING_SQ -> ReflectionContext.SCRIPT_STRING_SQ
            JsState.TEMPLATE -> ReflectionContext.SCRIPT_STRING_TEMPLATE
            JsState.LINE_COMMENT, JsState.BLOCK_COMMENT, JsState.UNKNOWN -> ReflectionContext.UNKNOWN
        }
        return ReflectionPoint(offset, context, null, "script", null)
    }
}
