package io.vulscan.xss.analysis

data class Reflection(val offset: Int)

object ReflectionLocator {
    /** Все непересекающиеся вхождения [canary] в [body]. */
    fun find(body: String, canary: String): List<Reflection> {
        if (canary.isEmpty()) return emptyList()
        val found = mutableListOf<Reflection>()
        var from = 0
        while (true) {
            val index = body.indexOf(canary, from)
            if (index < 0) return found
            found += Reflection(index)
            from = index + canary.length
        }
    }
}

/** Ответ, в котором браузер разбирает HTML. Остальные типы (JSON, text/plain) XSS через отражение не создают. */
object ResponseKind {
    private val HTML = setOf("text/html", "application/xhtml+xml")

    fun isHtml(contentType: String?): Boolean {
        val media = contentType?.substringBefore(';')?.trim()?.lowercase() ?: return false
        return media in HTML
    }
}
