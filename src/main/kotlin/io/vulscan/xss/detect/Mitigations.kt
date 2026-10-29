package io.vulscan.xss.detect

object Mitigations {
    const val CSP = "CSP"

    /** CSP считается смягчающим, если запрещает inline-скрипты (нет 'unsafe-inline' либо он отключён nonce/hash/strict-dynamic). */
    fun of(headers: Map<String, String>): List<String> {
        val csp = headers.entries.firstOrNull { it.key.equals("content-security-policy", ignoreCase = true) }?.value ?: return emptyList()
        val directives = csp.split(';').map { it.trim() }.filter { it.isNotEmpty() }.associate { d ->
            val parts = d.split(Regex("\\s+"))
            parts.first().lowercase() to parts.drop(1).map { it.lowercase() }
        }
        val sources = directives["script-src"] ?: directives["default-src"] ?: return emptyList()
        val inlineAllowed = "'unsafe-inline'" in sources &&
            sources.none { it.startsWith("'nonce-") || it.startsWith("'sha") || it == "'strict-dynamic'" }
        return if (inlineAllowed) emptyList() else listOf(CSP)
    }
}
