package io.vulscan.xss.detect

import io.vulscan.xss.analysis.JsStringLexer
import org.jsoup.Jsoup

/** Проверка того, что внедрённая разметка действительно стала частью DOM (разбор делает jsoup, а не регулярные выражения). */
object DomProof {
    fun tagInjected(html: String, canary: String): Boolean =
        Jsoup.parse(html).getElementsByTag(ProbeLibrary.TAG_NAME).any { it.id() == canary }

    fun attributeInjected(html: String, canary: String): Boolean =
        Jsoup.parse(html).select("[${ProbeLibrary.ATTR_NAME}]").any { it.attr(ProbeLibrary.ATTR_NAME) == canary }
}

/** Проверка выхода из JS-строки: внедрённый идентификатор должен оказаться в коде, а не в строке или комментарии. */
object JsProof {
    fun identifierInjected(html: String, canary: String): Boolean {
        val name = ProbeLibrary.VAR_PREFIX + canary
        return Jsoup.parse(html).select("script").any { name in JsStringLexer.identifiersInCode(it.data()) }
    }
}
