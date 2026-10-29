package io.vulscan.xss.report

import io.vulscan.kit.contracts.Fingerprint
import io.vulscan.kit.contracts.FindingPayload
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.Observation
import io.vulscan.kit.contracts.ParameterId
import io.vulscan.kit.contracts.VulnType
import io.vulscan.kit.contracts.XssDetails
import io.vulscan.xss.detect.CharacterSurvival
import io.vulscan.xss.detect.DetectionResult
import io.vulscan.xss.detect.Level
import io.vulscan.xss.detect.Mitigations
import io.vulscan.xss.detect.ProofKind

object XssFindingFactory {
    fun create(result: DetectionResult): FindingPayload {
        require(result.isFinding) { "Result is not a finding: ${result.level}" }
        val target = result.target
        val endpoint = target.endpoint
        val parameter = target.parameter
        val point = requireNotNull(result.point)
        val observe = result.observeEndpoint
        val stored = observe != null
        val vulnType = if (stored) VulnType.XSS_STORED else VulnType.XSS_REFLECTED
        val score = XssConfidenceScorer.score(result)
        val proven = result.level == Level.STRUCTURE
        val label = ContextLabels.label(point.context)

        val observations = buildList {
            add(Observation("reflectionCount", result.reflectionCount.toString()))
            add(Observation("requestsUsed", result.requestsUsed.toString()))
            result.probe?.let { add(Observation("probe", it.id)) }
            add(Observation("level", if (proven) "L3_STRUCTURE" else "L2_CHARS_SURVIVE"))
            add(Observation("survivalScope", "per-context"))
            add(Observation("confidenceBase", score.base.toString()))
            if (score.adjustments.isNotEmpty()) add(Observation("confidenceAdjustments", score.describe()))
            if (observe != null) {
                add(Observation("sourceEndpoint", "${endpoint.method} ${endpoint.url}"))
                add(Observation("observeEndpoint", "${observe.method} ${observe.url}"))
                add(Observation("writesPerformed", result.writesPerformed.toString()))
            }
            result.note?.let { add(Observation("note", it)) }
        }

        val chars = CharacterSurvival.CHARS.filter { it in result.surviving }.map { it.toString() }
        val summary = buildString {
            if (observe != null) {
                append("Значение параметра «${parameter.name}» (${parameter.location}) сохраняется приложением и выводится на странице наблюдения ${observe.url} в контексте «$label».")
            } else {
                append("Значение параметра «${parameter.name}» (${parameter.location}) попадает в ответ в контексте «$label».")
            }
            if (chars.isNotEmpty()) append(" Служебные символы проходят без обезвреживания: ${chars.joinToString(" ") { "`$it`" }}.")
            if (proven) {
                append(
                    when (result.probe?.proofKind) {
                        ProofKind.JS_IDENTIFIER ->
                            " Разбор показал, что внедрённый идентификатор оказался в коде скрипта: выйти из строки JavaScript возможно."
                        ProofKind.DOM_ATTRIBUTE ->
                            " Разбор DOM показал, что внедрённый атрибут стал частью элемента: из значения атрибута выйти возможно."
                        else -> " Разбор DOM показал, что внедрённый элемент стал частью документа."
                    },
                )
                append(" Выполнение скрипта в браузере не проверялось, поэтому уязвимость отмечена как вероятная.")
            } else {
                append(" Внедрение разметки не доказано, поэтому уязвимость отмечена как подозрение.")
            }
            if (Mitigations.CSP in result.mitigations) {
                append(" Политика Content-Security-Policy запрещает inline-скрипты, критичность снижена.")
            }
            if (stored) append(" Проверка записала в приложение тестовые данные (записей: ${result.writesPerformed}); их можно удалить вручную.")
        }

        return FindingPayload(
            moduleType = ModuleType.XSS,
            vulnType = vulnType,
            cwe = "CWE-79",
            endpointId = endpoint.endpointId,
            method = endpoint.method,
            url = endpoint.url,
            parameter = ParameterId(parameter.name, parameter.location),
            verdict = XssSeverityPolicy.verdict(result),
            severity = XssSeverityPolicy.severity(result),
            confidence = score.total,
            fingerprint = fingerprint(result),
            title = (if (stored) "Хранимый XSS" else "Отражённый XSS") + ": параметр ${parameter.name} ($label)",
            summary = summary,
            recommendation = Recommendations.forContext(point.context) +
                if (stored) " Кодируйте данные при каждом выводе сохранённых записей, а не только при записи." else "",
            details = XssDetails(
                type = vulnType,
                context = point.context.name,
                survivingChars = chars,
                injectionProof = if (proven) requireNotNull(result.probe).injectionProof else "NONE",
                mitigations = result.mitigations,
            ),
            evidence = EvidenceBuilder.build(result, observations),
        )
    }

    /**
     * Reflected: XSS / REFLECTED / метод / путь (+ имена параметров строки запроса) / место / имя / группа контекста.
     * Stored: XSS / STORED / то же для источника / OBSERVE / путь страницы наблюдения / группа контекста.
     */
    fun fingerprint(result: DetectionResult): String {
        val endpoint = result.target.endpoint
        val parameter = result.target.parameter
        val contextClass = ContextLabels.fingerprintClass(requireNotNull(result.point).context)
        val observe = result.observeEndpoint
        val head = arrayOf(
            "XSS", if (observe != null) "STORED" else "REFLECTED", endpoint.method.name, pathPart(endpoint.url),
            parameter.location.name, parameter.name,
        )
        return if (observe == null) {
            Fingerprint.of(*head, contextClass)
        } else {
            Fingerprint.of(*head, "OBSERVE", pathPart(observe.url), contextClass)
        }
    }

    private fun pathPart(url: String): String {
        val withoutOrigin = url.replace(Regex("^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*"), "").substringBefore('#')
        val path = withoutOrigin.substringBefore('?')
        val queryNames = withoutOrigin.substringAfter('?', "").split('&').filter { it.isNotEmpty() }
            .map { it.substringBefore('=') }.sorted().joinToString(",")
        return if (queryNames.isEmpty()) path else "$path?$queryNames"
    }
}
