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

object XssFindingFactory {
    fun create(result: DetectionResult): FindingPayload {
        require(result.isFinding) { "Result is not a finding: ${result.level}" }
        val target = result.target
        val endpoint = target.endpoint
        val parameter = target.parameter
        val point = requireNotNull(result.point)
        val score = XssConfidenceScorer.score(result)
        val verdict = XssSeverityPolicy.verdict(result)
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
        }

        val chars = CharacterSurvival.CHARS.filter { it in result.surviving }.map { it.toString() }
        val summary = buildString {
            append("Значение параметра «${parameter.name}» (${parameter.location}) попадает в ответ в контексте «$label».")
            if (chars.isNotEmpty()) append(" Служебные символы проходят без обезвреживания: ${chars.joinToString(" ") { "`$it`" }}.")
            if (proven) {
                append(
                    when (result.probe?.proofKind) {
                        io.vulscan.xss.detect.ProofKind.JS_IDENTIFIER ->
                            " Разбор показал, что внедрённый идентификатор оказался в коде скрипта: выйти из строки JavaScript возможно."
                        io.vulscan.xss.detect.ProofKind.DOM_ATTRIBUTE ->
                            " Разбор DOM показал, что внедрённый атрибут стал частью элемента: из значения атрибута выйти возможно."
                        else -> " Разбор DOM показал, что внедрённый элемент стал частью документа."
                    },
                )
                append(" Выполнение скрипта в браузере не проверялось, поэтому уязвимость отмечена как вероятная.")
            } else {
                append(" Внедрение разметки не доказано, поэтому уязвимость отмечена как подозрение.")
            }
            if (io.vulscan.xss.detect.Mitigations.CSP in result.mitigations) {
                append(" Политика Content-Security-Policy запрещает inline-скрипты, критичность снижена.")
            }
        }

        return FindingPayload(
            moduleType = ModuleType.XSS,
            vulnType = VulnType.XSS_REFLECTED,
            cwe = "CWE-79",
            endpointId = endpoint.endpointId,
            method = endpoint.method,
            url = endpoint.url,
            parameter = ParameterId(parameter.name, parameter.location),
            verdict = verdict,
            severity = XssSeverityPolicy.severity(result),
            confidence = score.total,
            fingerprint = fingerprint(result),
            title = "Отражённый XSS: параметр ${parameter.name} ($label)",
            summary = summary,
            recommendation = Recommendations.forContext(point.context),
            details = XssDetails(
                type = VulnType.XSS_REFLECTED,
                context = point.context.name,
                survivingChars = chars,
                injectionProof = if (proven) requireNotNull(result.probe).injectionProof else "NONE",
                mitigations = result.mitigations,
            ),
            evidence = EvidenceBuilder.build(result, observations),
        )
    }

    /** XSS / REFLECTED / метод / путь (+ имена параметров строки запроса) / место / имя / группа контекста. */
    fun fingerprint(result: DetectionResult): String {
        val endpoint = result.target.endpoint
        val parameter = result.target.parameter
        val withoutOrigin = endpoint.url.replace(Regex("^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*"), "").substringBefore('#')
        val path = withoutOrigin.substringBefore('?')
        val queryNames = withoutOrigin.substringAfter('?', "").split('&').filter { it.isNotEmpty() }
            .map { it.substringBefore('=') }.sorted().joinToString(",")
        val pathPart = if (queryNames.isEmpty()) path else "$path?$queryNames"
        return Fingerprint.of(
            "XSS", "REFLECTED", endpoint.method.name, pathPart, parameter.location.name, parameter.name,
            ContextLabels.fingerprintClass(requireNotNull(result.point).context),
        )
    }
}
