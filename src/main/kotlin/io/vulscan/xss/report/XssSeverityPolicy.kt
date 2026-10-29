package io.vulscan.xss.report

import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import io.vulscan.xss.detect.DetectionResult
import io.vulscan.xss.detect.Level
import io.vulscan.xss.detect.Mitigations

/** Без выполнения в браузере критичность не выше MEDIUM, CRITICAL модуль не назначает никогда; CSP снижает на одну ступень. */
object XssSeverityPolicy {
    fun verdict(result: DetectionResult): Verdict = when (result.level) {
        Level.STRUCTURE -> Verdict.LIKELY
        Level.SURVIVES -> Verdict.SUSPECTED
        else -> error("Verdict is defined only for findings, got ${result.level}")
    }

    fun severity(result: DetectionResult): Severity {
        val base = when (verdict(result)) {
            Verdict.CONFIRMED -> Severity.HIGH
            Verdict.LIKELY -> Severity.MEDIUM
            Verdict.SUSPECTED -> Severity.LOW
        }
        return if (Mitigations.CSP in result.mitigations) lowerOne(base) else base
    }

    fun lowerOne(severity: Severity): Severity = when (severity) {
        Severity.CRITICAL -> Severity.HIGH
        Severity.HIGH -> Severity.MEDIUM
        Severity.MEDIUM -> Severity.LOW
        Severity.LOW, Severity.INFO -> Severity.INFO
    }
}
