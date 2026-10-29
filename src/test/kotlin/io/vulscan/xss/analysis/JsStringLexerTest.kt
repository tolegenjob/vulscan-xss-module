package io.vulscan.xss.analysis

import io.vulscan.xss.analysis.JsState.*
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

class JsStringLexerTest {
    private fun state(fragment: String) = JsStringLexer.stateAt(fragment.replace("§", ""), fragment.indexOf('§'))

    @Test
    fun `escaped quotes stay inside the string`() {
        assertThat(state("var a=\"x\\\"§")).isEqualTo(STRING_DQ)
        assertThat(state("var a='it\\'s§")).isEqualTo(STRING_SQ)
    }

    @Test
    fun `closing quote returns to code`() {
        assertThat(state("var a=\"x\"; b = §")).isEqualTo(CODE)
        assertThat(state("var a=\"x\\\\\"; §")).isEqualTo(CODE)
    }

    @Test
    fun `comments are recognised`() {
        assertThat(state("// \"§")).isEqualTo(LINE_COMMENT)
        assertThat(state("/* \"§")).isEqualTo(BLOCK_COMMENT)
        assertThat(state("// c\nvar a = \"§")).isEqualTo(STRING_DQ)
        assertThat(state("/* c */ var a = '§")).isEqualTo(STRING_SQ)
    }

    @Test
    fun `template literal is recognised, nested expressions are not parsed`() {
        assertThat(state("var a=`x§")).isEqualTo(TEMPLATE)
        assertThat(state("var a=`x\${y}§")).isEqualTo(UNKNOWN)
    }

    @Test
    fun `regex literal makes the result unknown but division does not`() {
        assertThat(state("x = /\"§")).isEqualTo(UNKNOWN)
        assertThat(state("a = b / 2; c = \"§")).isEqualTo(STRING_DQ)
        assertThat(state("return /\"§")).isEqualTo(UNKNOWN)
    }

    @Test
    fun `unterminated string at a line break is unknown`() {
        assertThat(state("var a = \"abc\n§")).isEqualTo(UNKNOWN)
    }

    @ParameterizedTest
    @CsvSource(
        delimiter = '|',
        value = [
            "var a=\"X\";vsxvX=1;//\";|true",
            "var a=\"X\\\";vsxvX=1;//\";|false",
            "var a='X';vsxvX=1;//';|true",
            "var a=\"x;vsxvX=1\";|false",
            "// vsxvX=1|false",
            "/* vsxvX */|false",
        ],
    )
    fun `identifier is found only when it is real code`(script: String, expected: Boolean) {
        assertThat("vsxvX" in JsStringLexer.identifiersInCode(script)).isEqualTo(expected)
    }

    @Test
    fun `ambiguous scripts yield no identifiers`() {
        assertThat(JsStringLexer.identifiersInCode("x = /\"/; vsxvX=1;")).isEmpty()
    }
}
