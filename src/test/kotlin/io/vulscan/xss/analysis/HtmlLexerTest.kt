package io.vulscan.xss.analysis

import io.vulscan.xss.analysis.ReflectionContext.*
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.Arguments.arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream

class HtmlLexerTest {
    companion object {
        @JvmStatic
        fun table(): Stream<Arguments> = Stream.of(
            arguments("<p>§</p>", HTML_TEXT),
            arguments("§", HTML_TEXT),
            arguments("<p>a</p>§", HTML_TEXT),
            arguments("<a href=\"§\">", ATTR_URL),
            arguments("<a href='§'>", ATTR_URL),
            arguments("<a href=§>", ATTR_URL),
            arguments("<form action=\"§\">", ATTR_URL),
            arguments("<img src=\"§\">", ATTR_URL),
            arguments("<input value=\"§\">", ATTR_DOUBLE_QUOTED),
            arguments("<input value='§'>", ATTR_SINGLE_QUOTED),
            arguments("<input value=§>", ATTR_UNQUOTED),
            arguments("<input value= §>", ATTR_UNQUOTED),
            arguments("<!-- § -->", HTML_COMMENT),
            arguments("<!--§-->", HTML_COMMENT),
            arguments("<script>var a=\"§\";</script>", SCRIPT_STRING_DQ),
            arguments("<script>var a='§';</script>", SCRIPT_STRING_SQ),
            arguments("<script>var a=§;</script>", SCRIPT_CODE),
            arguments("<script>var a=`§`;</script>", SCRIPT_STRING_TEMPLATE),
            arguments("<textarea>§</textarea>", RCDATA),
            arguments("<title>§</title>", RCDATA),
            arguments("<p title=x data-a=\"§>\">", ATTR_DOUBLE_QUOTED),
            arguments("<SCRIPT>var a=\"§\";</SCRIPT>", SCRIPT_STRING_DQ),
            arguments("<P CLASS=\"§\">", ATTR_DOUBLE_QUOTED),
            arguments("<input value=\"§", ATTR_DOUBLE_QUOTED),
            arguments("<style>p{color:§}</style>", STYLE),
            arguments("<p §>", TAG_NAME_OR_ATTR_NAME),
            arguments("<p class=\"a\" §>", TAG_NAME_OR_ATTR_NAME),
            arguments("<§", TAG_NAME_OR_ATTR_NAME),
            arguments("<p>a</p><script>1</script><p>§</p>", HTML_TEXT),
            arguments("<script>var a=\"</script>§\"", HTML_TEXT),
            arguments("<script>var a=\"\\\"§\";</script>", SCRIPT_STRING_DQ),
            arguments("<script>// \"§\n</script>", UNKNOWN),
            arguments("<p data-x='a\"b§'>", ATTR_SINGLE_QUOTED),
            arguments("<a href=\"x\" title=§>", ATTR_UNQUOTED),
            arguments("<textarea>a</textarea>§", HTML_TEXT),
            arguments("<!DOCTYPE html><p>§</p>", HTML_TEXT),
            arguments("<p>§<!-- c --></p>", HTML_TEXT),
            arguments("<p><!-- c -->§</p>", HTML_TEXT),
            arguments("<script src=\"a.js\"></script>§", HTML_TEXT),
            arguments("<img src=x onerror=\"§\">", ATTR_DOUBLE_QUOTED),
            arguments("<script>var a = 1;\nvar b = \"§\";\n</script>", SCRIPT_STRING_DQ),
            arguments("<!--> <p>§</p>", HTML_TEXT),
            arguments("<p\n  class=\"a\"\n  title='§'>", ATTR_SINGLE_QUOTED),
        )

        @JvmStatic
        fun unknownFragments(): Stream<String> = Stream.of(
            "<!DOCTYPE §",
            "<?xml §",
            "</div §>",
            "<![CDATA[ § ]]>",
            "<script>x=/\"§</script>",
            "<script>var a=`\${b}§`;</script>",
            "<script>/* \"§ */</script>",
            "<script>var a = \"abc\n§\";</script>",
        )
    }

    @ParameterizedTest(name = "{0} -> {1}")
    @MethodSource("table")
    fun `marker position is classified`(fragment: String, expected: ReflectionContext) {
        val offset = fragment.indexOf('§')
        val body = fragment.replace("§", "")
        assertThat(HtmlContextClassifier.classify(body, offset).context).isEqualTo(expected)
    }

    @Test
    fun `quote of url attributes is reported`() {
        fun quote(f: String) = HtmlContextClassifier.classify(f.replace("§", ""), f.indexOf('§')).quote
        assertThat(quote("<a href=\"§\">")).isEqualTo('"')
        assertThat(quote("<a href='§'>")).isEqualTo('\'')
        assertThat(quote("<a href=§>")).isNull()
    }

    @Test
    fun `attribute and tag names are reported`() {
        val f = "<INPUT Value=\"§\">"
        val p = HtmlContextClassifier.classify(f.replace("§", ""), f.indexOf('§'))
        assertThat(p.tagName).isEqualTo("input")
        assertThat(p.attrName).isEqualTo("value")
    }

    @ParameterizedTest
    @MethodSource("unknownFragments")
    fun `unclear syntax is never classified as html text`(fragment: String) {
        val context = HtmlContextClassifier.classify(fragment.replace("§", ""), fragment.indexOf('§')).context
        assertThat(context).isNotEqualTo(HTML_TEXT)
    }
}
