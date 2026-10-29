package io.vulscan.xss.report

import io.vulscan.xss.analysis.ReflectionContext

object ContextLabels {
    fun label(context: ReflectionContext): String = when (context) {
        ReflectionContext.HTML_TEXT -> "текст HTML"
        ReflectionContext.HTML_COMMENT -> "HTML-комментарий"
        ReflectionContext.ATTR_DOUBLE_QUOTED -> "атрибут в двойных кавычках"
        ReflectionContext.ATTR_SINGLE_QUOTED -> "атрибут в одинарных кавычках"
        ReflectionContext.ATTR_UNQUOTED -> "атрибут без кавычек"
        ReflectionContext.ATTR_URL -> "атрибут с URL"
        ReflectionContext.SCRIPT_CODE -> "код JavaScript"
        ReflectionContext.SCRIPT_STRING_DQ -> "строка JavaScript в двойных кавычках"
        ReflectionContext.SCRIPT_STRING_SQ -> "строка JavaScript в одинарных кавычках"
        ReflectionContext.SCRIPT_STRING_TEMPLATE -> "шаблонная строка JavaScript"
        ReflectionContext.STYLE -> "блок стилей"
        ReflectionContext.RCDATA -> "содержимое textarea/title"
        ReflectionContext.TAG_NAME_OR_ATTR_NAME -> "внутри тега"
        ReflectionContext.UNKNOWN -> "неопределённый контекст"
    }

    /** Группа контекстов для отпечатка: близкие по природе контексты считаются одной уязвимостью. */
    fun fingerprintClass(context: ReflectionContext): String = when (context) {
        ReflectionContext.HTML_TEXT -> "HTML_TEXT"
        ReflectionContext.ATTR_DOUBLE_QUOTED, ReflectionContext.ATTR_SINGLE_QUOTED,
        ReflectionContext.ATTR_UNQUOTED, ReflectionContext.ATTR_URL -> "ATTRIBUTE"
        ReflectionContext.SCRIPT_CODE, ReflectionContext.SCRIPT_STRING_DQ, ReflectionContext.SCRIPT_STRING_SQ,
        ReflectionContext.SCRIPT_STRING_TEMPLATE -> "SCRIPT"
        ReflectionContext.STYLE -> "STYLE"
        ReflectionContext.RCDATA -> "RCDATA"
        ReflectionContext.HTML_COMMENT -> "COMMENT"
        ReflectionContext.TAG_NAME_OR_ATTR_NAME -> "TAG"
        ReflectionContext.UNKNOWN -> "UNKNOWN"
    }
}

object Recommendations {
    private const val COMMON =
        " Дополнительно задайте заголовок Content-Security-Policy без 'unsafe-inline' для script-src и проверяйте входные данные по белому списку."

    fun forContext(context: ReflectionContext): String = when (context) {
        ReflectionContext.HTML_TEXT, ReflectionContext.HTML_COMMENT, ReflectionContext.TAG_NAME_OR_ATTR_NAME ->
            "Кодируйте все данные пользователя при выводе в HTML (&, <, >, \", ') средствами шаблонизатора с автоэкранированием; не отключайте экранирование для пользовательских значений.$COMMON"
        ReflectionContext.ATTR_DOUBLE_QUOTED, ReflectionContext.ATTR_SINGLE_QUOTED, ReflectionContext.ATTR_UNQUOTED, ReflectionContext.ATTR_URL ->
            "Всегда заключайте значения атрибутов в кавычки и кодируйте кавычки, <, > и & в пользовательских данных. Для атрибутов с URL разрешайте только схемы http и https.$COMMON"
        ReflectionContext.SCRIPT_CODE, ReflectionContext.SCRIPT_STRING_DQ, ReflectionContext.SCRIPT_STRING_SQ, ReflectionContext.SCRIPT_STRING_TEMPLATE ->
            "Не вставляйте пользовательские данные внутрь <script>. Передавайте их через data-атрибуты или JSON с экранированием (в том числе <, >, U+2028/U+2029) и читайте через JSON.parse.$COMMON"
        ReflectionContext.STYLE ->
            "Не вставляйте пользовательские данные в блоки <style>; выбирайте стиль из фиксированного набора допустимых значений.$COMMON"
        ReflectionContext.RCDATA ->
            "Кодируйте <, > и & в содержимом textarea и title, чтобы нельзя было закрыть элемент.$COMMON"
        ReflectionContext.UNKNOWN ->
            "Кодируйте пользовательские данные в соответствии с контекстом вывода.$COMMON"
    }
}
