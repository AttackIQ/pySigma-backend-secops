import json
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
from typing import Any, ClassVar

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionType,
    ConditionValueExpression,
)
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.pipelines.secops.yara_l import yara_l_pipeline
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaQueryExpression,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)


@dataclass
class ExpressionPair:
    positive: str | None
    negative: str | None


class SecOpsBackend(TextQueryBackend):
    """Google SecOps UDM backend.

    This backend converts Sigma rules into UDM queries with these considerations:
    - UDM search does not support IN operator, so we use eq_token with regex.
    - Forward slashes denote regex in UDM, so we escape them in strings.
    - UDM search is case-sensitive, so we add nocase operator when necessary.
    - In NOT operations, UDM matches only the first NOT condition, so we split
      NOT IN regex into multiple conditions.
    - NOT gives inconsistent results vs !=, so we use != instead of NOT.
    """

    name: ClassVar[str] = "Google SecOps UDM backend"
    identifier: ClassVar[str] = "secops"
    formats: dict[str, str] = {
        "default": "Plain UDM queries",
        "yara_l": "YARA-L 2.0 Detection Rules Output Format",
    }

    udm_schema: ClassVar[dict[str, Any]] = json.loads(
        resources.read_text("sigma.pipelines.secops", "udm_field_schema.json")
    )

    output_format_processing_pipeline: ClassVar[dict[str, ProcessingPipeline]] = {
        "default": ProcessingPipeline(),
        "yara_l": yara_l_pipeline(),
    }

    requires_pipeline: bool = True

    precedence: ClassVar[tuple[type[ConditionItem], type[ConditionItem], type[ConditionItem]]] = (
        ConditionOR,
        ConditionAND,
        ConditionNOT,
    )

    group_expression: ClassVar[str] = "({expr})"

    token_separator: str = " "
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = "="
    ne_token: ClassVar[str] = "!="

    eq_expression: ClassVar[str] = "{field} {backend.eq_token} {value}"  # Expression for field = value
    ne_expression: ClassVar[str] = "{field} {backend.ne_token} {value}"  # Expression for field != value
    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "?"
    add_escaped: ClassVar[str] = "\\"
    re_not_expression: ClassVar[str] = "{field} != /{regex}/ nocase"
    re_expression: ClassVar[str] = "{field} = /{regex}/ nocase"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[tuple[str]] = ('"', "/")
    add_escaped_re: ClassVar[str] = "/"

    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    field_null_expression: ClassVar[str] = '{field} = ""'
    field_exists_expression: ClassVar[str] = '{field} != ""'
    field_not_exists_expression: ClassVar[str] = '{field} = ""'

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = False
    in_expressions_allow_wildcards: ClassVar[bool] = True
    field_in_list_expression: ClassVar[str] = "{field} {op} /{list}/ nocase"
    or_in_operator: ClassVar[str] = "="
    list_separator: ClassVar[str] = "|"

    unbound_value_str_expression: ClassVar[str] = '"{value}"'
    unbound_value_num_expression: ClassVar[str] = "{value}"
    unbound_value_re_expression: ClassVar[str] = "{value}"

    # String matching operators. if none is appropriate eq_token is used.
    # Since we use regex, we add '.*' where appropriate in convert_value_str.
    startswith_expression: ClassVar[str | None] = "{field} = /^{value}/ nocase"
    case_sensitive_startswith_expression: ClassVar[str | None] = "{field} = /^{value}/"
    not_startswith_expression: ClassVar[str | None] = "{field} != /^{value}/ nocase"
    endswith_expression: ClassVar[str | None] = "{field} = /{value}$/ nocase"
    case_sensitive_endswith_expression: ClassVar[str | None] = "{field} = /{value}$/"
    not_endswith_expression: ClassVar[str | None] = "{field} != /{value}$/ nocase"
    contains_expression: ClassVar[str | None] = "{field} = /{value}/ nocase"
    case_sensitive_contains_expression: ClassVar[str | None] = "{field} = /{value}/"
    not_contains_expression: ClassVar[str | None] = "{field} != /{value}/ nocase"
    wildcard_match_expression: ClassVar[str | None] = (
        None  # Special expression if wildcards can't be matched with the eq_token operator
    )

    # cidr expressions
    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_expression: ClassVar[str] = 'net.ip_in_range_cidr({field}, "{value}")'

    def __init__(self, processing_pipeline=None, **kwargs):
        super().__init__(processing_pipeline, **kwargs)

    def decide_string_quoting(self, s: SigmaString) -> bool:
        """
        Decide if string is quoted based on the pattern in the class attribute str_quote_pattern. If
        this matches (or not matches if str_quote_pattern_negation is set to True), the string is quoted.
        """
        if self.str_quote == "":  # No quoting if quoting string is empty.
            return False

        if s.contains_special() or self.wildcard_multi in s or self.wildcard_single in s:
            return False

        if self.str_quote_pattern is None:  # Always quote if pattern is not set.
            return True
        else:
            match = bool(self.str_quote_pattern.match(str(s)))
            if self.str_quote_pattern_negation:
                match = not match
            return match

    def convert_value_str(self, s: SigmaString, state: ConversionState, quote_string: bool = True) -> str:
        """Convert a SigmaString into a plain string which can be used in query.

        Override so when the wildcard is removed in startswith, endswith and contains
        expressions, we don't quote the string.
        """
        # Endswith, startswith and contains are converted to regex, so convert SigmaString
        # to regex then to plain string.
        # Remove surrounding '.*' since its not needed in UDM, contains is implied
        if s.contains_special():
            plain_str = s.to_regex(custom_escaped=self.add_escaped_re).to_plain()
            # Remove leading '.*' if present
            if plain_str.startswith(".*"):
                plain_str = plain_str[2:]
            # Remove trailing '.*' if present
            if plain_str.endswith(".*"):
                plain_str = plain_str[:-2]
            return plain_str

        # If the string contains no special characters, we can use the normal conversion.
        converted = s.convert(
            self.escape_char,
            self.wildcard_multi,
            self.wildcard_single,
            self.str_quote + self.add_escaped,
            self.filter_chars,
        )
        if not quote_string:
            return converted
        if self.decide_string_quoting(s):
            return self.quote_string(converted)
        return converted

    @contextmanager
    def _negated_expressions(self, negation: bool = False):
        """Context manager to temporarily swap expressions with their negated versions."""
        if not negation:
            yield
            return

        # Store original expressions
        original_expressions = {
            "eq_expression": self.eq_expression,
            "re_expression": self.re_expression,
            "startswith_expression": self.startswith_expression,
            "endswith_expression": self.endswith_expression,
            "contains_expression": self.contains_expression,
        }

        # Swap to negated versions
        try:
            self.eq_expression = self.ne_expression
            self.re_expression = self.re_not_expression
            self.startswith_expression = self.not_startswith_expression
            self.endswith_expression = self.not_endswith_expression
            self.contains_expression = self.not_contains_expression
            yield
        finally:
            # Restore original expressions
            self.eq_expression = original_expressions["eq_expression"]
            self.re_expression = original_expressions["re_expression"]
            self.startswith_expression = original_expressions["startswith_expression"]
            self.endswith_expression = original_expressions["endswith_expression"]
            self.contains_expression = original_expressions["contains_expression"]

    def convert_condition(
        self, cond: ConditionType, state: ConversionState, parent_cond: ConditionType | None = None
    ) -> Any:
        """
        Convert query of Sigma rule into target data structure (usually query, see above).
        Dispatches to methods (see above) specialized on specific condition parse tree node objects.

        The state mainly contains the deferred list, which is used to collect query parts that are not
        directly integrated into the generated query, but added at a postponed stage of the conversion
        process after the conversion of the condition to a query is finished. This is done in the
        finalize_query method and must be implemented individually.
        """
        if isinstance(cond, ConditionOR):
            if self.decide_convert_condition_as_in_expression(cond, state):
                if isinstance(parent_cond, ConditionNOT):
                    return self.convert_condition_as_in_not_expression(cond, state)
                else:
                    return self.convert_condition_as_in_expression(cond, state)
            else:
                return self.convert_condition_or(cond, state)
        elif isinstance(cond, ConditionAND):
            if isinstance(parent_cond, ConditionNOT):
                return self.convert_condition_and(cond, state, negation=True)
            elif self.decide_convert_condition_as_in_expression(cond, state):
                return self.convert_condition_as_in_expression(cond, state)
            else:
                return self.convert_condition_and(cond, state)
        elif isinstance(cond, ConditionNOT):
            return self.convert_condition_not(cond, state)
        elif isinstance(cond, ConditionFieldEqualsValueExpression):
            negation = bool(isinstance(parent_cond, ConditionNOT))
            return self.convert_condition_field_eq_val(cond, state, negation)
        elif isinstance(cond, ConditionValueExpression):
            return self.convert_condition_val(cond, state)
        else:  # pragma: no cover
            raise TypeError("Unexpected data type in condition parse tree: " + cond.__class__.__name__)

    def convert_condition_field_eq_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState, negation: bool = False
    ) -> Any:
        """Conversion dispatcher of field = value conditions. Dispatches to value-specific methods."""
        with self._negated_expressions(negation):
            if isinstance(cond.value, SigmaCasedString):
                return self.convert_condition_field_eq_val_str_case_sensitive(cond, state)
            elif isinstance(cond.value, SigmaString):
                return self.convert_condition_field_eq_val_str(cond, state)
            elif isinstance(cond.value, SigmaNumber):
                return self.convert_condition_field_eq_val_num(cond, state)
            elif isinstance(cond.value, SigmaBool):
                return self.convert_condition_field_eq_val_bool(cond, state)
            elif isinstance(cond.value, SigmaRegularExpression):
                return self.convert_condition_field_eq_val_re(cond, state)
            elif isinstance(cond.value, SigmaCIDRExpression):
                return self.convert_condition_field_eq_val_cidr(cond, state)
            elif isinstance(cond.value, SigmaCompareExpression):
                return self.convert_condition_field_compare_op_val(cond, state)
            elif isinstance(cond.value, SigmaFieldReference):
                return self.convert_condition_field_eq_field(cond, state)
            elif isinstance(cond.value, SigmaNull):
                return self.convert_condition_field_eq_val_null(cond, state)
            elif isinstance(cond.value, SigmaQueryExpression):
                return self.convert_condition_field_eq_query_expr(cond, state)
            elif isinstance(cond.value, SigmaExists):
                return self.convert_condition_field_eq_val_exists(cond, state)
            elif isinstance(cond.value, SigmaExpansion):
                return self.convert_condition_field_eq_expansion(cond, state)
            else:  # pragma: no cover
                raise TypeError("Unexpected value type class in condition parse tree: " + cond.value.__class__.__name__)

    def convert_condition_or(
        self, cond: ConditionOR, state: ConversionState, negation: bool = False
    ) -> str | DeferredQueryExpression:
        """Conversion of OR conditions."""
        try:
            if (
                self.token_separator == self.or_token
            ):  # don't repeat the same thing triple times if separator equals or token
                joiner = self.or_token
            else:
                joiner = self.token_separator + self.or_token + self.token_separator

            converted = joiner.join(
                converted
                for converted in (
                    (
                        self.convert_condition(arg, state, parent_cond=cond.parent)
                        if self.compare_precedence(cond, arg) or negation
                        else self.convert_condition_group(arg, state)
                    )
                    for arg in cond.args
                )
                if converted is not None and not isinstance(converted, DeferredQueryExpression)
            )

            # Don't group OR conditions if they do not have a parent, i.e. we are at te root level of a detection
            # See backend test `test_secops_or_expression_parens` for example
            if cond.parent is None:
                return converted
            return self.group_expression.format(expr=converted)

        except TypeError as err:  # pragma: no cover
            raise NotImplementedError("Operator 'or' not supported by the backend") from err

    def convert_condition_and(
        self, cond: ConditionAND, state: ConversionState, negation: bool = False
    ) -> str | DeferredQueryExpression:
        """Conversion of AND conditions."""
        try:
            if (
                self.token_separator == self.and_token
            ):  # don't repeat the same thing triple times if separator equals and token
                joiner = self.and_token
            else:
                joiner = self.token_separator + self.and_token + self.token_separator

            converted_parts = [
                converted
                for converted in (
                    (
                        self.convert_condition(arg, state, parent_cond=cond.parent)
                        if self.compare_precedence(cond, arg) or negation or isinstance(arg, ConditionNOT)
                        else self.convert_condition_group(arg, state)
                    )
                    for arg in cond.args
                )
                if converted is not None and not isinstance(converted, DeferredQueryExpression)
            ]
            converted = joiner.join(converted_parts)
            return converted

        except TypeError as err:  # pragma: no cover
            raise NotImplementedError("Operator 'and' not supported by the backend") from err

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> str | DeferredQueryExpression:
        """Conversion of NOT conditions."""
        arg = cond.args[0]
        try:
            # If the argument is an AND condition, we don't want to add extra parentheses
            # since the convert_condition_and method will handle the grouping
            expr = self.convert_condition(arg, state, parent_cond=cond)

            if isinstance(expr, DeferredQueryExpression):
                return expr.negate()
            return expr
        except TypeError as err:  # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend") from err

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        """Conversion of field = string value expressions.

        Override so when wildcard is removed in startswith/endswith/contains expressions,
        we don't quote the string.
        """
        try:
            quote_string = self.decide_string_quoting(cond.value)
            if (  # Check conditions for usage of 'startswith' operator
                self.startswith_expression is not None  # 'startswith' operator is defined in backend
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)  # String ends with wildcard
                and not cond.value[:-1].contains_special()  # Remainder of string doesn't contains special characters
            ):
                expr = (
                    self.startswith_expression
                )  # If all conditions are fulfilled, use 'startswith' operator instead of equal token
                value = cond.value
            elif (  # 'endswith': string starts with wildcard and has no other special chars
                self.endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:].contains_special()
            ):
                expr = self.endswith_expression
                value = cond.value
                # value = SigmaString.from_str(cond.value.to_regex().to_plain())
            elif (  # contains: string starts and ends with wildcard
                self.contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:-1].contains_special()
            ):
                expr = self.contains_expression
                value = cond.value
            elif (  # wildcard match expression: string contains wildcard
                self.wildcard_match_expression is not None and cond.value.contains_special()
            ):
                expr = self.wildcard_match_expression
                value = cond.value
            else:
                expr = self.eq_expression
                # if the field is not an enum, use nocase
                temp_field = cond.field
                if temp_field[0] == "$":
                    temp_field = ".".join(temp_field.split(".")[1:])
                if temp_field not in self.udm_schema.get("Enums", {}):
                    expr += " nocase"
                value = cond.value
            return expr.format(
                field=self.escape_and_quote_field(cond.field),
                value=self.convert_value_str(value, state, quote_string),
                backend=self,
            )
        except TypeError as err:  # pragma: no cover
            raise NotImplementedError(
                "Field equals string value expressions with strings are not supported by the backend."
            ) from err

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str | DeferredQueryExpression:
        """Conversion of field = number value expressions
        Override to add
        """
        try:
            return (
                self.escape_and_quote_field(cond.field)
                + self.token_separator
                + self.eq_token
                + self.token_separator
                + str(cond.value)
            )
        except TypeError as err:  # pragma: no cover
            raise NotImplementedError(
                "Field equals numeric value expressions are not supported by the backend."
            ) from err

    def convert_condition_as_in_expression(
        self, cond: ConditionOR | ConditionAND, state: ConversionState
    ) -> str | DeferredQueryExpression:
        """Conversion of field in value list conditions.

        Overridden since UDM doesn't support IN operator - we use eq_token with regex.
        Replace wildcards with .* and add nocase.
        """

        return self.field_in_list_expression.format(
            field=self.escape_and_quote_field(cond.args[0].field),
            op=self.or_in_operator if isinstance(cond, ConditionOR) else self.and_in_operator,
            list=self.list_separator.join(self.convert_value_for_in_expression(arg.value, state) for arg in cond.args),
        )

    def convert_condition_as_in_not_expression(
        self, cond: ConditionOR | ConditionAND, state: ConversionState
    ) -> str | DeferredQueryExpression:
        """Conversion of field in value list conditions for NOT expressions.

        Overridden since UDM doesn't support IN operator - we use eq_token with regex.
        We also separate each expression with AND instead of using | regex in one expression.
        """
        joiner = self.token_separator + self.and_token + self.token_separator
        converted = [
            self.re_not_expression.format(
                field=self.escape_and_quote_field(cond.args[0].field),
                regex=self.convert_value_for_in_expression(arg.value, state),
            )
            for arg in cond.args
        ]

        return self.group_expression.format(expr=joiner.join(converted))

    def convert_value_for_in_expression(self, value, state):
        """Convert a value for an IN expression.

        SecOps doesn't support IN operator, so we use eq_token with regex.
        We also escape the regex characters in the values.

        Args:
            value (SigmaString): The value to convert.
            state (ConversionState): The conversion state.

        Returns:
            _type_: _description_
        """
        if not isinstance(value, SigmaString):
            value = SigmaString.from_str(str(value))
        return self.convert_value_str(value, state, quote_string=False)

    def finalize_query(
        self,
        rule: SigmaRule,
        query: Any,
        index: int,
        state: ConversionState,
        output_format: str,
    ):
        """
        Finalize query. Dispatches to format-specific method. The index parameter enumerates generated queries if the
        conversion of a Sigma rule results in multiple queries.

        This is the place where syntactic elements of the target format for the specific query are added,
        e.g. adding query metadata.
        """
        backend_query = self.__getattribute__("finalize_query_" + output_format)(rule, query, index, state)

        return backend_query

    def finalize_query_default(self, rule: SigmaRule, query: Any, index: int, state: ConversionState) -> Any:
        """
        Finalize conversion result of a query. Handling of deferred query parts must be implemented by overriding
        this method.
        """
        return self.last_processing_pipeline.postprocess_query(rule, query)

    def finalize_query_yara_l(self, rule: SigmaRule, query: Any, index: int, state: ConversionState) -> Any:
        """
        Finalize conversion result of a query. Handling of deferred query parts must be implemented by overriding
        this method.
        """
        self.last_processing_pipeline.state["output_format"] = "yara_l"
        query = self.last_processing_pipeline.postprocess_query(rule, query)
        return query

    def finalize_output_yara_l(self, queries: list[Any]) -> Any:
        """
        Finalize output. Dispatches to format-specific method.
        """
        return queries
