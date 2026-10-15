"""PHP: superglobals are the source, and nearly every dangerous primitive is a plain function."""
from __future__ import annotations

from ..model import (Adapter, Barrier, Guard, ImportRule, LangSpec, ParamSource,
                     Propagator, Sanitizer, Sink, Source)

ADAPTER = Adapter(
    lang="php",
    call_nodes=("function_call_expression", "member_call_expression",
                "scoped_call_expression", "object_creation_expression"),
    call_fn_field="function",
    call_args_field="arguments",
    arg_wrapper_nodes=("argument",),
    identifier_nodes=("name", "variable_name"),
    member_nodes=("member_access_expression",),
    member_obj_field="object",
    member_prop_field="name",
    index_nodes=("subscript_expression",),
    assign_nodes=("assignment_expression", "augmented_assignment_expression"),
    assign_target_field="left",
    assign_value_field="right",
    function_nodes=("function_definition", "method_declaration", "anonymous_function",
                    "arrow_function"),
    function_name_field="name",
    function_params_field="parameters",
    function_body_field="body",
    param_nodes=("variable_name", "simple_parameter"),
    string_nodes=("string", "encapsed_string", "integer", "float"),
    number_nodes=("integer", "float", "boolean"),
    interp_string_nodes=("encapsed_string",),
    interp_inner_nodes=("variable_name", "dynamic_variable_name"),
    concat_nodes=("binary_expression",),
    concat_operators=(".", "+"),
    if_nodes=("if_statement", "else_if_clause"),
    loop_nodes=("for_statement", "foreach_statement", "while_statement", "do_statement"),
    try_nodes=("try_statement",),
    block_nodes=("compound_statement", "program"),
    return_nodes=("return_statement",),
    # path sensitivity. PHP spells the taken arm `body`, not `consequence`.
    consequence_field="body",
    else_nodes=("else_clause",),
    terminator_nodes=("return_statement", "throw_statement", "break_statement",
                      "continue_statement", "exit_statement"),
    terminator_calls=(r"^(exit|die)$",),
    binary_nodes=("binary_expression",),
    unary_nodes=("unary_op_expression", "unary_expression"),
    and_operators=("&&", "and"),
    or_operators=("||", "or"),
    not_operators=("!",),
    true_literals=("true", "TRUE"),
    false_literals=("false", "FALSE"),
    null_literals=("null", "NULL"),
    length_fns=("strlen", "mb_strlen", "count", "sizeof"),
    transparent_calls=("strval",),
)

SOURCES = (
    Source("php.super", r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b", "PHP superglobal"),
    Source("php.input", r"php://input", "raw request body"),
    Source("php.headers", r"\bgetallheaders\b|\bapache_request_headers\b", "request headers"),
    Source("php.argv", r"\$argv\b", "command line argument", kind="cli"),
)

SINKS = (
    Sink("php.log", r"^(error_log|var_dump|print_r|syslog)$", "disclosure",
         "credential written to a log",
         "The value came from a credential-named source.",
         args=(-1,), weight=6, value_kinds=("secret",)),
    Sink("php.exec", r"^(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)$", "cmd",
         "shell command built from input",
         "These run the string through a shell; attacker text becomes a command.",
         args=(0,), weight=9),
    Sink("php.eval", r"^(eval|assert|create_function)$", "code", "eval on untrusted data",
         "Arbitrary PHP execution.", args=(0,), weight=9),
    Sink("php.unserialize", r"^unserialize$", "deser", "unserialize of untrusted data",
         "Object injection through magic methods such as __wakeup/__destruct.",
         args=(0,), weight=9),
    Sink("php.sql", r"(?:^|\.|->)(query|exec|real_query|multi_query|prepare)$|^mysqli?_query$",
         "sqli", "SQL built from untrusted input",
         "The query text carries attacker data instead of a bound parameter.",
         args=(0, 1), weight=9),
    Sink("php.file", r"^(file_get_contents|file_put_contents|fopen|readfile|unlink|copy|rename|"
                     r"scandir|glob|require|include)$", "path",
         "filesystem path from untrusted input",
         "Path traversal, and for include/require it is code execution.", args=(0,), weight=8),
    Sink("php.upload", r"^move_uploaded_file$", "upload", "upload moved to an untrusted path",
         "A webshell lands in a served directory if the destination is attacker-chosen.",
         args=(1,), weight=8),
    Sink("php.header", r"^header$", "redirect", "response header built from input",
         "Header injection or an open redirect through Location.", args=(0,), weight=7),
    Sink("php.curl", r"^curl_setopt$", "ssrf", "cURL target from untrusted input",
         "Server-side request forgery.", args=(2,), weight=7),
    Sink("php.extract", r"^extract$", "proto", "extract() on untrusted array",
         "Overwrites arbitrary local variables from request data.", args=(0,), weight=8),
)

SANITIZERS = (
    Sanitizer("php.escapeshell", r"^(escapeshellarg|escapeshellcmd)$", "escapeshell*()",
              kills=("cmd",)),
    Sanitizer("php.int", r"^(intval|floatval|settype)$", "integer cast"),
    Sanitizer("php.htmlspecial", r"^(htmlspecialchars|htmlentities|strip_tags)$",
              "HTML escaping", kills=("xss",)),
    Sanitizer("php.sqlescape", r"(?:^|_)real_escape_string$|^addslashes$", "SQL escaping",
              kills=("sqli",)),
    Sanitizer("php.basename", r"^basename$", "basename()", kills=("path", "upload")),
    Sanitizer("php.filter", r"^filter_var$", "filter_var()"),
)

PROPAGATORS = (
    Propagator("php.string", r"^(strval|trim|strtolower|strtoupper|sprintf|implode|str_replace|"
                             r"substr|rawurldecode|urldecode|json_decode)$"),
)

GUARDS = (
    Guard("php.preg_match", r"^preg_match(_all)?$", "regex", value_arg=1, pattern_arg=0),
    Guard("php.in_array", r"^in_array$", "membership", value_arg=0, pattern_arg=1),
    Guard("php.array_key", r"^array_key_exists$", "membership", value_arg=0, pattern_arg=1),
    Guard("php.starts", r"^str_starts_with$", "prefix", value_arg=0, pattern_arg=1),
    Guard("php.ends", r"^str_ends_with$", "suffix", value_arg=0, pattern_arg=1),
    Guard("php.contains", r"^str_contains$", "contains", value_arg=0, pattern_arg=1),
    Guard("php.numeric", r"^(is_numeric|is_int|is_float|ctype_digit)$", "numeric", value_arg=0),
    Guard("php.alnum", r"^ctype_alnum$", "regex", value_arg=0, literal=r"^[A-Za-z0-9]+$"),
    Guard("php.alpha", r"^ctype_alpha$", "regex", value_arg=0, literal=r"^[A-Za-z]+$"),
)

IMPORTS = (
    # The path is routinely built from a constant - `require_once ROOT . 'lib/x.php'` - so
    # anything up to the first quote is skipped and the literal part is what gets resolved.
    ImportRule("php.require",
               r"\b(?:require|include)(?:_once)?\s*\(?[^;'\"\n]{0,80}['\"]"
               r"(?P<spec>[^'\"\n]+)['\"]",
               kind="relative"),
    ImportRule("php.use",
               r"^\s*use\s+(?P<spec>[\w\\]+)(?:\s+as\s+(?P<alias>\w+))?\s*;", kind="class"),
)

EXPORTS = (r"\bfunction\s+(\w+)\s*\(", r"\bclass\s+(\w+)", r"\btrait\s+(\w+)")

BINDINGS = (
    r"(?P<type>[A-Z]\w*)\s+\$(?P<name>\w+)",
    r"\$(?:this->)?(?P<name>\w+)\s*=\s*new\s+(?P<type>[A-Z]\w*)",
)

SPEC = LangSpec(
    lang="php",
    adapter=ADAPTER,
    sources=SOURCES,
    sinks=SINKS,
    sanitizers=SANITIZERS,
    propagators=PROPAGATORS,
    handler_params=(),
    param_sources=(
        ParamSource("php.symfony", "symfony request",
                    type_pattern=r"(?:^|[\\])Request$"),
        ParamSource("php.psr", "psr-7 request",
                    type_pattern=r"ServerRequestInterface$"),
    ),
    never_params=(r"(?:^|[\\])(?:Response|ResponseInterface|LoggerInterface|Logger|"
                  r"ContainerInterface|EntityManager|Connection)$",
                  r"^\$?(?:logger|log|db|conn|em|container|app|response|res)$"),
    barriers=(
        Barrier("php.log", r"^(error_log|syslog|trigger_error)$", "logging"),
        Barrier("php.len", r"^(count|strlen|is_array|is_string|isset|empty|gettype)$",
                "inspection"),
    ),
    shells=(r"^(/bin/)?(sh|bash|zsh)$", r"^cmd(\.exe)?$"),
    replacers=((r"^str_replace$", 0, 1),),
    guards=GUARDS,
    imports=IMPORTS,
    exports=EXPORTS,
    bindings=BINDINGS,
)
