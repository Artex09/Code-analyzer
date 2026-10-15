"""Java, Go, Ruby and C#.

These carry the same engine but smaller rule sets than python/javascript/php. The dataflow is
real - taint is tracked through assignments and calls the same way - but the source and sink
catalogues cover the common web surface rather than every framework, so treat a quiet result
here as "not yet modelled" rather than "clean".
"""
from __future__ import annotations

from ..model import (Adapter, Barrier, Guard, ImportRule, LangSpec, ParamSource,
                     Propagator, Sanitizer, Sink, Source)

CLASS_BINDINGS = (
    r"(?:private|public|protected|internal)\s+(?:final\s+|readonly\s+|static\s+)*"
    r"(?P<type>[A-Z]\w*)(?:<[^>]*>)?\s+(?P<name>\w+)",
    r"(?P<type>[A-Z]\w*)(?:<[^>]*>)?\s+(?P<name>\w+)\s*=\s*new\s+",
)

RUBY_BINDINGS = (r"@(?P<name>\w+)\s*=\s*(?P<type>[A-Z]\w*)\.new",)

# ------------------------------------------------------------------------ java

JAVA = Adapter(
    lang="java",
    call_nodes=("method_invocation", "object_creation_expression"),
    call_fn_field="name",
    call_args_field="arguments",
    identifier_nodes=("identifier",),
    member_nodes=("field_access",),
    member_obj_field="object",
    member_prop_field="field",
    index_nodes=("array_access",),
    assign_nodes=("assignment_expression",),
    assign_target_field="left",
    assign_value_field="right",
    declarator_nodes=("variable_declarator",),
    declarator_name_field="name",
    declarator_value_field="value",
    function_nodes=("method_declaration", "constructor_declaration", "lambda_expression"),
    function_name_field="name",
    function_params_field="parameters",
    function_body_field="body",
    param_nodes=("identifier", "formal_parameter"),
    string_nodes=("string_literal",),
    number_nodes=("decimal_integer_literal", "true", "false", "null_literal"),
    interp_string_nodes=(),
    concat_nodes=("binary_expression",),
    block_nodes=("block", "program"),
    loop_nodes=("for_statement", "while_statement", "enhanced_for_statement"),
    return_nodes=("return_statement",),
    if_nodes=("if_statement",),
    else_nodes=(),
    terminator_nodes=("return_statement", "throw_statement", "break_statement",
                      "continue_statement"),
    terminator_calls=(r"\bSystem\.exit$",),
    binary_nodes=("binary_expression",),
    unary_nodes=("unary_expression",),
    and_operators=("&&",),
    or_operators=("||",),
    not_operators=("!",),
    true_literals=("true",),
    false_literals=("false",),
    null_literals=("null",),
    length_fns=("length", "size"),
    transparent_calls=("valueOf", "toString"),
)

JAVA_GUARDS = (
    Guard("java.matches", r"^matches$", "regex", value_arg=-1, pattern_arg=0),
    Guard("java.pattern", r"^(matches|compile)$", "regex", value_arg=1, pattern_arg=0),
    Guard("java.starts", r"^startsWith$", "prefix", value_arg=-1, pattern_arg=0),
    Guard("java.ends", r"^endsWith$", "suffix", value_arg=-1, pattern_arg=0),
    Guard("java.contains", r"^contains$", "membership", value_arg=0, pattern_arg=-1),
    Guard("java.equals", r"^equals(IgnoreCase)?$", "equals", value_arg=-1, pattern_arg=0),
)

JAVA_IMPORTS = (
    ImportRule("java.import", r"^\s*import\s+(?:static\s+)?(?P<spec>[\w.]+)\s*;",
               kind="class"),
)

JAVA_SPEC = LangSpec(
    lang="java", adapter=JAVA,
    guards=JAVA_GUARDS, imports=JAVA_IMPORTS, bindings=CLASS_BINDINGS,
    param_sources=(
        ParamSource("java.servlet", "servlet request",
                    type_pattern=r"^(Http)?ServletRequest$",
                    name_pattern=r"^(request|req)$",
                    requires=r"javax\.servlet|jakarta\.servlet|springframework\.web|"
                             r"@(?:Rest)?Controller\b|@RequestMapping\b"),
        ParamSource("java.spring", "spring request",
                    type_pattern=r"^(WebRequest|NativeWebRequest|ServerRequest)$"),
    ),
    never_params=(r"^(Http)?ServletResponse$", r"^(Logger|Log)$", r"^Model$",
                  r"^(DataSource|Connection|EntityManager|JdbcTemplate)$",
                  r"^(response|resp|logger|log|model|session)$", r"^Exception$"),
    barriers=(
        Barrier("java.log", r"\b(logger|log|LOG|LOGGER)\.(debug|info|warn|error|trace)$",
                "logging"),
        Barrier("java.len", r"(?:^|\.)(length|size|isEmpty|hashCode)$", "inspection"),
    ),
    shells=(r"^(/bin/)?(sh|bash)$", r"^cmd(\.exe)?$", r"^powershell$"),
    exports=(r"\bclass\s+(\w+)", r"\b(?:public|private|protected)\s+[\w<>\[\]]+\s+(\w+)\s*\("),
    sources=(
        Source("java.param", r"\b(getParameter|getHeader|getQueryString|getInputStream|"
                             r"getCookies|getRequestURI|getPathInfo)\b", "servlet request data"),
        Source("java.spring", r"\b(RequestParam|PathVariable|RequestBody)\b", "spring binding"),
    ),
    sinks=(
        Sink("java.exec", r"^(exec|command|start)$", "cmd", "command built from input",
             "Runtime.exec / ProcessBuilder runs an attacker-influenced command.",
             args=(0,), weight=9),
        Sink("java.sql", r"^(executeQuery|executeUpdate|execute|createQuery|createNativeQuery)$",
             "sqli", "SQL built from untrusted input",
             "Statement text carries attacker data instead of a bound parameter.",
             args=(0,), weight=9),
        Sink("java.deser", r"^(readObject|fromXML|readValue)$", "deser",
             "deserialising untrusted data", "Gadget-chain remote code execution.",
             args=(0,), weight=8),
        Sink("java.file", r"^(File|FileInputStream|FileOutputStream|get|newInputStream)$", "path",
             "filesystem path from untrusted input", "Path traversal.", args=(0,), weight=7),
        Sink("java.expr", r"^(getValue|parseExpression|eval|evaluate)$", "code",
             "expression language evaluating input", "SpEL/OGNL/MVEL evaluation is RCE.",
             args=(0,), weight=9),
    ),
    sanitizers=(
        Sanitizer("java.int", r"^(parseInt|parseLong|valueOf)$", "numeric parse"),
        Sanitizer("java.escape", r"^(escapeHtml4?|encodeForHTML|htmlEscape)$", "HTML escaping",
                  kills=("xss",)),
        Sanitizer("java.basename", r"^getFileName$", "getFileName()", kills=("path",)),
    ),
    propagators=(Propagator("java.str", r"^(toString|trim|concat|format|substring|valueOf)$"),),
    handler_params=(r"^request$", r"^req$"),
)

# -------------------------------------------------------------------------- go

GO = Adapter(
    lang="go",
    call_nodes=("call_expression",),
    call_fn_field="function",
    call_args_field="arguments",
    identifier_nodes=("identifier", "field_identifier"),
    member_nodes=("selector_expression",),
    member_obj_field="operand",
    member_prop_field="field",
    index_nodes=("index_expression",),
    assign_nodes=("assignment_statement", "short_var_declaration"),
    assign_target_field="left",
    assign_value_field="right",
    declarator_nodes=("const_spec", "var_spec"),
    declarator_name_field="name",
    declarator_value_field="value",
    function_nodes=("function_declaration", "method_declaration", "func_literal"),
    function_name_field="name",
    function_params_field="parameters",
    function_body_field="body",
    param_nodes=("identifier", "parameter_declaration"),
    string_nodes=("interpreted_string_literal", "raw_string_literal"),
    number_nodes=("int_literal", "float_literal", "true", "false", "nil"),
    concat_nodes=("binary_expression",),
    block_nodes=("block", "statement_list", "source_file"),
    loop_nodes=("for_statement",),
    return_nodes=("return_statement",),
    if_nodes=("if_statement",),
    terminator_nodes=("return_statement", "break_statement", "continue_statement",
                      "goto_statement"),
    terminator_calls=(r"\b(os\.Exit|panic|log\.Fatal\w*)$",),
    binary_nodes=("binary_expression",),
    unary_nodes=("unary_expression",),
    and_operators=("&&",),
    or_operators=("||",),
    not_operators=("!",),
    true_literals=("true",),
    false_literals=("false",),
    null_literals=("nil",),
    length_fns=("len",),
    transparent_calls=("string",),
)

GO_GUARDS = (
    Guard("go.prefix", r"\bstrings\.HasPrefix$", "prefix", value_arg=0, pattern_arg=1),
    Guard("go.suffix", r"\bstrings\.HasSuffix$", "suffix", value_arg=0, pattern_arg=1),
    Guard("go.contains", r"\bstrings\.Contains$", "contains", value_arg=0, pattern_arg=1),
    Guard("go.match", r"\.MatchString$", "regex", value_arg=0, pattern_arg=-1),
    Guard("go.regexp_match", r"\bregexp\.MatchString$", "regex", value_arg=1, pattern_arg=0),
    Guard("go.atoi", r"\bstrconv\.(Atoi|ParseInt|ParseFloat)$", "numeric", value_arg=0),
)

# Go has no import aliasing to resolve for same-package calls: files in one directory share
# a namespace, which the resolver treats as the strongest possible link.
GO_IMPORTS = (
    ImportRule("go.import", r"^\s*(?:(?P<alias>[\w.]+)\s+)?\"(?P<spec>[^\"]+)\"",
               kind="package"),
)

# Matched on the declared type, not the name. `ctx context.Context` used to match `^ctx$`
# and seed every Go function in the repository with request taint.
GO_PARAM_SOURCES = (
    ParamSource("go.httpreq", "http request", type_pattern=r"^\*?(http|nethttp)\.Request$",
                name_pattern=r"^(r|req|request)$",
                requires=r"net/http|\bhttp\.(?:Handle|HandleFunc|ResponseWriter|"
                         r"ListenAndServe)\b|gin-gonic|labstack/echo|gofiber"),
    ParamSource("go.gin", "gin request context", type_pattern=r"^\*?gin\.Context$"),
    ParamSource("go.echo", "echo request context", type_pattern=r"^echo\.Context$"),
    ParamSource("go.fiber", "fiber request context", type_pattern=r"^\*?fiber\.Ctx$"),
    ParamSource("go.lambda", "lambda event",
                type_pattern=r"^events\.APIGatewayProxyRequest$"),
)

# Nothing here is ever user input, whatever the parameter is called.
GO_NEVER = (
    r"^context\.Context$", r"^\*?slog\.Logger$", r"^\*?log\.Logger$", r"^\*?zap\.(Sugared)?Logger$",
    r"^\*?logrus\.(Logger|Entry)$", r"^\*?testing\.[TBMF]$", r"^error$", r"^http\.ResponseWriter$",
    r"^\*?sql\.(DB|Tx|Conn)$", r"^\*?sync\.(Mutex|RWMutex|WaitGroup)$", r"^time\.(Duration|Time)$",
    r"^chan\b", r"^func\(", r"^\*?grpc\.(Server|ClientConn)$",
)

# Calls whose result is a new scope, not the data that went in.
GO_BARRIERS = (
    Barrier("go.ctx", r"\bcontext\.(WithTimeout|WithCancel|WithDeadline|Background|TODO|"
                      r"WithoutCancel)$", "context lifecycle"),
    Barrier("go.len", r"^len$|^cap$", "length"),
    Barrier("go.errors", r"\berrors\.(New|Is|As|Wrap)$|\bfmt\.Errorf$", "error construction"),
    Barrier("go.timer", r"\btime\.(NewTimer|NewTicker|After|Since)$", "timer"),
)

GO_SPEC = LangSpec(
    lang="go", adapter=GO,
    guards=GO_GUARDS, imports=GO_IMPORTS,
    exports=(r"^\s*func\s+(?:\([^)]*\)\s*)?(\w+)",),
    param_sources=GO_PARAM_SOURCES,
    never_params=GO_NEVER,
    barriers=GO_BARRIERS,
    shells=(r"^(/bin/)?(sh|bash|zsh|ash|dash|ksh)$", r"^cmd(\.exe)?$", r"^powershell(\.exe)?$",
            r"^pwsh$", r"^/usr/bin/env$"),
    replacers=((r"\bstrings\.(Replace|ReplaceAll)$", 1, 2),),
    handler_registrars=(r"\b(http|mux|r|router|e|app)\.(HandleFunc|Handle|Get|Post|Put|Patch|"
                        r"Delete|Any|Use)$", r"\bhttp\.HandlerFunc$"),
    sources=(
        # Field semantics: a form value is free-form text, a parsed int is not.
        Source("go.req_text", r"\b\w*[Rr]eq(uest)?\.(URL|Form|PostForm|Body|Header|Host)\b|"
                              r"\bFormValue\b|\bmux\.Vars\b|\b\w*\.(Param|Query|PostForm|"
                              r"QueryParam|FormFile)\(", "http request data"),
        Source("go.argv", r"\bos\.Args\b|\bflag\.Args\(\)", "command line argument",
               kind="cli"),
        Source("go.env", r"\bos\.(Getenv|LookupEnv|Environ)\b", "environment variable",
               kind="env"),
        Source("go.stdin", r"\bos\.Stdin\b", "standard input", kind="cli"),
    ),
    sinks=(
        # argv semantics: exec.Command("open", url) passes url as an argument, it is not a
        # shell command. Only a shell program in position 0 makes a later argument into one.
        Sink("go.log", r"\b(log|logger|slog)\.(Print|Printf|Println|Debug|Info|Warn|Error|Fatal)\w*$|\bfmt\.(Print|Printf|Println|Sprintf)$", "disclosure",
             "credential written to a log",
             "The value came from a credential-named source. Logs are read by more people and systems than the code that wrote them.",
             args=(-1,), weight=6, value_kinds=("secret",)),
        Sink("go.exec", r"\bexec\.Command$", "cmd", "external program run with untrusted data",
             "A tainted program name is command execution; a tainted argument to a fixed "
             "program is argument injection, which depends on what that program does.",
             args=(-1,), weight=9, shell="argv", program_arg=0),
        Sink("go.exec_ctx", r"\bexec\.CommandContext$", "cmd",
             "external program run with untrusted data",
             "A tainted program name is command execution; a tainted argument to a fixed "
             "program is argument injection.",
             roles=("ctx", "program", "arg", "arg", "arg", "arg", "arg", "arg"),
             danger_roles=("program", "arg"), weight=9, shell="argv", program_arg=1),
        Sink("go.sql", r"(?:^|\.)(Query|QueryRow|Exec)$", "sqli",
             "SQL built from untrusted input",
             "Query text carries attacker data instead of a placeholder.", args=(0,),
             weight=9),
        Sink("go.sql_ctx", r"(?:^|\.)(QueryContext|QueryRowContext|ExecContext)$", "sqli",
             "SQL built from untrusted input",
             "Query text carries attacker data instead of a placeholder.",
             roles=("ctx", "query", "arg", "arg", "arg", "arg"), danger_roles=("query",),
             weight=9),
        Sink("go.file", r"\bos\.(Open|OpenFile|ReadFile|Create|Remove|RemoveAll)$|"
                        r"\bioutil\.ReadFile$", "path",
             "filesystem path from untrusted input", "Path traversal.", args=(0,), weight=8),
        Sink("go.servefile", r"\bhttp\.ServeFile$", "path",
             "file served from an untrusted path", "Arbitrary file read.",
             roles=("w", "r", "path"), danger_roles=("path",), weight=8),
        Sink("go.ssrf_simple", r"\bhttp\.(Get|Head)$", "ssrf",
             "outbound request to an untrusted URL",
             "Server-side request forgery: the server fetches a target the attacker chooses.",
             roles=("url",), danger_roles=("url",), weight=8),
        Sink("go.ssrf_post", r"\bhttp\.Post$", "ssrf",
             "outbound request to an untrusted URL", "Server-side request forgery.",
             roles=("url", "contentType", "body"), danger_roles=("url",), weight=8),
        # argument 0 is the method, 1 is the URL
        Sink("go.ssrf_new", r"\bhttp\.NewRequest$", "ssrf",
             "outbound request to an untrusted URL", "Server-side request forgery.",
             roles=("method", "url", "body"), danger_roles=("url",), weight=8),
        # argument 0 is the context, 2 is the URL: taint in the context is not an SSRF
        Sink("go.ssrf_new_ctx", r"\bhttp\.NewRequestWithContext$", "ssrf",
             "outbound request to an untrusted URL", "Server-side request forgery.",
             roles=("ctx", "method", "url", "body"), danger_roles=("url",), weight=8),
        Sink("go.template", r"\btemplate\.(HTML|JS|URL|HTMLAttr)$", "xss",
             "value marked as trusted markup", "Bypasses contextual escaping.",
             args=(0,), weight=7),
    ),
    sanitizers=(
        Sanitizer("go.int", r"\bstrconv\.(Atoi|ParseInt|ParseUint|ParseFloat)$",
                  "numeric parse"),
        Sanitizer("go.escape", r"\bhtml\.EscapeString$|\btemplate\.HTMLEscapeString$",
                  "HTML escaping", kills=("xss",)),
        Sanitizer("go.base", r"\bfilepath\.Base$", "filepath.Base()", kills=("path",)),
        Sanitizer("go.quote", r"\burl\.QueryEscape$|\burl\.PathEscape$", "URL escaping",
                  kills=("ssrf", "redirect")),
        # filepath.Clean removes ../ but leaves an absolute path absolute, so it is not on
        # its own a traversal fix
        Sanitizer("go.clean", r"\bfilepath\.Clean$", "filepath.Clean()", partial=True,
                  removes=("..",)),
    ),
    propagators=(Propagator("go.fmt", r"\bfmt\.(Sprintf|Sprint|Sprintln)$|\bstrings\.(Join|"
                                      r"TrimSpace|ToLower|ToUpper|Replace|ReplaceAll|Trim|"
                                      r"TrimPrefix|TrimSuffix|Split|Fields)$"),
                 Propagator("go.pathjoin", r"\bfilepath\.Join$|\bpath\.Join$"),
                 Propagator("go.string", r"^string$|\bstrconv\.Itoa$"),
                 Propagator("go.urlparse", r"\burl\.(Parse|ParseRequestURI)$")),
    handler_params=(),
)

# ------------------------------------------------------------------------ ruby

RUBY = Adapter(
    lang="ruby",
    call_nodes=("call", "command_call", "method_call"),
    call_fn_field="method",
    call_args_field="arguments",
    identifier_nodes=("identifier", "constant"),
    member_nodes=("call",),
    member_obj_field="receiver",
    member_prop_field="method",
    index_nodes=("element_reference",),
    assign_nodes=("assignment", "operator_assignment"),
    assign_target_field="left",
    assign_value_field="right",
    function_nodes=("method", "singleton_method", "block", "do_block"),
    function_name_field="name",
    function_params_field="parameters",
    function_body_field="body",
    param_nodes=("identifier",),
    string_nodes=("string",),
    number_nodes=("integer", "float", "true", "false", "nil"),
    interp_string_nodes=("string",),
    interp_inner_nodes=("interpolation",),
    concat_nodes=("binary",),
    block_nodes=("body_statement", "program", "then", "else"),
    loop_nodes=("while", "until", "for"),
    return_nodes=("return",),
    # `unless` is deliberately left out of if_nodes: its arm is taken when the test is
    # false, and guessing the polarity wrong is worse than carrying no condition.
    if_nodes=("if", "elsif"),
    else_nodes=("else",),
    consequence_field="consequence",
    terminator_nodes=("return", "break", "next", "redo"),
    terminator_calls=(r"^(abort|exit|raise)$",),
    binary_nodes=("binary",),
    unary_nodes=("unary",),
    and_operators=("&&", "and"),
    or_operators=("||", "or"),
    not_operators=("!", "not"),
    true_literals=("true",),
    false_literals=("false",),
    null_literals=("nil",),
    length_fns=("length", "size", "count"),
    regex_operators=("=~",),
    regex_nodes=("regex",),
    transparent_calls=("to_s",),
)

RUBY_GUARDS = (
    Guard("rb.match", r"(?:^|\.)match\??$", "regex", value_arg=-1, pattern_arg=0),
    Guard("rb.starts", r"(?:^|\.)start_with\?$", "prefix", value_arg=-1, pattern_arg=0),
    Guard("rb.ends", r"(?:^|\.)end_with\?$", "suffix", value_arg=-1, pattern_arg=0),
    Guard("rb.include", r"(?:^|\.)include\?$", "membership", value_arg=0, pattern_arg=-1),
)

RUBY_IMPORTS = (
    ImportRule("rb.require_relative",
               r"\brequire_relative\s*\(?\s*['\"](?P<spec>[^'\"]+)['\"]", kind="relative"),
    ImportRule("rb.require", r"\brequire\s*\(?\s*['\"](?P<spec>[^'\"]+)['\"]"),
)

RUBY_SPEC = LangSpec(
    lang="ruby", adapter=RUBY,
    guards=RUBY_GUARDS, imports=RUBY_IMPORTS, bindings=RUBY_BINDINGS,
    never_params=(r"^(logger|log|response|res|session|config|options|opts)$", r"^self$"),
    barriers=(
        Barrier("rb.log", r"\b(logger|Rails\.logger)\.(debug|info|warn|error|fatal)$",
                "logging"),
        Barrier("rb.len", r"(?:^|\.)(length|size|count|empty\?|nil\?)$", "inspection"),
    ),
    shells=(r"^(/bin/)?(sh|bash)$",),
    exports=(r"^\s*def\s+(?:self\.)?(\w+)", r"^\s*class\s+(\w+)", r"^\s*module\s+(\w+)"),
    sources=(
        Source("rb.params", r"\bparams\b", "rails params"),
        Source("rb.request", r"\brequest\.(body|headers|env|query_parameters|parameters)\b",
               "rails request data"),
        Source("rb.cookies", r"\bcookies\b", "cookie data"),
    ),
    sinks=(
        Sink("rb.exec", r"^(system|exec|spawn|popen|`)$", "cmd", "command built from input",
             "Shell execution with attacker-influenced text.", args=(0,), weight=9,
             receiver_counts=True),
        Sink("rb.eval", r"^(eval|instance_eval|class_eval|send|public_send|const_get)$", "code",
             "dynamic evaluation of untrusted data", "Arbitrary Ruby execution or dispatch.",
             args=(0,), weight=9),
        Sink("rb.deser", r"^(load|safe_load|from_yaml)$", "deser",
             "deserialising untrusted data", "Marshal/YAML load instantiates arbitrary objects.",
             args=(0,), weight=8),
        Sink("rb.sql", r"^(where|find_by_sql|execute|select_all|order|group|pluck)$", "sqli",
             "SQL fragment built from input",
             "String interpolation inside a query fragment is injectable.", args=(0,), weight=8),
        Sink("rb.file", r"^(open|read|write|delete|send_file|send_data)$", "path",
             "filesystem path from untrusted input",
             "Path traversal, and Kernel#open with a pipe prefix executes commands.",
             args=(0,), weight=8),
        Sink("rb.render", r"^(render|render_to_string)$", "tmpl",
             "template rendered from untrusted input", "ERB template injection is RCE.",
             args=(0,), weight=8),
    ),
    sanitizers=(
        Sanitizer("rb.int", r"^(to_i|to_f|Integer)$", "numeric conversion"),
        Sanitizer("rb.escape", r"^(html_escape|sanitize|h|ERB::Util\.html_escape)$",
                  "HTML escaping", kills=("xss",)),
        Sanitizer("rb.shellescape", r"^(shellescape|Shellwords\.escape)$", "shellescape",
                  kills=("cmd",)),
        Sanitizer("rb.basename", r"^basename$", "File.basename()", kills=("path",)),
    ),
    propagators=(Propagator("rb.str", r"^(to_s|strip|chomp|downcase|upcase|gsub|sub|join|"
                                       r"format|slice)$"),),
    handler_params=(),
)

# -------------------------------------------------------------------------- c#

CSHARP = Adapter(
    lang="csharp",
    call_nodes=("invocation_expression", "object_creation_expression"),
    call_fn_field="function",
    call_args_field="arguments",
    identifier_nodes=("identifier",),
    member_nodes=("member_access_expression",),
    member_obj_field="expression",
    member_prop_field="name",
    index_nodes=("element_access_expression",),
    assign_nodes=("assignment_expression",),
    assign_target_field="left",
    assign_value_field="right",
    declarator_nodes=("variable_declarator",),
    declarator_name_field="name",
    declarator_value_field="value",
    function_nodes=("method_declaration", "constructor_declaration", "lambda_expression",
                    "local_function_statement"),
    function_name_field="name",
    function_params_field="parameters",
    function_body_field="body",
    param_nodes=("identifier", "parameter"),
    arg_wrapper_nodes=("argument",),
    string_nodes=("string_literal", "verbatim_string_literal"),
    number_nodes=("integer_literal", "real_literal", "boolean_literal", "null_literal"),
    interp_string_nodes=("interpolated_string_expression",),
    interp_inner_nodes=("interpolation",),
    concat_nodes=("binary_expression",),
    block_nodes=("block", "compilation_unit", "global_statement"),
    loop_nodes=("for_statement", "while_statement", "foreach_statement"),
    return_nodes=("return_statement",),
    if_nodes=("if_statement",),
    terminator_nodes=("return_statement", "throw_statement", "break_statement",
                      "continue_statement"),
    terminator_calls=(r"\bEnvironment\.Exit$",),
    binary_nodes=("binary_expression",),
    unary_nodes=("prefix_unary_expression",),
    and_operators=("&&",),
    or_operators=("||", "??"),
    not_operators=("!",),
    true_literals=("true",),
    false_literals=("false",),
    null_literals=("null",),
    length_props=("Length", "Count"),
    transparent_calls=("ToString",),
)

CSHARP_GUARDS = (
    Guard("cs.ismatch", r"\bRegex\.IsMatch$|^IsMatch$", "regex", value_arg=0, pattern_arg=1),
    Guard("cs.starts", r"^StartsWith$", "prefix", value_arg=-1, pattern_arg=0),
    Guard("cs.ends", r"^EndsWith$", "suffix", value_arg=-1, pattern_arg=0),
    Guard("cs.contains", r"^Contains$", "membership", value_arg=0, pattern_arg=-1),
    Guard("cs.equals", r"^Equals$", "equals", value_arg=-1, pattern_arg=0),
    Guard("cs.tryparse", r"\b(int|Int32|long|double)\.TryParse$", "numeric", value_arg=0),
)

CSHARP_IMPORTS = (
    ImportRule("cs.using", r"^\s*using\s+(?:static\s+)?(?P<spec>[\w.]+)\s*;", kind="class"),
)

CSHARP_SPEC = LangSpec(
    lang="csharp", adapter=CSHARP,
    guards=CSHARP_GUARDS, imports=CSHARP_IMPORTS, bindings=CLASS_BINDINGS,
    param_sources=(
        ParamSource("cs.request", "asp.net request",
                    type_pattern=r"^(HttpRequest|HttpRequestMessage)$",
                    name_pattern=r"^(request|req)$",
                    requires=r"Microsoft\.AspNetCore|System\.Web|"
                             r"\[(?:Http(?:Get|Post|Put|Delete)|Route|ApiController)\b"),
    ),
    never_params=(r"^(HttpResponse|HttpContext|ILogger|ILogger<.*>|Logger)$",
                  r"^(CancellationToken|IServiceProvider|DbContext|IConfiguration)$",
                  r"^(response|logger|log|context|token|ct)$", r"^Exception$"),
    barriers=(
        Barrier("cs.log", r"\b_?(logger|log)\.Log\w*$", "logging"),
        Barrier("cs.len", r"(?:^|\.)(Length|Count|Any)$", "inspection"),
    ),
    shells=(r"^cmd(\.exe)?$", r"^powershell(\.exe)?$", r"^(/bin/)?(sh|bash)$"),
    exports=(r"\bclass\s+(\w+)",
             r"\b(?:public|private|protected|internal)\s+[\w<>\[\]]+\s+(\w+)\s*\("),
    sources=(
        Source("cs.request", r"\bRequest\.(Query|Form|Body|Headers|Cookies|QueryString|Params|"
                             r"RouteValues)\b", "asp.net request data"),
        Source("cs.binding", r"\b(FromQuery|FromBody|FromRoute|FromForm)\b", "model binding"),
    ),
    sinks=(
        Sink("cs.process", r"\bProcess\.Start$|^Start$", "cmd", "process started from input",
             "The program or arguments come from request data.", args=(0,), weight=9),
        Sink("cs.sql", r"^(SqlCommand|ExecuteReader|ExecuteNonQuery|ExecuteScalar|FromSqlRaw|"
                       r"ExecuteSqlRaw)$", "sqli", "SQL built from untrusted input",
             "Command text carries attacker data instead of a parameter.", args=(0,), weight=9),
        Sink("cs.deser", r"^(Deserialize|ReadObject|BinaryFormatter)$", "deser",
             "deserialising untrusted data", "Known .NET gadget-chain RCE surfaces.",
             args=(0,), weight=8),
        Sink("cs.file", r"^(ReadAllText|ReadAllBytes|WriteAllText|OpenRead|Delete|Combine)$",
             "path", "filesystem path from untrusted input", "Path traversal.",
             args=(0, 1), weight=7),
        Sink("cs.redirect", r"^(Redirect|RedirectPermanent)$", "redirect",
             "redirect to an untrusted location", "Open redirect.", args=(0,), weight=6),
    ),
    sanitizers=(
        Sanitizer("cs.int", r"^(Parse|TryParse|ToInt32)$", "numeric parse"),
        Sanitizer("cs.encode", r"^(HtmlEncode|UrlEncode)$", "output encoding",
                  kills=("xss", "redirect")),
        Sanitizer("cs.filename", r"^GetFileName$", "Path.GetFileName()", kills=("path",)),
    ),
    propagators=(Propagator("cs.str", r"^(ToString|Trim|ToLower|ToUpper|Replace|Substring|"
                                       r"Format|Concat|Join)$"),),
    handler_params=(),
)
