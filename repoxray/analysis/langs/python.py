"""Python: node shapes, untrusted sources, dangerous sinks, sanitizers."""
from __future__ import annotations

from ..model import (Adapter, Barrier, Guard, ImportRule, LangSpec, ParamSource,
                     Propagator, Sanitizer, Sink, Source)

ADAPTER = Adapter(
    lang="python",
    call_nodes=("call",),
    call_fn_field="function",
    call_args_field="arguments",
    identifier_nodes=("identifier",),
    member_nodes=("attribute",),
    member_obj_field="object",
    member_prop_field="attribute",
    index_nodes=("subscript",),
    assign_nodes=("assignment", "augmented_assignment"),
    assign_target_field="left",
    assign_value_field="right",
    declarator_nodes=(),
    function_nodes=("function_definition", "lambda"),
    function_name_field="name",
    function_params_field="parameters",
    function_body_field="body",
    param_nodes=("identifier",),
    string_nodes=("string", "concatenated_string"),
    number_nodes=("integer", "float", "true", "false", "none"),
    interp_string_nodes=("string", "concatenated_string"),
    interp_inner_nodes=("interpolation",),
    concat_nodes=("binary_operator",),
    if_nodes=("if_statement", "elif_clause"),
    loop_nodes=("for_statement", "while_statement"),
    try_nodes=("try_statement",),
    block_nodes=("block", "module"),
    return_nodes=("return_statement",),
    # path sensitivity: elif/else arms, and the statements that end a path
    else_nodes=("else_clause",),
    terminator_nodes=("return_statement", "raise_statement", "break_statement",
                      "continue_statement"),
    terminator_calls=(r"\b(sys\.exit|os\._exit|abort)$",),
    binary_nodes=("comparison_operator", "boolean_operator", "binary_operator"),
    unary_nodes=("not_operator",),
    and_operators=("and",),
    or_operators=("or",),
    not_operators=("not",),
    true_literals=("True",),
    false_literals=("False",),
    null_literals=("None",),
    length_fns=("len",),
    in_operators=("in",),
    transparent_calls=("str", "int", "float", "unicode", "repr"),
    # `os.path.join(os.path.dirname(__file__), "launch_impl.py")` names this package's own
    # fixed sibling. Two calls deep, so without this it read as a path built at runtime
    # and `exec(compile(...))` on it read as code execution.
    const_calls=(r"(?:^|\.)(?:join|dirname|basename|abspath|normpath|realpath|"
                 r"expanduser|splitext|resolve|parent|with_name|with_suffix)$",
                 r"^(?:Path|PurePath|PurePosixPath|str|bytes|format)$"),
    const_idents=(r"^__file__$", r"^__name__$", r"^__package__$",
                  r"^sys\.(?:executable|prefix|exec_prefix)$"),
)

SOURCES = (
    Source("py.flask", r"\brequest\.(args|form|json|data|files|values|cookies|headers|view_args)",
           "flask request data"),
    Source("py.flask_json", r"\brequest\.get_json\b", "flask request json"),
    Source("py.django", r"\brequest\.(GET|POST|FILES|COOKIES|META|body|headers)",
           "django request data"),
    Source("py.aiohttp", r"\brequest\.(query|match_info|rel_url|post|text|read)\b",
           "aiohttp request data"),
    Source("py.argv", r"\bsys\.argv", "command line argument", kind="cli"),
    Source("py.env", r"\bos\.environ(\.get)?\b", "environment variable", kind="env"),
    Source("py.stdin", r"^(input|sys\.stdin\.read(line)?)$", "standard input", kind="cli"),
)

PARAM_SOURCES = (
    ParamSource("py.flask_req", "flask request",
                type_pattern=r"(^|\.)Request$|^flask\.Request$",
                name_pattern=r"^(request|req)$",
                # `request` is the commonest variable name in Python. Without this it made
                # a gdb bridge that reads a JSON request file into a Flask handler, and
                # reported its `exec(compile(...))` as a web RCE.
                requires=r"\bfrom\s+flask\b|\bimport\s+flask\b|\bflask\s*\.|"
                         r"\bFlask\s*\(|\b@(?:app|bp|blueprint)\s*\.\s*route\b"),
    ParamSource("py.django_req", "django request",
                type_pattern=r"^(Http|WSGI|ASGI)Request$"),
    ParamSource("py.starlette", "starlette/fastapi request",
                type_pattern=r"^(Request|WebSocket)$"),
    ParamSource("py.aiohttp", "aiohttp request", type_pattern=r"^web\.Request$"),
)

# `self` is not user input. Neither is a logger, a session or a database handle, and
# matching them by name was a large share of the noise.
NEVER_PARAMS = (
    r"^self$", r"^cls$", r"^mcs$",
    r"(^|\.)Logger$", r"^logger$", r"^log$",
    r"(^|\.)Session$", r"^db$", r"^session$", r"^engine$", r"^conn(ection)?$",
    r"(^|\.)Context$", r"^ctx$", r"^context$",
    r"^settings$", r"^config$", r"^app$", r"^loop$",
    r"(^|\.)(Callable|Awaitable|Iterator|Iterable|Generator)\b",
)

BARRIERS = (
    Barrier("py.log", r"\b(logging|logger|log|self\.logger|self\.log)\."
                      r"(debug|info|warning|warn|error|exception|critical)$", "logging"),
    Barrier("py.len", r"^(len|id|hash|type|isinstance|bool|callable)$", "inspection"),
    Barrier("py.exc", r"^(Exception|ValueError|TypeError|RuntimeError|KeyError)$",
            "exception construction"),
    Barrier("py.ctx", r"\bcontextlib\.|\bfunctools\.(wraps|partial)$", "context manager"),
)

HANDLER_REGISTRARS = (
    r"@?\w*\.(route|get|post|put|patch|delete|websocket|head|options)$",
    r"\badd_url_rule$", r"\badd_api_route$",
    r"@(app|bp|blueprint|router|api|ns)\.",
)

SINKS = (
    Sink("py.log", r"^(print)$|\b(logging|logger|log|self\.logger)\.(debug|info|warning|warn|error|exception|critical)$", "disclosure",
         "credential written to a log",
         "The value came from a credential-named source. Logs are read by more people and systems than the code that wrote them.",
         args=(-1,), weight=6, value_kinds=("secret",)),
    Sink("py.os_system", r"\bos\.(system|popen)$", "cmd", "OS command built from input",
         "The string is handed to a shell, so any attacker-controlled part becomes a command.",
         args=(0,), weight=9, shell="always"),
    # One function, two different bugs. `shell=True` makes the argument a command line;
    # without it, a list is an argv vector and a tainted entry is argument injection.
    Sink("py.subprocess", r"\bsubprocess\.(run|call|check_call|check_output|Popen)$", "cmd",
         "subprocess call with untrusted argument",
         "Reaches a process launcher. With shell=True the value is a command line; without "
         "it, the program or one of its arguments is attacker-influenced.",
         args=(0,), weight=8, shell="conditional", shell_kwarg="shell", program_arg=0),
    Sink("py.os_exec", r"\bos\.(execl|execle|execlp|execv|execve|execvp|spawnl|spawnv)$", "cmd",
         "process replacement with untrusted argument",
         "Executes a program chosen at runtime.", args=(0, 1), weight=8),
    Sink("py.eval", r"(?:^|\.)\b(eval|exec)$", "code", "eval/exec on untrusted data",
         "Arbitrary Python execution.", args=(0,), weight=9),
    Sink("py.pickle", r"\b(pickle|cPickle|dill|cloudpickle|joblib)\.loads?$", "deser",
         "deserialising untrusted bytes",
         "Pickle reconstructs arbitrary objects; this is remote code execution by design.",
         args=(0,), weight=9),
    Sink("py.yaml", r"\byaml\.(load|unsafe_load|full_load)$", "deser",
         "yaml.load on untrusted data",
         "Non-safe YAML loaders instantiate arbitrary Python types.", args=(0,), weight=8),
    Sink("py.torch_load", r"\b(torch\.load|numpy\.load|np\.load|pandas\.read_pickle)$", "deser",
         "model/array load from untrusted path",
         "These loaders unpickle by default.", args=(0,), weight=7),
    Sink("py.sql", r"(?:^|\.)(execute|executemany|executescript|raw|execute_sql)$", "sqli",
         "SQL built from untrusted input",
         "The query text itself carries attacker data instead of being parameterised.",
         args=(0,), weight=9),
    Sink("py.sqlalchemy_text", r"\b(text|literal_column)$", "sqli",
         "SQLAlchemy text() built from input",
         "text() does not bind interpolated values.", args=(0,), weight=7),
    Sink("py.open", r"(?:^|\.)\b(open|remove|unlink|rmtree|rename|copyfile|chmod)$", "path",
         "filesystem path from untrusted input",
         "Path traversal: ../ or an absolute path escapes the intended directory.",
         args=(0,), weight=8),
    Sink("py.send_file", r"\b(send_file|send_from_directory|FileResponse)$", "path",
         "file served from an untrusted path",
         "Arbitrary file read if the path is not contained.", args=(0,), weight=8),
    # These take the URL first. `requests.request` does not - it takes the method first -
    # so it gets its own entry rather than being folded in by name.
    Sink("py.requests", r"\b(requests\.(get|post|put|patch|delete|head)|urlopen|"
                        r"httpx\.(get|post|Client))$", "ssrf",
         "outbound request to an untrusted URL",
         "Server-side request forgery: the server fetches a target the attacker chooses.",
         roles=("url",), danger_roles=("url",), weight=8),
    Sink("py.requests_req", r"\b(requests|httpx|session|Session)\.request$", "ssrf",
         "outbound request to an untrusted URL",
         "Server-side request forgery: the server fetches a target the attacker chooses.",
         roles=("method", "url"), danger_roles=("url",), weight=8),
    Sink("py.template", r"\b(render_template_string|from_string|Template)$", "tmpl",
         "template compiled from untrusted input",
         "Server-side template injection in Jinja is remote code execution.",
         args=(0,), weight=9),
    Sink("py.redirect", r"\b(redirect|HttpResponseRedirect)$", "redirect",
         "redirect to an untrusted location",
         "Open redirect used for phishing and OAuth token theft.", args=(0,), weight=6),
    Sink("py.extract", r"(?:^|\.)extractall$", "path", "archive extracted to an untrusted path",
         "Zip slip: archive members can escape the target directory.", args=(0,), weight=7),
)

SANITIZERS = (
    Sanitizer("py.shlex", r"\bshlex\.quote$", "shlex.quote()"),
    Sanitizer("py.int", r"^(int|float)$", "int()/float() conversion"),
    Sanitizer("py.escape", r"\b(html\.escape|markupsafe\.escape|escape|bleach\.clean)$",
              "HTML escaping", kills=("xss",)),
    Sanitizer("py.basename", r"\b(os\.path\.basename|secure_filename|Path\(.*\)\.name)$",
              "basename()/secure_filename()", kills=("path",)),
    Sanitizer("py.quote", r"\b(urllib\.parse\.quote|quote_plus)$", "URL quoting",
              kills=("ssrf", "redirect")),
    Sanitizer("py.re_escape", r"\bre\.escape$", "re.escape()"),
)

PROPAGATORS = (
    Propagator("py.str", r"^(str|repr|format|f)$"),
    Propagator("py.join", r"(?:^|\.)(join|format|strip|lstrip|rstrip|lower|upper|replace|"
                          r"decode|encode|get|split|title)$"),
    Propagator("py.pathjoin", r"\bos\.path\.join$"),
)

# Checks the solver can read. A guard it does not recognise stays an opaque atom, which
# keeps the finding - only an understood check can prove a value safe.
GUARDS = (
    Guard("py.re_match", r"\bre\.(match|fullmatch|search)$", "regex",
          value_arg=1, pattern_arg=0),
    Guard("py.re_obj_match", r"\.(match|fullmatch|search)$", "regex",
          value_arg=0, pattern_arg=-1),
    Guard("py.startswith", r"\.startswith$", "prefix", value_arg=-1, pattern_arg=0),
    Guard("py.endswith", r"\.endswith$", "suffix", value_arg=-1, pattern_arg=0),
    Guard("py.isdigit", r"\.(isdigit|isnumeric|isdecimal)$", "numeric", value_arg=-1),
    Guard("py.isalnum", r"\.isalnum$", "regex", value_arg=-1, literal=r"^[A-Za-z0-9]+$"),
    Guard("py.isalpha", r"\.isalpha$", "regex", value_arg=-1, literal=r"^[A-Za-z]+$"),
    Guard("py.isidentifier", r"\.isidentifier$", "regex", value_arg=-1,
          literal=r"^[A-Za-z_][A-Za-z0-9_]*$"),
    Guard("py.uuid", r"\buuid\.UUID$", "regex", value_arg=0,
          literal=r"^[0-9a-fA-F-]{32,36}$"),
)

IMPORTS = (
    ImportRule("py.from", r"^[ \t]*from[ \t]+(?P<spec>[.\w]+)[ \t]+import[ \t]+"
                          r"\(?(?P<names>[^\n()]+)"),
    ImportRule("py.import_as", r"^[ \t]*import[ \t]+(?P<spec>[.\w]+)[ \t]+as[ \t]+"
                               r"(?P<alias>\w+)"),
    ImportRule("py.import", r"^[ \t]*import[ \t]+(?P<spec>[.\w]+)[ \t]*$"),
)

EXPORTS = (r"^[ \t]*def[ \t]+(\w+)", r"^[ \t]*async[ \t]+def[ \t]+(\w+)",
           r"^[ \t]*class[ \t]+(\w+)")

BINDINGS = (
    r"(?:self\.)?(?P<name>\w+)\s*=\s*(?P<type>[A-Z]\w*)\s*\(",
    r"(?P<name>\w+)\s*:\s*(?P<type>[A-Z]\w*)",
)

SPEC = LangSpec(
    lang="python",
    adapter=ADAPTER,
    sources=SOURCES,
    sinks=SINKS,
    sanitizers=SANITIZERS,
    propagators=PROPAGATORS,
    handler_params=(),
    param_sources=PARAM_SOURCES,
    never_params=NEVER_PARAMS,
    barriers=BARRIERS,
    handler_registrars=HANDLER_REGISTRARS,
    shells=(r"^(/bin/)?(sh|bash|zsh|dash|ksh)$", r"^cmd(\.exe)?$", r"^powershell$"),
    replacers=((r"(?:^|\.)replace$", 0, 1),),
    guards=GUARDS,
    imports=IMPORTS,
    exports=EXPORTS,
    bindings=BINDINGS,
)
