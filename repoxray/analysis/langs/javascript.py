"""JavaScript and TypeScript: node shapes, untrusted sources, dangerous sinks, sanitizers.

The same spec serves .js, .jsx, .ts, .tsx and the script blocks of .vue/.svelte - the grammars
differ slightly but the node names the engine needs are shared.
"""
from __future__ import annotations

from ..model import (Adapter, Barrier, Guard, ImportRule, LangSpec, ParamSource,
                     Propagator, Sanitizer, Sink, Source)

ADAPTER = Adapter(
    lang="javascript",
    call_nodes=("call_expression", "new_expression"),
    call_fn_field="function",
    call_args_field="arguments",
    identifier_nodes=("identifier", "shorthand_property_identifier", "property_identifier"),
    member_nodes=("member_expression",),
    member_obj_field="object",
    member_prop_field="property",
    index_nodes=("subscript_expression",),
    assign_nodes=("assignment_expression", "augmented_assignment_expression"),
    assign_target_field="left",
    assign_value_field="right",
    declarator_nodes=("variable_declarator",),
    declarator_name_field="name",
    declarator_value_field="value",
    function_nodes=("function_declaration", "function_expression", "arrow_function",
                    "method_definition", "generator_function_declaration"),
    function_name_field="name",
    function_params_field="parameters",
    function_body_field="body",
    param_nodes=("identifier", "required_parameter", "optional_parameter"),
    string_nodes=("string", "template_string"),
    number_nodes=("number", "true", "false", "null", "undefined"),
    interp_string_nodes=("template_string",),
    interp_inner_nodes=("template_substitution",),
    concat_nodes=("binary_expression",),
    if_nodes=("if_statement",),
    loop_nodes=("for_statement", "for_in_statement", "while_statement", "do_statement"),
    try_nodes=("try_statement",),
    block_nodes=("statement_block", "program"),
    return_nodes=("return_statement",),
    # path sensitivity
    else_nodes=("else_clause",),
    terminator_nodes=("return_statement", "throw_statement", "break_statement",
                      "continue_statement"),
    terminator_calls=(r"\bprocess\.(exit|abort)$",),
    binary_nodes=("binary_expression",),
    unary_nodes=("unary_expression",),
    and_operators=("&&",),
    or_operators=("||", "??"),
    not_operators=("!",),
    true_literals=("true",),
    false_literals=("false",),
    null_literals=("null", "undefined"),
    length_props=("length", "size"),
    regex_nodes=("regex",),
    transparent_calls=("String", "Number", "BigInt"),
    # `fileURLToPath(new URL("..", import.meta.url))` is this module's own directory.
    # `path.join(uploadDir, req.body.name)` is still not constant, and cannot become so:
    # the rule is that *every* argument has to be.
    const_calls=(r"(?:^|\.)(?:join|dirname|basename|resolve|normalize|relative|extname)$",
                 r"^(?:fileURLToPath|pathToFileURL|URL)$"),
    const_idents=(r"^__dirname$", r"^__filename$", r"^import\.meta\.(?:url|dirname)$",
                  r"^process\.execPath$"),
)

SOURCES = (
    Source("js.express", r"\breq(uest)?\.(query|body|params|headers|cookies|url|originalUrl)",
           "express request data"),
    Source("js.koa", r"\bctx\.(request|query|params|body)", "koa request data"),
    Source("js.lambda", r"\bevent\.(body|queryStringParameters|pathParameters|headers)",
           "lambda event data"),
    Source("js.next", r"\b(searchParams|useSearchParams|context\.query|req\.nextUrl)",
           "next.js request data"),
    Source("js.dom", r"\b(location\.(search|hash|href)|document\.referrer|window\.name|"
                     r"document\.location)", "browser-controlled value"),
    Source("js.message", r"\b(event\.data|e\.data)\b", "postMessage payload"),
    Source("js.angular_route",
           r"\b\w*[Rr]oute\.(snapshot\.)?(params|queryParams|paramMap|queryParamMap)\b",
           "angular route parameter"),
    Source("js.argv", r"\bprocess\.argv", "command line argument", kind="cli"),
    Source("js.env", r"\bprocess\.env\b", "environment variable", kind="env"),
)

SINKS = (
    Sink("js.log", r"\b(console|logger|log)\.(log|info|warn|error|debug|trace)$", "disclosure",
         "credential written to a log",
         "The value came from a credential-named source. Logs are read by more people and systems than the code that wrote them.",
         args=(-1,), weight=6, value_kinds=("secret",)),
    Sink("js.exec", r"(?:^|\.)(exec|execSync)$", "cmd", "shell command built from input",
         "exec runs the string through a shell, so interpolated input becomes a command.",
         args=(0,), weight=9, shell="always", identity="shell"),
    Sink("js.spawn", r"(?:^|\.)(spawn|spawnSync|execFile|execFileSync)$", "cmd",
         "process spawned with untrusted argument",
         "The program or its arguments come from input. Without shell:true the arguments "
         "are passed as an argv vector rather than parsed by a shell.",
         roles=("program", "args", "options"), danger_roles=("program", "args"),
         weight=8, shell="conditional", shell_kwarg="shell", program_arg=0,
         identity="argv"),
    Sink("js.eval", r"^(eval|Function)$", "code", "eval on untrusted data",
         "Arbitrary JavaScript execution.", args=(0,), weight=9),
    Sink("js.vm", r"\bvm\d?\.(runInNewContext|runInThisContext|runInContext|Script)$", "code",
         "vm sandbox executing untrusted code",
         "Node sandboxes are routinely escaped; treat as arbitrary execution.",
         args=(0,), weight=9),
    Sink("js.require", r"^(require|import)$", "code", "module loaded by untrusted name",
         "A require path under attacker control can load arbitrary code.", args=(0,), weight=8),
    Sink("js.sql", r"(?:^|\.)(query|execute|raw|queryRaw|executeRaw|queryRawUnsafe|"
                   r"executeRawUnsafe)$", "sqli", "SQL built from untrusted input",
         "The query text carries attacker data instead of a bound parameter.",
         args=(0,), weight=9, identity="db"),
    Sink("js.mongo", r"(?:^|\.)(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|"
                     r"deleteMany|aggregate)$", "nosql", "query object built from input",
         "A raw request object allows operator injection ($ne, $gt, $where).",
         args=(0,), weight=7),
    Sink("js.fs", r"\bfs(\.promises)?\.(readFile|readFileSync|writeFile|writeFileSync|unlink|"
                  r"unlinkSync|createReadStream|createWriteStream|readdir|rename|rm|rmdir)$",
         "path", "filesystem path from untrusted input",
         "Path traversal: ../ or an absolute path escapes the intended directory.",
         args=(0,), weight=8),
    Sink("js.sendfile", r"\bres\.(sendFile|download)$", "path",
         "file served from an untrusted path",
         "Arbitrary file read if the path is not contained.", args=(0,), weight=8),
    Sink("js.fetch", r"^(fetch|axios|got|superagent|undici)$|\b(axios|got)\.(get|post|put|patch|"
                     r"delete|head|request)$|\bhttps?\.(get|request)$", "ssrf",
         "outbound request to an untrusted URL",
         "Server-side request forgery: the server fetches a target the attacker chooses.",
         args=(0,), weight=8),
    Sink("js.redirect", r"\bres\.redirect$", "redirect", "redirect to an untrusted location",
         "Open redirect used for phishing and OAuth token theft.", args=(0, 1), weight=6),
    Sink("js.res_send", r"\bres\.(send|write|end)$", "xss",
         "request data written into the response",
         "Reflected XSS if the response is HTML and the value is not escaped.",
         args=(0,), weight=7),
    Sink("js.header", r"\bres\.(setHeader|writeHead|append|header)$", "redirect",
         "response header built from input",
         "Header injection, or an open redirect through Location.", args=(1, 0), weight=6),
    Sink("js.template", r"\b(pug|jade|ejs|handlebars|hbs|nunjucks|eta|mustache)\.(compile|render|"
                        r"renderString|renderFile|compileFile)$|\bres\.render$", "tmpl",
         "template compiled from untrusted input",
         "Server-side template injection is remote code execution in most engines.",
         args=(0,), weight=9),
    Sink("js.ng_bypass", r"\bbypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)$", "xss",
         "Angular sanitizer bypassed on untrusted value",
         "Marks attacker data as trusted markup, defeating Angular's escaping.",
         args=(0,), weight=8),
    Sink("js.extract", r"(?:^|\.)(extract|extractAll|unzip)$", "path",
         "archive extracted to an untrusted path",
         "Zip slip: archive members can escape the target directory.", args=(0,), weight=7),
)

SANITIZERS = (
    Sanitizer("js.int", r"^(parseInt|parseFloat|Number|BigInt)$", "numeric conversion"),
    Sanitizer("js.encode", r"^(encodeURIComponent|encodeURI|escape)$", "URI encoding",
              kills=("ssrf", "redirect", "xss")),
    Sanitizer("js.escape_html", r"\b(escapeHtml|escape-html|sanitizeHtml|DOMPurify\.sanitize|"
                                r"validator\.escape)$", "HTML escaping", kills=("xss",)),
    Sanitizer("js.basename", r"\bpath\.basename$", "path.basename()", kills=("path",)),
    Sanitizer("js.shellquote", r"\b(shellQuote\.quote|shell-quote|escapeShell)$",
              "shell quoting", kills=("cmd",)),
    Sanitizer("js.sqlescape", r"\b(mysql\.escape|escapeId|connection\.escape)$",
              "SQL escaping", kills=("sqli",)),
    Sanitizer("js.validator", r"\bvalidator\.(isURL|isEmail|isUUID|isInt|isAlphanumeric)$",
              "validator.js check"),
)

PROPAGATORS = (
    Propagator("js.string", r"^(String|JSON\.stringify|decodeURIComponent|decodeURI)$"),
    Propagator("js.methods", r"(?:^|\.)(toString|trim|toLowerCase|toUpperCase|replace|slice|"
                             r"substring|substr|concat|join|split|padStart|padEnd|normalize)$"),
    Propagator("js.pathjoin", r"\bpath\.(join|resolve|normalize)$"),
    Propagator("js.await", r"^(await|Promise\.resolve)$"),
)

PARAM_SOURCES = (
    ParamSource("js.express", "express request",
                type_pattern=r"(^|\.)(Request|express\.Request)$",
                name_pattern=r"^(req|request)$",
                requires=r"\bexpress\b|\brouter\s*\.\s*(get|post|put|patch|delete|all)\b|"
                         r"\bapp\s*\.\s*(get|post|put|patch|delete|use|all)\s*\(|"
                         r"\bres\s*\.\s*(send|json|status|render|redirect)\b"),
    ParamSource("js.koa", "koa context", type_pattern=r"(^|\.)Context$",
                name_pattern=r"^ctx$",
                requires=r"\bkoa\b|\bKoa\b|\bctx\s*\.\s*(request|response|throw|body)\b"),
    ParamSource("js.lambda", "lambda event",
                type_pattern=r"(^|\.)(APIGatewayProxyEvent|APIGatewayEvent)$",
                name_pattern=r"^event$",
                requires=r"\bexports\s*\.\s*handler\b|\bhandler\s*[:=]|aws-lambda|"
                         r"\bevent\s*\.\s*(requestContext|pathParameters|queryStringParameters)\b"),
    ParamSource("js.fastify", "fastify request",
                type_pattern=r"(^|\.)FastifyRequest$"),
)

# A response object, a callback and an error are not user input. `res` reaching `res.send`
# is the framework working as designed.
NEVER_PARAMS = (
    r"^(res|response|reply)$", r"(^|\.)(Response|ServerResponse|FastifyReply)$",
    r"^next$", r"^(err|error|e)$", r"(^|\.)Error$",
    r"^(done|cb|callback)$", r"^logger$", r"^log$", r"^self$", r"^_$",
    r"(^|\.)(Logger|Console)$", r"^options$", r"^config$",
)

BARRIERS = (
    Barrier("js.console", r"\b(console|logger|log)\.(log|info|warn|error|debug|trace)$",
            "logging"),
    Barrier("js.len", r"^(Boolean|Array\.isArray|typeof)$", "inspection"),
    Barrier("js.abort", r"^(AbortController|setTimeout|setInterval|clearTimeout)$",
            "timers and cancellation"),
    Barrier("js.error", r"^(Error|TypeError|RangeError)$", "error construction"),
)

HANDLER_REGISTRARS = (
    r"\b\w*(app|router|server|api|route|fastify)\."
    r"(get|post|put|patch|delete|use|all|options|head|route|register)$",
    r"\b\w*\.(addHook|on|addEventListener)$",
    r"\b(createServer|serve)$",
)

GUARDS = (
    # /^[a-z]+$/.test(name) - the receiver is the pattern, the argument is the value
    Guard("js.test", r"(?:^|\.)test$", "regex", value_arg=0, pattern_arg=-1),
    Guard("js.match", r"(?:^|\.)(match|matchAll)$", "regex", value_arg=-1, pattern_arg=0),
    Guard("js.includes", r"(?:^|\.)(includes|has)$", "membership", value_arg=0,
          pattern_arg=-1),
    Guard("js.startswith", r"(?:^|\.)startsWith$", "prefix", value_arg=-1, pattern_arg=0),
    Guard("js.endswith", r"(?:^|\.)endsWith$", "suffix", value_arg=-1, pattern_arg=0),
    Guard("js.isinteger", r"\b(Number\.isInteger|Number\.isSafeInteger)$", "numeric",
          value_arg=0),
    Guard("js.validator_int", r"\bvalidator\.(isInt|isFloat|isNumeric|isDecimal)$", "numeric",
          value_arg=0),
    Guard("js.validator_uuid", r"\bvalidator\.isUUID$", "regex", value_arg=0,
          literal=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),
    Guard("js.validator_alnum", r"\bvalidator\.isAlphanumeric$", "regex", value_arg=0,
          literal=r"^[A-Za-z0-9]+$"),
    Guard("js.validator_slug", r"\bvalidator\.isSlug$", "regex", value_arg=0,
          literal=r"^[A-Za-z0-9-]+$"),
    Guard("js.validator_hex", r"\bvalidator\.(isHexadecimal|isMongoId)$", "regex",
          value_arg=0, literal=r"^[0-9a-fA-F]+$"),
)

IMPORTS = (
    ImportRule("js.require_destructure",
               r"(?:const|let|var)\s*\{(?P<names>[^}]*)\}\s*=\s*require\(\s*"
               r"['\"](?P<spec>[^'\"]+)['\"]"),
    ImportRule("js.require",
               r"(?:const|let|var)\s+(?P<alias>[A-Za-z_$][\w$]*)\s*=\s*require\(\s*"
               r"['\"](?P<spec>[^'\"]+)['\"]"),
    ImportRule("js.esm_named",
               r"import\s*\{(?P<names>[^}]*)\}\s*from\s*['\"](?P<spec>[^'\"]+)['\"]"),
    ImportRule("js.esm_star",
               r"import\s*\*\s*as\s+(?P<alias>[A-Za-z_$][\w$]*)\s*from\s*"
               r"['\"](?P<spec>[^'\"]+)['\"]"),
    ImportRule("js.esm_default",
               r"import\s+(?P<alias>[A-Za-z_$][\w$]*)\s*(?:,\s*\{(?P<names>[^}]*)\}\s*)?"
               r"from\s*['\"](?P<spec>[^'\"]+)['\"]"),
    ImportRule("js.bare", r"^\s*import\s+['\"](?P<spec>[^'\"]+)['\"]"),
)

EXPORTS = (
    r"\bexports\.(\w+)\s*=",
    r"\bmodule\.exports\.(\w+)\s*=",
    r"\bexport\s+(?:async\s+)?function\s*\*?\s*(\w+)",
    r"\bexport\s+(?:const|let|var|class)\s+(\w+)",
    r"\bexport\s*\{\s*([^}]*)\}",
)

BINDINGS = (
    # constructor(private userService: UserService) / field: UserService
    r"(?:private|public|protected|readonly)\s+(?P<name>[A-Za-z_$][\w$]*)\s*:\s*"
    r"(?P<type>[A-Z][\w$]*)",
    r"(?P<name>[A-Za-z_$][\w$]*)\s*:\s*(?P<type>[A-Z][\w$]*)\s*[,)]",
    r"(?:this\.)?(?P<name>[A-Za-z_$][\w$]*)\s*=\s*new\s+(?P<type>[A-Z][\w$]*)",
)

SPEC = LangSpec(
    lang="javascript",
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
    shells=(r"^(/bin/)?(sh|bash|zsh|dash)$", r"^cmd(\.exe)?$", r"^powershell(\.exe)?$"),
    replacers=((r"(?:^|\.)(replace|replaceAll)$", 0, 1),),
    guards=GUARDS,
    imports=IMPORTS,
    exports=EXPORTS,
    bindings=BINDINGS,
)
