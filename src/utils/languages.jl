"""
Language detection and support for Oracle.
"""

# ══════════════════════════════════════════════════════════════════════════════
# LANGUAGE DETECTION
# ══════════════════════════════════════════════════════════════════════════════

"""
Detect programming language from file path.
"""
function detect_language(filepath::String)::Symbol
    ext = lowercase(splitext(filepath)[2])
    return get(EXTENSION_MAP, ext, :unknown)
end

const EXTENSION_MAP = Dict{String, Symbol}(
    # C/C++
    ".c" => :c,
    ".h" => :c,
    ".cpp" => :cpp,
    ".cc" => :cpp,
    ".cxx" => :cpp,
    ".hpp" => :cpp,
    ".hxx" => :cpp,
    
    # Java/Kotlin
    ".java" => :java,
    ".kt" => :kotlin,
    ".kts" => :kotlin,
    
    # JavaScript/TypeScript
    ".js" => :javascript,
    ".jsx" => :javascript,
    ".mjs" => :javascript,
    ".ts" => :typescript,
    ".tsx" => :typescript,
    
    # Python
    ".py" => :python,
    ".pyw" => :python,
    ".pyx" => :python,
    
    # Ruby
    ".rb" => :ruby,
    ".erb" => :ruby,
    
    # Go
    ".go" => :go,
    
    # Rust
    ".rs" => :rust,
    
    # PHP
    ".php" => :php,
    ".phtml" => :php,
    
    # Swift
    ".swift" => :swift,
    
    # C#
    ".cs" => :csharp,
    
    # Scala
    ".scala" => :scala,
    
    # Julia
    ".jl" => :julia,
    
    # Shell
    ".sh" => :shell,
    ".bash" => :shell,
    ".zsh" => :shell,
    
    # Perl
    ".pl" => :perl,
    ".pm" => :perl,
    
    # Lua
    ".lua" => :lua,
    
    # R
    ".r" => :r,
    ".R" => :r,
    
    # Objective-C
    ".m" => :objc,
    ".mm" => :objc,
    
    # Assembly
    ".asm" => :assembly,
    ".s" => :assembly,
    
    # Web
    ".html" => :html,
    ".htm" => :html,
    ".css" => :css,
    ".scss" => :scss,
    ".sass" => :sass,
    
    # Config/Data
    ".json" => :json,
    ".yaml" => :yaml,
    ".yml" => :yaml,
    ".xml" => :xml,
    ".toml" => :toml,
    
    # SQL
    ".sql" => :sql,
)

"""
Get supported file extensions for scanning.
"""
function supported_extensions()::Set{String}
    # Security-relevant extensions
    return Set([
        ".c", ".h", ".cpp", ".cc", ".hpp",
        ".java", ".kt",
        ".js", ".jsx", ".ts", ".tsx",
        ".py",
        ".rb",
        ".go",
        ".rs",
        ".php",
        ".swift",
        ".cs",
        ".scala",
        ".jl",
        ".sh",
        ".pl",
        ".lua",
    ])
end

# ══════════════════════════════════════════════════════════════════════════════
# LANGUAGE-SPECIFIC PATTERNS
# ══════════════════════════════════════════════════════════════════════════════

"""
Dangerous functions by language that are common vulnerability sources.
"""
const DANGEROUS_FUNCTIONS = Dict{Symbol, Vector{String}}(
    :c => [
        # Memory
        "strcpy", "strncpy", "strcat", "strncat", "sprintf", "vsprintf",
        "gets", "scanf", "fscanf", "sscanf",
        "memcpy", "memmove", "memset",
        "malloc", "calloc", "realloc", "free",
        "alloca",
        # Format strings
        "printf", "fprintf", "snprintf", "vprintf", "vfprintf",
        # System
        "system", "popen", "exec", "execl", "execle", "execlp",
        "execv", "execve", "execvp",
        # File
        "fopen", "freopen", "tmpfile", "tmpnam", "tempnam",
        "mktemp", "mkstemp",
    ],
    
    :cpp => [
        # Inherited from C
        "strcpy", "strncpy", "strcat", "sprintf", "gets",
        "memcpy", "memmove", "malloc", "free",
        "system", "popen",
        # C++ specific
        "new", "delete",
        "reinterpret_cast",
        "const_cast",
    ],
    
    :java => [
        # Code execution
        "Runtime.exec", "ProcessBuilder",
        # Reflection
        "Class.forName", "Method.invoke",
        # Deserialization
        "ObjectInputStream.readObject", "XMLDecoder",
        # SQL
        "Statement.execute", "Statement.executeQuery", "Statement.executeUpdate",
        # LDAP
        "InitialContext.lookup",
        # XXE
        "XMLReader", "SAXParser", "DocumentBuilder",
        # SSRF
        "URL.openConnection", "HttpURLConnection",
        # Path traversal
        "new File", "FileInputStream", "FileOutputStream",
        # XSS
        "PrintWriter.print", "PrintWriter.println",
    ],
    
    :javascript => [
        # Code execution
        "eval", "Function", "setTimeout", "setInterval",
        # DOM XSS
        "innerHTML", "outerHTML", "document.write", "document.writeln",
        "insertAdjacentHTML",
        # Prototype pollution
        "__proto__", "constructor.prototype",
        # Command injection
        "child_process.exec", "child_process.spawn",
        "require('child_process')",
        # SQL injection
        "mysql.query", "connection.query",
        # Path traversal
        "fs.readFile", "fs.writeFile", "fs.readFileSync",
        # Deserialization
        "JSON.parse", "serialize", "unserialize",
    ],
    
    :python => [
        # Code execution
        "eval", "exec", "compile", "__import__",
        # Command injection
        "os.system", "os.popen", "subprocess.call", "subprocess.run",
        "subprocess.Popen", "commands.getoutput",
        # Deserialization
        "pickle.load", "pickle.loads", "cPickle.load",
        "yaml.load", "yaml.unsafe_load",
        "marshal.load", "shelve.open",
        # SQL injection
        "cursor.execute", "connection.execute",
        # Path traversal
        "open", "file", "os.path.join",
        # SSRF
        "urllib.urlopen", "urllib2.urlopen", "requests.get",
        # XXE
        "xml.etree.ElementTree.parse", "lxml.etree.parse",
        # Template injection
        "render_template_string", "Template",
    ],
    
    :php => [
        # Code execution
        "eval", "assert", "create_function", "preg_replace",
        # Command injection
        "system", "exec", "shell_exec", "passthru", "popen",
        "proc_open", "pcntl_exec", "backticks",
        # File inclusion
        "include", "include_once", "require", "require_once",
        # SQL injection
        "mysql_query", "mysqli_query", "pg_query",
        # Deserialization
        "unserialize", "maybe_unserialize",
        # File operations
        "file_get_contents", "file_put_contents", "fopen", "readfile",
        "move_uploaded_file",
        # XXE
        "simplexml_load_string", "DOMDocument::loadXML",
        # SSRF
        "curl_exec", "file_get_contents",
    ],
    
    :go => [
        # Command injection
        "exec.Command", "os/exec",
        # SQL injection  
        "db.Query", "db.Exec", "db.QueryRow",
        # Path traversal
        "os.Open", "ioutil.ReadFile", "os.Create",
        # Template injection
        "template.HTML", "template.JS", "template.CSS",
        # Deserialization
        "json.Unmarshal", "gob.Decode", "xml.Unmarshal",
        # Unsafe
        "unsafe.Pointer",
    ],
    
    :rust => [
        # Unsafe
        "unsafe", "transmute", "from_raw_parts",
        # Command execution
        "Command::new", "process::Command",
        # Raw pointers
        "as_ptr", "as_mut_ptr",
        # Memory
        "std::mem::forget", "std::mem::uninitialized",
    ],
    
    :ruby => [
        # Code execution
        "eval", "instance_eval", "class_eval", "module_eval",
        "send", "__send__", "public_send",
        # Command injection
        "system", "exec", "`", "spawn", "popen",
        "IO.popen", "Open3.popen3",
        # Deserialization
        "Marshal.load", "YAML.load",
        # SQL injection
        "find_by_sql", "execute",
        # File operations
        "File.open", "File.read", "File.write",
        # ERB injection
        "ERB.new",
    ],
)

"""
Get dangerous functions for a language.
"""
function get_dangerous_functions(language::Symbol)::Vector{String}
    return get(DANGEROUS_FUNCTIONS, language, String[])
end

# ══════════════════════════════════════════════════════════════════════════════
# INPUT/OUTPUT PATTERNS
# ══════════════════════════════════════════════════════════════════════════════

"""
Input source patterns (where tainted data enters).
"""
const INPUT_SOURCES = Dict{Symbol, Vector{Regex}}(
    :c => [
        r"scanf\s*\(",
        r"fgets\s*\(",
        r"gets\s*\(",
        r"read\s*\(",
        r"recv\s*\(",
        r"getenv\s*\(",
        r"argv\[",
    ],
    
    :python => [
        r"input\s*\(",
        r"raw_input\s*\(",
        r"sys\.argv",
        r"request\.(args|form|data|json|values)",
        r"os\.environ",
        r"\.read\(\)",
        r"socket\.recv",
    ],
    
    :javascript => [
        r"req\.(params|query|body|headers)",
        r"process\.argv",
        r"process\.env",
        r"document\.(location|cookie|referrer)",
        r"window\.location",
        r"\.value\b",
        r"localStorage\.getItem",
        r"sessionStorage\.getItem",
    ],
    
    :java => [
        r"request\.getParameter",
        r"request\.getHeader",
        r"request\.getCookies",
        r"System\.getenv",
        r"\.readLine\(\)",
        r"Scanner\s*\(",
        r"args\[",
    ],
    
    :php => [
        r"\$_GET",
        r"\$_POST",
        r"\$_REQUEST",
        r"\$_COOKIE",
        r"\$_SERVER",
        r"\$_FILES",
        r"getenv\s*\(",
        r"file_get_contents\s*\(\s*['\"]php://input",
    ],
    
    :go => [
        r"r\.URL\.Query\(\)",
        r"r\.FormValue\(",
        r"r\.Header\.Get\(",
        r"os\.Args",
        r"os\.Getenv\(",
        r"bufio\.NewReader",
    ],
)

"""
Output sink patterns (where dangerous operations occur).
"""
const OUTPUT_SINKS = Dict{Symbol, Vector{Regex}}(
    :c => [
        r"printf\s*\(",
        r"sprintf\s*\(",
        r"system\s*\(",
        r"exec\w*\s*\(",
        r"write\s*\(",
        r"send\s*\(",
    ],
    
    :python => [
        r"print\s*\(",
        r"os\.system\s*\(",
        r"subprocess\.\w+\s*\(",
        r"cursor\.execute\s*\(",
        r"\.write\s*\(",
        r"render_template\s*\(",
    ],
    
    :javascript => [
        r"eval\s*\(",
        r"innerHTML\s*=",
        r"document\.write\s*\(",
        r"\.exec\s*\(",
        r"\.query\s*\(",
        r"res\.(send|write|render)\s*\(",
    ],
    
    :java => [
        r"Runtime\..*exec\s*\(",
        r"Statement\.execute\w*\s*\(",
        r"\.write\s*\(",
        r"response\.getWriter\(\)\.print",
    ],
    
    :php => [
        r"echo\s+",
        r"print\s+",
        r"system\s*\(",
        r"exec\s*\(",
        r"mysql\w*_query\s*\(",
        r"include\s*\(",
    ],
    
    :go => [
        r"fmt\.Print",
        r"io\.WriteString",
        r"exec\.Command",
        r"db\.(Query|Exec)",
        r"template\.Execute",
    ],
)

"""
Get input source patterns for a language.
"""
function get_input_sources(language::Symbol)::Vector{Regex}
    return get(INPUT_SOURCES, language, Regex[])
end

"""
Get output sink patterns for a language.
"""
function get_output_sinks(language::Symbol)::Vector{Regex}
    return get(OUTPUT_SINKS, language, Regex[])
end

# ══════════════════════════════════════════════════════════════════════════════
# LANGUAGE FEATURES
# ══════════════════════════════════════════════════════════════════════════════

"""
Language feature support matrix.
"""
struct LanguageFeatures
    has_pointers::Bool
    has_manual_memory::Bool
    has_garbage_collection::Bool
    has_type_safety::Bool
    has_bounds_checking::Bool
    has_null_safety::Bool
    common_vulns::Vector{VulnClass}
end

const LANGUAGE_FEATURES = Dict{Symbol, LanguageFeatures}(
    :c => LanguageFeatures(
        true, true, false, false, false, false,
        [BUFFER_OVERFLOW, USE_AFTER_FREE, INJECTION, CODE_EXECUTION]
    ),
    :cpp => LanguageFeatures(
        true, true, false, true, false, false,
        [BUFFER_OVERFLOW, USE_AFTER_FREE, TYPE_CONFUSION, INJECTION]
    ),
    :java => LanguageFeatures(
        false, false, true, true, true, false,
        [INJECTION, DESERIALIZATION, SSRF, XSS]
    ),
    :javascript => LanguageFeatures(
        false, false, true, false, true, false,
        [XSS, INJECTION, DESERIALIZATION, CODE_EXECUTION]
    ),
    :python => LanguageFeatures(
        false, false, true, false, true, false,
        [INJECTION, DESERIALIZATION, CODE_EXECUTION, PATH_TRAVERSAL]
    ),
    :go => LanguageFeatures(
        true, false, true, true, true, false,
        [INJECTION, RACE_CONDITION, INFORMATION_DISCLOSURE]
    ),
    :rust => LanguageFeatures(
        true, true, false, true, true, true,
        [RACE_CONDITION, USE_AFTER_FREE]  # Rare due to borrow checker
    ),
    :php => LanguageFeatures(
        false, false, true, false, true, false,
        [INJECTION, XSS, DESERIALIZATION, CODE_EXECUTION, PATH_TRAVERSAL]
    ),
)

"""
Get language features.
"""
function get_language_features(language::Symbol)::Union{LanguageFeatures, Nothing}
    return get(LANGUAGE_FEATURES, language, nothing)
end

"""
Get common vulnerability classes for a language.
"""
function common_vulns_for_language(language::Symbol)::Vector{VulnClass}
    features = get_language_features(language)
    isnothing(features) && return VulnClass[]
    return features.common_vulns
end
