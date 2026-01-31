"""
Vulnerability pattern database for Oracle.
"""

# ══════════════════════════════════════════════════════════════════════════════
# PATTERN DATABASE
# ══════════════════════════════════════════════════════════════════════════════

"""
In-memory pattern database.
"""
mutable struct PatternDatabase
    patterns::Dict{UUID, VulnerabilityPattern}
    index_by_class::Dict{VulnClass, Vector{UUID}}
    index_by_language::Dict{Symbol, Vector{UUID}}
    index_by_cwe::Dict{String, Vector{UUID}}
    last_updated::DateTime
    
    PatternDatabase() = new(
        Dict{UUID, VulnerabilityPattern}(),
        Dict{VulnClass, Vector{UUID}}(),
        Dict{Symbol, Vector{UUID}}(),
        Dict{String, Vector{UUID}}(),
        now()
    )
end

# Global pattern database
const PATTERN_DB = Ref{PatternDatabase}()

"""
Initialize the pattern database.
"""
function init_pattern_database()
    PATTERN_DB[] = PatternDatabase()
    load_builtin_patterns!()
end

"""
Load default patterns.
"""
function load_default_patterns()::Vector{VulnerabilityPattern}
    if !isassigned(PATTERN_DB)
        init_pattern_database()
    end
    return collect(values(PATTERN_DB[].patterns))
end

"""
Load built-in vulnerability patterns.
"""
function load_builtin_patterns!()
    db = PATTERN_DB[]
    
    # SQL Injection patterns
    add_pattern!(db, create_sql_injection_patterns()...)
    
    # Command Injection patterns
    add_pattern!(db, create_command_injection_patterns()...)
    
    # XSS patterns
    add_pattern!(db, create_xss_patterns()...)
    
    # Buffer Overflow patterns
    add_pattern!(db, create_buffer_overflow_patterns()...)
    
    # Deserialization patterns
    add_pattern!(db, create_deserialization_patterns()...)
    
    # Path Traversal patterns
    add_pattern!(db, create_path_traversal_patterns()...)
    
    # Authentication patterns
    add_pattern!(db, create_auth_patterns()...)
    
    # Crypto patterns
    add_pattern!(db, create_crypto_patterns()...)
    
    db.last_updated = now()
end

"""
Add patterns to the database.
"""
function add_pattern!(db::PatternDatabase, patterns::VulnerabilityPattern...)
    for pattern in patterns
        db.patterns[pattern.id] = pattern
        
        # Index by class
        if !haskey(db.index_by_class, pattern.vuln_class)
            db.index_by_class[pattern.vuln_class] = UUID[]
        end
        push!(db.index_by_class[pattern.vuln_class], pattern.id)
        
        # Index by language
        for lang in pattern.languages
            if !haskey(db.index_by_language, lang)
                db.index_by_language[lang] = UUID[]
            end
            push!(db.index_by_language[lang], pattern.id)
        end
        
        # Index by CWE
        for cwe in pattern.cwe_ids
            if !haskey(db.index_by_cwe, cwe)
                db.index_by_cwe[cwe] = UUID[]
            end
            push!(db.index_by_cwe[cwe], pattern.id)
        end
    end
end

# ══════════════════════════════════════════════════════════════════════════════
# PATTERN CREATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Create SQL injection patterns.
"""
function create_sql_injection_patterns()::Vector{VulnerabilityPattern}
    patterns = VulnerabilityPattern[]
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "SQL Injection - String Concatenation",
        INJECTION,
        "SQL query built using string concatenation with user input",
        [
            r"(?i)(select|insert|update|delete|drop)\s+.*\+\s*\w+",
            r"(?i)\".*\s+(select|insert|update|delete).*\"\s*\+",
            r"(?i)f\".*\{.*\}.*(?:select|insert|update|delete)",
            r"(?i)\$\".*\{.*\}.*(?:select|insert|update|delete)",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(),
        0.9,
        0.95,
        ["CWE-89", "CWE-564"],
        ["https://owasp.org/www-community/attacks/SQL_Injection"],
        [:python, :javascript, :java, :php, :csharp, :go, :ruby],
        now(),
        now()
    ))
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "SQL Injection - Format String",
        INJECTION,
        "SQL query built using format strings with user input",
        [
            r"(?i)\.format\s*\([^)]*\).*(?:select|insert|update|delete)",
            r"(?i)sprintf\s*\([^)]*(?:select|insert|update|delete)",
            r"(?i)%s.*(?:select|insert|update|delete)",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(),
        0.85,
        0.9,
        ["CWE-89"],
        ["https://cwe.mitre.org/data/definitions/89.html"],
        [:python, :php, :c, :cpp],
        now(),
        now()
    ))
    
    return patterns
end

"""
Create command injection patterns.
"""
function create_command_injection_patterns()::Vector{VulnerabilityPattern}
    patterns = VulnerabilityPattern[]
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Command Injection - System Call",
        CODE_EXECUTION,
        "System command execution with user-controlled input",
        [
            r"(?i)system\s*\([^)]*\+",
            r"(?i)exec\s*\([^)]*\+",
            r"(?i)popen\s*\([^)]*\+",
            r"(?i)subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True",
            r"(?i)os\.system\s*\([^)]*\+",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(),
        0.95,
        0.98,
        ["CWE-78", "CWE-77"],
        ["https://owasp.org/www-community/attacks/Command_Injection"],
        [:python, :php, :ruby, :c, :cpp, :java],
        now(),
        now()
    ))
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Command Injection - Backticks",
        CODE_EXECUTION,
        "Command execution using backticks with user input",
        [
            r"`[^`]*\$",
            r"(?i)shell_exec\s*\(",
            r"(?i)`\s*\+",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(),
        0.9,
        0.95,
        ["CWE-78"],
        [],
        [:php, :ruby, :perl, :shell],
        now(),
        now()
    ))
    
    return patterns
end

"""
Create XSS patterns.
"""
function create_xss_patterns()::Vector{VulnerabilityPattern}
    patterns = VulnerabilityPattern[]
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "XSS - innerHTML Assignment",
        XSS,
        "Direct assignment to innerHTML with user input",
        [
            r"(?i)\.innerHTML\s*=\s*[^;]*\+",
            r"(?i)\.innerHTML\s*=\s*`[^`]*\$\{",
            r"(?i)\.innerHTML\s*=\s*[^;]*(?:request|params|query|input)",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(),
        0.85,
        0.9,
        ["CWE-79"],
        ["https://owasp.org/www-community/attacks/xss/"],
        [:javascript, :typescript],
        now(),
        now()
    ))
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "XSS - document.write",
        XSS,
        "document.write with user input",
        [
            r"(?i)document\.write\s*\([^)]*\+",
            r"(?i)document\.write\s*\([^)]*(?:location|cookie|referrer)",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(),
        0.9,
        0.92,
        ["CWE-79"],
        [],
        [:javascript, :typescript],
        now(),
        now()
    ))
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "XSS - Template Without Escaping",
        XSS,
        "Template rendering without proper escaping",
        [
            r"\{\{\s*\w+\s*\}\}",  # Double braces without escape
            r"\{\%\s*autoescape\s+false",
            r"(?i)render_template_string\s*\(",
            r"\|\s*safe\s*\}\}",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(),
        0.7,
        0.8,
        ["CWE-79"],
        [],
        [:python, :javascript, :ruby, :php],
        now(),
        now()
    ))
    
    return patterns
end

"""
Create buffer overflow patterns.
"""
function create_buffer_overflow_patterns()::Vector{VulnerabilityPattern}
    patterns = VulnerabilityPattern[]
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Buffer Overflow - strcpy",
        BUFFER_OVERFLOW,
        "Use of strcpy without bounds checking",
        [
            r"\bstrcpy\s*\(",
            r"\bstrcat\s*\(",
            r"\bsprintf\s*\(",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(:uses_strncpy => true),
        0.8,
        0.85,
        ["CWE-120", "CWE-119"],
        ["https://cwe.mitre.org/data/definitions/120.html"],
        [:c, :cpp],
        now(),
        now()
    ))
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Buffer Overflow - gets",
        BUFFER_OVERFLOW,
        "Use of gets() - always vulnerable",
        [
            r"\bgets\s*\(",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(),
        1.0,
        1.0,
        ["CWE-120", "CWE-242"],
        [],
        [:c, :cpp],
        now(),
        now()
    ))
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Buffer Overflow - Unchecked Array Access",
        BUFFER_OVERFLOW,
        "Array access without bounds checking",
        [
            r"\w+\s*\[\s*\w+\s*\]\s*=",
            r"\*\s*\(\s*\w+\s*\+\s*\w+\s*\)",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(:has_bounds_check => false),
        Dict{Symbol, Any}(),
        0.6,
        0.7,
        ["CWE-119", "CWE-787"],
        [],
        [:c, :cpp],
        now(),
        now()
    ))
    
    return patterns
end

"""
Create deserialization patterns.
"""
function create_deserialization_patterns()::Vector{VulnerabilityPattern}
    patterns = VulnerabilityPattern[]
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Insecure Deserialization - Pickle",
        DESERIALIZATION,
        "Python pickle deserialization of untrusted data",
        [
            r"(?i)pickle\.loads?\s*\(",
            r"(?i)cPickle\.loads?\s*\(",
            r"(?i)_pickle\.loads?\s*\(",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(),
        0.9,
        0.95,
        ["CWE-502"],
        ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests"],
        [:python],
        now(),
        now()
    ))
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Insecure Deserialization - YAML",
        DESERIALIZATION,
        "YAML deserialization with unsafe loader",
        [
            r"(?i)yaml\.load\s*\([^)]*\)",
            r"(?i)yaml\.unsafe_load\s*\(",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(:uses_safe_load => true),
        0.85,
        0.9,
        ["CWE-502"],
        [],
        [:python, :ruby],
        now(),
        now()
    ))
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Insecure Deserialization - PHP unserialize",
        DESERIALIZATION,
        "PHP unserialize with user input",
        [
            r"(?i)unserialize\s*\(\s*\$",
            r"(?i)maybe_unserialize\s*\(",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(),
        0.9,
        0.92,
        ["CWE-502"],
        [],
        [:php],
        now(),
        now()
    ))
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Insecure Deserialization - Java ObjectInputStream",
        DESERIALIZATION,
        "Java ObjectInputStream without validation",
        [
            r"(?i)ObjectInputStream\s*\(",
            r"(?i)\.readObject\s*\(\s*\)",
            r"(?i)XMLDecoder\s*\(",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(),
        0.85,
        0.9,
        ["CWE-502"],
        [],
        [:java],
        now(),
        now()
    ))
    
    return patterns
end

"""
Create path traversal patterns.
"""
function create_path_traversal_patterns()::Vector{VulnerabilityPattern}
    patterns = VulnerabilityPattern[]
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Path Traversal - Direct Concatenation",
        PATH_TRAVERSAL,
        "File path built with user input without validation",
        [
            r"(?i)open\s*\([^)]*\+",
            r"(?i)fopen\s*\([^)]*\+",
            r"(?i)file_get_contents\s*\([^)]*\+",
            r"(?i)readFile\s*\([^)]*\+",
            r"(?i)os\.path\.join\s*\([^)]*(?:request|params|input)",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(),
        0.8,
        0.85,
        ["CWE-22", "CWE-73"],
        ["https://owasp.org/www-community/attacks/Path_Traversal"],
        [:python, :javascript, :php, :java, :ruby, :go],
        now(),
        now()
    ))
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Path Traversal - Include/Require",
        PATH_TRAVERSAL,
        "PHP include/require with user input",
        [
            r"(?i)include\s*\(\s*\$",
            r"(?i)include_once\s*\(\s*\$",
            r"(?i)require\s*\(\s*\$",
            r"(?i)require_once\s*\(\s*\$",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(),
        0.95,
        0.98,
        ["CWE-22", "CWE-98"],
        [],
        [:php],
        now(),
        now()
    ))
    
    return patterns
end

"""
Create authentication patterns.
"""
function create_auth_patterns()::Vector{VulnerabilityPattern}
    patterns = VulnerabilityPattern[]
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Hardcoded Credentials",
        AUTHENTICATION_BYPASS,
        "Hardcoded password or API key in source code",
        [
            r"(?i)password\s*=\s*['\"][^'\"]+['\"]",
            r"(?i)api_key\s*=\s*['\"][^'\"]+['\"]",
            r"(?i)secret\s*=\s*['\"][^'\"]+['\"]",
            r"(?i)token\s*=\s*['\"][A-Za-z0-9+/=]{20,}['\"]",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(:is_config_file => true),
        0.7,
        0.8,
        ["CWE-798", "CWE-259"],
        [],
        [:python, :javascript, :java, :php, :go, :ruby, :csharp],
        now(),
        now()
    ))
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Weak Password Comparison",
        AUTHENTICATION_BYPASS,
        "Password comparison that may be vulnerable to timing attacks",
        [
            r"(?i)password\s*==\s*",
            r"(?i)\.equals\s*\(\s*password",
            r"(?i)strcmp\s*\([^)]*password",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(:uses_constant_time => true),
        0.6,
        0.7,
        ["CWE-208"],
        [],
        [:python, :javascript, :java, :php, :c, :cpp],
        now(),
        now()
    ))
    
    return patterns
end

"""
Create cryptography patterns.
"""
function create_crypto_patterns()::Vector{VulnerabilityPattern}
    patterns = VulnerabilityPattern[]
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Weak Cryptographic Algorithm - MD5",
        CRYPTO_WEAKNESS,
        "Use of MD5 for security purposes",
        [
            r"(?i)\bmd5\s*\(",
            r"(?i)hashlib\.md5",
            r"(?i)MessageDigest\.getInstance\s*\(\s*['\"]MD5",
            r"(?i)crypto\.createHash\s*\(\s*['\"]md5",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(:is_checksum => true),
        0.7,
        0.8,
        ["CWE-327", "CWE-328"],
        [],
        [:python, :javascript, :java, :php, :go, :ruby],
        now(),
        now()
    ))
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Weak Cryptographic Algorithm - SHA1",
        CRYPTO_WEAKNESS,
        "Use of SHA1 for security purposes",
        [
            r"(?i)\bsha1\s*\(",
            r"(?i)hashlib\.sha1",
            r"(?i)MessageDigest\.getInstance\s*\(\s*['\"]SHA-?1",
            r"(?i)crypto\.createHash\s*\(\s*['\"]sha1",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(:is_checksum => true),
        0.6,
        0.7,
        ["CWE-327", "CWE-328"],
        [],
        [:python, :javascript, :java, :php, :go, :ruby],
        now(),
        now()
    ))
    
    push!(patterns, VulnerabilityPattern(
        uuid4(),
        "Weak Random Number Generator",
        CRYPTO_WEAKNESS,
        "Use of weak random number generator for security",
        [
            r"(?i)\brandom\s*\(",
            r"(?i)Math\.random\s*\(",
            r"(?i)rand\s*\(",
            r"(?i)java\.util\.Random",
        ],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(:in_security_context => true),
        Dict{Symbol, Any}(),
        0.5,
        0.6,
        ["CWE-330", "CWE-338"],
        [],
        [:python, :javascript, :java, :php, :c, :cpp],
        now(),
        now()
    ))
    
    return patterns
end

# ══════════════════════════════════════════════════════════════════════════════
# PATTERN QUERIES
# ══════════════════════════════════════════════════════════════════════════════

"""
Get patterns for a vulnerability class.
"""
function get_patterns_for_class(vuln_class::VulnClass)::Vector{VulnerabilityPattern}
    if !isassigned(PATTERN_DB)
        init_pattern_database()
    end
    
    db = PATTERN_DB[]
    pattern_ids = get(db.index_by_class, vuln_class, UUID[])
    return [db.patterns[id] for id in pattern_ids if haskey(db.patterns, id)]
end

"""
Get patterns for a language.
"""
function get_patterns_for_language(language::Symbol)::Vector{VulnerabilityPattern}
    if !isassigned(PATTERN_DB)
        init_pattern_database()
    end
    
    db = PATTERN_DB[]
    pattern_ids = get(db.index_by_language, language, UUID[])
    return [db.patterns[id] for id in pattern_ids if haskey(db.patterns, id)]
end

"""
Get patterns for a CWE ID.
"""
function get_patterns_for_cwe(cwe_id::String)::Vector{VulnerabilityPattern}
    if !isassigned(PATTERN_DB)
        init_pattern_database()
    end
    
    db = PATTERN_DB[]
    pattern_ids = get(db.index_by_cwe, cwe_id, UUID[])
    return [db.patterns[id] for id in pattern_ids if haskey(db.patterns, id)]
end

"""
Save patterns to file.
"""
function save_patterns(filepath::String)
    if !isassigned(PATTERN_DB)
        init_pattern_database()
    end
    
    open(filepath, "w") do io
        serialize(io, PATTERN_DB[])
    end
end

"""
Load patterns from file.
"""
function load_patterns(filepath::String)
    if isfile(filepath)
        open(filepath, "r") do io
            PATTERN_DB[] = deserialize(io)
        end
    else
        init_pattern_database()
    end
end

"""
Update patterns from external source.
"""
function update_patterns(source::String)
    # Would fetch from NullSec pattern repository
    @info "Updating patterns from $source"
    # For now, just reinitialize
    init_pattern_database()
end
