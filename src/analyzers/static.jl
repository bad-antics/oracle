"""
Static code analysis for Oracle.
"""

# ══════════════════════════════════════════════════════════════════════════════
# STATIC ANALYZER
# ══════════════════════════════════════════════════════════════════════════════

"""
    StaticAnalyzer

Performs static code analysis to extract security-relevant features.
"""
mutable struct StaticAnalyzer
    language::Symbol
    patterns::Dict{Symbol, Vector{Regex}}
    dangerous_funcs::Set{String}
    config::Dict{Symbol, Any}
    
    function StaticAnalyzer(language::Symbol=:auto; kwargs...)
        config = Dict{Symbol, Any}(kwargs)
        dangerous = Set(get_dangerous_functions(language))
        patterns = build_analysis_patterns(language)
        new(language, patterns, dangerous, config)
    end
end

"""
Build language-specific analysis patterns.
"""
function build_analysis_patterns(language::Symbol)::Dict{Symbol, Vector{Regex}}
    patterns = Dict{Symbol, Vector{Regex}}()
    
    # Input sources
    patterns[:inputs] = get_input_sources(language)
    
    # Output sinks
    patterns[:sinks] = get_output_sinks(language)
    
    # Memory operations (C/C++)
    if language in [:c, :cpp]
        patterns[:memory] = [
            r"malloc\s*\(",
            r"calloc\s*\(",
            r"realloc\s*\(",
            r"free\s*\(",
            r"new\s+",
            r"delete\s+",
            r"memcpy\s*\(",
            r"memmove\s*\(",
            r"memset\s*\(",
        ]
        
        patterns[:buffer] = [
            r"strcpy\s*\(",
            r"strncpy\s*\(",
            r"strcat\s*\(",
            r"strncat\s*\(",
            r"sprintf\s*\(",
            r"gets\s*\(",
            r"\[\s*\w+\s*\]",  # Array access
        ]
        
        patterns[:pointer] = [
            r"\*\s*\w+",       # Pointer dereference
            r"\w+\s*\*",       # Pointer declaration
            r"->\s*\w+",       # Arrow operator
            r"&\s*\w+",        # Address-of
        ]
    end
    
    # Crypto operations
    patterns[:crypto] = [
        r"(?i)(md5|sha1|sha256|sha512|aes|des|rsa|hmac|pbkdf)",
        r"(?i)(encrypt|decrypt|hash|sign|verify|key|secret|password)",
        r"(?i)(crypto|cipher|digest|random)",
    ]
    
    # File operations
    patterns[:file] = [
        r"(?i)(fopen|open|read|write|close|unlink|remove|rename)",
        r"(?i)(file|path|directory|folder)",
        r"\.\.\/",  # Path traversal
    ]
    
    # Network operations
    patterns[:network] = [
        r"(?i)(socket|connect|bind|listen|accept|send|recv)",
        r"(?i)(http|https|ftp|ssh|tcp|udp|url)",
        r"(?i)(request|response|client|server)",
    ]
    
    # Authentication/Authorization
    patterns[:auth] = [
        r"(?i)(login|logout|auth|session|token|cookie)",
        r"(?i)(user|password|credential|permission|role|access)",
        r"(?i)(jwt|oauth|saml|ldap)",
    ]
    
    # SQL patterns
    patterns[:sql] = [
        r"(?i)(select|insert|update|delete|drop|create|alter)\s+",
        r"(?i)(from|where|join|union|order\s+by|group\s+by)",
        r"(?i)(exec|execute|query|prepare)",
    ]
    
    return patterns
end

"""
    analyze(analyzer::StaticAnalyzer, code::String) -> CodeFeatures

Perform static analysis on code and extract features.
"""
function analyze(analyzer::StaticAnalyzer, code::String; 
                 filepath::String="<unknown>")::CodeFeatures
    
    # Auto-detect language if needed
    language = analyzer.language
    if language == :auto
        language = detect_language(filepath)
    end
    
    # Extract structural features
    complexity = calculate_cyclomatic_complexity(code, language)
    nesting = calculate_nesting_depth(code)
    loc = count_loc(code, language)
    functions = extract_functions(code, language)
    
    # Count pattern matches
    input_count = count_pattern_matches(code, get(analyzer.patterns, :inputs, Regex[]))
    sink_count = count_pattern_matches(code, get(analyzer.patterns, :sinks, Regex[]))
    crypto_count = count_pattern_matches(code, get(analyzer.patterns, :crypto, Regex[]))
    memory_count = count_pattern_matches(code, get(analyzer.patterns, :memory, Regex[]))
    file_count = count_pattern_matches(code, get(analyzer.patterns, :file, Regex[]))
    network_count = count_pattern_matches(code, get(analyzer.patterns, :network, Regex[]))
    
    # Find dangerous function calls
    dangerous_calls = find_dangerous_functions(code, analyzer.dangerous_funcs)
    
    # Count taint flows and unchecked returns
    taint_flows = estimate_taint_flows(code, analyzer.patterns)
    unchecked = count_unchecked_returns(code, language)
    
    # Count pointer arithmetic (C/C++)
    pointer_arith = 0
    if language in [:c, :cpp]
        pointer_arith = count_pointer_arithmetic(code)
    end
    
    # Statistical features
    entropy = calculate_entropy(code)
    tokens = tokenize(code, language)
    diversity = calculate_token_diversity(tokens)
    comment_ratio = calculate_comment_ratio(code, language)
    
    # Generate embedding
    embedding = generate_code_embedding(code, tokens, language)
    
    return CodeFeatures(
        complexity,
        nesting,
        loc,
        length(functions),
        input_count,
        sink_count,
        crypto_count,
        memory_count,
        file_count,
        network_count,
        dangerous_calls,
        taint_flows,
        unchecked,
        pointer_arith,
        entropy,
        diversity,
        comment_ratio,
        embedding
    )
end

"""
Count pattern matches in code.
"""
function count_pattern_matches(code::String, patterns::Vector{Regex})::Int
    count = 0
    for pattern in patterns
        count += length(collect(eachmatch(pattern, code)))
    end
    return count
end

"""
Find dangerous function calls in code.
"""
function find_dangerous_functions(code::String, dangerous::Set{String})::Vector{String}
    found = String[]
    
    # Look for function calls
    for m in eachmatch(r"([a-zA-Z_][a-zA-Z0-9_.:]*)\s*\(", code)
        func_name = m.captures[1]
        
        # Check full name and basename
        if func_name in dangerous
            push!(found, func_name)
        end
        
        # Check basename (for namespaced functions)
        basename = split(func_name, r"[.:]")[end]
        if basename in dangerous && !(func_name in found)
            push!(found, func_name)
        end
    end
    
    return unique(found)
end

"""
Estimate number of potential taint flows.
"""
function estimate_taint_flows(code::String, patterns::Dict{Symbol, Vector{Regex}})::Int
    inputs = get(patterns, :inputs, Regex[])
    sinks = get(patterns, :sinks, Regex[])
    
    input_count = count_pattern_matches(code, inputs)
    sink_count = count_pattern_matches(code, sinks)
    
    # Estimate: each input could flow to each sink
    # In reality, this needs proper data flow analysis
    return min(input_count * sink_count, 100)  # Cap at 100
end

"""
Count unchecked return values.
"""
function count_unchecked_returns(code::String, language::Symbol)::Int
    # Look for function calls that aren't assigned or checked
    unchecked = 0
    
    lines = split(code, '\n')
    for line in lines
        stripped = strip(line)
        
        # Skip comments and empty lines
        isempty(stripped) && continue
        startswith(stripped, "//") && continue
        startswith(stripped, "#") && continue
        
        # Look for standalone function calls (not assigned)
        if occursin(r"^\s*[a-zA-Z_][a-zA-Z0-9_.:]*\s*\([^)]*\)\s*;?\s*$", stripped)
            # Check if it's a common void function
            if !occursin(r"^\s*(print|log|debug|assert|return)", stripped)
                unchecked += 1
            end
        end
    end
    
    return unchecked
end

"""
Count pointer arithmetic operations (C/C++).
"""
function count_pointer_arithmetic(code::String)::Int
    patterns = [
        r"\w+\s*\+\+",           # ptr++
        r"\+\+\s*\w+",           # ++ptr
        r"\w+\s*--",             # ptr--
        r"--\s*\w+",             # --ptr
        r"\w+\s*\+=\s*\d+",      # ptr += n
        r"\w+\s*-=\s*\d+",       # ptr -= n
        r"\w+\s*\+\s*\d+",       # ptr + n
        r"\w+\s*-\s*\d+",        # ptr - n
        r"\[\s*\w+\s*\+",        # [i + 
        r"\[\s*\w+\s*-",         # [i -
    ]
    
    count = 0
    for pattern in patterns
        count += length(collect(eachmatch(pattern, code)))
    end
    
    return count
end

"""
Generate a dense code embedding vector.
"""
function generate_code_embedding(code::String, tokens::Vector{String}, 
                                  language::Symbol)::Vector{Float32}
    # Create a simple embedding based on token frequencies and patterns
    # In production, would use a trained neural embedding model
    
    embedding_size = 128
    embedding = zeros(Float32, embedding_size)
    
    # Token frequency features (first 64 dimensions)
    token_vocab = [
        "if", "else", "for", "while", "return", "function", "def", "class",
        "public", "private", "static", "const", "var", "let", "int", "string",
        "try", "catch", "throw", "new", "delete", "import", "export", "from",
        "true", "false", "null", "none", "nil", "void", "async", "await",
        "eval", "exec", "system", "query", "execute", "read", "write", "open",
        "password", "secret", "key", "token", "auth", "user", "admin", "root",
        "http", "https", "url", "request", "response", "socket", "connect",
        "file", "path", "directory", "buffer", "memory", "pointer", "malloc",
    ]
    
    token_lower = lowercase.(tokens)
    for (i, vocab_word) in enumerate(token_vocab)
        if i <= 64
            embedding[i] = Float32(count(t -> t == vocab_word, token_lower))
        end
    end
    
    # Structural features (dimensions 65-96)
    embedding[65] = Float32(length(tokens)) / 1000.0
    embedding[66] = Float32(calculate_cyclomatic_complexity(code, language)) / 50.0
    embedding[67] = Float32(calculate_nesting_depth(code)) / 10.0
    embedding[68] = Float32(count(==('\n'), code)) / 500.0
    embedding[69] = Float32(calculate_entropy(code)) / 8.0
    embedding[70] = Float32(calculate_token_diversity(tokens))
    
    # Security pattern indicators (dimensions 97-128)
    security_patterns = [
        r"(?i)password", r"(?i)secret", r"(?i)key", r"(?i)token",
        r"(?i)eval", r"(?i)exec", r"(?i)system", r"(?i)query",
        r"(?i)sql", r"(?i)injection", r"(?i)xss", r"(?i)csrf",
        r"\$_", r"request\.", r"\.query", r"\.execute",
        r"strcpy", r"sprintf", r"gets", r"malloc",
        r"free", r"delete", r"new\s+", r"unsafe",
        r"admin", r"root", r"sudo", r"chmod",
        r"http://", r"https://", r"ftp://", r"file://",
    ]
    
    for (i, pattern) in enumerate(security_patterns)
        if 96 + i <= embedding_size
            embedding[96 + i] = Float32(length(collect(eachmatch(pattern, code)))) / 10.0
        end
    end
    
    # Normalize
    norm = sqrt(sum(embedding .^ 2))
    if norm > 0
        embedding ./= norm
    end
    
    return embedding
end

# ══════════════════════════════════════════════════════════════════════════════
# FILE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

"""
Analyze a single file.
"""
function analyze_file(filepath::String; kwargs...)::Vector{PredictionResult}
    results = PredictionResult[]
    
    # Read file
    code = safe_read_file(filepath)
    isnothing(code) && return results
    
    # Detect language
    language = get(kwargs, :language, detect_language(filepath))
    
    # Create analyzer
    analyzer = StaticAnalyzer(language)
    
    # Extract features
    features = analyze(analyzer, code; filepath=filepath)
    
    # Create context
    context = CodeContext(filepath; language=language)
    
    # Load patterns and match
    patterns = get(kwargs, :patterns, load_default_patterns())
    matched = match_patterns(code, language, patterns)
    
    # Predict vulnerabilities
    predictions = predict_vulnerabilities(features)
    
    # Generate results for high-confidence predictions
    for (vuln_class, confidence) in predictions
        if confidence >= 0.3  # Threshold
            # Find relevant code location
            location = find_vuln_location(code, vuln_class, language)
            
            result = create_prediction_result(
                filepath=filepath,
                code=code,
                vuln_class=vuln_class,
                confidence=confidence,
                features=features,
                context=context,
                matched_patterns=matched,
                location=location
            )
            
            push!(results, result)
        end
    end
    
    return results
end

"""
Analyze code string directly.
"""
function analyze_code(code::String; kwargs...)::Vector{PredictionResult}
    language = get(kwargs, :language, :auto)
    
    # Try to detect language from content if auto
    if language == :auto
        language = detect_language_from_content(code)
    end
    
    # Use temporary filepath
    filepath = "<inline:$(language)>"
    
    return analyze_file(filepath; code=code, language=language, kwargs...)
end

"""
Detect language from code content.
"""
function detect_language_from_content(code::String)::Symbol
    # Check for language-specific markers
    markers = [
        (:python, [r"^def\s+\w+\s*\(", r"^import\s+\w+", r"^from\s+\w+\s+import"]),
        (:javascript, [r"^const\s+", r"^let\s+", r"^var\s+", r"function\s*\w*\s*\("]),
        (:java, [r"^public\s+class", r"^private\s+", r"^import\s+java\."]),
        (:c, [r"^#include\s*<", r"^int\s+main\s*\(", r"printf\s*\("]),
        (:cpp, [r"^#include\s*<iostream>", r"^using\s+namespace", r"cout\s*<<"]),
        (:go, [r"^package\s+\w+", r"^func\s+", r"^import\s+\("]),
        (:rust, [r"^fn\s+main\s*\(", r"^use\s+std::", r"^let\s+mut\s+"]),
        (:php, [r"<\?php", r"\$\w+\s*=", r"^function\s+\w+\s*\("]),
        (:ruby, [r"^def\s+\w+", r"^class\s+\w+", r"^require\s+['\"]"]),
    ]
    
    for (lang, patterns) in markers
        for pattern in patterns
            if occursin(pattern, code)
                return lang
            end
        end
    end
    
    return :unknown
end

"""
Find likely vulnerability location in code.
"""
function find_vuln_location(code::String, vuln_class::VulnClass, 
                            language::Symbol)::Tuple{Int, Int}
    lines = split(code, '\n')
    
    # Patterns associated with each vulnerability class
    vuln_patterns = Dict(
        INJECTION => [r"(?i)(query|execute|eval|system|exec)"],
        BUFFER_OVERFLOW => [r"(strcpy|sprintf|gets|memcpy)"],
        USE_AFTER_FREE => [r"(free|delete)"],
        XSS => [r"(innerHTML|document\.write|\.html\()"],
        CODE_EXECUTION => [r"(eval|exec|system|popen)"],
        DESERIALIZATION => [r"(unserialize|pickle|Marshal|yaml\.load)"],
        PATH_TRAVERSAL => [r"(\.\./|\.\.\\|file_get_contents|readFile)"],
        SSRF => [r"(curl|http|request|fetch|urlopen)"],
    )
    
    patterns = get(vuln_patterns, vuln_class, Regex[])
    
    for (i, line) in enumerate(lines)
        for pattern in patterns
            if occursin(pattern, line)
                return (i, i)
            end
        end
    end
    
    # Default to first line
    return (1, min(10, length(lines)))
end

"""
Create a PredictionResult from analysis.
"""
function create_prediction_result(; 
                                  filepath::String,
                                  code::String,
                                  vuln_class::VulnClass,
                                  confidence::Float64,
                                  features::CodeFeatures,
                                  context::CodeContext,
                                  matched_patterns::Vector{UUID},
                                  location::Tuple{Int, Int})
    
    lines = split(code, '\n')
    line_start, line_end = location
    
    # Extract snippet
    snippet = join(lines[line_start:min(line_end, length(lines))], '\n')
    
    # Calculate risk score
    risk = RiskScore(
        confidence;
        exploitability=estimate_exploitability(vuln_class),
        impact=estimate_impact(vuln_class),
        confidence=confidence
    )
    
    # Generate explanations
    reasoning = generate_reasoning(vuln_class, features)
    evidence = generate_evidence(code, vuln_class, features)
    
    # Generate remediation
    remediation = generate_remediation(vuln_class)
    references = get_references(vuln_class)
    
    return PredictionResult(
        uuid4(),
        now(),
        filepath,
        line_start,
        line_end,
        snippet,
        vuln_class,
        risk,
        matched_patterns,
        features,
        context,
        reasoning,
        evidence,
        remediation,
        references,
        string(ORACLE_VERSION),
        confidence
    )
end

"""
Estimate exploitability based on vulnerability class.
"""
function estimate_exploitability(vuln_class::VulnClass)::Float64
    exploitability = Dict(
        INJECTION => 0.9,
        BUFFER_OVERFLOW => 0.7,
        USE_AFTER_FREE => 0.6,
        RACE_CONDITION => 0.5,
        AUTHENTICATION_BYPASS => 0.8,
        CRYPTO_WEAKNESS => 0.4,
        PRIVILEGE_ESCALATION => 0.7,
        INFORMATION_DISCLOSURE => 0.8,
        DENIAL_OF_SERVICE => 0.9,
        CODE_EXECUTION => 0.8,
        XSS => 0.9,
        SSRF => 0.7,
        DESERIALIZATION => 0.6,
        PATH_TRAVERSAL => 0.8,
        TYPE_CONFUSION => 0.5,
    )
    return get(exploitability, vuln_class, 0.5)
end

"""
Estimate impact based on vulnerability class.
"""
function estimate_impact(vuln_class::VulnClass)::Float64
    impact = Dict(
        INJECTION => 0.9,
        BUFFER_OVERFLOW => 0.9,
        USE_AFTER_FREE => 0.9,
        RACE_CONDITION => 0.6,
        AUTHENTICATION_BYPASS => 0.9,
        CRYPTO_WEAKNESS => 0.7,
        PRIVILEGE_ESCALATION => 0.9,
        INFORMATION_DISCLOSURE => 0.6,
        DENIAL_OF_SERVICE => 0.5,
        CODE_EXECUTION => 1.0,
        XSS => 0.6,
        SSRF => 0.7,
        DESERIALIZATION => 0.9,
        PATH_TRAVERSAL => 0.7,
        TYPE_CONFUSION => 0.8,
    )
    return get(impact, vuln_class, 0.5)
end

"""
Generate reasoning for the prediction.
"""
function generate_reasoning(vuln_class::VulnClass, features::CodeFeatures)::Vector{String}
    reasons = String[]
    
    # Based on features
    if features.input_sources > 0
        push!(reasons, "Code contains $(features.input_sources) potential input sources (user-controlled data)")
    end
    
    if features.output_sinks > 0
        push!(reasons, "Code contains $(features.output_sinks) sensitive output sinks")
    end
    
    if !isempty(features.dangerous_functions)
        push!(reasons, "Uses potentially dangerous functions: $(join(features.dangerous_functions, ", "))")
    end
    
    if features.taint_flows > 0
        push!(reasons, "Detected $(features.taint_flows) potential taint flow paths")
    end
    
    if features.unchecked_returns > 0
        push!(reasons, "$(features.unchecked_returns) return values may not be checked")
    end
    
    # Vulnerability-specific reasoning
    vuln_reasons = Dict(
        INJECTION => "User input may flow to command/query execution without proper sanitization",
        BUFFER_OVERFLOW => "Buffer operations detected without apparent bounds checking",
        USE_AFTER_FREE => "Memory deallocation patterns suggest potential use-after-free",
        XSS => "User input may be rendered in output without proper encoding",
        CODE_EXECUTION => "Dynamic code execution with potentially untrusted input",
        DESERIALIZATION => "Deserialization of potentially untrusted data",
    )
    
    if haskey(vuln_reasons, vuln_class)
        push!(reasons, vuln_reasons[vuln_class])
    end
    
    return reasons
end

"""
Generate evidence for the prediction.
"""
function generate_evidence(code::String, vuln_class::VulnClass, 
                          features::CodeFeatures)::Vector{String}
    evidence = String[]
    
    # Add dangerous function evidence
    for func in features.dangerous_functions
        # Find the line containing this function
        for (i, line) in enumerate(split(code, '\n'))
            if contains(line, func)
                push!(evidence, "Line $i: $(strip(line))")
                break
            end
        end
    end
    
    return evidence[1:min(5, length(evidence))]  # Limit to 5 evidence items
end

"""
Generate remediation suggestions.
"""
function generate_remediation(vuln_class::VulnClass)::Vector{String}
    remediation = Dict(
        INJECTION => [
            "Use parameterized queries or prepared statements",
            "Implement input validation and sanitization",
            "Apply the principle of least privilege",
            "Use allowlists instead of blocklists for input validation",
        ],
        BUFFER_OVERFLOW => [
            "Use safe string functions (strncpy, snprintf)",
            "Implement bounds checking before buffer operations",
            "Consider using modern languages with memory safety",
            "Enable compiler protections (ASLR, stack canaries)",
        ],
        USE_AFTER_FREE => [
            "Set pointers to NULL after freeing",
            "Use smart pointers in C++",
            "Implement proper ownership tracking",
            "Consider using memory-safe languages",
        ],
        XSS => [
            "Encode output based on context (HTML, JavaScript, URL)",
            "Use Content Security Policy (CSP)",
            "Implement input validation",
            "Use frameworks with automatic escaping",
        ],
        CODE_EXECUTION => [
            "Avoid eval() and similar dynamic code execution",
            "Use allowlists for any required dynamic execution",
            "Implement sandboxing for untrusted code",
            "Apply strict input validation",
        ],
        DESERIALIZATION => [
            "Avoid deserializing untrusted data",
            "Use safe serialization formats (JSON)",
            "Implement integrity checks on serialized data",
            "Use allowlists for deserializable classes",
        ],
        PATH_TRAVERSAL => [
            "Validate and canonicalize file paths",
            "Use allowlists for accessible directories",
            "Implement proper access controls",
            "Avoid constructing paths from user input",
        ],
        SSRF => [
            "Validate and allowlist URLs",
            "Block requests to internal networks",
            "Use URL parsers to validate destinations",
            "Implement proper access controls",
        ],
    )
    
    return get(remediation, vuln_class, [
        "Review and fix the identified vulnerability",
        "Implement appropriate security controls",
        "Consider security testing and code review",
    ])
end

"""
Get references for a vulnerability class.
"""
function get_references(vuln_class::VulnClass)::Vector{String}
    base_refs = [
        "https://owasp.org/www-project-web-security-testing-guide/",
        "https://cwe.mitre.org/",
    ]
    
    cwe_refs = Dict(
        INJECTION => ["https://cwe.mitre.org/data/definitions/89.html"],
        BUFFER_OVERFLOW => ["https://cwe.mitre.org/data/definitions/120.html"],
        USE_AFTER_FREE => ["https://cwe.mitre.org/data/definitions/416.html"],
        XSS => ["https://cwe.mitre.org/data/definitions/79.html"],
        CODE_EXECUTION => ["https://cwe.mitre.org/data/definitions/94.html"],
        DESERIALIZATION => ["https://cwe.mitre.org/data/definitions/502.html"],
    )
    
    return vcat(base_refs, get(cwe_refs, vuln_class, String[]))
end
