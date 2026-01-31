"""
Semantic code analysis for Oracle.
"""

# ══════════════════════════════════════════════════════════════════════════════
# SEMANTIC ANALYZER
# ══════════════════════════════════════════════════════════════════════════════

"""
    SemanticAnalyzer

Performs semantic analysis to understand code meaning and intent.
"""
mutable struct SemanticAnalyzer
    language::Symbol
    symbol_table::Dict{String, SymbolInfo}
    call_graph::Dict{String, Set{String}}
    type_info::Dict{String, TypeInfo}
    config::Dict{Symbol, Any}
    
    function SemanticAnalyzer(language::Symbol=:auto; kwargs...)
        new(
            language,
            Dict{String, SymbolInfo}(),
            Dict{String, Set{String}}(),
            Dict{String, TypeInfo}(),
            Dict{Symbol, Any}(kwargs)
        )
    end
end

"""
Symbol information tracked during semantic analysis.
"""
struct SymbolInfo
    name::String
    kind::Symbol  # :variable, :function, :class, :parameter
    type_hint::Union{String, Nothing}
    scope::String
    line::Int
    is_tainted::Bool
    sources::Vector{String}
end

"""
Type information for type inference.
"""
struct TypeInfo
    name::String
    base_types::Vector{String}
    methods::Vector{String}
    fields::Vector{String}
    is_dangerous::Bool
end

"""
    analyze(analyzer::SemanticAnalyzer, code::String) -> SemanticResult

Perform semantic analysis on code.
"""
function analyze(analyzer::SemanticAnalyzer, code::String;
                 filepath::String="<unknown>")
    
    language = analyzer.language
    if language == :auto
        language = detect_language(filepath)
    end
    
    # Build symbol table
    build_symbol_table!(analyzer, code, language)
    
    # Build call graph
    build_call_graph!(analyzer, code, language)
    
    # Infer types
    infer_types!(analyzer, code, language)
    
    # Find security-relevant patterns
    patterns = find_semantic_patterns(analyzer, code, language)
    
    return SemanticResult(
        analyzer.symbol_table,
        analyzer.call_graph,
        analyzer.type_info,
        patterns
    )
end

"""
Semantic analysis result.
"""
struct SemanticResult
    symbols::Dict{String, SymbolInfo}
    call_graph::Dict{String, Set{String}}
    types::Dict{String, TypeInfo}
    patterns::Vector{SemanticPattern}
end

"""
Detected semantic pattern.
"""
struct SemanticPattern
    kind::Symbol
    location::Int
    symbols::Vector{String}
    description::String
    severity::Float64
end

# ══════════════════════════════════════════════════════════════════════════════
# SYMBOL TABLE CONSTRUCTION
# ══════════════════════════════════════════════════════════════════════════════

"""
Build symbol table from code.
"""
function build_symbol_table!(analyzer::SemanticAnalyzer, code::String, language::Symbol)
    empty!(analyzer.symbol_table)
    
    lines = split(code, '\n')
    current_scope = "global"
    
    for (line_num, line) in enumerate(lines)
        stripped = strip(line)
        isempty(stripped) && continue
        
        # Extract declarations based on language
        symbols = extract_declarations(stripped, language, line_num, current_scope)
        
        for sym in symbols
            analyzer.symbol_table[sym.name] = sym
        end
        
        # Track scope changes
        current_scope = update_scope(current_scope, stripped, language)
    end
end

"""
Extract variable/function declarations from a line.
"""
function extract_declarations(line::String, language::Symbol, 
                             line_num::Int, scope::String)::Vector{SymbolInfo}
    symbols = SymbolInfo[]
    
    patterns = get_declaration_patterns(language)
    
    for (kind, pattern) in patterns
        for m in eachmatch(pattern, line)
            name = m.captures[1]
            type_hint = length(m.captures) > 1 ? m.captures[2] : nothing
            
            # Check if tainted (from user input)
            is_tainted = check_taint_source(line, language)
            sources = is_tainted ? [line] : String[]
            
            push!(symbols, SymbolInfo(
                name, kind, type_hint, scope, line_num, is_tainted, sources
            ))
        end
    end
    
    return symbols
end

"""
Get declaration patterns for a language.
"""
function get_declaration_patterns(language::Symbol)::Vector{Tuple{Symbol, Regex}}
    patterns = Dict(
        :python => [
            (:variable, r"^([a-zA-Z_]\w*)\s*="),
            (:function, r"^def\s+([a-zA-Z_]\w*)\s*\("),
            (:class, r"^class\s+([a-zA-Z_]\w*)"),
            (:parameter, r"def\s+\w+\s*\(([^)]+)\)"),
        ],
        :javascript => [
            (:variable, r"(?:const|let|var)\s+([a-zA-Z_$]\w*)"),
            (:function, r"function\s+([a-zA-Z_$]\w*)\s*\("),
            (:class, r"class\s+([a-zA-Z_$]\w*)"),
        ],
        :java => [
            (:variable, r"(?:int|String|boolean|long|double|float|Object|\w+)\s+([a-zA-Z_]\w*)\s*[=;]"),
            (:function, r"(?:public|private|protected)?\s*(?:static\s+)?(?:\w+\s+)+([a-zA-Z_]\w*)\s*\("),
            (:class, r"class\s+([a-zA-Z_]\w*)"),
        ],
        :c => [
            (:variable, r"(?:int|char|long|float|double|void|unsigned|signed|\w+\s*\*?)\s+([a-zA-Z_]\w*)\s*[=;,\[]"),
            (:function, r"(?:\w+\s+)+([a-zA-Z_]\w*)\s*\([^)]*\)\s*\{"),
        ],
        :go => [
            (:variable, r"(?:var|const)\s+([a-zA-Z_]\w*)"),
            (:variable, r"([a-zA-Z_]\w*)\s*:="),
            (:function, r"func\s+([a-zA-Z_]\w*)\s*\("),
        ],
    )
    
    return get(patterns, language, Tuple{Symbol, Regex}[])
end

"""
Check if a line contains taint sources.
"""
function check_taint_source(line::String, language::Symbol)::Bool
    sources = get_input_sources(language)
    for source in sources
        if occursin(source, line)
            return true
        end
    end
    return false
end

"""
Update current scope based on code structure.
"""
function update_scope(current::String, line::String, language::Symbol)::String
    # Simple scope tracking - would be more sophisticated in production
    if occursin(r"(?:def|function|func|fn)\s+(\w+)", line)
        m = match(r"(?:def|function|func|fn)\s+(\w+)", line)
        return "$(current).$(m.captures[1])"
    elseif occursin(r"class\s+(\w+)", line)
        m = match(r"class\s+(\w+)", line)
        return m.captures[1]
    elseif occursin(r"^\s*\}\s*$", line) && current != "global"
        # Exit scope
        parts = split(current, '.')
        return length(parts) > 1 ? join(parts[1:end-1], '.') : "global"
    end
    return current
end

# ══════════════════════════════════════════════════════════════════════════════
# CALL GRAPH CONSTRUCTION
# ══════════════════════════════════════════════════════════════════════════════

"""
Build call graph from code.
"""
function build_call_graph!(analyzer::SemanticAnalyzer, code::String, language::Symbol)
    empty!(analyzer.call_graph)
    
    functions = extract_functions(code, language)
    current_function = "global"
    
    lines = split(code, '\n')
    func_ranges = Dict{String, Tuple{Int, Int}}()
    
    # Map functions to line ranges
    for func in functions
        name = func[:name]
        start_pos = func[:start_pos]
        start_line = count(==('\n'), code[1:start_pos]) + 1
        func_ranges[name] = (start_line, length(lines))  # Simplified
    end
    
    # Extract calls per function
    for (func_name, (start_line, end_line)) in func_ranges
        analyzer.call_graph[func_name] = Set{String}()
        
        for line_num in start_line:min(end_line, length(lines))
            line = lines[line_num]
            calls = extract_function_calls(line, language)
            union!(analyzer.call_graph[func_name], calls)
        end
    end
end

"""
Extract function calls from a line.
"""
function extract_function_calls(line::String, language::Symbol)::Set{String}
    calls = Set{String}()
    
    # Match function calls
    for m in eachmatch(r"([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\s*\(", line)
        call = m.captures[1]
        # Filter out language keywords
        if !is_keyword(call, language)
            push!(calls, call)
        end
    end
    
    return calls
end

"""
Check if a name is a language keyword.
"""
function is_keyword(name::String, language::Symbol)::Bool
    keywords = Dict(
        :python => Set(["if", "else", "elif", "for", "while", "def", "class", "return",
                        "import", "from", "try", "except", "finally", "with", "as",
                        "print", "range", "len", "str", "int", "float", "list", "dict"]),
        :javascript => Set(["if", "else", "for", "while", "function", "return", "const",
                            "let", "var", "class", "new", "this", "typeof", "instanceof",
                            "console", "Array", "Object", "String", "Number"]),
        :java => Set(["if", "else", "for", "while", "return", "class", "public", "private",
                      "static", "new", "this", "super", "extends", "implements"]),
        :c => Set(["if", "else", "for", "while", "return", "struct", "typedef", "sizeof"]),
        :go => Set(["if", "else", "for", "func", "return", "package", "import", "struct",
                    "interface", "make", "new", "len", "cap", "append"]),
    )
    
    return name in get(keywords, language, Set{String}())
end

# ══════════════════════════════════════════════════════════════════════════════
# TYPE INFERENCE
# ══════════════════════════════════════════════════════════════════════════════

"""
Infer types from code.
"""
function infer_types!(analyzer::SemanticAnalyzer, code::String, language::Symbol)
    empty!(analyzer.type_info)
    
    # Extract type definitions
    type_patterns = get_type_patterns(language)
    
    for (type_pattern, field_pattern) in type_patterns
        for m in eachmatch(type_pattern, code)
            type_name = m.captures[1]
            
            # Find fields/methods
            type_block = extract_type_block(code, m.offset)
            fields = extract_fields(type_block, field_pattern)
            methods = extract_methods(type_block, language)
            
            # Check if type is dangerous (e.g., wraps unsafe operations)
            is_dangerous = check_dangerous_type(type_name, methods)
            
            analyzer.type_info[type_name] = TypeInfo(
                type_name,
                String[],  # Base types would need more parsing
                methods,
                fields,
                is_dangerous
            )
        end
    end
end

"""
Get type definition patterns for a language.
"""
function get_type_patterns(language::Symbol)
    patterns = Dict(
        :python => [(r"class\s+(\w+)", r"self\.(\w+)\s*=")],
        :javascript => [(r"class\s+(\w+)", r"this\.(\w+)\s*=")],
        :java => [(r"class\s+(\w+)", r"(?:private|public|protected)\s+\w+\s+(\w+)\s*[;=]")],
        :c => [(r"struct\s+(\w+)", r"(\w+)\s+\w+\s*;")],
        :go => [(r"type\s+(\w+)\s+struct", r"(\w+)\s+\w+")],
    )
    return get(patterns, language, [(r"class\s+(\w+)", r"(\w+)")])
end

"""
Extract type block (simplified).
"""
function extract_type_block(code::String, start_pos::Int)::String
    # Find matching braces/indentation
    depth = 0
    end_pos = start_pos
    
    for i in start_pos:length(code)
        if code[i] == '{' || code[i] == ':'
            depth += 1
        elseif code[i] == '}'
            depth -= 1
            if depth <= 0
                end_pos = i
                break
            end
        end
    end
    
    return code[start_pos:min(end_pos, length(code))]
end

"""
Extract fields from type block.
"""
function extract_fields(block::String, pattern::Regex)::Vector{String}
    fields = String[]
    for m in eachmatch(pattern, block)
        push!(fields, m.captures[1])
    end
    return unique(fields)
end

"""
Extract methods from type block.
"""
function extract_methods(block::String, language::Symbol)::Vector{String}
    methods = String[]
    patterns = get_function_patterns(language)
    
    for pattern in patterns
        for m in eachmatch(pattern, block)
            if haskey(m, :name)
                push!(methods, m[:name])
            end
        end
    end
    
    return unique(methods)
end

"""
Check if a type wraps dangerous operations.
"""
function check_dangerous_type(name::String, methods::Vector{String})::Bool
    dangerous_indicators = [
        "exec", "eval", "system", "query", "deserialize",
        "unserialize", "load", "parse", "execute"
    ]
    
    for method in methods
        for indicator in dangerous_indicators
            if contains(lowercase(method), indicator)
                return true
            end
        end
    end
    
    return false
end

# ══════════════════════════════════════════════════════════════════════════════
# SEMANTIC PATTERN DETECTION
# ══════════════════════════════════════════════════════════════════════════════

"""
Find security-relevant semantic patterns.
"""
function find_semantic_patterns(analyzer::SemanticAnalyzer, code::String, 
                               language::Symbol)::Vector{SemanticPattern}
    patterns = SemanticPattern[]
    
    # Pattern 1: Tainted data flows to sinks
    tainted_flow_patterns = find_tainted_flows(analyzer, code, language)
    append!(patterns, tainted_flow_patterns)
    
    # Pattern 2: Unsafe type casts
    cast_patterns = find_unsafe_casts(code, language)
    append!(patterns, cast_patterns)
    
    # Pattern 3: Resource leaks
    leak_patterns = find_resource_leaks(analyzer, code, language)
    append!(patterns, leak_patterns)
    
    # Pattern 4: Null/undefined dereferences
    null_patterns = find_null_dereferences(analyzer, code, language)
    append!(patterns, null_patterns)
    
    # Pattern 5: Privilege escalation paths
    priv_patterns = find_privilege_escalation(analyzer, code, language)
    append!(patterns, priv_patterns)
    
    return patterns
end

"""
Find tainted data flows.
"""
function find_tainted_flows(analyzer::SemanticAnalyzer, code::String,
                           language::Symbol)::Vector{SemanticPattern}
    patterns = SemanticPattern[]
    
    # Get tainted symbols
    tainted = [name for (name, info) in analyzer.symbol_table if info.is_tainted]
    
    # Get sink patterns
    sinks = get_output_sinks(language)
    
    lines = split(code, '\n')
    for (line_num, line) in enumerate(lines)
        # Check if tainted variable reaches a sink
        for tainted_var in tainted
            if contains(line, tainted_var)
                for sink in sinks
                    if occursin(sink, line)
                        push!(patterns, SemanticPattern(
                            :tainted_flow,
                            line_num,
                            [tainted_var],
                            "Tainted variable '$tainted_var' flows to sensitive sink",
                            0.8
                        ))
                    end
                end
            end
        end
    end
    
    return patterns
end

"""
Find unsafe type casts.
"""
function find_unsafe_casts(code::String, language::Symbol)::Vector{SemanticPattern}
    patterns = SemanticPattern[]
    
    cast_patterns = Dict(
        :c => [r"(\([\w\s\*]+\))\s*\w+", r"reinterpret_cast<"],
        :cpp => [r"reinterpret_cast<", r"const_cast<", r"(\([\w\s\*]+\))\s*\w+"],
        :java => [r"\((\w+)\)\s*\w+"],
    )
    
    lang_patterns = get(cast_patterns, language, Regex[])
    
    lines = split(code, '\n')
    for (line_num, line) in enumerate(lines)
        for pattern in lang_patterns
            if occursin(pattern, line)
                push!(patterns, SemanticPattern(
                    :unsafe_cast,
                    line_num,
                    String[],
                    "Potentially unsafe type cast detected",
                    0.5
                ))
            end
        end
    end
    
    return patterns
end

"""
Find resource leaks.
"""
function find_resource_leaks(analyzer::SemanticAnalyzer, code::String,
                            language::Symbol)::Vector{SemanticPattern}
    patterns = SemanticPattern[]
    
    # Track open/close pairs
    open_patterns = Dict(
        :c => [r"fopen\s*\(", r"open\s*\(", r"malloc\s*\(", r"socket\s*\("],
        :python => [r"open\s*\(", r"connect\s*\("],
        :java => [r"new\s+\w*Stream", r"new\s+\w*Connection"],
    )
    
    close_patterns = Dict(
        :c => [r"fclose\s*\(", r"close\s*\(", r"free\s*\("],
        :python => [r"\.close\s*\(", r"with\s+"],
        :java => [r"\.close\s*\(", r"try-with-resources"],
    )
    
    opens = get(open_patterns, language, Regex[])
    closes = get(close_patterns, language, Regex[])
    
    open_count = sum(length(collect(eachmatch(p, code))) for p in opens; init=0)
    close_count = sum(length(collect(eachmatch(p, code))) for p in closes; init=0)
    
    if open_count > close_count
        push!(patterns, SemanticPattern(
            :resource_leak,
            1,
            String[],
            "Potential resource leak: $open_count opens vs $close_count closes",
            0.6
        ))
    end
    
    return patterns
end

"""
Find potential null dereferences.
"""
function find_null_dereferences(analyzer::SemanticAnalyzer, code::String,
                               language::Symbol)::Vector{SemanticPattern}
    patterns = SemanticPattern[]
    
    # Look for null assignments followed by dereferences without checks
    null_patterns = Dict(
        :c => r"(\w+)\s*=\s*NULL",
        :cpp => r"(\w+)\s*=\s*(?:NULL|nullptr)",
        :java => r"(\w+)\s*=\s*null",
        :javascript => r"(\w+)\s*=\s*(?:null|undefined)",
        :python => r"(\w+)\s*=\s*None",
    )
    
    pattern = get(null_patterns, language, nothing)
    isnothing(pattern) && return patterns
    
    lines = split(code, '\n')
    null_vars = String[]
    
    for (line_num, line) in enumerate(lines)
        # Find null assignments
        for m in eachmatch(pattern, line)
            push!(null_vars, m.captures[1])
        end
        
        # Check for dereference without null check
        for var in null_vars
            # Check if used without null check
            if contains(line, "$var.") || contains(line, "$var->")
                # Check if preceded by null check on same line or previous lines
                context = join(lines[max(1, line_num-3):line_num], '\n')
                if !occursin(Regex("if\\s*\\(?\\s*$var\\s*(?:!=|!==)\\s*(?:NULL|nullptr|null|None)"), context)
                    push!(patterns, SemanticPattern(
                        :null_deref,
                        line_num,
                        [var],
                        "Potential null dereference of '$var'",
                        0.7
                    ))
                end
            end
        end
    end
    
    return patterns
end

"""
Find privilege escalation patterns.
"""
function find_privilege_escalation(analyzer::SemanticAnalyzer, code::String,
                                  language::Symbol)::Vector{SemanticPattern}
    patterns = SemanticPattern[]
    
    priv_indicators = [
        r"(?i)setuid", r"(?i)setgid", r"(?i)seteuid",
        r"(?i)chmod\s*\(\s*['\"]?\d{3,4}", 
        r"(?i)admin", r"(?i)root", r"(?i)sudo",
        r"(?i)privilege", r"(?i)elevat",
    ]
    
    lines = split(code, '\n')
    for (line_num, line) in enumerate(lines)
        for indicator in priv_indicators
            if occursin(indicator, line)
                push!(patterns, SemanticPattern(
                    :privilege_escalation,
                    line_num,
                    String[],
                    "Potential privilege-related operation detected",
                    0.6
                ))
                break
            end
        end
    end
    
    return patterns
end
