"""
Helper utilities for Oracle.
"""

# ══════════════════════════════════════════════════════════════════════════════
# STRING UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

"""
Calculate string entropy (Shannon entropy).
"""
function calculate_entropy(s::String)::Float64
    isempty(s) && return 0.0
    
    # Count character frequencies
    freq = Dict{Char, Int}()
    for c in s
        freq[c] = get(freq, c, 0) + 1
    end
    
    # Calculate entropy
    n = length(s)
    entropy = 0.0
    for count in values(freq)
        p = count / n
        entropy -= p * log2(p)
    end
    
    return entropy
end

"""
Calculate token diversity (unique tokens / total tokens).
"""
function calculate_token_diversity(tokens::Vector{String})::Float64
    isempty(tokens) && return 0.0
    return length(unique(tokens)) / length(tokens)
end

"""
Calculate comment ratio in code.
"""
function calculate_comment_ratio(code::String, language::Symbol)::Float64
    lines = split(code, '\n')
    total_lines = length(lines)
    total_lines == 0 && return 0.0
    
    comment_patterns = get_comment_patterns(language)
    comment_lines = 0
    in_block_comment = false
    
    for line in lines
        stripped = strip(line)
        isempty(stripped) && continue
        
        # Check block comments
        if !isnothing(comment_patterns.block_start)
            if contains(stripped, comment_patterns.block_start)
                in_block_comment = true
            end
            if contains(stripped, comment_patterns.block_end)
                in_block_comment = false
                comment_lines += 1
                continue
            end
        end
        
        if in_block_comment
            comment_lines += 1
            continue
        end
        
        # Check line comments
        for pattern in comment_patterns.line
            if startswith(stripped, pattern)
                comment_lines += 1
                break
            end
        end
    end
    
    return comment_lines / total_lines
end

struct CommentPatterns
    line::Vector{String}
    block_start::Union{String, Nothing}
    block_end::Union{String, Nothing}
end

function get_comment_patterns(language::Symbol)::CommentPatterns
    patterns = Dict(
        :c => CommentPatterns(["//"], "/*", "*/"),
        :cpp => CommentPatterns(["//"], "/*", "*/"),
        :java => CommentPatterns(["//"], "/*", "*/"),
        :javascript => CommentPatterns(["//"], "/*", "*/"),
        :typescript => CommentPatterns(["//"], "/*", "*/"),
        :python => CommentPatterns(["#"], "\"\"\"", "\"\"\""),
        :ruby => CommentPatterns(["#"], "=begin", "=end"),
        :rust => CommentPatterns(["//"], "/*", "*/"),
        :go => CommentPatterns(["//"], "/*", "*/"),
        :php => CommentPatterns(["//", "#"], "/*", "*/"),
        :swift => CommentPatterns(["//"], "/*", "*/"),
        :kotlin => CommentPatterns(["//"], "/*", "*/"),
        :julia => CommentPatterns(["#"], "#=", "=#"),
    )
    return get(patterns, language, CommentPatterns(["#"], nothing, nothing))
end

# ══════════════════════════════════════════════════════════════════════════════
# CODE PARSING UTILITIES  
# ══════════════════════════════════════════════════════════════════════════════

"""
Tokenize source code into tokens.
"""
function tokenize(code::String, language::Symbol)::Vector{String}
    # Basic tokenization - would use language-specific lexer in production
    tokens = String[]
    
    # Pattern for identifiers, keywords, operators, literals
    patterns = [
        r"[a-zA-Z_][a-zA-Z0-9_]*",     # Identifiers
        r"0[xX][0-9a-fA-F]+",           # Hex literals
        r"0[bB][01]+",                  # Binary literals
        r"\d+\.?\d*[eE]?[+-]?\d*",      # Numbers
        r"\"(?:[^\"\\]|\\.)*\"",        # Double-quoted strings
        r"'(?:[^'\\]|\\.)*'",           # Single-quoted strings
        r"[+\-*/%=<>!&|^~?:]+",         # Operators
        r"[\[\]{}();,.]",               # Delimiters
    ]
    
    remaining = code
    while !isempty(remaining)
        # Skip whitespace
        m = match(r"^\s+", remaining)
        if !isnothing(m)
            remaining = remaining[length(m.match)+1:end]
            continue
        end
        
        # Try each pattern
        matched = false
        for pattern in patterns
            m = match(Regex("^" * pattern.pattern), remaining)
            if !isnothing(m)
                push!(tokens, m.match)
                remaining = remaining[length(m.match)+1:end]
                matched = true
                break
            end
        end
        
        # Skip unmatched character
        if !matched && !isempty(remaining)
            remaining = remaining[2:end]
        end
    end
    
    return tokens
end

"""
Extract function definitions from code.
"""
function extract_functions(code::String, language::Symbol)::Vector{Dict{Symbol, Any}}
    functions = Dict{Symbol, Any}[]
    
    patterns = get_function_patterns(language)
    
    for pattern in patterns
        for m in eachmatch(pattern, code)
            func = Dict{Symbol, Any}(
                :name => haskey(m, :name) ? m[:name] : m.match,
                :params => haskey(m, :params) ? split(m[:params], ",") : String[],
                :start_pos => m.offset,
                :match => m.match
            )
            push!(functions, func)
        end
    end
    
    return functions
end

function get_function_patterns(language::Symbol)::Vector{Regex}
    patterns = Dict(
        :c => [r"(?:static\s+)?(?:\w+\s+)+(?<name>\w+)\s*\((?<params>[^)]*)\)\s*\{"],
        :cpp => [r"(?:static\s+)?(?:\w+\s+)+(?<name>\w+)\s*\((?<params>[^)]*)\)\s*(?:const\s*)?\{"],
        :java => [r"(?:public|private|protected)?\s*(?:static\s+)?(?:\w+\s+)+(?<name>\w+)\s*\((?<params>[^)]*)\)\s*\{"],
        :javascript => [
            r"function\s+(?<name>\w+)\s*\((?<params>[^)]*)\)\s*\{",
            r"(?:const|let|var)\s+(?<name>\w+)\s*=\s*(?:async\s+)?\((?<params>[^)]*)\)\s*=>",
            r"(?<name>\w+)\s*:\s*(?:async\s+)?function\s*\((?<params>[^)]*)\)"
        ],
        :python => [r"def\s+(?<name>\w+)\s*\((?<params>[^)]*)\)\s*:"],
        :rust => [r"(?:pub\s+)?(?:async\s+)?fn\s+(?<name>\w+)\s*\((?<params>[^)]*)\)"],
        :go => [r"func\s+(?:\([^)]+\)\s+)?(?<name>\w+)\s*\((?<params>[^)]*)\)"],
        :julia => [r"function\s+(?<name>\w+)\s*\((?<params>[^)]*)\)"],
    )
    return get(patterns, language, Regex[])
end

# ══════════════════════════════════════════════════════════════════════════════
# COMPLEXITY METRICS
# ══════════════════════════════════════════════════════════════════════════════

"""
Calculate cyclomatic complexity of code.
"""
function calculate_cyclomatic_complexity(code::String, language::Symbol)::Int
    complexity = 1  # Base complexity
    
    # Decision points that increase complexity
    decision_patterns = [
        r"\bif\b",
        r"\belse\s+if\b",
        r"\belif\b",
        r"\bfor\b",
        r"\bwhile\b",
        r"\bcase\b",
        r"\bcatch\b",
        r"\b\?\s*[^:]+\s*:",   # Ternary operator
        r"\b&&\b",
        r"\b\|\|\b",
        r"\band\b",
        r"\bor\b",
    ]
    
    for pattern in decision_patterns
        complexity += length(collect(eachmatch(pattern, code)))
    end
    
    return complexity
end

"""
Calculate maximum nesting depth.
"""
function calculate_nesting_depth(code::String)::Int
    max_depth = 0
    current_depth = 0
    
    for char in code
        if char in ['{', '(', '[']
            current_depth += 1
            max_depth = max(max_depth, current_depth)
        elseif char in ['}', ')', ']']
            current_depth = max(0, current_depth - 1)
        end
    end
    
    return max_depth
end

"""
Count lines of code (excluding blanks and comments).
"""
function count_loc(code::String, language::Symbol)::Int
    lines = split(code, '\n')
    comment_patterns = get_comment_patterns(language)
    
    loc = 0
    in_block = false
    
    for line in lines
        stripped = strip(line)
        isempty(stripped) && continue
        
        # Handle block comments
        if !isnothing(comment_patterns.block_start)
            if contains(stripped, comment_patterns.block_start)
                in_block = true
            end
            if contains(stripped, comment_patterns.block_end)
                in_block = false
                continue
            end
        end
        
        in_block && continue
        
        # Check line comments
        is_comment = false
        for pattern in comment_patterns.line
            if startswith(stripped, pattern)
                is_comment = true
                break
            end
        end
        
        !is_comment && (loc += 1)
    end
    
    return loc
end

# ══════════════════════════════════════════════════════════════════════════════
# FILE UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

"""
Read file safely with encoding detection.
"""
function safe_read_file(filepath::String)::Union{String, Nothing}
    try
        return read(filepath, String)
    catch e
        @warn "Failed to read file" filepath=filepath error=e
        return nothing
    end
end

"""
Get file hash for deduplication.
"""
function file_hash(filepath::String)::String
    content = safe_read_file(filepath)
    isnothing(content) && return ""
    return bytes2hex(sha256(content))
end

"""
Extract code snippet around a line.
"""
function extract_snippet(code::String, line::Int; context::Int=3)::String
    lines = split(code, '\n')
    start_line = max(1, line - context)
    end_line = min(length(lines), line + context)
    
    snippet_lines = String[]
    for i in start_line:end_line
        prefix = i == line ? "→ " : "  "
        push!(snippet_lines, @sprintf("%s%4d │ %s", prefix, i, lines[i]))
    end
    
    return join(snippet_lines, '\n')
end

# ══════════════════════════════════════════════════════════════════════════════
# HASH & ID UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

"""
Generate unique ID for findings.
"""
function generate_finding_id(filepath::String, line::Int, vuln_class::VulnClass)::UUID
    seed = "$filepath:$line:$(Int(vuln_class))"
    return uuid5(UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"), seed)
end

"""
Generate deterministic UUID from string.
"""
function deterministic_uuid(s::String)::UUID
    return uuid5(UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"), s)
end
