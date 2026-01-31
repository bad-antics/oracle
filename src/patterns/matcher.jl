"""
Pattern matching engine for Oracle.
"""

# ══════════════════════════════════════════════════════════════════════════════
# PATTERN MATCHER
# ══════════════════════════════════════════════════════════════════════════════

"""
    PatternMatcher

Matches vulnerability patterns against code.
"""
mutable struct PatternMatcher
    patterns::Vector{VulnerabilityPattern}
    language::Symbol
    match_cache::Dict{String, Vector{PatternMatch}}
    config::Dict{Symbol, Any}
    
    function PatternMatcher(language::Symbol=:auto; kwargs...)
        patterns = get_patterns_for_language(language)
        new(
            patterns,
            language,
            Dict{String, Vector{PatternMatch}}(),
            Dict{Symbol, Any}(kwargs)
        )
    end
end

"""
Result of a pattern match.
"""
struct PatternMatch
    pattern::VulnerabilityPattern
    line::Int
    column::Int
    matched_text::String
    context::String
    confidence::Float64
    is_false_positive::Bool
    suppression_reason::Union{String, Nothing}
end

# ══════════════════════════════════════════════════════════════════════════════
# MATCHING
# ══════════════════════════════════════════════════════════════════════════════

"""
Match patterns against code and return matched pattern IDs.
"""
function match_patterns(code::String, language::Symbol, 
                       patterns::Vector{VulnerabilityPattern})::Vector{UUID}
    matched_ids = UUID[]
    
    for pattern in patterns
        # Check language compatibility
        if language != :auto && !(language in pattern.languages)
            continue
        end
        
        # Check regex patterns
        for regex in pattern.regex_patterns
            if occursin(regex, code)
                push!(matched_ids, pattern.id)
                break
            end
        end
    end
    
    return unique(matched_ids)
end

"""
    match(matcher::PatternMatcher, code::String) -> Vector{PatternMatch}

Find all pattern matches in code.
"""
function match_all(matcher::PatternMatcher, code::String;
              filepath::String="<unknown>")::Vector{PatternMatch}
    
    # Check cache
    cache_key = bytes2hex(sha256(code))
    if haskey(matcher.match_cache, cache_key)
        return matcher.match_cache[cache_key]
    end
    
    matches = PatternMatch[]
    lines = split(code, '\n')
    
    for pattern in matcher.patterns
        # Match regex patterns
        for regex in pattern.regex_patterns
            for (line_num, line) in enumerate(lines)
                for m in eachmatch(regex, line)
                    # Get context
                    context_start = max(1, line_num - 2)
                    context_end = min(length(lines), line_num + 2)
                    context = join(lines[context_start:context_end], '\n')
                    
                    # Check for false positive indicators
                    is_fp, reason = check_false_positive(
                        pattern, line, context, matcher.language
                    )
                    
                    # Calculate confidence
                    confidence = calculate_match_confidence(
                        pattern, m.match, context, matcher.language
                    )
                    
                    push!(matches, PatternMatch(
                        pattern,
                        line_num,
                        m.offset,
                        m.match,
                        context,
                        confidence,
                        is_fp,
                        reason
                    ))
                end
            end
        end
        
        # Match semantic patterns (simplified)
        for semantic in pattern.semantic_patterns
            if contains(code, semantic)
                # Find location
                for (line_num, line) in enumerate(lines)
                    if contains(line, semantic)
                        push!(matches, PatternMatch(
                            pattern,
                            line_num,
                            1,
                            semantic,
                            line,
                            pattern.confidence_weight * 0.8,
                            false,
                            nothing
                        ))
                        break
                    end
                end
            end
        end
    end
    
    # Filter out likely false positives unless configured to include them
    if !get(matcher.config, :include_false_positives, false)
        filter!(m -> !m.is_false_positive, matches)
    end
    
    # Sort by confidence
    sort!(matches, by=m -> m.confidence, rev=true)
    
    # Cache results
    matcher.match_cache[cache_key] = matches
    
    return matches
end

"""
Check if a match is likely a false positive.
"""
function check_false_positive(pattern::VulnerabilityPattern, line::String,
                             context::String, language::Symbol)::Tuple{Bool, Union{String, Nothing}}
    
    # Check excluded context patterns
    for (key, value) in pattern.excluded_context
        if key == :uses_strncpy && value == true
            if occursin(r"\bstrncpy\b", context)
                return (true, "Uses safe strncpy alternative")
            end
        elseif key == :uses_safe_load && value == true
            if occursin(r"(?i)safe_load", context)
                return (true, "Uses safe_load")
            end
        elseif key == :uses_constant_time && value == true
            if occursin(r"(?i)(constant_time|secure_compare|hmac\.compare)", context)
                return (true, "Uses constant-time comparison")
            end
        elseif key == :is_config_file && value == true
            # Config files often have example credentials
            if occursin(r"(?i)(example|sample|template|default|placeholder)", context)
                return (true, "Appears to be example/template")
            end
        elseif key == :is_checksum && value == true
            # MD5/SHA1 for checksums is OK
            if occursin(r"(?i)(checksum|hash.*file|integrity|etag)", context)
                return (true, "Used for checksum/integrity, not security")
            end
        end
    end
    
    # Check for comment/string indicating test/example
    if occursin(r"(?i)(test|example|demo|sample|mock|fake|dummy)", context)
        if occursin(r"(?i)(//|#|/\*|\"\"\"|''')", line)
            return (true, "Appears to be test/example code")
        end
    end
    
    # Check for sanitization nearby
    sanitizers = ["escape", "sanitize", "encode", "clean", "filter", "validate"]
    for sanitizer in sanitizers
        if occursin(Regex("(?i)$sanitizer"), context)
            return (true, "Sanitization appears to be present")
        end
    end
    
    # Check for parameterized queries
    if pattern.vuln_class == INJECTION
        if occursin(r"(?i)(prepare|parameterized|\?|:\w+|\$\d+)", context)
            return (true, "Appears to use parameterized query")
        end
    end
    
    return (false, nothing)
end

"""
Calculate confidence for a match.
"""
function calculate_match_confidence(pattern::VulnerabilityPattern, matched::String,
                                   context::String, language::Symbol)::Float64
    
    confidence = pattern.base_severity * pattern.confidence_weight
    
    # Boost confidence for required context
    for (key, value) in pattern.required_context
        if key == :has_bounds_check
            if !occursin(r"(?i)(if|assert|check|validate|verify).*\b(len|length|size|bound)", context)
                confidence *= 1.1  # Boost if no bounds check
            end
        elseif key == :in_security_context
            if occursin(r"(?i)(password|secret|key|token|auth|crypt|secure)", context)
                confidence *= 1.2  # Boost if in security context
            end
        end
    end
    
    # Reduce confidence if matched text is very common
    common_patterns = ["=", "+", "(", ")"]
    if matched in common_patterns
        confidence *= 0.7
    end
    
    # Reduce confidence for short matches
    if length(matched) < 5
        confidence *= 0.8
    end
    
    # Clamp to valid range
    return clamp(confidence, 0.0, 1.0)
end

# ══════════════════════════════════════════════════════════════════════════════
# INCREMENTAL MATCHING
# ══════════════════════════════════════════════════════════════════════════════

"""
Match patterns incrementally (for IDE integration).
"""
function match_incremental(matcher::PatternMatcher, code::String,
                          changed_lines::Vector{Int})::Vector{PatternMatch}
    
    # Only analyze changed lines and context
    lines = split(code, '\n')
    matches = PatternMatch[]
    
    for line_num in changed_lines
        # Get context around changed line
        start_line = max(1, line_num - 5)
        end_line = min(length(lines), line_num + 5)
        
        chunk = join(lines[start_line:end_line], '\n')
        
        for pattern in matcher.patterns
            for regex in pattern.regex_patterns
                for m in eachmatch(regex, chunk)
                    actual_line = start_line + count(==('\n'), chunk[1:m.offset])
                    
                    is_fp, reason = check_false_positive(
                        pattern, lines[actual_line], chunk, matcher.language
                    )
                    
                    confidence = calculate_match_confidence(
                        pattern, m.match, chunk, matcher.language
                    )
                    
                    push!(matches, PatternMatch(
                        pattern,
                        actual_line,
                        m.offset,
                        m.match,
                        chunk,
                        confidence,
                        is_fp,
                        reason
                    ))
                end
            end
        end
    end
    
    # Deduplicate
    unique_matches = Dict{Tuple{UUID, Int}, PatternMatch}()
    for m in matches
        key = (m.pattern.id, m.line)
        if !haskey(unique_matches, key) || m.confidence > unique_matches[key].confidence
            unique_matches[key] = m
        end
    end
    
    return collect(values(unique_matches))
end

# ══════════════════════════════════════════════════════════════════════════════
# PATTERN RANKING
# ══════════════════════════════════════════════════════════════════════════════

"""
Rank matches by severity and confidence.
"""
function rank_matches(matches::Vector{PatternMatch})::Vector{PatternMatch}
    # Score each match
    scored = [(m, score_match(m)) for m in matches]
    
    # Sort by score
    sort!(scored, by=x -> x[2], rev=true)
    
    return [x[1] for x in scored]
end

"""
Score a match for ranking.
"""
function score_match(m::PatternMatch)::Float64
    # Base score from pattern severity
    score = m.pattern.base_severity * 100
    
    # Multiply by confidence
    score *= m.confidence
    
    # Adjust for false positive
    if m.is_false_positive
        score *= 0.1
    end
    
    # Boost critical vulnerabilities
    critical_classes = [CODE_EXECUTION, INJECTION, BUFFER_OVERFLOW, DESERIALIZATION]
    if m.pattern.vuln_class in critical_classes
        score *= 1.5
    end
    
    return score
end

# ══════════════════════════════════════════════════════════════════════════════
# CUSTOM PATTERNS
# ══════════════════════════════════════════════════════════════════════════════

"""
Add a custom pattern to the matcher.
"""
function add_custom_pattern!(matcher::PatternMatcher, pattern::VulnerabilityPattern)
    push!(matcher.patterns, pattern)
    empty!(matcher.match_cache)  # Clear cache
end

"""
Create a simple pattern from regex.
"""
function create_simple_pattern(name::String, regex::Regex, vuln_class::VulnClass;
                               severity::Float64=0.7,
                               cwe::Vector{String}=String[],
                               languages::Vector{Symbol}=Symbol[])::VulnerabilityPattern
    
    return VulnerabilityPattern(
        uuid4(),
        name,
        vuln_class,
        "Custom pattern: $name",
        [regex],
        Dict{Symbol, Any}[],
        String[],
        Dict{Symbol, Any}(),
        Dict{Symbol, Any}(),
        severity,
        0.8,
        cwe,
        String[],
        isempty(languages) ? [:python, :javascript, :java, :php, :c, :cpp, :go, :ruby] : languages,
        now(),
        now()
    )
end

# ══════════════════════════════════════════════════════════════════════════════
# REPORTING
# ══════════════════════════════════════════════════════════════════════════════

"""
Generate match summary.
"""
function summarize_matches(matches::Vector{PatternMatch})::Dict{Symbol, Any}
    summary = Dict{Symbol, Any}()
    
    # Count by severity
    severity_counts = Dict{Symbol, Int}()
    for m in matches
        sev = m.pattern.base_severity >= 0.9 ? :critical :
              m.pattern.base_severity >= 0.7 ? :high :
              m.pattern.base_severity >= 0.5 ? :medium :
              m.pattern.base_severity >= 0.3 ? :low : :info
        severity_counts[sev] = get(severity_counts, sev, 0) + 1
    end
    summary[:by_severity] = severity_counts
    
    # Count by vuln class
    class_counts = Dict{VulnClass, Int}()
    for m in matches
        class_counts[m.pattern.vuln_class] = get(class_counts, m.pattern.vuln_class, 0) + 1
    end
    summary[:by_class] = class_counts
    
    # Count false positives
    fp_count = count(m -> m.is_false_positive, matches)
    summary[:false_positives] = fp_count
    summary[:true_positives] = length(matches) - fp_count
    
    # Average confidence
    summary[:avg_confidence] = isempty(matches) ? 0.0 : mean(m.confidence for m in matches)
    
    # Top patterns
    pattern_counts = Dict{UUID, Int}()
    for m in matches
        pattern_counts[m.pattern.id] = get(pattern_counts, m.pattern.id, 0) + 1
    end
    summary[:top_patterns] = sort(collect(pattern_counts), by=x->x[2], rev=true)[1:min(5, length(pattern_counts))]
    
    return summary
end
