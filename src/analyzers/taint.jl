"""
Taint tracking analysis for Oracle.
"""

# ══════════════════════════════════════════════════════════════════════════════
# TAINT TRACKER
# ══════════════════════════════════════════════════════════════════════════════

"""
    TaintTracker

Tracks tainted (user-controlled) data through code execution.
"""
mutable struct TaintTracker
    language::Symbol
    taint_state::Dict{String, TaintInfo}
    taint_history::Vector{TaintEvent}
    sinks_reached::Vector{SinkReach}
    sanitizers::Set{String}
    config::Dict{Symbol, Any}
    
    function TaintTracker(language::Symbol=:auto; kwargs...)
        new(
            language,
            Dict{String, TaintInfo}(),
            TaintEvent[],
            SinkReach[],
            Set{String}(),
            Dict{Symbol, Any}(kwargs)
        )
    end
end

"""
Information about tainted data.
"""
struct TaintInfo
    variable::String
    source_type::Symbol  # :user_input, :file, :network, :env, :database
    source_line::Int
    source_expression::String
    propagation_chain::Vector{Int}
    is_sanitized::Bool
    sanitizer::Union{String, Nothing}
    confidence::Float64
end

"""
Taint propagation event.
"""
struct TaintEvent
    line::Int
    event_type::Symbol  # :introduce, :propagate, :sanitize, :sink
    from_var::Union{String, Nothing}
    to_var::String
    expression::String
    timestamp::Int  # Logical time
end

"""
Information about tainted data reaching a sink.
"""
struct SinkReach
    taint_info::TaintInfo
    sink_line::Int
    sink_type::Symbol  # :sql, :command, :xss, :file, :network, :code
    sink_expression::String
    is_exploitable::Bool
    exploitation_path::Vector{Int}
    remediation::String
end

"""
Taint tracking result.
"""
struct TaintResult
    tainted_vars::Dict{String, TaintInfo}
    events::Vector{TaintEvent}
    sinks_reached::Vector{SinkReach}
    exploitable_paths::Vector{ExploitablePath}
    coverage::TaintCoverage
end

"""
Exploitable taint path.
"""
struct ExploitablePath
    source::TaintInfo
    sink::SinkReach
    path::Vector{Int}
    vuln_type::VulnClass
    confidence::Float64
    exploit_complexity::Symbol  # :low, :medium, :high
end

"""
Taint analysis coverage statistics.
"""
struct TaintCoverage
    total_sources::Int
    tracked_sources::Int
    total_sinks::Int
    reached_sinks::Int
    sanitized_flows::Int
    exploitable_flows::Int
end

# ══════════════════════════════════════════════════════════════════════════════
# MAIN TRACKING
# ══════════════════════════════════════════════════════════════════════════════

"""
    track(tracker::TaintTracker, code::String) -> TaintResult

Perform taint tracking analysis on code.
"""
function track(tracker::TaintTracker, code::String;
               filepath::String="<unknown>")::TaintResult
    
    language = tracker.language
    if language == :auto
        language = detect_language(filepath)
    end
    
    lines = split(code, '\n')
    
    # Initialize sanitizers for language
    tracker.sanitizers = get_sanitizers(language)
    
    # Phase 1: Identify taint sources
    identify_sources!(tracker, lines, language)
    
    # Phase 2: Track propagation
    track_propagation!(tracker, lines, language)
    
    # Phase 3: Identify sinks
    identify_sinks!(tracker, lines, language)
    
    # Phase 4: Check for sanitization
    check_sanitization!(tracker, lines, language)
    
    # Phase 5: Build exploitable paths
    exploitable = build_exploitable_paths(tracker)
    
    # Compute coverage
    coverage = compute_coverage(tracker)
    
    return TaintResult(
        tracker.taint_state,
        tracker.taint_history,
        tracker.sinks_reached,
        exploitable,
        coverage
    )
end

# ══════════════════════════════════════════════════════════════════════════════
# SOURCE IDENTIFICATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Identify taint sources in code.
"""
function identify_sources!(tracker::TaintTracker, lines::Vector{<:AbstractString},
                          language::Symbol)
    
    source_patterns = get_source_patterns(language)
    timestamp = 0
    
    for (line_num, line) in enumerate(lines)
        stripped = strip(line)
        isempty(stripped) && continue
        
        for (source_type, patterns) in source_patterns
            for pattern in patterns
                if occursin(pattern, stripped)
                    # Extract variable being assigned
                    var_name = extract_assigned_variable(stripped, language)
                    isnothing(var_name) && continue
                    
                    timestamp += 1
                    
                    # Create taint info
                    taint = TaintInfo(
                        var_name,
                        source_type,
                        line_num,
                        stripped,
                        [line_num],
                        false,
                        nothing,
                        0.9
                    )
                    
                    tracker.taint_state[var_name] = taint
                    
                    # Record event
                    push!(tracker.taint_history, TaintEvent(
                        line_num,
                        :introduce,
                        nothing,
                        var_name,
                        stripped,
                        timestamp
                    ))
                    
                    break
                end
            end
        end
    end
end

"""
Get source patterns by type.
"""
function get_source_patterns(language::Symbol)::Dict{Symbol, Vector{Regex}}
    patterns = Dict{Symbol, Vector{Regex}}()
    
    # User input sources
    patterns[:user_input] = get_user_input_patterns(language)
    
    # File sources
    patterns[:file] = [
        r"(?i)read\s*\(",
        r"(?i)fread\s*\(",
        r"(?i)file_get_contents\s*\(",
        r"(?i)open\s*\([^)]+,\s*['\"]r",
        r"(?i)\.read\s*\(",
        r"(?i)\.readlines\s*\(",
    ]
    
    # Network sources
    patterns[:network] = [
        r"(?i)recv\s*\(",
        r"(?i)socket\.recv",
        r"(?i)\.get\s*\(",
        r"(?i)fetch\s*\(",
        r"(?i)XMLHttpRequest",
        r"(?i)axios\.",
    ]
    
    # Environment sources
    patterns[:env] = [
        r"(?i)getenv\s*\(",
        r"(?i)os\.environ",
        r"(?i)process\.env",
        r"(?i)System\.getenv",
        r"(?i)\$_ENV",
    ]
    
    # Database sources
    patterns[:database] = [
        r"(?i)\.fetch\w*\s*\(",
        r"(?i)cursor\.execute",
        r"(?i)\.query\s*\(",
        r"(?i)ResultSet\.",
    ]
    
    return patterns
end

"""
Get user input patterns for a language.
"""
function get_user_input_patterns(language::Symbol)::Vector{Regex}
    patterns = Dict(
        :python => [
            r"input\s*\(",
            r"raw_input\s*\(",
            r"sys\.argv",
            r"request\.(args|form|data|json|values|get|post)",
            r"flask\.request",
            r"django\.request",
        ],
        :javascript => [
            r"req\.(params|query|body|headers|cookies)",
            r"request\.(params|query|body)",
            r"process\.argv",
            r"document\.(location|URL|cookie|referrer)",
            r"window\.location",
            r"\.value\b",
            r"prompt\s*\(",
        ],
        :java => [
            r"request\.getParameter\s*\(",
            r"request\.getHeader\s*\(",
            r"request\.getCookies\s*\(",
            r"request\.getInputStream\s*\(",
            r"Scanner\s*\(\s*System\.in",
            r"args\[",
        ],
        :php => [
            r"\$_GET",
            r"\$_POST",
            r"\$_REQUEST",
            r"\$_COOKIE",
            r"\$_SERVER\s*\[\s*['\"](?:HTTP_|REQUEST_|QUERY_)",
            r"file_get_contents\s*\(\s*['\"]php://input",
            r"\$argv",
        ],
        :c => [
            r"scanf\s*\(",
            r"gets\s*\(",
            r"fgets\s*\(",
            r"getchar\s*\(",
            r"argv\[",
            r"getenv\s*\(",
        ],
        :go => [
            r"r\.URL\.Query\s*\(",
            r"r\.FormValue\s*\(",
            r"r\.PostFormValue\s*\(",
            r"r\.Header\.Get\s*\(",
            r"os\.Args",
            r"bufio\.NewReader\s*\(\s*os\.Stdin",
        ],
    )
    
    return get(patterns, language, [r"(?i)input", r"(?i)request"])
end

"""
Extract variable being assigned.
"""
function extract_assigned_variable(line::String, language::Symbol)::Union{String, Nothing}
    patterns = Dict(
        :python => r"^([a-zA-Z_]\w*)\s*=",
        :javascript => r"(?:const|let|var)?\s*([a-zA-Z_$]\w*)\s*=",
        :java => r"(?:\w+\s+)+([a-zA-Z_]\w*)\s*=",
        :php => r"(\$[a-zA-Z_]\w*)\s*=",
        :c => r"(?:\w+\s*\*?\s*)+([a-zA-Z_]\w*)\s*=",
        :go => r"([a-zA-Z_]\w*)\s*(?::=|=)",
    )
    
    pattern = get(patterns, language, r"([a-zA-Z_]\w*)\s*=")
    m = match(pattern, line)
    
    return isnothing(m) ? nothing : m.captures[1]
end

# ══════════════════════════════════════════════════════════════════════════════
# PROPAGATION TRACKING
# ══════════════════════════════════════════════════════════════════════════════

"""
Track taint propagation through code.
"""
function track_propagation!(tracker::TaintTracker, lines::Vector{<:AbstractString},
                           language::Symbol)
    
    timestamp = length(tracker.taint_history)
    max_iterations = 10  # Prevent infinite loops
    
    for iteration in 1:max_iterations
        new_taints = Dict{String, TaintInfo}()
        
        for (line_num, line) in enumerate(lines)
            stripped = strip(line)
            isempty(stripped) && continue
            
            # Check if any tainted variable is used
            for (tainted_var, taint_info) in tracker.taint_state
                if contains(stripped, tainted_var)
                    # Check if this is an assignment to a new variable
                    new_var = extract_assigned_variable(stripped, language)
                    
                    if !isnothing(new_var) && new_var != tainted_var
                        # Check if not already tainted with same source
                        if !haskey(tracker.taint_state, new_var) && !haskey(new_taints, new_var)
                            timestamp += 1
                            
                            # Propagate taint
                            propagated_chain = vcat(taint_info.propagation_chain, [line_num])
                            
                            new_taint = TaintInfo(
                                new_var,
                                taint_info.source_type,
                                taint_info.source_line,
                                taint_info.source_expression,
                                propagated_chain,
                                false,
                                nothing,
                                taint_info.confidence * 0.95  # Slight decay
                            )
                            
                            new_taints[new_var] = new_taint
                            
                            push!(tracker.taint_history, TaintEvent(
                                line_num,
                                :propagate,
                                tainted_var,
                                new_var,
                                stripped,
                                timestamp
                            ))
                        end
                    end
                end
            end
        end
        
        # Merge new taints
        if isempty(new_taints)
            break
        end
        
        merge!(tracker.taint_state, new_taints)
    end
end

# ══════════════════════════════════════════════════════════════════════════════
# SINK IDENTIFICATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Identify sinks where tainted data flows.
"""
function identify_sinks!(tracker::TaintTracker, lines::Vector{<:AbstractString},
                        language::Symbol)
    
    sink_patterns = get_sink_patterns(language)
    
    for (line_num, line) in enumerate(lines)
        stripped = strip(line)
        isempty(stripped) && continue
        
        # Check each tainted variable
        for (tainted_var, taint_info) in tracker.taint_state
            if contains(stripped, tainted_var)
                # Check if this line is a sink
                for (sink_type, patterns) in sink_patterns
                    for pattern in patterns
                        if occursin(pattern, stripped)
                            # Found tainted data at sink!
                            exploitable = check_exploitability(
                                taint_info, sink_type, stripped, language
                            )
                            
                            path = vcat(taint_info.propagation_chain, [line_num])
                            remediation = get_remediation(sink_type, language)
                            
                            push!(tracker.sinks_reached, SinkReach(
                                taint_info,
                                line_num,
                                sink_type,
                                stripped,
                                exploitable,
                                path,
                                remediation
                            ))
                            
                            push!(tracker.taint_history, TaintEvent(
                                line_num,
                                :sink,
                                tainted_var,
                                tainted_var,
                                stripped,
                                length(tracker.taint_history) + 1
                            ))
                        end
                    end
                end
            end
        end
    end
end

"""
Get sink patterns by type.
"""
function get_sink_patterns(language::Symbol)::Dict{Symbol, Vector{Regex}}
    patterns = Dict{Symbol, Vector{Regex}}()
    
    # SQL injection sinks
    patterns[:sql] = [
        r"(?i)\.execute\s*\(",
        r"(?i)\.query\s*\(",
        r"(?i)mysql_query\s*\(",
        r"(?i)mysqli_query\s*\(",
        r"(?i)pg_query\s*\(",
        r"(?i)cursor\.execute\s*\(",
        r"(?i)Statement\.execute",
        r"(?i)db\.(Query|Exec)\s*\(",
    ]
    
    # Command injection sinks
    patterns[:command] = [
        r"(?i)system\s*\(",
        r"(?i)exec\s*\(",
        r"(?i)popen\s*\(",
        r"(?i)shell_exec\s*\(",
        r"(?i)subprocess\.",
        r"(?i)os\.system\s*\(",
        r"(?i)Runtime\..*exec\s*\(",
        r"(?i)ProcessBuilder\s*\(",
        r"(?i)child_process",
        r"(?i)exec\.Command\s*\(",
    ]
    
    # XSS sinks
    patterns[:xss] = [
        r"(?i)innerHTML\s*=",
        r"(?i)outerHTML\s*=",
        r"(?i)document\.write\s*\(",
        r"(?i)\.html\s*\(",
        r"(?i)echo\s+",
        r"(?i)print\s*\(",
        r"(?i)response\.write\s*\(",
        r"(?i)render_template\s*\(",
        r"(?i)fmt\.Fprint",
    ]
    
    # File operation sinks
    patterns[:file] = [
        r"(?i)fopen\s*\(",
        r"(?i)open\s*\(",
        r"(?i)file_get_contents\s*\(",
        r"(?i)include\s*\(",
        r"(?i)require\s*\(",
        r"(?i)readFile\s*\(",
        r"(?i)writeFile\s*\(",
        r"(?i)os\.Open\s*\(",
    ]
    
    # Code execution sinks
    patterns[:code] = [
        r"(?i)\beval\s*\(",
        r"(?i)Function\s*\(",
        r"(?i)exec\s*\(",
        r"(?i)compile\s*\(",
        r"(?i)__import__\s*\(",
        r"(?i)create_function\s*\(",
        r"(?i)preg_replace\s*\([^)]*\/[^\/]*e",
    ]
    
    # LDAP injection sinks
    patterns[:ldap] = [
        r"(?i)ldap_search\s*\(",
        r"(?i)ldap_bind\s*\(",
        r"(?i)InitialContext\.lookup\s*\(",
    ]
    
    # XPath injection sinks
    patterns[:xpath] = [
        r"(?i)xpath\s*\(",
        r"(?i)evaluate\s*\(",
        r"(?i)selectNodes\s*\(",
    ]
    
    return patterns
end

"""
Check if a taint to sink flow is exploitable.
"""
function check_exploitability(taint::TaintInfo, sink_type::Symbol,
                             sink_expr::String, language::Symbol)::Bool
    
    # If sanitized, not directly exploitable
    taint.is_sanitized && return false
    
    # Check for obvious protections
    protection_patterns = [
        r"(?i)escape",
        r"(?i)sanitize",
        r"(?i)encode",
        r"(?i)quote",
        r"(?i)prepared",
        r"(?i)parameterized",
        r"(?i)htmlspecialchars",
        r"(?i)htmlentities",
    ]
    
    for pattern in protection_patterns
        if occursin(pattern, sink_expr)
            return false
        end
    end
    
    return true
end

"""
Get remediation advice for a sink type.
"""
function get_remediation(sink_type::Symbol, language::Symbol)::String
    remediations = Dict(
        :sql => "Use parameterized queries or prepared statements",
        :command => "Avoid shell commands with user input, use safe APIs",
        :xss => "Encode output using context-appropriate encoding",
        :file => "Validate and sanitize file paths, use allowlists",
        :code => "Never use eval() with user input",
        :ldap => "Use parameterized LDAP queries",
        :xpath => "Use parameterized XPath queries",
    )
    
    return get(remediations, sink_type, "Sanitize user input before use")
end

# ══════════════════════════════════════════════════════════════════════════════
# SANITIZATION CHECKING
# ══════════════════════════════════════════════════════════════════════════════

"""
Check for sanitization of tainted data.
"""
function check_sanitization!(tracker::TaintTracker, lines::Vector{<:AbstractString},
                            language::Symbol)
    
    for (line_num, line) in enumerate(lines)
        stripped = strip(line)
        isempty(stripped) && continue
        
        # Check if any sanitizer is applied
        for sanitizer in tracker.sanitizers
            if contains(stripped, sanitizer)
                # Find which tainted variable is being sanitized
                for (var_name, taint_info) in tracker.taint_state
                    if contains(stripped, var_name)
                        # Update taint info
                        tracker.taint_state[var_name] = TaintInfo(
                            taint_info.variable,
                            taint_info.source_type,
                            taint_info.source_line,
                            taint_info.source_expression,
                            taint_info.propagation_chain,
                            true,
                            sanitizer,
                            taint_info.confidence
                        )
                        
                        push!(tracker.taint_history, TaintEvent(
                            line_num,
                            :sanitize,
                            var_name,
                            var_name,
                            stripped,
                            length(tracker.taint_history) + 1
                        ))
                    end
                end
            end
        end
    end
end

"""
Get sanitizer functions for a language.
"""
function get_sanitizers(language::Symbol)::Set{String}
    sanitizers = Dict(
        :python => Set([
            "escape", "quote", "sanitize", "clean",
            "html.escape", "urllib.parse.quote",
            "bleach.clean", "markupsafe.escape",
        ]),
        :javascript => Set([
            "escape", "encodeURIComponent", "encodeURI",
            "sanitize", "DOMPurify.sanitize",
            "validator.escape", "he.encode",
        ]),
        :java => Set([
            "escapeHtml", "escapeXml", "escapeSql",
            "StringEscapeUtils", "HtmlUtils.htmlEscape",
            "PreparedStatement",
        ]),
        :php => Set([
            "htmlspecialchars", "htmlentities",
            "mysqli_real_escape_string", "addslashes",
            "filter_var", "strip_tags",
        ]),
        :go => Set([
            "html.EscapeString", "url.QueryEscape",
            "template.HTMLEscapeString",
        ]),
        :c => Set([
            "escape", "sanitize", "encode",
        ]),
    )
    
    return get(sanitizers, language, Set{String}())
end

# ══════════════════════════════════════════════════════════════════════════════
# PATH BUILDING
# ══════════════════════════════════════════════════════════════════════════════

"""
Build exploitable paths from analysis.
"""
function build_exploitable_paths(tracker::TaintTracker)::Vector{ExploitablePath}
    paths = ExploitablePath[]
    
    for sink in tracker.sinks_reached
        if sink.is_exploitable
            vuln_type = sink_type_to_vuln_class(sink.sink_type)
            complexity = assess_complexity(sink)
            
            push!(paths, ExploitablePath(
                sink.taint_info,
                sink,
                sink.exploitation_path,
                vuln_type,
                sink.taint_info.confidence,
                complexity
            ))
        end
    end
    
    # Sort by confidence
    sort!(paths, by=p -> p.confidence, rev=true)
    
    return paths
end

"""
Convert sink type to vulnerability class.
"""
function sink_type_to_vuln_class(sink_type::Symbol)::VulnClass
    mapping = Dict(
        :sql => INJECTION,
        :command => CODE_EXECUTION,
        :xss => XSS,
        :file => PATH_TRAVERSAL,
        :code => CODE_EXECUTION,
        :ldap => INJECTION,
        :xpath => INJECTION,
        :network => SSRF,
    )
    
    return get(mapping, sink_type, INJECTION)
end

"""
Assess exploitation complexity.
"""
function assess_complexity(sink::SinkReach)::Symbol
    path_length = length(sink.exploitation_path)
    
    if path_length <= 2
        return :low
    elseif path_length <= 5
        return :medium
    else
        return :high
    end
end

# ══════════════════════════════════════════════════════════════════════════════
# COVERAGE COMPUTATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Compute taint analysis coverage.
"""
function compute_coverage(tracker::TaintTracker)::TaintCoverage
    # Count sources
    source_events = filter(e -> e.event_type == :introduce, tracker.taint_history)
    total_sources = length(source_events)
    tracked_sources = length(tracker.taint_state)
    
    # Count sinks
    sink_events = filter(e -> e.event_type == :sink, tracker.taint_history)
    total_sinks = length(sink_events)
    reached_sinks = length(tracker.sinks_reached)
    
    # Count sanitized flows
    sanitized = count(t -> t.is_sanitized, values(tracker.taint_state))
    
    # Count exploitable flows
    exploitable = count(s -> s.is_exploitable, tracker.sinks_reached)
    
    return TaintCoverage(
        total_sources,
        tracked_sources,
        total_sinks,
        reached_sinks,
        sanitized,
        exploitable
    )
end
