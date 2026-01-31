"""
Data flow analysis for Oracle.
"""

# ══════════════════════════════════════════════════════════════════════════════
# DATA FLOW ANALYZER
# ══════════════════════════════════════════════════════════════════════════════

"""
    DataFlowAnalyzer

Performs data flow analysis to track how data moves through code.
"""
mutable struct DataFlowAnalyzer
    language::Symbol
    reaching_defs::Dict{Int, Set{Definition}}
    live_vars::Dict{Int, Set{String}}
    def_use_chains::Dict{String, Vector{UseDefPair}}
    config::Dict{Symbol, Any}
    
    function DataFlowAnalyzer(language::Symbol=:auto; kwargs...)
        new(
            language,
            Dict{Int, Set{Definition}}(),
            Dict{Int, Set{String}}(),
            Dict{String, Vector{UseDefPair}}(),
            Dict{Symbol, Any}(kwargs)
        )
    end
end

"""
Variable definition information.
"""
struct Definition
    variable::String
    line::Int
    expression::String
    is_tainted::Bool
end

"""
Use-definition pair for tracking data flow.
"""
struct UseDefPair
    definition::Definition
    use_line::Int
    use_context::String
end

"""
Data flow analysis result.
"""
struct DataFlowResult
    reaching_definitions::Dict{Int, Set{Definition}}
    live_variables::Dict{Int, Set{String}}
    def_use_chains::Dict{String, Vector{UseDefPair}}
    taint_propagation::Vector{TaintPath}
    data_dependencies::Dict{String, Set{String}}
end

"""
Taint propagation path.
"""
struct TaintPath
    source::Definition
    sink_line::Int
    sink_expression::String
    path::Vector{Int}  # Line numbers
    confidence::Float64
end

# ══════════════════════════════════════════════════════════════════════════════
# MAIN ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

"""
    analyze(analyzer::DataFlowAnalyzer, code::String) -> DataFlowResult

Perform data flow analysis on code.
"""
function analyze(analyzer::DataFlowAnalyzer, code::String;
                 filepath::String="<unknown>")::DataFlowResult
    
    language = analyzer.language
    if language == :auto
        language = detect_language(filepath)
    end
    
    lines = split(code, '\n')
    
    # Phase 1: Extract definitions and uses
    definitions, uses = extract_defs_and_uses(lines, language)
    
    # Phase 2: Compute reaching definitions
    reaching_defs = compute_reaching_definitions(definitions, uses, length(lines))
    
    # Phase 3: Compute live variables
    live_vars = compute_live_variables(definitions, uses, length(lines))
    
    # Phase 4: Build def-use chains
    def_use_chains = build_def_use_chains(definitions, uses, reaching_defs)
    
    # Phase 5: Track taint propagation
    taint_paths = track_taint_propagation(definitions, uses, reaching_defs, code, language)
    
    # Phase 6: Compute data dependencies
    dependencies = compute_data_dependencies(definitions, uses)
    
    return DataFlowResult(
        reaching_defs,
        live_vars,
        def_use_chains,
        taint_paths,
        dependencies
    )
end

# ══════════════════════════════════════════════════════════════════════════════
# DEFINITION AND USE EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

"""
Extract variable definitions and uses from code.
"""
function extract_defs_and_uses(lines::Vector{<:AbstractString}, language::Symbol)
    definitions = Dict{Int, Vector{Definition}}()
    uses = Dict{Int, Vector{String}}()
    
    for (line_num, line) in enumerate(lines)
        stripped = strip(line)
        isempty(stripped) && continue
        
        # Extract definitions
        line_defs = extract_definitions(stripped, line_num, language)
        if !isempty(line_defs)
            definitions[line_num] = line_defs
        end
        
        # Extract uses
        line_uses = extract_uses(stripped, language)
        if !isempty(line_uses)
            uses[line_num] = line_uses
        end
    end
    
    return definitions, uses
end

"""
Extract variable definitions from a line.
"""
function extract_definitions(line::String, line_num::Int, language::Symbol)::Vector{Definition}
    defs = Definition[]
    
    # Assignment patterns by language
    patterns = get_assignment_patterns(language)
    
    for pattern in patterns
        for m in eachmatch(pattern, line)
            var_name = m.captures[1]
            expr = length(m.captures) > 1 ? string(m.captures[2]) : ""
            
            # Check if RHS contains taint sources
            is_tainted = check_taint_source(line, language)
            
            push!(defs, Definition(var_name, line_num, expr, is_tainted))
        end
    end
    
    return defs
end

"""
Get assignment patterns for a language.
"""
function get_assignment_patterns(language::Symbol)::Vector{Regex}
    patterns = Dict(
        :python => [
            r"^([a-zA-Z_]\w*)\s*=\s*(.+)$",
            r"^([a-zA-Z_]\w*)\s*\+=",
            r"^([a-zA-Z_]\w*)\s*-=",
        ],
        :javascript => [
            r"(?:const|let|var)\s+([a-zA-Z_$]\w*)\s*=\s*(.+)",
            r"([a-zA-Z_$]\w*)\s*=\s*(.+)",
        ],
        :java => [
            r"(?:\w+\s+)+([a-zA-Z_]\w*)\s*=\s*(.+)",
            r"([a-zA-Z_]\w*)\s*=\s*(.+)",
        ],
        :c => [
            r"(?:\w+\s*\*?\s+)+([a-zA-Z_]\w*)\s*=\s*(.+)",
            r"([a-zA-Z_]\w*)\s*=\s*(.+)",
        ],
        :go => [
            r"([a-zA-Z_]\w*)\s*:=\s*(.+)",
            r"(?:var\s+)?([a-zA-Z_]\w*)\s*=\s*(.+)",
        ],
    )
    
    return get(patterns, language, [r"([a-zA-Z_]\w*)\s*=\s*(.+)"])
end

"""
Extract variable uses from a line.
"""
function extract_uses(line::String, language::Symbol)::Vector{String}
    uses = String[]
    
    # Find all identifiers
    for m in eachmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", line)
        identifier = m.match
        
        # Filter out keywords and common built-ins
        if !is_keyword(identifier, language) && !is_builtin(identifier, language)
            push!(uses, identifier)
        end
    end
    
    return unique(uses)
end

"""
Check if identifier is a built-in.
"""
function is_builtin(name::String, language::Symbol)::Bool
    builtins = Dict(
        :python => Set(["True", "False", "None", "print", "len", "range", 
                        "str", "int", "float", "list", "dict", "set", "tuple"]),
        :javascript => Set(["true", "false", "null", "undefined", "console", 
                            "window", "document", "Math", "JSON", "Array"]),
        :java => Set(["true", "false", "null", "System", "String", "Integer"]),
        :c => Set(["NULL", "true", "false", "sizeof"]),
        :go => Set(["true", "false", "nil", "make", "new", "len", "cap"]),
    )
    
    return name in get(builtins, language, Set{String}())
end

# ══════════════════════════════════════════════════════════════════════════════
# REACHING DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

"""
Compute reaching definitions for each program point.
"""
function compute_reaching_definitions(definitions::Dict{Int, Vector{Definition}},
                                      uses::Dict{Int, Vector{String}},
                                      num_lines::Int)::Dict{Int, Set{Definition}}
    
    reaching = Dict{Int, Set{Definition}}()
    
    # Initialize
    for i in 1:num_lines
        reaching[i] = Set{Definition}()
    end
    
    # Forward data flow - iterate until fixed point
    changed = true
    iterations = 0
    max_iterations = 100
    
    while changed && iterations < max_iterations
        changed = false
        iterations += 1
        
        for line in 1:num_lines
            # IN[line] = union of OUT[predecessors]
            if line > 1
                old_size = length(reaching[line])
                union!(reaching[line], reaching[line - 1])
                
                # Kill definitions that are redefined
                if haskey(definitions, line)
                    for def in definitions[line]
                        # Remove old definitions of same variable
                        filter!(d -> d.variable != def.variable, reaching[line])
                    end
                end
                
                if length(reaching[line]) != old_size
                    changed = true
                end
            end
            
            # Add definitions at this line
            if haskey(definitions, line)
                for def in definitions[line]
                    push!(reaching[line], def)
                end
            end
        end
    end
    
    return reaching
end

# ══════════════════════════════════════════════════════════════════════════════
# LIVE VARIABLE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

"""
Compute live variables at each program point.
"""
function compute_live_variables(definitions::Dict{Int, Vector{Definition}},
                                uses::Dict{Int, Vector{String}},
                                num_lines::Int)::Dict{Int, Set{String}}
    
    live = Dict{Int, Set{String}}()
    
    # Initialize
    for i in 1:num_lines
        live[i] = Set{String}()
    end
    
    # Backward data flow
    changed = true
    iterations = 0
    max_iterations = 100
    
    while changed && iterations < max_iterations
        changed = false
        iterations += 1
        
        for line in num_lines:-1:1
            old_live = copy(live[line])
            
            # OUT[line] = union of IN[successors]
            if line < num_lines
                union!(live[line], live[line + 1])
            end
            
            # Kill variables defined here
            if haskey(definitions, line)
                for def in definitions[line]
                    delete!(live[line], def.variable)
                end
            end
            
            # Add variables used here
            if haskey(uses, line)
                union!(live[line], uses[line])
            end
            
            if live[line] != old_live
                changed = true
            end
        end
    end
    
    return live
end

# ══════════════════════════════════════════════════════════════════════════════
# DEF-USE CHAINS
# ══════════════════════════════════════════════════════════════════════════════

"""
Build definition-use chains.
"""
function build_def_use_chains(definitions::Dict{Int, Vector{Definition}},
                              uses::Dict{Int, Vector{String}},
                              reaching::Dict{Int, Set{Definition}})::Dict{String, Vector{UseDefPair}}
    
    chains = Dict{String, Vector{UseDefPair}}()
    
    for (use_line, used_vars) in uses
        for var in used_vars
            # Find reaching definition for this use
            for def in get(reaching, use_line, Set{Definition}())
                if def.variable == var
                    if !haskey(chains, var)
                        chains[var] = UseDefPair[]
                    end
                    push!(chains[var], UseDefPair(def, use_line, var))
                end
            end
        end
    end
    
    return chains
end

# ══════════════════════════════════════════════════════════════════════════════
# TAINT PROPAGATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Track taint propagation through the code.
"""
function track_taint_propagation(definitions::Dict{Int, Vector{Definition}},
                                 uses::Dict{Int, Vector{String}},
                                 reaching::Dict{Int, Set{Definition}},
                                 code::String,
                                 language::Symbol)::Vector{TaintPath}
    
    paths = TaintPath[]
    lines = split(code, '\n')
    sinks = get_output_sinks(language)
    
    # Find tainted definitions
    tainted_defs = Definition[]
    for (line, defs) in definitions
        for def in defs
            if def.is_tainted
                push!(tainted_defs, def)
            end
        end
    end
    
    # Track each tainted value to sinks
    for tainted in tainted_defs
        # Find uses of this tainted variable
        for (use_line, used_vars) in uses
            if tainted.variable in used_vars
                line_content = lines[use_line]
                
                # Check if use is at a sink
                for sink in sinks
                    if occursin(sink, line_content)
                        path = find_path(tainted.line, use_line)
                        push!(paths, TaintPath(
                            tainted,
                            use_line,
                            strip(line_content),
                            path,
                            0.8  # High confidence for direct flow
                        ))
                    end
                end
                
                # Check for propagation to other variables
                if haskey(definitions, use_line)
                    for def in definitions[use_line]
                        if contains(def.expression, tainted.variable)
                            # Mark this definition as tainted too
                            # (would need to add to tainted_defs and iterate)
                        end
                    end
                end
            end
        end
    end
    
    return paths
end

"""
Find path between two lines (simplified).
"""
function find_path(start_line::Int, end_line::Int)::Vector{Int}
    return collect(start_line:end_line)
end

# ══════════════════════════════════════════════════════════════════════════════
# DATA DEPENDENCIES
# ══════════════════════════════════════════════════════════════════════════════

"""
Compute data dependencies between variables.
"""
function compute_data_dependencies(definitions::Dict{Int, Vector{Definition}},
                                   uses::Dict{Int, Vector{String}})::Dict{String, Set{String}}
    
    deps = Dict{String, Set{String}}()
    
    for (line, defs) in definitions
        for def in defs
            if !haskey(deps, def.variable)
                deps[def.variable] = Set{String}()
            end
            
            # Find what variables are used in the definition
            used_in_def = extract_identifiers(def.expression)
            union!(deps[def.variable], used_in_def)
        end
    end
    
    return deps
end

"""
Extract identifiers from an expression.
"""
function extract_identifiers(expr::String)::Set{String}
    identifiers = Set{String}()
    
    for m in eachmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", expr)
        push!(identifiers, m.match)
    end
    
    return identifiers
end

# ══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

"""
Check if a variable is tainted at a given line.
"""
function is_tainted_at(analyzer::DataFlowAnalyzer, variable::String, line::Int)::Bool
    reaching = get(analyzer.reaching_defs, line, Set{Definition}())
    
    for def in reaching
        if def.variable == variable && def.is_tainted
            return true
        end
    end
    
    return false
end

"""
Get all tainted variables at a line.
"""
function tainted_variables_at(analyzer::DataFlowAnalyzer, line::Int)::Set{String}
    tainted = Set{String}()
    reaching = get(analyzer.reaching_defs, line, Set{Definition}())
    
    for def in reaching
        if def.is_tainted
            push!(tainted, def.variable)
        end
    end
    
    return tainted
end

"""
Get dependencies for a variable (transitive closure).
"""
function get_all_dependencies(deps::Dict{String, Set{String}}, 
                              variable::String)::Set{String}
    all_deps = Set{String}()
    to_process = [variable]
    
    while !isempty(to_process)
        current = popfirst!(to_process)
        
        for dep in get(deps, current, Set{String}())
            if !(dep in all_deps)
                push!(all_deps, dep)
                push!(to_process, dep)
            end
        end
    end
    
    return all_deps
end
