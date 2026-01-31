"""
Control flow analysis for Oracle.
"""

# ══════════════════════════════════════════════════════════════════════════════
# CONTROL FLOW ANALYZER
# ══════════════════════════════════════════════════════════════════════════════

"""
    ControlFlowAnalyzer

Builds and analyzes control flow graphs (CFG) for vulnerability detection.
"""
mutable struct ControlFlowAnalyzer
    language::Symbol
    cfg::ControlFlowGraph
    dominators::Dict{Int, Set{Int}}
    post_dominators::Dict{Int, Set{Int}}
    config::Dict{Symbol, Any}
    
    function ControlFlowAnalyzer(language::Symbol=:auto; kwargs...)
        new(
            language,
            ControlFlowGraph(),
            Dict{Int, Set{Int}}(),
            Dict{Int, Set{Int}}(),
            Dict{Symbol, Any}(kwargs)
        )
    end
end

"""
Control flow graph representation.
"""
mutable struct ControlFlowGraph
    nodes::Dict{Int, CFGNode}
    edges::Vector{CFGEdge}
    entry::Int
    exits::Vector{Int}
    
    ControlFlowGraph() = new(
        Dict{Int, CFGNode}(),
        CFGEdge[],
        0,
        Int[]
    )
end

"""
CFG node representing a basic block.
"""
struct CFGNode
    id::Int
    start_line::Int
    end_line::Int
    statements::Vector{String}
    node_type::Symbol  # :entry, :exit, :branch, :loop, :normal
    condition::Union{String, Nothing}
end

"""
CFG edge representing control flow.
"""
struct CFGEdge
    from::Int
    to::Int
    edge_type::Symbol  # :fall_through, :branch_true, :branch_false, :loop_back, :exception
    condition::Union{String, Nothing}
end

"""
Control flow analysis result.
"""
struct ControlFlowResult
    cfg::ControlFlowGraph
    dominators::Dict{Int, Set{Int}}
    post_dominators::Dict{Int, Set{Int}}
    loops::Vector{LoopInfo}
    unreachable_code::Vector{Int}
    infinite_loops::Vector{Int}
end

"""
Loop information.
"""
struct LoopInfo
    header::Int
    body_nodes::Set{Int}
    back_edges::Vector{Tuple{Int, Int}}
    exit_nodes::Set{Int}
    is_bounded::Bool
    bound_variable::Union{String, Nothing}
end

# ══════════════════════════════════════════════════════════════════════════════
# CFG CONSTRUCTION
# ══════════════════════════════════════════════════════════════════════════════

"""
    analyze(analyzer::ControlFlowAnalyzer, code::String) -> ControlFlowResult

Build and analyze control flow graph.
"""
function analyze(analyzer::ControlFlowAnalyzer, code::String;
                 filepath::String="<unknown>")::ControlFlowResult
    
    language = analyzer.language
    if language == :auto
        language = detect_language(filepath)
    end
    
    lines = split(code, '\n')
    
    # Build CFG
    build_cfg!(analyzer, lines, language)
    
    # Compute dominators
    compute_dominators!(analyzer)
    
    # Compute post-dominators
    compute_post_dominators!(analyzer)
    
    # Find loops
    loops = find_loops(analyzer)
    
    # Find unreachable code
    unreachable = find_unreachable_code(analyzer)
    
    # Detect infinite loops
    infinite = detect_infinite_loops(analyzer, loops, code)
    
    return ControlFlowResult(
        analyzer.cfg,
        analyzer.dominators,
        analyzer.post_dominators,
        loops,
        unreachable,
        infinite
    )
end

"""
Build control flow graph from code.
"""
function build_cfg!(analyzer::ControlFlowAnalyzer, lines::Vector{<:AbstractString}, 
                   language::Symbol)
    
    cfg = analyzer.cfg
    empty!(cfg.nodes)
    empty!(cfg.edges)
    empty!(cfg.exits)
    
    # Create entry node
    cfg.entry = 0
    cfg.nodes[0] = CFGNode(0, 0, 0, String[], :entry, nothing)
    
    node_id = 1
    current_statements = String[]
    current_start = 1
    branch_stack = Tuple{Int, Symbol}[]  # (node_id, type)
    
    for (line_num, line) in enumerate(lines)
        stripped = strip(line)
        isempty(stripped) && continue
        
        # Check for control flow statements
        control_type = get_control_type(stripped, language)
        
        if control_type != :none
            # End current basic block
            if !isempty(current_statements)
                cfg.nodes[node_id] = CFGNode(
                    node_id, current_start, line_num - 1,
                    copy(current_statements), :normal, nothing
                )
                
                # Connect to previous
                if node_id == 1
                    push!(cfg.edges, CFGEdge(0, node_id, :fall_through, nothing))
                end
                
                node_id += 1
                current_statements = String[]
                current_start = line_num
            end
            
            # Handle control flow
            if control_type == :if
                condition = extract_condition(stripped, language)
                cfg.nodes[node_id] = CFGNode(
                    node_id, line_num, line_num,
                    [stripped], :branch, condition
                )
                push!(branch_stack, (node_id, :if))
                node_id += 1
                current_start = line_num + 1
                
            elseif control_type == :else
                if !isempty(branch_stack)
                    # Connect from if block to after else
                    if_node = branch_stack[end][1]
                    push!(cfg.edges, CFGEdge(node_id - 1, node_id + 100, :fall_through, nothing))
                end
                
            elseif control_type == :loop
                condition = extract_condition(stripped, language)
                cfg.nodes[node_id] = CFGNode(
                    node_id, line_num, line_num,
                    [stripped], :loop, condition
                )
                push!(branch_stack, (node_id, :loop))
                node_id += 1
                current_start = line_num + 1
                
            elseif control_type == :return
                cfg.nodes[node_id] = CFGNode(
                    node_id, line_num, line_num,
                    [stripped], :exit, nothing
                )
                push!(cfg.exits, node_id)
                node_id += 1
                current_start = line_num + 1
            end
        else
            push!(current_statements, stripped)
        end
    end
    
    # End final basic block
    if !isempty(current_statements)
        cfg.nodes[node_id] = CFGNode(
            node_id, current_start, length(lines),
            copy(current_statements), :normal, nothing
        )
        push!(cfg.exits, node_id)
    end
    
    # Add edges between consecutive blocks
    node_ids = sort(collect(keys(cfg.nodes)))
    for i in 1:length(node_ids)-1
        from_id = node_ids[i]
        to_id = node_ids[i+1]
        
        from_node = cfg.nodes[from_id]
        
        if from_node.node_type == :branch
            # Add true and false branches
            push!(cfg.edges, CFGEdge(from_id, to_id, :branch_true, from_node.condition))
        elseif from_node.node_type == :loop
            # Add loop entry and back edge placeholder
            push!(cfg.edges, CFGEdge(from_id, to_id, :branch_true, from_node.condition))
        elseif from_node.node_type != :exit
            push!(cfg.edges, CFGEdge(from_id, to_id, :fall_through, nothing))
        end
    end
end

"""
Get control flow type from a line.
"""
function get_control_type(line::String, language::Symbol)::Symbol
    if_patterns = Dict(
        :python => r"^if\s+",
        :javascript => r"^if\s*\(",
        :java => r"^if\s*\(",
        :c => r"^if\s*\(",
        :go => r"^if\s+",
    )
    
    else_patterns = Dict(
        :python => r"^else\s*:",
        :javascript => r"^}\s*else\s*{",
        :java => r"^}\s*else\s*{",
        :c => r"^}\s*else\s*{",
        :go => r"^}\s*else\s*{",
    )
    
    loop_patterns = Dict(
        :python => r"^(for|while)\s+",
        :javascript => r"^(for|while)\s*\(",
        :java => r"^(for|while)\s*\(",
        :c => r"^(for|while)\s*\(",
        :go => r"^for\s+",
    )
    
    return_patterns = [r"^return\b", r"^throw\b", r"^raise\b"]
    
    # Check if
    if_pat = get(if_patterns, language, r"^if\s+")
    if occursin(if_pat, line)
        return :if
    end
    
    # Check else
    else_pat = get(else_patterns, language, r"^else\b")
    if occursin(else_pat, line)
        return :else
    end
    
    # Check loops
    loop_pat = get(loop_patterns, language, r"^(for|while)\s+")
    if occursin(loop_pat, line)
        return :loop
    end
    
    # Check return
    for pat in return_patterns
        if occursin(pat, line)
            return :return
        end
    end
    
    return :none
end

"""
Extract condition from control statement.
"""
function extract_condition(line::String, language::Symbol)::String
    # Extract condition from if/while/for
    m = match(r"(?:if|while|for)\s*\(([^)]+)\)", line)
    if !isnothing(m)
        return m.captures[1]
    end
    
    # Python style
    m = match(r"(?:if|while|for)\s+(.+):", line)
    if !isnothing(m)
        return m.captures[1]
    end
    
    return ""
end

# ══════════════════════════════════════════════════════════════════════════════
# DOMINATOR ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

"""
Compute dominators for all nodes.
"""
function compute_dominators!(analyzer::ControlFlowAnalyzer)
    cfg = analyzer.cfg
    empty!(analyzer.dominators)
    
    nodes = collect(keys(cfg.nodes))
    
    # Initialize
    for node in nodes
        if node == cfg.entry
            analyzer.dominators[node] = Set([node])
        else
            analyzer.dominators[node] = Set(nodes)
        end
    end
    
    # Compute predecessors
    predecessors = Dict{Int, Set{Int}}()
    for node in nodes
        predecessors[node] = Set{Int}()
    end
    for edge in cfg.edges
        push!(predecessors[edge.to], edge.from)
    end
    
    # Iterate until fixed point
    changed = true
    while changed
        changed = false
        
        for node in nodes
            node == cfg.entry && continue
            
            # Dom[n] = {n} ∪ (∩ Dom[p] for p in predecessors)
            preds = predecessors[node]
            if !isempty(preds)
                new_dom = Set([node])
                pred_doms = [analyzer.dominators[p] for p in preds]
                
                if !isempty(pred_doms)
                    common = intersect(pred_doms...)
                    union!(new_dom, common)
                end
                
                if new_dom != analyzer.dominators[node]
                    analyzer.dominators[node] = new_dom
                    changed = true
                end
            end
        end
    end
end

"""
Compute post-dominators for all nodes.
"""
function compute_post_dominators!(analyzer::ControlFlowAnalyzer)
    cfg = analyzer.cfg
    empty!(analyzer.post_dominators)
    
    nodes = collect(keys(cfg.nodes))
    
    # Initialize
    for node in nodes
        if node in cfg.exits
            analyzer.post_dominators[node] = Set([node])
        else
            analyzer.post_dominators[node] = Set(nodes)
        end
    end
    
    # Compute successors
    successors = Dict{Int, Set{Int}}()
    for node in nodes
        successors[node] = Set{Int}()
    end
    for edge in cfg.edges
        push!(successors[edge.from], edge.to)
    end
    
    # Iterate until fixed point
    changed = true
    while changed
        changed = false
        
        for node in nodes
            node in cfg.exits && continue
            
            succs = successors[node]
            if !isempty(succs)
                new_pdom = Set([node])
                succ_pdoms = [analyzer.post_dominators[s] for s in succs]
                
                if !isempty(succ_pdoms)
                    common = intersect(succ_pdoms...)
                    union!(new_pdom, common)
                end
                
                if new_pdom != analyzer.post_dominators[node]
                    analyzer.post_dominators[node] = new_pdom
                    changed = true
                end
            end
        end
    end
end

# ══════════════════════════════════════════════════════════════════════════════
# LOOP DETECTION
# ══════════════════════════════════════════════════════════════════════════════

"""
Find all loops in the CFG.
"""
function find_loops(analyzer::ControlFlowAnalyzer)::Vector{LoopInfo}
    loops = LoopInfo[]
    cfg = analyzer.cfg
    
    # Find back edges (edge where target dominates source)
    back_edges = Tuple{Int, Int}[]
    for edge in cfg.edges
        if edge.to in get(analyzer.dominators, edge.from, Set{Int}())
            push!(back_edges, (edge.from, edge.to))
        end
    end
    
    # For each back edge, identify the natural loop
    for (tail, header) in back_edges
        body = find_loop_body(analyzer, header, tail)
        exits = find_loop_exits(analyzer, body)
        
        # Check if loop is bounded
        header_node = cfg.nodes[header]
        is_bounded, bound_var = check_loop_bounded(header_node)
        
        push!(loops, LoopInfo(
            header,
            body,
            [(tail, header)],
            exits,
            is_bounded,
            bound_var
        ))
    end
    
    return loops
end

"""
Find the body of a natural loop.
"""
function find_loop_body(analyzer::ControlFlowAnalyzer, header::Int, tail::Int)::Set{Int}
    body = Set([header, tail])
    worklist = [tail]
    
    # Compute predecessors
    predecessors = Dict{Int, Set{Int}}()
    for node in keys(analyzer.cfg.nodes)
        predecessors[node] = Set{Int}()
    end
    for edge in analyzer.cfg.edges
        push!(predecessors[edge.to], edge.from)
    end
    
    while !isempty(worklist)
        node = popfirst!(worklist)
        
        for pred in predecessors[node]
            if !(pred in body)
                push!(body, pred)
                push!(worklist, pred)
            end
        end
    end
    
    return body
end

"""
Find exit nodes for a loop.
"""
function find_loop_exits(analyzer::ControlFlowAnalyzer, body::Set{Int})::Set{Int}
    exits = Set{Int}()
    
    for edge in analyzer.cfg.edges
        if edge.from in body && !(edge.to in body)
            push!(exits, edge.from)
        end
    end
    
    return exits
end

"""
Check if a loop is bounded.
"""
function check_loop_bounded(header_node::CFGNode)::Tuple{Bool, Union{String, Nothing}}
    condition = header_node.condition
    isnothing(condition) && return (false, nothing)
    
    # Check for common bounded patterns
    # for i in range(n), for(i=0; i<n; i++)
    bounded_patterns = [
        r"(\w+)\s*<\s*\w+",      # i < n
        r"(\w+)\s*<=\s*\w+",     # i <= n
        r"(\w+)\s*in\s+range",   # i in range(n)
        r"(\w+)\s*:=\s*range",   # for i := range ...
    ]
    
    for pattern in bounded_patterns
        m = match(pattern, condition)
        if !isnothing(m)
            return (true, m.captures[1])
        end
    end
    
    return (false, nothing)
end

# ══════════════════════════════════════════════════════════════════════════════
# CODE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

"""
Find unreachable code.
"""
function find_unreachable_code(analyzer::ControlFlowAnalyzer)::Vector{Int}
    unreachable = Int[]
    
    # BFS from entry
    reachable = Set{Int}()
    worklist = [analyzer.cfg.entry]
    
    # Compute successors
    successors = Dict{Int, Set{Int}}()
    for node in keys(analyzer.cfg.nodes)
        successors[node] = Set{Int}()
    end
    for edge in analyzer.cfg.edges
        push!(successors[edge.from], edge.to)
    end
    
    while !isempty(worklist)
        node = popfirst!(worklist)
        
        if !(node in reachable)
            push!(reachable, node)
            
            for succ in successors[node]
                if !(succ in reachable)
                    push!(worklist, succ)
                end
            end
        end
    end
    
    # Find unreachable
    for node in keys(analyzer.cfg.nodes)
        if !(node in reachable) && node != 0
            push!(unreachable, node)
        end
    end
    
    return sort(unreachable)
end

"""
Detect potentially infinite loops.
"""
function detect_infinite_loops(analyzer::ControlFlowAnalyzer, loops::Vector{LoopInfo},
                               code::String)::Vector{Int}
    infinite = Int[]
    
    for loop in loops
        # Check if loop has no bounded exit condition
        if !loop.is_bounded
            # Check if loop has break/return inside
            header_node = analyzer.cfg.nodes[loop.header]
            has_exit = false
            
            for node_id in loop.body_nodes
                if haskey(analyzer.cfg.nodes, node_id)
                    node = analyzer.cfg.nodes[node_id]
                    for stmt in node.statements
                        if occursin(r"\b(break|return|throw|raise)\b", stmt)
                            has_exit = true
                            break
                        end
                    end
                end
                has_exit && break
            end
            
            if !has_exit && isempty(loop.exit_nodes)
                push!(infinite, loop.header)
            end
        end
    end
    
    return infinite
end

# ══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

"""
Check if node A dominates node B.
"""
function dominates(analyzer::ControlFlowAnalyzer, a::Int, b::Int)::Bool
    return a in get(analyzer.dominators, b, Set{Int}())
end

"""
Check if node A post-dominates node B.
"""
function post_dominates(analyzer::ControlFlowAnalyzer, a::Int, b::Int)::Bool
    return a in get(analyzer.post_dominators, b, Set{Int}())
end

"""
Get all paths from entry to a node.
"""
function paths_to_node(analyzer::ControlFlowAnalyzer, target::Int)::Vector{Vector{Int}}
    paths = Vector{Int}[]
    
    function dfs(current::Int, path::Vector{Int}, visited::Set{Int})
        if current == target
            push!(paths, copy(path))
            return
        end
        
        if current in visited
            return
        end
        
        push!(visited, current)
        push!(path, current)
        
        # Get successors
        for edge in analyzer.cfg.edges
            if edge.from == current
                dfs(edge.to, path, visited)
            end
        end
        
        pop!(path)
        delete!(visited, current)
    end
    
    dfs(analyzer.cfg.entry, Int[], Set{Int}())
    return paths
end
