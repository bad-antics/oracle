"""
Main scanning engine orchestrating all analysis components.
"""

# ══════════════════════════════════════════════════════════════════════════════
# SCANNER CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

"""
    ScanConfig

Configuration for vulnerability scanning.
"""
@kwdef struct ScanConfig
    # Scan scope
    include_patterns::Vector{String} = ["*.c", "*.cpp", "*.h", "*.java", "*.py", 
                                         "*.js", "*.ts", "*.php", "*.go", "*.rs"]
    exclude_patterns::Vector{String} = ["*test*", "*spec*", "*node_modules*", 
                                         "*vendor*", "*.min.js"]
    max_file_size::Int = 1_000_000  # 1MB
    
    # Analysis options
    enable_static::Bool = true
    enable_semantic::Bool = true
    enable_dataflow::Bool = true
    enable_controlflow::Bool = true
    enable_taint::Bool = true
    enable_ml::Bool = true
    enable_anomaly::Bool = true
    
    # Thresholds
    min_confidence::Float64 = 0.3
    max_findings_per_file::Int = 50
    
    # Performance
    parallel::Bool = true
    max_workers::Int = Threads.nthreads()
    timeout_seconds::Int = 60
    
    # Output
    verbose::Bool = false
    generate_report::Bool = true
    report_format::String = "html"  # html, json, sarif
end

"""
Default scan configuration.
"""
const DEFAULT_SCAN_CONFIG = ScanConfig()

# ══════════════════════════════════════════════════════════════════════════════
# SCANNER
# ══════════════════════════════════════════════════════════════════════════════

"""
    Scanner

Main scanning engine.
"""
mutable struct Scanner
    config::ScanConfig
    static_analyzer::StaticAnalyzer
    semantic_analyzer::SemanticAnalyzer
    dataflow_analyzer::DataFlowAnalyzer
    controlflow_analyzer::ControlFlowAnalyzer
    taint_tracker::TaintTracker
    pattern_db::PatternDatabase
    pattern_matcher::PatternMatcher
    predictor::VulnerabilityPredictor
    classifier::PatternClassifier
    anomaly_detector::AnomalyDetector
    findings::Vector{Finding}
    stats::ScanStats
    
    function Scanner(; config::ScanConfig=DEFAULT_SCAN_CONFIG)
        new(
            config,
            StaticAnalyzer(),
            SemanticAnalyzer(),
            DataFlowAnalyzer(),
            ControlFlowAnalyzer(),
            TaintTracker(),
            init_pattern_database(),
            PatternMatcher(),
            load_default_predictor(),
            PatternClassifier(),
            AnomalyDetector(),
            Finding[],
            ScanStats()
        )
    end
end

"""
    Finding

A discovered vulnerability or security issue.
"""
struct Finding
    id::String
    vuln_class::VulnClass
    severity::Severity
    confidence::Float64
    title::String
    description::String
    file_path::String
    line_start::Int
    line_end::Int
    column::Int
    code_snippet::String
    cwe_id::Union{String, Nothing}
    remediation::String
    references::Vector{String}
    tags::Vector{String}
    false_positive_likelihood::Float64
    timestamp::DateTime
end

"""
Severity levels.
"""
@enum Severity begin
    CRITICAL
    HIGH
    MEDIUM
    LOW
    INFO
end

"""
    ScanStats

Statistics from a scan.
"""
mutable struct ScanStats
    files_scanned::Int
    files_skipped::Int
    total_lines::Int
    total_findings::Int
    findings_by_severity::Dict{Severity, Int}
    findings_by_class::Dict{VulnClass, Int}
    scan_duration_ms::Int
    errors::Vector{String}
    
    function ScanStats()
        new(
            0, 0, 0, 0,
            Dict{Severity, Int}(),
            Dict{VulnClass, Int}(),
            0,
            String[]
        )
    end
end

# ══════════════════════════════════════════════════════════════════════════════
# SCANNING
# ══════════════════════════════════════════════════════════════════════════════

"""
    scan(scanner::Scanner, target::String) -> ScanResult

Scan a file or directory for vulnerabilities.
"""
function scan(scanner::Scanner, target::String)::ScanResult
    start_time = time_ns()
    
    scanner.findings = Finding[]
    scanner.stats = ScanStats()
    
    if isdir(target)
        scan_directory!(scanner, target)
    elseif isfile(target)
        scan_file!(scanner, target)
    else
        push!(scanner.stats.errors, "Target not found: $target")
    end
    
    elapsed = (time_ns() - start_time) / 1e6
    scanner.stats.scan_duration_ms = round(Int, elapsed)
    
    # Sort findings by severity
    sort!(scanner.findings, by=f -> (severity_to_int(f.severity), -f.confidence), rev=true)
    
    return ScanResult(scanner.findings, scanner.stats)
end

"""
    ScanResult

Result of a vulnerability scan.
"""
struct ScanResult
    findings::Vector{Finding}
    stats::ScanStats
end

"""
Convert severity to integer for sorting.
"""
function severity_to_int(sev::Severity)::Int
    return Dict(CRITICAL => 4, HIGH => 3, MEDIUM => 2, LOW => 1, INFO => 0)[sev]
end

"""
Scan a directory recursively.
"""
function scan_directory!(scanner::Scanner, dir::String)
    files = collect_files(dir, scanner.config)
    
    scanner.config.verbose && @info "Scanning directory" path=dir files=length(files)
    
    if scanner.config.parallel && length(files) > 1
        # Parallel scanning
        findings_channel = Channel{Vector{Finding}}(100)
        errors_channel = Channel{String}(100)
        
        @sync begin
            # Producer tasks
            for file in files
                Threads.@spawn begin
                    try
                        file_findings = scan_single_file(scanner, file)
                        put!(findings_channel, file_findings)
                    catch e
                        put!(errors_channel, "Error scanning $file: $(sprint(showerror, e))")
                    end
                end
            end
        end
        
        close(findings_channel)
        close(errors_channel)
        
        for file_findings in findings_channel
            append!(scanner.findings, file_findings)
        end
        
        for error in errors_channel
            push!(scanner.stats.errors, error)
        end
    else
        # Sequential scanning
        for file in files
            try
                scan_file!(scanner, file)
            catch e
                push!(scanner.stats.errors, "Error scanning $file: $(sprint(showerror, e))")
            end
        end
    end
end

"""
Collect files matching patterns.
"""
function collect_files(dir::String, config::ScanConfig)::Vector{String}
    files = String[]
    
    for (root, _, filenames) in walkdir(dir)
        for filename in filenames
            filepath = joinpath(root, filename)
            
            # Check include patterns
            include_match = any(fnmatch(pattern, filename) 
                               for pattern in config.include_patterns)
            
            # Check exclude patterns
            exclude_match = any(fnmatch(pattern, filepath) || fnmatch(pattern, filename)
                               for pattern in config.exclude_patterns)
            
            if include_match && !exclude_match
                # Check file size
                try
                    if filesize(filepath) <= config.max_file_size
                        push!(files, filepath)
                    end
                catch
                    # Skip files we can't stat
                end
            end
        end
    end
    
    return files
end

"""
Simple glob pattern matching.
"""
function fnmatch(pattern::String, text::String)::Bool
    # Convert glob to regex
    regex_pattern = replace(pattern, "*" => ".*")
    regex_pattern = replace(regex_pattern, "?" => ".")
    regex = Regex("^" * regex_pattern * "\$", "i")
    return occursin(regex, text)
end

"""
Scan a single file.
"""
function scan_file!(scanner::Scanner, filepath::String)
    findings = scan_single_file(scanner, filepath)
    append!(scanner.findings, findings)
    scanner.stats.files_scanned += 1
    scanner.stats.total_findings += length(findings)
    
    for finding in findings
        scanner.stats.findings_by_severity[finding.severity] = 
            get(scanner.stats.findings_by_severity, finding.severity, 0) + 1
        scanner.stats.findings_by_class[finding.vuln_class] = 
            get(scanner.stats.findings_by_class, finding.vuln_class, 0) + 1
    end
end

"""
Analyze a single file and return findings.
"""
function scan_single_file(scanner::Scanner, filepath::String)::Vector{Finding}
    findings = Finding[]
    
    # Read file
    code = safe_read_file(filepath)
    if isempty(code)
        return findings
    end
    
    # Detect language
    language = detect_language(filepath)
    
    scanner.config.verbose && @info "Scanning file" path=filepath language=language
    
    # Count lines
    lines = count(==('\n'), code) + 1
    scanner.stats.total_lines += lines
    
    # Static analysis
    if scanner.config.enable_static
        static_findings = analyze_static(scanner, filepath, code, language)
        append!(findings, static_findings)
    end
    
    # Semantic analysis
    if scanner.config.enable_semantic
        semantic_findings = analyze_semantic(scanner, filepath, code, language)
        append!(findings, semantic_findings)
    end
    
    # Data flow analysis
    if scanner.config.enable_dataflow
        dataflow_findings = analyze_dataflow(scanner, filepath, code, language)
        append!(findings, dataflow_findings)
    end
    
    # Taint tracking
    if scanner.config.enable_taint
        taint_findings = analyze_taint(scanner, filepath, code, language)
        append!(findings, taint_findings)
    end
    
    # Pattern matching
    pattern_findings = analyze_patterns(scanner, filepath, code, language)
    append!(findings, pattern_findings)
    
    # ML prediction
    if scanner.config.enable_ml
        ml_findings = analyze_ml(scanner, filepath, code, language)
        append!(findings, ml_findings)
    end
    
    # Anomaly detection
    if scanner.config.enable_anomaly
        anomaly_findings = analyze_anomaly(scanner, filepath, code, language)
        append!(findings, anomaly_findings)
    end
    
    # Filter by confidence
    filter!(f -> f.confidence >= scanner.config.min_confidence, findings)
    
    # Limit findings per file
    if length(findings) > scanner.config.max_findings_per_file
        sort!(findings, by=f -> (severity_to_int(f.severity), f.confidence), rev=true)
        findings = findings[1:scanner.config.max_findings_per_file]
    end
    
    # Deduplicate
    unique!(f -> (f.line_start, f.vuln_class), findings)
    
    return findings
end

# ══════════════════════════════════════════════════════════════════════════════
# ANALYSIS FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

"""
Static analysis pass.
"""
function analyze_static(scanner::Scanner, filepath::String, 
                       code::String, language::String)::Vector{Finding}
    findings = Finding[]
    
    # Analyze with static analyzer
    result = analyze_file(scanner.static_analyzer, filepath)
    
    # Check for dangerous functions
    for func in result.features.dangerous_functions
        finding = Finding(
            generate_finding_id(),
            INJECTION,
            HIGH,
            0.7,
            "Dangerous function usage: $func",
            "Usage of potentially dangerous function '$func' detected. This function may be vulnerable to injection attacks if user input is not properly sanitized.",
            filepath,
            1, 1, 1,
            extract_snippet(code, 1, 10),
            "CWE-78",
            "Replace with safer alternatives or ensure proper input validation.",
            ["https://cwe.mitre.org/data/definitions/78.html"],
            ["dangerous-function", "injection"],
            0.2,
            now()
        )
        push!(findings, finding)
    end
    
    # High complexity warning
    if result.features.cyclomatic_complexity > 20
        finding = Finding(
            generate_finding_id(),
            INFO,
            LOW,
            0.5,
            "High cyclomatic complexity",
            "Function has cyclomatic complexity of $(result.features.cyclomatic_complexity), which increases the risk of bugs and security issues.",
            filepath,
            1, 1, 1,
            "",
            "CWE-1121",
            "Refactor complex functions into smaller, more manageable pieces.",
            String[],
            ["complexity", "code-quality"],
            0.0,
            now()
        )
        push!(findings, finding)
    end
    
    return findings
end

"""
Semantic analysis pass.
"""
function analyze_semantic(scanner::Scanner, filepath::String,
                         code::String, language::String)::Vector{Finding}
    findings = Finding[]
    
    result = analyze_semantic(scanner.semantic_analyzer, code, language)
    
    for pattern in result.patterns_found
        severity = pattern.severity == "high" ? HIGH : 
                  pattern.severity == "medium" ? MEDIUM : LOW
        
        finding = Finding(
            generate_finding_id(),
            string_to_vulnclass(pattern.vuln_type),
            severity,
            pattern.confidence,
            pattern.pattern_type,
            pattern.description,
            filepath,
            pattern.line_start,
            pattern.line_end,
            1,
            extract_snippet(code, pattern.line_start, pattern.line_end),
            pattern.cwe_id,
            "Review the code for potential security issues.",
            String[],
            ["semantic-analysis"],
            0.1,
            now()
        )
        push!(findings, finding)
    end
    
    return findings
end

"""
Data flow analysis pass.
"""
function analyze_dataflow(scanner::Scanner, filepath::String,
                         code::String, language::String)::Vector{Finding}
    findings = Finding[]
    
    analyze_dataflow!(scanner.dataflow_analyzer, code, language)
    
    # Check for taint propagation
    taint_paths = track_taint(scanner.dataflow_analyzer)
    
    for path in taint_paths
        finding = Finding(
            generate_finding_id(),
            INJECTION,
            HIGH,
            0.8,
            "Tainted data flow detected",
            "User-controlled data flows from input to a sensitive sink without proper sanitization.",
            filepath,
            1, 1, 1,
            "",
            "CWE-20",
            "Validate and sanitize all user input before use.",
            String[],
            ["taint-flow", "data-flow"],
            0.15,
            now()
        )
        push!(findings, finding)
    end
    
    return findings
end

"""
Taint tracking pass.
"""
function analyze_taint(scanner::Scanner, filepath::String,
                      code::String, language::String)::Vector{Finding}
    findings = Finding[]
    
    exploitable = find_exploitable_paths(scanner.taint_tracker, code, language)
    
    for path in exploitable
        severity = path.risk_score >= 0.8 ? CRITICAL :
                  path.risk_score >= 0.6 ? HIGH :
                  path.risk_score >= 0.4 ? MEDIUM : LOW
        
        vuln_class = sink_to_vulnclass(path.sink_type)
        
        finding = Finding(
            generate_finding_id(),
            vuln_class,
            severity,
            path.risk_score,
            "Exploitable taint path: $(path.sink_type)",
            path.exploit_description,
            filepath,
            path.source_line,
            path.sink_line,
            1,
            extract_snippet(code, path.source_line, path.sink_line),
            sink_to_cwe(path.sink_type),
            "Sanitize input before passing to $(path.sink_type) sink.",
            String[],
            ["taint", "exploitable"],
            0.1,
            now()
        )
        push!(findings, finding)
    end
    
    return findings
end

"""
Pattern matching pass.
"""
function analyze_patterns(scanner::Scanner, filepath::String,
                         code::String, language::String)::Vector{Finding}
    findings = Finding[]
    
    matches = match_patterns(scanner.pattern_matcher, scanner.pattern_db, 
                            code, language)
    
    for match in matches
        if match.is_false_positive
            continue
        end
        
        severity = match.pattern.severity == "critical" ? CRITICAL :
                  match.pattern.severity == "high" ? HIGH :
                  match.pattern.severity == "medium" ? MEDIUM : LOW
        
        finding = Finding(
            generate_finding_id(),
            match.pattern.vuln_class,
            severity,
            match.confidence,
            match.pattern.name,
            match.pattern.description,
            filepath,
            match.line,
            match.line,
            1,
            match.matched_code,
            match.pattern.cwe_id,
            match.pattern.remediation,
            match.pattern.references,
            match.pattern.tags,
            0.1,
            now()
        )
        push!(findings, finding)
    end
    
    return findings
end

"""
ML prediction pass.
"""
function analyze_ml(scanner::Scanner, filepath::String,
                   code::String, language::String)::Vector{Finding}
    findings = Finding[]
    
    # Extract features
    features = extract_features(scanner.static_analyzer, code, language)
    
    # Get predictions
    predictions = predict(scanner.predictor, features)
    
    for (vuln_class, prob) in predictions
        if prob >= 0.6
            severity = prob >= 0.9 ? CRITICAL :
                      prob >= 0.8 ? HIGH :
                      prob >= 0.7 ? MEDIUM : LOW
            
            finding = Finding(
                generate_finding_id(),
                vuln_class,
                severity,
                prob,
                "ML-predicted vulnerability: $(vuln_class)",
                "Machine learning model predicts this code may contain a $(vuln_class) vulnerability with $(round(prob * 100))% confidence.",
                filepath,
                1, 1, 1,
                "",
                vulnclass_to_cwe(vuln_class),
                "Review code for $(vuln_class) vulnerabilities.",
                String[],
                ["ml-predicted"],
                0.2,
                now()
            )
            push!(findings, finding)
        end
    end
    
    return findings
end

"""
Anomaly detection pass.
"""
function analyze_anomaly(scanner::Scanner, filepath::String,
                        code::String, language::String)::Vector{Finding}
    findings = Finding[]
    
    if !scanner.anomaly_detector.trained
        return findings
    end
    
    # Extract features
    features = extract_features(scanner.static_analyzer, code, language)
    feature_vec = features_to_vector(features)
    
    # Check for anomaly
    score = anomaly_score(scanner.anomaly_detector, feature_vec)
    
    if score >= scanner.anomaly_detector.threshold
        finding = Finding(
            generate_finding_id(),
            CODE_EXECUTION,  # Unknown vulnerability type
            score >= 0.8 ? HIGH : MEDIUM,
            score,
            "Anomalous code pattern detected",
            "This code exhibits unusual patterns that deviate significantly from normal code. This may indicate a zero-day vulnerability or novel attack pattern.",
            filepath,
            1, 1, 1,
            "",
            nothing,
            "Review code carefully for security issues.",
            String[],
            ["anomaly", "zero-day-candidate"],
            0.3,
            now()
        )
        push!(findings, finding)
    end
    
    return findings
end

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

"""
Generate unique finding ID.
"""
function generate_finding_id()::String
    return string(uuid4())
end

"""
Convert string to VulnClass.
"""
function string_to_vulnclass(s::String)::VulnClass
    mapping = Dict(
        "injection" => INJECTION,
        "buffer_overflow" => BUFFER_OVERFLOW,
        "xss" => XSS,
        "sql_injection" => INJECTION,
        "command_injection" => CODE_EXECUTION,
        "path_traversal" => PATH_TRAVERSAL,
        "deserialization" => DESERIALIZATION,
        "authentication" => AUTHENTICATION_BYPASS,
        "crypto" => CRYPTO_WEAKNESS,
        "ssrf" => SSRF
    )
    return get(mapping, lowercase(s), INJECTION)
end

"""
Convert sink type to VulnClass.
"""
function sink_to_vulnclass(sink::String)::VulnClass
    mapping = Dict(
        "sql" => INJECTION,
        "command" => CODE_EXECUTION,
        "xss" => XSS,
        "file" => PATH_TRAVERSAL,
        "code" => CODE_EXECUTION,
        "ldap" => INJECTION,
        "xpath" => INJECTION
    )
    return get(mapping, lowercase(sink), INJECTION)
end

"""
Convert sink type to CWE.
"""
function sink_to_cwe(sink::String)::String
    mapping = Dict(
        "sql" => "CWE-89",
        "command" => "CWE-78",
        "xss" => "CWE-79",
        "file" => "CWE-22",
        "code" => "CWE-94",
        "ldap" => "CWE-90",
        "xpath" => "CWE-643"
    )
    return get(mapping, lowercase(sink), "CWE-20")
end

"""
Convert VulnClass to CWE.
"""
function vulnclass_to_cwe(vc::VulnClass)::String
    mapping = Dict(
        INJECTION => "CWE-89",
        BUFFER_OVERFLOW => "CWE-120",
        USE_AFTER_FREE => "CWE-416",
        RACE_CONDITION => "CWE-362",
        AUTHENTICATION_BYPASS => "CWE-287",
        CRYPTO_WEAKNESS => "CWE-327",
        PRIVILEGE_ESCALATION => "CWE-269",
        INFORMATION_DISCLOSURE => "CWE-200",
        DENIAL_OF_SERVICE => "CWE-400",
        CODE_EXECUTION => "CWE-94",
        XSS => "CWE-79",
        SSRF => "CWE-918",
        DESERIALIZATION => "CWE-502",
        PATH_TRAVERSAL => "CWE-22",
        TYPE_CONFUSION => "CWE-843"
    )
    return get(mapping, vc, "CWE-20")
end
