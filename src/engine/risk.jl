"""
Risk calculation and prioritization for Oracle findings.
"""

# ══════════════════════════════════════════════════════════════════════════════
# RISK MODELS
# ══════════════════════════════════════════════════════════════════════════════

"""
    RiskCalculator

Calculates risk scores based on multiple factors.
"""
struct RiskCalculator
    severity_weights::Dict{Severity, Float64}
    vuln_class_weights::Dict{VulnClass, Float64}
    confidence_factor::Float64
    exploitability_factor::Float64
    
    function RiskCalculator()
        severity_weights = Dict(
            CRITICAL => 1.0,
            HIGH => 0.8,
            MEDIUM => 0.5,
            LOW => 0.2,
            INFO => 0.05
        )
        
        vuln_class_weights = Dict(
            CODE_EXECUTION => 1.0,
            INJECTION => 0.95,
            BUFFER_OVERFLOW => 0.95,
            USE_AFTER_FREE => 0.9,
            AUTHENTICATION_BYPASS => 0.9,
            PRIVILEGE_ESCALATION => 0.85,
            DESERIALIZATION => 0.85,
            PATH_TRAVERSAL => 0.8,
            XSS => 0.75,
            SSRF => 0.75,
            CRYPTO_WEAKNESS => 0.7,
            RACE_CONDITION => 0.7,
            INFORMATION_DISCLOSURE => 0.5,
            DENIAL_OF_SERVICE => 0.4,
            TYPE_CONFUSION => 0.6
        )
        
        new(severity_weights, vuln_class_weights, 0.3, 0.2)
    end
end

"""
    calculate_risk(calc::RiskCalculator, finding::Finding) -> Float64

Calculate risk score for a finding.
"""
function calculate_risk(calc::RiskCalculator, finding::Finding)::Float64
    # Base severity score
    severity_score = get(calc.severity_weights, finding.severity, 0.5)
    
    # Vulnerability class weight
    vuln_weight = get(calc.vuln_class_weights, finding.vuln_class, 0.5)
    
    # Confidence adjustment
    confidence_adj = 1.0 - calc.confidence_factor * (1.0 - finding.confidence)
    
    # False positive adjustment
    fp_adj = 1.0 - finding.false_positive_likelihood
    
    # Combined risk score
    risk = severity_score * vuln_weight * confidence_adj * fp_adj
    
    return clamp(risk, 0.0, 1.0)
end

"""
    calculate_cvss(finding::Finding) -> CVSSScore

Calculate CVSS-like score for a finding.
"""
function calculate_cvss(finding::Finding)::CVSSScore
    # Attack Vector (Network, Adjacent, Local, Physical)
    av = 0.85  # Assume network by default
    
    # Attack Complexity
    ac = finding.vuln_class in [RACE_CONDITION, USE_AFTER_FREE] ? 0.44 : 0.77
    
    # Privileges Required
    pr = finding.vuln_class == AUTHENTICATION_BYPASS ? 0.85 : 0.62
    
    # User Interaction
    ui = finding.vuln_class in [XSS, DESERIALIZATION] ? 0.62 : 0.85
    
    # Scope
    scope_changed = finding.vuln_class in [CODE_EXECUTION, PRIVILEGE_ESCALATION]
    
    # Impact scores
    confidentiality = impact_for_class(finding.vuln_class, :confidentiality)
    integrity = impact_for_class(finding.vuln_class, :integrity)
    availability = impact_for_class(finding.vuln_class, :availability)
    
    # Calculate exploitability
    exploitability = 8.22 * av * ac * pr * ui
    
    # Calculate impact
    isc_base = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
    impact = scope_changed ? 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02)^15 :
                            6.42 * isc_base
    
    # Calculate base score
    if impact <= 0
        base = 0.0
    elseif scope_changed
        base = min(1.08 * (impact + exploitability), 10.0)
    else
        base = min(impact + exploitability, 10.0)
    end
    
    # Round up
    base = ceil(base * 10) / 10
    
    return CVSSScore(
        base,
        exploitability,
        impact,
        av, ac, pr, ui,
        confidentiality, integrity, availability
    )
end

"""
Impact score for vulnerability class.
"""
function impact_for_class(vc::VulnClass, dimension::Symbol)::Float64
    impacts = Dict(
        CODE_EXECUTION => (0.56, 0.56, 0.56),
        INJECTION => (0.56, 0.56, 0.22),
        BUFFER_OVERFLOW => (0.56, 0.56, 0.56),
        USE_AFTER_FREE => (0.56, 0.56, 0.56),
        AUTHENTICATION_BYPASS => (0.56, 0.56, 0.0),
        PRIVILEGE_ESCALATION => (0.56, 0.56, 0.0),
        DESERIALIZATION => (0.56, 0.56, 0.22),
        PATH_TRAVERSAL => (0.56, 0.22, 0.0),
        XSS => (0.22, 0.22, 0.0),
        SSRF => (0.22, 0.22, 0.22),
        CRYPTO_WEAKNESS => (0.56, 0.0, 0.0),
        RACE_CONDITION => (0.22, 0.22, 0.22),
        INFORMATION_DISCLOSURE => (0.56, 0.0, 0.0),
        DENIAL_OF_SERVICE => (0.0, 0.0, 0.56),
        TYPE_CONFUSION => (0.22, 0.22, 0.22)
    )
    
    c, i, a = get(impacts, vc, (0.22, 0.22, 0.22))
    
    return dimension == :confidentiality ? c :
           dimension == :integrity ? i : a
end

"""
CVSS score components.
"""
struct CVSSScore
    base::Float64
    exploitability::Float64
    impact::Float64
    attack_vector::Float64
    attack_complexity::Float64
    privileges_required::Float64
    user_interaction::Float64
    confidentiality::Float64
    integrity::Float64
    availability::Float64
end

"""
Convert CVSS base score to severity.
"""
function cvss_to_severity(score::Float64)::Severity
    if score >= 9.0
        return CRITICAL
    elseif score >= 7.0
        return HIGH
    elseif score >= 4.0
        return MEDIUM
    elseif score >= 0.1
        return LOW
    else
        return INFO
    end
end

# ══════════════════════════════════════════════════════════════════════════════
# PRIORITIZATION
# ══════════════════════════════════════════════════════════════════════════════

"""
    RiskPrioritizer

Prioritizes findings based on risk and business context.
"""
struct RiskPrioritizer
    calculator::RiskCalculator
    context_weights::Dict{String, Float64}
    
    function RiskPrioritizer(; context_weights::Dict{String, Float64}=Dict{String, Float64}())
        new(RiskCalculator(), context_weights)
    end
end

"""
    prioritize(prioritizer::RiskPrioritizer, findings::Vector{Finding}) 
        -> Vector{PrioritizedFinding}

Prioritize findings by risk.
"""
function prioritize(prioritizer::RiskPrioritizer, 
                   findings::Vector{Finding})::Vector{PrioritizedFinding}
    
    prioritized = PrioritizedFinding[]
    
    for finding in findings
        risk = calculate_risk(prioritizer.calculator, finding)
        cvss = calculate_cvss(finding)
        
        # Context adjustments
        context_multiplier = 1.0
        for (context, weight) in prioritizer.context_weights
            if context in finding.tags
                context_multiplier *= weight
            end
        end
        
        adjusted_risk = clamp(risk * context_multiplier, 0.0, 1.0)
        
        pf = PrioritizedFinding(
            finding,
            adjusted_risk,
            cvss,
            risk_to_priority(adjusted_risk),
            estimate_remediation_effort(finding)
        )
        
        push!(prioritized, pf)
    end
    
    # Sort by priority (higher risk first)
    sort!(prioritized, by=f -> f.risk_score, rev=true)
    
    return prioritized
end

"""
    PrioritizedFinding

Finding with priority metadata.
"""
struct PrioritizedFinding
    finding::Finding
    risk_score::Float64
    cvss::CVSSScore
    priority::Int
    remediation_effort::String
end

"""
Convert risk score to priority level (1 = highest).
"""
function risk_to_priority(risk::Float64)::Int
    if risk >= 0.9
        return 1
    elseif risk >= 0.7
        return 2
    elseif risk >= 0.5
        return 3
    elseif risk >= 0.3
        return 4
    else
        return 5
    end
end

"""
Estimate remediation effort.
"""
function estimate_remediation_effort(finding::Finding)::String
    # Simple heuristic based on vulnerability type
    high_effort = [USE_AFTER_FREE, RACE_CONDITION, TYPE_CONFUSION, BUFFER_OVERFLOW]
    medium_effort = [CODE_EXECUTION, DESERIALIZATION, AUTHENTICATION_BYPASS]
    
    if finding.vuln_class in high_effort
        return "High (days)"
    elseif finding.vuln_class in medium_effort
        return "Medium (hours)"
    else
        return "Low (minutes)"
    end
end

# ══════════════════════════════════════════════════════════════════════════════
# AGGREGATION
# ══════════════════════════════════════════════════════════════════════════════

"""
    RiskAggregator

Aggregates risk across multiple findings.
"""
struct RiskAggregator
    calculator::RiskCalculator
end

"""
    aggregate_risk(aggregator::RiskAggregator, findings::Vector{Finding}) -> AggregateRisk

Calculate aggregate risk for a codebase.
"""
function aggregate_risk(aggregator::RiskAggregator, 
                       findings::Vector{Finding})::AggregateRisk
    if isempty(findings)
        return AggregateRisk(0.0, "LOW", Dict(), Dict())
    end
    
    # Calculate individual risks
    risks = [calculate_risk(aggregator.calculator, f) for f in findings]
    
    # Overall risk (not just average - high risks dominate)
    max_risk = maximum(risks)
    avg_risk = mean(risks)
    overall = 0.7 * max_risk + 0.3 * avg_risk
    
    # Risk by category
    by_severity = Dict{Severity, Float64}()
    for (f, r) in zip(findings, risks)
        by_severity[f.severity] = max(get(by_severity, f.severity, 0.0), r)
    end
    
    by_class = Dict{VulnClass, Float64}()
    for (f, r) in zip(findings, risks)
        by_class[f.vuln_class] = max(get(by_class, f.vuln_class, 0.0), r)
    end
    
    # Risk level
    level = overall >= 0.9 ? "CRITICAL" :
           overall >= 0.7 ? "HIGH" :
           overall >= 0.5 ? "MEDIUM" :
           overall >= 0.2 ? "LOW" : "MINIMAL"
    
    return AggregateRisk(overall, level, by_severity, by_class)
end

"""
Aggregate risk information.
"""
struct AggregateRisk
    overall_risk::Float64
    risk_level::String
    risk_by_severity::Dict{Severity, Float64}
    risk_by_class::Dict{VulnClass, Float64}
end

# ══════════════════════════════════════════════════════════════════════════════
# TREND ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

"""
    RiskTrendAnalyzer

Analyzes risk trends over time.
"""
mutable struct RiskTrendAnalyzer
    history::Vector{Tuple{DateTime, Float64}}
    window_size::Int
    
    function RiskTrendAnalyzer(; window_size::Int=30)
        new(Tuple{DateTime, Float64}[], window_size)
    end
end

"""
Record a risk measurement.
"""
function record_risk!(analyzer::RiskTrendAnalyzer, risk::Float64)
    push!(analyzer.history, (now(), risk))
    
    # Keep only window_size entries
    if length(analyzer.history) > analyzer.window_size
        popfirst!(analyzer.history)
    end
end

"""
Analyze trend direction.
"""
function analyze_trend(analyzer::RiskTrendAnalyzer)::RiskTrend
    n = length(analyzer.history)
    
    if n < 2
        return RiskTrend("STABLE", 0.0, Float64[])
    end
    
    risks = [r for (_, r) in analyzer.history]
    
    # Simple linear regression
    x = collect(1:n)
    x_mean = mean(x)
    y_mean = mean(risks)
    
    slope = sum((x .- x_mean) .* (risks .- y_mean)) / sum((x .- x_mean).^2)
    
    direction = if slope > 0.01
        "INCREASING"
    elseif slope < -0.01
        "DECREASING"
    else
        "STABLE"
    end
    
    return RiskTrend(direction, slope, risks)
end

"""
Risk trend information.
"""
struct RiskTrend
    direction::String
    slope::Float64
    history::Vector{Float64}
end

# ══════════════════════════════════════════════════════════════════════════════
# REMEDIATION RECOMMENDATIONS
# ══════════════════════════════════════════════════════════════════════════════

"""
Generate remediation recommendations based on prioritized findings.
"""
function generate_recommendations(findings::Vector{PrioritizedFinding})::Vector{Recommendation}
    recommendations = Recommendation[]
    
    # Group by vulnerability class
    by_class = Dict{VulnClass, Vector{PrioritizedFinding}}()
    for pf in findings
        class = pf.finding.vuln_class
        if !haskey(by_class, class)
            by_class[class] = PrioritizedFinding[]
        end
        push!(by_class[class], pf)
    end
    
    # Generate recommendations per class
    for (vc, class_findings) in by_class
        count = length(class_findings)
        max_risk = maximum(f.risk_score for f in class_findings)
        
        priority = max_risk >= 0.8 ? "IMMEDIATE" :
                  max_risk >= 0.6 ? "HIGH" :
                  max_risk >= 0.4 ? "MEDIUM" : "LOW"
        
        rec = Recommendation(
            vc,
            count,
            priority,
            get_remediation_steps(vc),
            get_secure_coding_guidelines(vc),
            get_tools_for_vuln(vc)
        )
        
        push!(recommendations, rec)
    end
    
    # Sort by priority
    priority_order = Dict("IMMEDIATE" => 1, "HIGH" => 2, "MEDIUM" => 3, "LOW" => 4)
    sort!(recommendations, by=r -> priority_order[r.priority])
    
    return recommendations
end

"""
Remediation recommendation.
"""
struct Recommendation
    vuln_class::VulnClass
    finding_count::Int
    priority::String
    remediation_steps::Vector{String}
    secure_coding_guidelines::Vector{String}
    recommended_tools::Vector{String}
end

"""
Get remediation steps for vulnerability class.
"""
function get_remediation_steps(vc::VulnClass)::Vector{String}
    steps = Dict(
        INJECTION => [
            "Use parameterized queries or prepared statements",
            "Implement strict input validation",
            "Apply principle of least privilege to database accounts",
            "Use stored procedures where possible"
        ],
        XSS => [
            "Encode all output data",
            "Use Content Security Policy (CSP) headers",
            "Validate and sanitize all user input",
            "Use modern frameworks with automatic escaping"
        ],
        BUFFER_OVERFLOW => [
            "Use safe string functions (strncpy, snprintf)",
            "Enable compiler protections (ASLR, stack canaries)",
            "Perform bounds checking on all array accesses",
            "Consider using memory-safe languages"
        ],
        CODE_EXECUTION => [
            "Never pass user input to system commands",
            "Use whitelists for allowed operations",
            "Implement strict input validation",
            "Use sandboxing and containerization"
        ],
        AUTHENTICATION_BYPASS => [
            "Implement multi-factor authentication",
            "Use secure session management",
            "Implement account lockout policies",
            "Audit all authentication paths"
        ]
    )
    
    return get(steps, vc, ["Review and fix identified vulnerabilities"])
end

"""
Get secure coding guidelines for vulnerability class.
"""
function get_secure_coding_guidelines(vc::VulnClass)::Vector{String}
    guidelines = Dict(
        INJECTION => [
            "OWASP SQL Injection Prevention Cheat Sheet",
            "CWE-89: Improper Neutralization of Special Elements"
        ],
        XSS => [
            "OWASP XSS Prevention Cheat Sheet",
            "CWE-79: Improper Neutralization of Input During Web Page Generation"
        ],
        BUFFER_OVERFLOW => [
            "SEI CERT C Coding Standard",
            "CWE-120: Buffer Copy without Checking Size of Input"
        ]
    )
    
    return get(guidelines, vc, ["OWASP Secure Coding Practices"])
end

"""
Get recommended tools for vulnerability class.
"""
function get_tools_for_vuln(vc::VulnClass)::Vector{String}
    tools = Dict(
        INJECTION => ["SQLMap", "Burp Suite", "OWASP ZAP"],
        XSS => ["DOMPurify", "CSP Evaluator", "XSS Hunter"],
        BUFFER_OVERFLOW => ["AddressSanitizer", "Valgrind", "AFL++"],
        CODE_EXECUTION => ["AppArmor", "SELinux", "Seccomp"]
    )
    
    return get(tools, vc, ["Static Analysis Tools"])
end
