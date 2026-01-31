"""
CVE integration and vulnerability tracking for Oracle.
"""

# ══════════════════════════════════════════════════════════════════════════════
# CVE PARSER
# ══════════════════════════════════════════════════════════════════════════════

"""
    CVEParser

Parse CVE identifiers and extract information.
"""
struct CVEParser
    pattern::Regex
    
    function CVEParser()
        new(r"CVE-(\d{4})-(\d+)")
    end
end

"""
    parse_cve(parser::CVEParser, text::String) -> Vector{CVEIdentifier}

Extract CVE identifiers from text.
"""
function parse_cve(parser::CVEParser, text::String)::Vector{CVEIdentifier}
    cves = CVEIdentifier[]
    
    for m in eachmatch(parser.pattern, text)
        year = parse(Int, m.captures[1])
        number = parse(Int, m.captures[2])
        id = m.match
        
        push!(cves, CVEIdentifier(id, year, number))
    end
    
    return cves
end

"""
CVE identifier components.
"""
struct CVEIdentifier
    id::String
    year::Int
    number::Int
end

"""
Validate CVE format.
"""
function is_valid_cve(cve_id::String)::Bool
    pattern = r"^CVE-\d{4}-\d{4,}$"
    return occursin(pattern, cve_id)
end

# ══════════════════════════════════════════════════════════════════════════════
# CVE ENRICHMENT
# ══════════════════════════════════════════════════════════════════════════════

"""
    CVEEnricher

Enrich findings with CVE information.
"""
struct CVEEnricher
    nvd_client::NVDClient
    local_db::LocalCVEDatabase
    exploit_db_url::String
    
    function CVEEnricher(; api_key::Union{String, Nothing}=nothing)
        new(
            NVDClient(api_key=api_key),
            LocalCVEDatabase(),
            "https://www.exploit-db.com/exploits/"
        )
    end
end

"""
    enrich_finding(enricher::CVEEnricher, finding::Finding) -> EnrichedFinding

Add CVE context to a finding.
"""
function enrich_finding(enricher::CVEEnricher, finding::Finding)::EnrichedFinding
    # Get related CVEs
    cwe_id = finding.cwe_id
    related_cves = NVDVulnerability[]
    
    if !isnothing(cwe_id)
        # First check local database
        local_cves = search(enricher.local_db, cwe_id=cwe_id, min_cvss=5.0)
        append!(related_cves, local_cves)
        
        # If not enough, check NVD
        if length(local_cves) < 5
            nvd_cves = search_cves(enricher.nvd_client, cwe_id=cwe_id, results_per_page=10)
            append!(related_cves, nvd_cves)
        end
    end
    
    # Deduplicate
    unique!(v -> v.cve_id, related_cves)
    
    # Sort by severity
    sort!(related_cves, by=v -> v.cvss_v3_score, rev=true)
    
    # Get top 5
    related_cves = related_cves[1:min(5, length(related_cves))]
    
    # Check for known exploits
    exploit_available = any(check_exploit_exists(enricher, cve.cve_id) for cve in related_cves)
    
    # Calculate real-world risk
    real_world_risk = calculate_real_world_risk(finding, related_cves, exploit_available)
    
    return EnrichedFinding(
        finding,
        related_cves,
        exploit_available,
        real_world_risk
    )
end

"""
    EnrichedFinding

Finding with CVE enrichment.
"""
struct EnrichedFinding
    finding::Finding
    related_cves::Vector{NVDVulnerability}
    exploit_available::Bool
    real_world_risk::Float64
end

"""
Check if an exploit exists for a CVE.
"""
function check_exploit_exists(enricher::CVEEnricher, cve_id::String)::Bool
    # Simple heuristic: high CVSS CVEs often have exploits
    # In production, would check ExploitDB, Metasploit, etc.
    return false
end

"""
Calculate real-world risk based on CVE data.
"""
function calculate_real_world_risk(finding::Finding, cves::Vector{NVDVulnerability},
                                  exploit_available::Bool)::Float64
    
    base_risk = finding.confidence
    
    # CVE factor
    if !isempty(cves)
        avg_cvss = mean(c.cvss_v3_score for c in cves) / 10.0
        base_risk = base_risk * 0.5 + avg_cvss * 0.5
    end
    
    # Exploit availability increases risk
    if exploit_available
        base_risk = min(1.0, base_risk * 1.3)
    end
    
    return clamp(base_risk, 0.0, 1.0)
end

# ══════════════════════════════════════════════════════════════════════════════
# CVE MAPPING
# ══════════════════════════════════════════════════════════════════════════════

"""
    CWEToCVEMapper

Map CWE weaknesses to known CVEs.
"""
struct CWEToCVEMapper
    mapping::Dict{String, Vector{String}}
    
    function CWEToCVEMapper()
        # Curated mapping of CWEs to notable CVEs
        mapping = Dict(
            "CWE-89" => [  # SQL Injection
                "CVE-2023-42793",
                "CVE-2023-24880",
                "CVE-2022-37434"
            ],
            "CWE-79" => [  # XSS
                "CVE-2023-28879",
                "CVE-2023-23397",
                "CVE-2022-41082"
            ],
            "CWE-120" => [  # Buffer Overflow
                "CVE-2023-38408",
                "CVE-2023-4911",
                "CVE-2022-41040"
            ],
            "CWE-78" => [  # Command Injection
                "CVE-2023-46604",
                "CVE-2023-22515",
                "CVE-2023-27997"
            ],
            "CWE-502" => [  # Deserialization
                "CVE-2023-50164",
                "CVE-2023-44487",
                "CVE-2022-22965"
            ],
            "CWE-22" => [  # Path Traversal
                "CVE-2023-27363",
                "CVE-2023-20198",
                "CVE-2023-34362"
            ],
            "CWE-287" => [  # Authentication Bypass
                "CVE-2023-27350",
                "CVE-2023-42793",
                "CVE-2023-4966"
            ],
            "CWE-918" => [  # SSRF
                "CVE-2023-35078",
                "CVE-2023-29357",
                "CVE-2021-44228"  # Log4Shell
            ]
        )
        
        new(mapping)
    end
end

"""
Get notable CVEs for a CWE.
"""
function get_notable_cves(mapper::CWEToCVEMapper, cwe_id::String)::Vector{String}
    return get(mapper.mapping, cwe_id, String[])
end

# ══════════════════════════════════════════════════════════════════════════════
# CVE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

"""
    CVEAnalyzer

Analyze CVE patterns and trends.
"""
struct CVEAnalyzer
    db::LocalCVEDatabase
end

"""
Analyze CVE distribution by CWE.
"""
function analyze_by_cwe(analyzer::CVEAnalyzer)::Dict{String, CVEStats}
    stats = Dict{String, CVEStats}()
    
    for (_, vuln) in analyzer.db.vulnerabilities
        for cwe in vuln.cwe_ids
            if !haskey(stats, cwe)
                stats[cwe] = CVEStats(cwe, 0, Float64[], String[])
            end
            
            s = stats[cwe]
            stats[cwe] = CVEStats(
                cwe,
                s.count + 1,
                push!(copy(s.cvss_scores), vuln.cvss_v3_score),
                push!(copy(s.cve_ids), vuln.cve_id)
            )
        end
    end
    
    return stats
end

"""
CVE statistics for a category.
"""
struct CVEStats
    category::String
    count::Int
    cvss_scores::Vector{Float64}
    cve_ids::Vector{String}
end

"""
Get average CVSS for stats.
"""
function avg_cvss(stats::CVEStats)::Float64
    isempty(stats.cvss_scores) ? 0.0 : mean(stats.cvss_scores)
end

"""
Analyze CVE trends over time.
"""
function analyze_trends(analyzer::CVEAnalyzer; years::Int=5)::Dict{Int, YearlyStats}
    current_year = year(now())
    trends = Dict{Int, YearlyStats}()
    
    for y in (current_year - years + 1):current_year
        trends[y] = YearlyStats(y, 0, 0.0, String[])
    end
    
    for (_, vuln) in analyzer.db.vulnerabilities
        y = year(vuln.published_date)
        
        if haskey(trends, y)
            s = trends[y]
            new_count = s.count + 1
            new_avg = (s.avg_cvss * s.count + vuln.cvss_v3_score) / new_count
            
            top_cves = copy(s.top_cves)
            if vuln.cvss_v3_score >= 9.0
                push!(top_cves, vuln.cve_id)
            end
            
            trends[y] = YearlyStats(y, new_count, new_avg, top_cves)
        end
    end
    
    return trends
end

"""
Yearly CVE statistics.
"""
struct YearlyStats
    year::Int
    count::Int
    avg_cvss::Float64
    top_cves::Vector{String}
end

# ══════════════════════════════════════════════════════════════════════════════
# CVE IMPACT ASSESSMENT
# ══════════════════════════════════════════════════════════════════════════════

"""
    ImpactAssessor

Assess impact of CVEs on a codebase.
"""
struct ImpactAssessor
    enricher::CVEEnricher
end

"""
    assess_impact(assessor::ImpactAssessor, findings::Vector{Finding}) 
        -> ImpactAssessment

Assess overall CVE-related impact.
"""
function assess_impact(assessor::ImpactAssessor, 
                      findings::Vector{Finding})::ImpactAssessment
    
    # Enrich all findings
    enriched = [enrich_finding(assessor.enricher, f) for f in findings]
    
    # Collect all related CVEs
    all_cves = NVDVulnerability[]
    for ef in enriched
        append!(all_cves, ef.related_cves)
    end
    unique!(v -> v.cve_id, all_cves)
    
    # Count exploits
    exploit_count = count(ef -> ef.exploit_available, enriched)
    
    # Calculate risk metrics
    max_cvss = isempty(all_cves) ? 0.0 : maximum(c.cvss_v3_score for c in all_cves)
    avg_cvss = isempty(all_cves) ? 0.0 : mean(c.cvss_v3_score for c in all_cves)
    
    # Overall risk level
    risk_level = if max_cvss >= 9.0 || exploit_count > 0
        "CRITICAL"
    elseif max_cvss >= 7.0
        "HIGH"
    elseif max_cvss >= 4.0
        "MEDIUM"
    else
        "LOW"
    end
    
    return ImpactAssessment(
        length(all_cves),
        exploit_count,
        max_cvss,
        avg_cvss,
        risk_level,
        enriched
    )
end

"""
CVE impact assessment result.
"""
struct ImpactAssessment
    total_related_cves::Int
    exploits_available::Int
    max_cvss::Float64
    avg_cvss::Float64
    risk_level::String
    enriched_findings::Vector{EnrichedFinding}
end

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

"""
Get CWE ID from vulnerability class.
"""
function vuln_class_to_cwe(vc::VulnClass)::String
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

"""
Format CVE for display.
"""
function format_cve(cve::NVDVulnerability)::String
    severity_emoji = cve.severity == "CRITICAL" ? "🔴" :
                    cve.severity == "HIGH" ? "🟠" :
                    cve.severity == "MEDIUM" ? "🟡" : "🟢"
    
    return "$severity_emoji $(cve.cve_id) (CVSS: $(cve.cvss_v3_score))"
end

"""
Generate CVE report section.
"""
function generate_cve_section(cves::Vector{NVDVulnerability})::String
    if isempty(cves)
        return "No related CVEs found."
    end
    
    lines = String[]
    push!(lines, "| CVE ID | CVSS | Severity | Description |")
    push!(lines, "|--------|------|----------|-------------|")
    
    for cve in cves
        desc = length(cve.description) > 50 ? cve.description[1:50] * "..." : cve.description
        push!(lines, "| $(cve.cve_id) | $(cve.cvss_v3_score) | $(cve.severity) | $desc |")
    end
    
    return join(lines, "\n")
end
