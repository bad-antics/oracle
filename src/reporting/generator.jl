"""
Report generation for Oracle scan results.
Supports HTML, JSON, SARIF, and Markdown formats.
"""

# ══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

"""
    ReportGenerator

Generates vulnerability reports in various formats.
"""
struct ReportGenerator
    template_dir::String
    output_dir::String
    
    function ReportGenerator(; output_dir::String="./reports")
        mkpath(output_dir)
        new(joinpath(@__DIR__, "..", "..", "templates"), output_dir)
    end
end

"""
    generate_report(gen::ReportGenerator, result::ScanResult; 
                   format::String="html") -> String

Generate a report from scan results.
"""
function generate_report(gen::ReportGenerator, result::ScanResult;
                        format::String="html", 
                        target::String="unknown",
                        output_file::Union{String, Nothing}=nothing)::String
    
    if format == "html"
        return generate_html_report(gen, result, target, output_file)
    elseif format == "json"
        return generate_json_report(gen, result, target, output_file)
    elseif format == "sarif"
        return generate_sarif_report(gen, result, target, output_file)
    elseif format == "markdown" || format == "md"
        return generate_markdown_report(gen, result, target, output_file)
    else
        error("Unsupported format: $format")
    end
end

# ══════════════════════════════════════════════════════════════════════════════
# HTML REPORT
# ══════════════════════════════════════════════════════════════════════════════

"""
Generate HTML report.
"""
function generate_html_report(gen::ReportGenerator, result::ScanResult,
                             target::String, output_file::Union{String, Nothing})::String
    
    timestamp = Dates.format(now(), "yyyy-mm-dd HH:MM:SS")
    
    # Count by severity
    critical = count(f -> f.severity == CRITICAL, result.findings)
    high = count(f -> f.severity == HIGH, result.findings)
    medium = count(f -> f.severity == MEDIUM, result.findings)
    low = count(f -> f.severity == LOW, result.findings)
    info = count(f -> f.severity == INFO, result.findings)
    
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Oracle Security Scan Report</title>
        <style>
            :root {
                --critical: #ff4444;
                --high: #ff8800;
                --medium: #ffcc00;
                --low: #88cc00;
                --info: #4488ff;
                --bg: #0d1117;
                --surface: #161b22;
                --text: #c9d1d9;
                --border: #30363d;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: var(--bg);
                color: var(--text);
                line-height: 1.6;
            }
            .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
            header {
                background: linear-gradient(135deg, #6e00ff, #00d4ff);
                padding: 2rem;
                margin-bottom: 2rem;
                border-radius: 8px;
            }
            header h1 { font-size: 2rem; margin-bottom: 0.5rem; color: white; }
            header p { color: rgba(255,255,255,0.8); }
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 1rem;
                margin-bottom: 2rem;
            }
            .stat-card {
                background: var(--surface);
                padding: 1.5rem;
                border-radius: 8px;
                border: 1px solid var(--border);
                text-align: center;
            }
            .stat-card .value { font-size: 2.5rem; font-weight: bold; }
            .stat-card .label { color: #8b949e; text-transform: uppercase; font-size: 0.75rem; }
            .stat-card.critical .value { color: var(--critical); }
            .stat-card.high .value { color: var(--high); }
            .stat-card.medium .value { color: var(--medium); }
            .stat-card.low .value { color: var(--low); }
            .stat-card.info .value { color: var(--info); }
            .findings { margin-top: 2rem; }
            .finding {
                background: var(--surface);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 1.5rem;
                margin-bottom: 1rem;
            }
            .finding-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1rem;
            }
            .finding-title { font-size: 1.1rem; font-weight: 600; }
            .severity-badge {
                padding: 0.25rem 0.75rem;
                border-radius: 20px;
                font-size: 0.75rem;
                font-weight: bold;
                text-transform: uppercase;
            }
            .severity-CRITICAL { background: var(--critical); color: white; }
            .severity-HIGH { background: var(--high); color: black; }
            .severity-MEDIUM { background: var(--medium); color: black; }
            .severity-LOW { background: var(--low); color: black; }
            .severity-INFO { background: var(--info); color: white; }
            .finding-meta { color: #8b949e; font-size: 0.875rem; margin-bottom: 0.75rem; }
            .finding-description { margin-bottom: 1rem; }
            .code-snippet {
                background: #0d1117;
                padding: 1rem;
                border-radius: 4px;
                font-family: 'Fira Code', monospace;
                font-size: 0.875rem;
                overflow-x: auto;
                margin-bottom: 1rem;
            }
            .remediation {
                background: rgba(0,255,128,0.1);
                border-left: 3px solid #00ff80;
                padding: 1rem;
                border-radius: 0 4px 4px 0;
            }
            .remediation-title { color: #00ff80; font-weight: 600; margin-bottom: 0.5rem; }
            footer {
                text-align: center;
                color: #8b949e;
                padding: 2rem 0;
                border-top: 1px solid var(--border);
                margin-top: 2rem;
            }
            .chart-container {
                background: var(--surface);
                border-radius: 8px;
                padding: 1.5rem;
                margin-bottom: 2rem;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🔮 Oracle Security Scan Report</h1>
                <p>Target: $target | Generated: $timestamp</p>
            </header>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="value">$(result.stats.files_scanned)</div>
                    <div class="label">Files Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="value">$(result.stats.total_lines)</div>
                    <div class="label">Lines of Code</div>
                </div>
                <div class="stat-card critical">
                    <div class="value">$critical</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="value">$high</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="value">$medium</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="value">$low</div>
                    <div class="label">Low</div>
                </div>
            </div>
            
            <div class="findings">
                <h2>Findings ($(length(result.findings)))</h2>
    """
    
    for finding in result.findings
        severity_class = "severity-$(finding.severity)"
        
        html *= """
                <div class="finding">
                    <div class="finding-header">
                        <span class="finding-title">$(finding.title)</span>
                        <span class="severity-badge $severity_class">$(finding.severity)</span>
                    </div>
                    <div class="finding-meta">
                        📁 $(finding.file_path):$(finding.line_start) | 
                        🏷️ $(finding.vuln_class) |
                        $(isnothing(finding.cwe_id) ? "" : "📋 $(finding.cwe_id) |")
                        📊 Confidence: $(round(finding.confidence * 100))%
                    </div>
                    <div class="finding-description">$(finding.description)</div>
        """
        
        if !isempty(finding.code_snippet)
            html *= """
                    <div class="code-snippet"><pre>$(escape_html(finding.code_snippet))</pre></div>
            """
        end
        
        html *= """
                    <div class="remediation">
                        <div class="remediation-title">💡 Remediation</div>
                        <p>$(finding.remediation)</p>
                    </div>
                </div>
        """
    end
    
    html *= """
            </div>
            
            <footer>
                <p>Generated by Oracle v$(ORACLE_VERSION) | AI-Powered Vulnerability Discovery</p>
            </footer>
        </div>
    </body>
    </html>
    """
    
    # Write to file
    if isnothing(output_file)
        output_file = joinpath(gen.output_dir, "oracle-report-$(Dates.format(now(), "yyyymmdd-HHMMSS")).html")
    end
    
    write(output_file, html)
    @info "HTML report generated" path=output_file
    
    return output_file
end

"""
Escape HTML special characters.
"""
function escape_html(s::String)::String
    s = replace(s, "&" => "&amp;")
    s = replace(s, "<" => "&lt;")
    s = replace(s, ">" => "&gt;")
    s = replace(s, "\"" => "&quot;")
    return s
end

# ══════════════════════════════════════════════════════════════════════════════
# JSON REPORT
# ══════════════════════════════════════════════════════════════════════════════

"""
Generate JSON report.
"""
function generate_json_report(gen::ReportGenerator, result::ScanResult,
                             target::String, output_file::Union{String, Nothing})::String
    
    report = Dict(
        "tool" => Dict(
            "name" => "Oracle",
            "version" => string(ORACLE_VERSION)
        ),
        "target" => target,
        "timestamp" => string(now()),
        "statistics" => Dict(
            "files_scanned" => result.stats.files_scanned,
            "files_skipped" => result.stats.files_skipped,
            "total_lines" => result.stats.total_lines,
            "total_findings" => result.stats.total_findings,
            "scan_duration_ms" => result.stats.scan_duration_ms,
            "findings_by_severity" => Dict(string(k) => v for (k, v) in result.stats.findings_by_severity),
            "findings_by_class" => Dict(string(k) => v for (k, v) in result.stats.findings_by_class)
        ),
        "findings" => [finding_to_dict(f) for f in result.findings],
        "errors" => result.stats.errors
    )
    
    json_str = JSON3.write(report)
    
    if isnothing(output_file)
        output_file = joinpath(gen.output_dir, "oracle-report-$(Dates.format(now(), "yyyymmdd-HHMMSS")).json")
    end
    
    write(output_file, json_str)
    @info "JSON report generated" path=output_file
    
    return output_file
end

"""
Convert finding to dictionary.
"""
function finding_to_dict(f::Finding)::Dict{String, Any}
    return Dict{String, Any}(
        "id" => f.id,
        "vuln_class" => string(f.vuln_class),
        "severity" => string(f.severity),
        "confidence" => f.confidence,
        "title" => f.title,
        "description" => f.description,
        "location" => Dict(
            "file" => f.file_path,
            "line_start" => f.line_start,
            "line_end" => f.line_end,
            "column" => f.column
        ),
        "code_snippet" => f.code_snippet,
        "cwe_id" => f.cwe_id,
        "remediation" => f.remediation,
        "references" => f.references,
        "tags" => f.tags,
        "false_positive_likelihood" => f.false_positive_likelihood,
        "timestamp" => string(f.timestamp)
    )
end

# ══════════════════════════════════════════════════════════════════════════════
# SARIF REPORT
# ══════════════════════════════════════════════════════════════════════════════

"""
Generate SARIF (Static Analysis Results Interchange Format) report.
"""
function generate_sarif_report(gen::ReportGenerator, result::ScanResult,
                              target::String, output_file::Union{String, Nothing})::String
    
    # SARIF 2.1.0 format
    sarif = Dict(
        "\$schema" => "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version" => "2.1.0",
        "runs" => [
            Dict(
                "tool" => Dict(
                    "driver" => Dict(
                        "name" => "Oracle",
                        "version" => string(ORACLE_VERSION),
                        "informationUri" => "https://github.com/yourusername/oracle",
                        "rules" => [generate_sarif_rule(vc) for vc in instances(VulnClass)]
                    )
                ),
                "results" => [finding_to_sarif(f) for f in result.findings],
                "invocations" => [
                    Dict(
                        "executionSuccessful" => true,
                        "endTimeUtc" => string(now())
                    )
                ]
            )
        ]
    )
    
    json_str = JSON3.write(sarif)
    
    if isnothing(output_file)
        output_file = joinpath(gen.output_dir, "oracle-report-$(Dates.format(now(), "yyyymmdd-HHMMSS")).sarif")
    end
    
    write(output_file, json_str)
    @info "SARIF report generated" path=output_file
    
    return output_file
end

"""
Generate SARIF rule definition.
"""
function generate_sarif_rule(vc::VulnClass)::Dict{String, Any}
    return Dict{String, Any}(
        "id" => string(vc),
        "name" => string(vc),
        "shortDescription" => Dict("text" => "$(vc) vulnerability detection"),
        "fullDescription" => Dict("text" => "Detects $(vc) vulnerabilities in source code"),
        "helpUri" => "https://cwe.mitre.org/",
        "defaultConfiguration" => Dict(
            "level" => vuln_class_to_sarif_level(vc)
        )
    )
end

"""
Convert vulnerability class to SARIF level.
"""
function vuln_class_to_sarif_level(vc::VulnClass)::String
    high_severity = [CODE_EXECUTION, INJECTION, BUFFER_OVERFLOW, USE_AFTER_FREE, 
                    AUTHENTICATION_BYPASS, DESERIALIZATION]
    medium_severity = [XSS, PATH_TRAVERSAL, SSRF, PRIVILEGE_ESCALATION, CRYPTO_WEAKNESS]
    
    if vc in high_severity
        return "error"
    elseif vc in medium_severity
        return "warning"
    else
        return "note"
    end
end

"""
Convert finding to SARIF result.
"""
function finding_to_sarif(f::Finding)::Dict{String, Any}
    level = f.severity == CRITICAL ? "error" :
           f.severity == HIGH ? "error" :
           f.severity == MEDIUM ? "warning" : "note"
    
    return Dict{String, Any}(
        "ruleId" => string(f.vuln_class),
        "level" => level,
        "message" => Dict("text" => f.description),
        "locations" => [
            Dict(
                "physicalLocation" => Dict(
                    "artifactLocation" => Dict("uri" => f.file_path),
                    "region" => Dict(
                        "startLine" => f.line_start,
                        "endLine" => f.line_end,
                        "startColumn" => f.column
                    )
                )
            )
        ],
        "partialFingerprints" => Dict(
            "primaryLocationLineHash" => bytes2hex(sha256(f.file_path * string(f.line_start)))
        ),
        "properties" => Dict(
            "confidence" => f.confidence,
            "cweId" => f.cwe_id,
            "tags" => f.tags
        )
    )
end

# ══════════════════════════════════════════════════════════════════════════════
# MARKDOWN REPORT
# ══════════════════════════════════════════════════════════════════════════════

"""
Generate Markdown report.
"""
function generate_markdown_report(gen::ReportGenerator, result::ScanResult,
                                 target::String, output_file::Union{String, Nothing})::String
    
    timestamp = Dates.format(now(), "yyyy-mm-dd HH:MM:SS")
    
    md = """
    # 🔮 Oracle Security Scan Report

    **Target:** `$target`  
    **Scan Date:** $timestamp  
    **Oracle Version:** $(ORACLE_VERSION)

    ---

    ## 📊 Summary

    | Metric | Value |
    |--------|-------|
    | Files Scanned | $(result.stats.files_scanned) |
    | Lines of Code | $(result.stats.total_lines) |
    | Total Findings | $(result.stats.total_findings) |
    | Scan Duration | $(result.stats.scan_duration_ms)ms |

    ### Findings by Severity

    | Severity | Count |
    |----------|-------|
    | 🔴 Critical | $(get(result.stats.findings_by_severity, CRITICAL, 0)) |
    | 🟠 High | $(get(result.stats.findings_by_severity, HIGH, 0)) |
    | 🟡 Medium | $(get(result.stats.findings_by_severity, MEDIUM, 0)) |
    | 🟢 Low | $(get(result.stats.findings_by_severity, LOW, 0)) |
    | 🔵 Info | $(get(result.stats.findings_by_severity, INFO, 0)) |

    ---

    ## 🔍 Findings

    """
    
    for (i, finding) in enumerate(result.findings)
        severity_emoji = finding.severity == CRITICAL ? "🔴" :
                        finding.severity == HIGH ? "🟠" :
                        finding.severity == MEDIUM ? "🟡" :
                        finding.severity == LOW ? "🟢" : "🔵"
        
        md *= """
        ### $i. $severity_emoji $(finding.title)

        **Severity:** $(finding.severity)  
        **Vulnerability Type:** $(finding.vuln_class)  
        **Location:** `$(finding.file_path):$(finding.line_start)`  
        **Confidence:** $(round(finding.confidence * 100))%  
        $(isnothing(finding.cwe_id) ? "" : "**CWE:** $(finding.cwe_id)  ")

        #### Description
        $(finding.description)

        """
        
        if !isempty(finding.code_snippet)
            md *= """
            #### Code
            ```
            $(finding.code_snippet)
            ```

            """
        end
        
        md *= """
        #### 💡 Remediation
        $(finding.remediation)

        ---

        """
    end
    
    md *= """
    ## 📝 Notes

    - This report was generated automatically by Oracle
    - Findings should be reviewed and validated by a security expert
    - False positives may exist; verify before taking action

    ---

    *Generated by Oracle v$(ORACLE_VERSION) - AI-Powered Vulnerability Discovery*
    """
    
    if isnothing(output_file)
        output_file = joinpath(gen.output_dir, "oracle-report-$(Dates.format(now(), "yyyymmdd-HHMMSS")).md")
    end
    
    write(output_file, md)
    @info "Markdown report generated" path=output_file
    
    return output_file
end

# ══════════════════════════════════════════════════════════════════════════════
# REPORT COMPARISON
# ══════════════════════════════════════════════════════════════════════════════

"""
Compare two scan results to identify new, fixed, and persistent findings.
"""
function compare_reports(old_result::ScanResult, new_result::ScanResult)::ReportComparison
    old_ids = Set(f.id for f in old_result.findings)
    new_ids = Set(f.id for f in new_result.findings)
    
    # Match by content hash instead of ID for better comparison
    old_hashes = Dict{String, Finding}()
    new_hashes = Dict{String, Finding}()
    
    for f in old_result.findings
        h = finding_hash(f)
        old_hashes[h] = f
    end
    
    for f in new_result.findings
        h = finding_hash(f)
        new_hashes[h] = f
    end
    
    new_findings = Finding[]
    fixed_findings = Finding[]
    persistent_findings = Finding[]
    
    for (h, f) in new_hashes
        if !haskey(old_hashes, h)
            push!(new_findings, f)
        else
            push!(persistent_findings, f)
        end
    end
    
    for (h, f) in old_hashes
        if !haskey(new_hashes, h)
            push!(fixed_findings, f)
        end
    end
    
    return ReportComparison(new_findings, fixed_findings, persistent_findings)
end

"""
Hash a finding for comparison.
"""
function finding_hash(f::Finding)::String
    content = "$(f.file_path)|$(f.line_start)|$(f.vuln_class)|$(f.title)"
    return bytes2hex(sha256(content))
end

"""
Report comparison result.
"""
struct ReportComparison
    new_findings::Vector{Finding}
    fixed_findings::Vector{Finding}
    persistent_findings::Vector{Finding}
end
