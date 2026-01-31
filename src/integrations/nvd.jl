"""
NVD (National Vulnerability Database) integration for Oracle.
Fetches and correlates known vulnerabilities.
"""

# ══════════════════════════════════════════════════════════════════════════════
# NVD CLIENT
# ══════════════════════════════════════════════════════════════════════════════

"""
    NVDClient

Client for interacting with NVD API.
"""
mutable struct NVDClient
    api_key::Union{String, Nothing}
    base_url::String
    cache::Dict{String, Any}
    cache_ttl::Int  # seconds
    rate_limit::Int  # requests per minute
    last_request::DateTime
    
    function NVDClient(; api_key::Union{String, Nothing}=nothing)
        new(
            api_key,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            Dict{String, Any}(),
            3600,  # 1 hour cache
            api_key === nothing ? 5 : 50,  # Higher rate with API key
            DateTime(0)
        )
    end
end

"""
    NVDVulnerability

Vulnerability from NVD.
"""
struct NVDVulnerability
    cve_id::String
    description::String
    cvss_v3_score::Float64
    cvss_v3_vector::String
    severity::String
    cwe_ids::Vector{String}
    affected_products::Vector{String}
    references::Vector{String}
    published_date::DateTime
    last_modified::DateTime
end

# ══════════════════════════════════════════════════════════════════════════════
# API REQUESTS
# ══════════════════════════════════════════════════════════════════════════════

"""
    search_cves(client::NVDClient; kwargs...) -> Vector{NVDVulnerability}

Search NVD for CVEs matching criteria.
"""
function search_cves(client::NVDClient;
                    keyword::Union{String, Nothing}=nothing,
                    cpe_name::Union{String, Nothing}=nothing,
                    cve_id::Union{String, Nothing}=nothing,
                    cwe_id::Union{String, Nothing}=nothing,
                    start_index::Int=0,
                    results_per_page::Int=100)::Vector{NVDVulnerability}
    
    # Rate limiting
    rate_limit!(client)
    
    # Build query params
    params = Dict{String, String}()
    
    if !isnothing(keyword)
        params["keywordSearch"] = keyword
    end
    if !isnothing(cpe_name)
        params["cpeName"] = cpe_name
    end
    if !isnothing(cve_id)
        params["cveId"] = cve_id
    end
    if !isnothing(cwe_id)
        params["cweId"] = cwe_id
    end
    
    params["startIndex"] = string(start_index)
    params["resultsPerPage"] = string(results_per_page)
    
    # Check cache
    cache_key = join(sort(collect(params)), "|")
    if haskey(client.cache, cache_key)
        cached_time, cached_data = client.cache[cache_key]
        if now() - cached_time < Second(client.cache_ttl)
            return cached_data
        end
    end
    
    # Make request
    headers = Dict{String, String}()
    if !isnothing(client.api_key)
        headers["apiKey"] = client.api_key
    end
    
    query_string = join(["$k=$v" for (k, v) in params], "&")
    url = "$(client.base_url)?$query_string"
    
    try
        response = HTTP.get(url, headers)
        data = JSON3.read(String(response.body))
        
        vulnerabilities = parse_nvd_response(data)
        
        # Cache result
        client.cache[cache_key] = (now(), vulnerabilities)
        
        return vulnerabilities
        
    catch e
        @warn "NVD API request failed" error=e
        return NVDVulnerability[]
    end
end

"""
Rate limit requests.
"""
function rate_limit!(client::NVDClient)
    elapsed = now() - client.last_request
    min_interval = Millisecond(ceil(Int, 60000 / client.rate_limit))
    
    if elapsed < min_interval
        sleep_time = (min_interval - elapsed).value / 1000
        sleep(sleep_time)
    end
    
    client.last_request = now()
end

"""
Parse NVD API response.
"""
function parse_nvd_response(data)::Vector{NVDVulnerability}
    vulnerabilities = NVDVulnerability[]
    
    if !haskey(data, :vulnerabilities)
        return vulnerabilities
    end
    
    for item in data.vulnerabilities
        try
            cve = item.cve
            
            # Parse description
            description = ""
            if haskey(cve, :descriptions)
                for desc in cve.descriptions
                    if desc.lang == "en"
                        description = desc.value
                        break
                    end
                end
            end
            
            # Parse CVSS
            cvss_score = 0.0
            cvss_vector = ""
            severity = "UNKNOWN"
            
            if haskey(cve, :metrics) && haskey(cve.metrics, :cvssMetricV31)
                for metric in cve.metrics.cvssMetricV31
                    cvss_score = metric.cvssData.baseScore
                    cvss_vector = metric.cvssData.vectorString
                    severity = metric.cvssData.baseSeverity
                    break
                end
            elseif haskey(cve, :metrics) && haskey(cve.metrics, :cvssMetricV30)
                for metric in cve.metrics.cvssMetricV30
                    cvss_score = metric.cvssData.baseScore
                    cvss_vector = metric.cvssData.vectorString
                    severity = metric.cvssData.baseSeverity
                    break
                end
            end
            
            # Parse CWEs
            cwe_ids = String[]
            if haskey(cve, :weaknesses)
                for weakness in cve.weaknesses
                    for desc in weakness.description
                        if startswith(desc.value, "CWE-")
                            push!(cwe_ids, desc.value)
                        end
                    end
                end
            end
            
            # Parse affected products
            affected = String[]
            if haskey(cve, :configurations)
                for config in cve.configurations
                    if haskey(config, :nodes)
                        for node in config.nodes
                            if haskey(node, :cpeMatch)
                                for match in node.cpeMatch
                                    push!(affected, match.criteria)
                                end
                            end
                        end
                    end
                end
            end
            
            # Parse references
            refs = String[]
            if haskey(cve, :references)
                for ref in cve.references
                    push!(refs, ref.url)
                end
            end
            
            # Parse dates
            published = haskey(cve, :published) ? 
                       DateTime(cve.published[1:19], dateformat"yyyy-mm-ddTHH:MM:SS") :
                       DateTime(0)
            modified = haskey(cve, :lastModified) ? 
                      DateTime(cve.lastModified[1:19], dateformat"yyyy-mm-ddTHH:MM:SS") :
                      DateTime(0)
            
            vuln = NVDVulnerability(
                cve.id,
                description,
                cvss_score,
                cvss_vector,
                severity,
                cwe_ids,
                affected,
                refs,
                published,
                modified
            )
            
            push!(vulnerabilities, vuln)
            
        catch e
            @debug "Failed to parse CVE" error=e
        end
    end
    
    return vulnerabilities
end

# ══════════════════════════════════════════════════════════════════════════════
# CVE CORRELATION
# ══════════════════════════════════════════════════════════════════════════════

"""
    correlate_findings(client::NVDClient, findings::Vector{Finding}) 
        -> Vector{CorrelatedFinding}

Correlate scan findings with known CVEs.
"""
function correlate_findings(client::NVDClient, 
                           findings::Vector{Finding})::Vector{CorrelatedFinding}
    
    correlated = CorrelatedFinding[]
    
    for finding in findings
        related_cves = NVDVulnerability[]
        
        # Search by CWE if available
        if !isnothing(finding.cwe_id)
            cwe_cves = search_cves(client, cwe_id=finding.cwe_id, results_per_page=10)
            append!(related_cves, cwe_cves)
        end
        
        # Search by vulnerability type keywords
        keywords = vuln_class_to_keywords(finding.vuln_class)
        for kw in keywords
            kw_cves = search_cves(client, keyword=kw, results_per_page=5)
            append!(related_cves, kw_cves)
        end
        
        # Deduplicate
        unique!(v -> v.cve_id, related_cves)
        
        # Sort by relevance (CVSS score)
        sort!(related_cves, by=v -> v.cvss_v3_score, rev=true)
        
        # Take top 5 most relevant
        related_cves = related_cves[1:min(5, length(related_cves))]
        
        push!(correlated, CorrelatedFinding(finding, related_cves))
    end
    
    return correlated
end

"""
    CorrelatedFinding

Finding with related CVEs.
"""
struct CorrelatedFinding
    finding::Finding
    related_cves::Vector{NVDVulnerability}
end

"""
Convert vulnerability class to search keywords.
"""
function vuln_class_to_keywords(vc::VulnClass)::Vector{String}
    keywords = Dict(
        INJECTION => ["sql injection", "command injection"],
        BUFFER_OVERFLOW => ["buffer overflow", "stack overflow"],
        USE_AFTER_FREE => ["use after free", "memory corruption"],
        XSS => ["cross-site scripting", "xss"],
        CODE_EXECUTION => ["remote code execution", "arbitrary code"],
        DESERIALIZATION => ["deserialization", "insecure deserialization"],
        PATH_TRAVERSAL => ["path traversal", "directory traversal"],
        SSRF => ["server-side request forgery", "ssrf"],
        AUTHENTICATION_BYPASS => ["authentication bypass", "auth bypass"],
        CRYPTO_WEAKNESS => ["cryptographic", "weak cipher"]
    )
    
    return get(keywords, vc, [string(vc)])
end

# ══════════════════════════════════════════════════════════════════════════════
# CVE MONITORING
# ══════════════════════════════════════════════════════════════════════════════

"""
    CVEMonitor

Monitor for new CVEs affecting tracked products.
"""
mutable struct CVEMonitor
    client::NVDClient
    tracked_products::Set{String}
    tracked_cwes::Set{String}
    last_check::DateTime
    new_cves::Vector{NVDVulnerability}
    
    function CVEMonitor(client::NVDClient)
        new(
            client,
            Set{String}(),
            Set{String}(),
            DateTime(0),
            NVDVulnerability[]
        )
    end
end

"""
Track a product for new CVEs.
"""
function track_product!(monitor::CVEMonitor, cpe_name::String)
    push!(monitor.tracked_products, cpe_name)
end

"""
Track a CWE for new CVEs.
"""
function track_cwe!(monitor::CVEMonitor, cwe_id::String)
    push!(monitor.tracked_cwes, cwe_id)
end

"""
Check for new CVEs since last check.
"""
function check_for_new_cves!(monitor::CVEMonitor)::Vector{NVDVulnerability}
    new_cves = NVDVulnerability[]
    
    # Check tracked products
    for cpe in monitor.tracked_products
        cves = search_cves(monitor.client, cpe_name=cpe, results_per_page=20)
        
        for cve in cves
            if cve.published_date > monitor.last_check
                push!(new_cves, cve)
            end
        end
    end
    
    # Check tracked CWEs
    for cwe in monitor.tracked_cwes
        cves = search_cves(monitor.client, cwe_id=cwe, results_per_page=20)
        
        for cve in cves
            if cve.published_date > monitor.last_check
                push!(new_cves, cve)
            end
        end
    end
    
    # Deduplicate
    unique!(v -> v.cve_id, new_cves)
    
    monitor.last_check = now()
    monitor.new_cves = new_cves
    
    return new_cves
end

# ══════════════════════════════════════════════════════════════════════════════
# CVE DATABASE
# ══════════════════════════════════════════════════════════════════════════════

"""
    LocalCVEDatabase

Local cache of CVE data for offline use.
"""
mutable struct LocalCVEDatabase
    db_path::String
    vulnerabilities::Dict{String, NVDVulnerability}
    last_updated::DateTime
    
    function LocalCVEDatabase(; db_path::String="cve_database.json")
        db = new(db_path, Dict{String, NVDVulnerability}(), DateTime(0))
        
        if isfile(db_path)
            load!(db)
        end
        
        return db
    end
end

"""
Load database from file.
"""
function load!(db::LocalCVEDatabase)
    try
        data = JSON3.read(read(db.db_path, String))
        
        for (cve_id, vuln_data) in data.vulnerabilities
            db.vulnerabilities[string(cve_id)] = parse_stored_vuln(vuln_data)
        end
        
        db.last_updated = DateTime(data.last_updated)
        @info "Loaded CVE database" entries=length(db.vulnerabilities)
        
    catch e
        @warn "Failed to load CVE database" error=e
    end
end

"""
Save database to file.
"""
function save!(db::LocalCVEDatabase)
    data = Dict(
        "last_updated" => string(db.last_updated),
        "vulnerabilities" => Dict(
            cve_id => vuln_to_dict(vuln) 
            for (cve_id, vuln) in db.vulnerabilities
        )
    )
    
    write(db.db_path, JSON3.write(data))
    @info "Saved CVE database" entries=length(db.vulnerabilities)
end

"""
Convert vulnerability to dictionary for storage.
"""
function vuln_to_dict(v::NVDVulnerability)::Dict{String, Any}
    return Dict{String, Any}(
        "cve_id" => v.cve_id,
        "description" => v.description,
        "cvss_v3_score" => v.cvss_v3_score,
        "cvss_v3_vector" => v.cvss_v3_vector,
        "severity" => v.severity,
        "cwe_ids" => v.cwe_ids,
        "affected_products" => v.affected_products,
        "references" => v.references,
        "published_date" => string(v.published_date),
        "last_modified" => string(v.last_modified)
    )
end

"""
Parse stored vulnerability.
"""
function parse_stored_vuln(data)::NVDVulnerability
    return NVDVulnerability(
        data.cve_id,
        data.description,
        data.cvss_v3_score,
        data.cvss_v3_vector,
        data.severity,
        collect(data.cwe_ids),
        collect(data.affected_products),
        collect(data.references),
        DateTime(data.published_date),
        DateTime(data.last_modified)
    )
end

"""
Update database from NVD.
"""
function update!(db::LocalCVEDatabase, client::NVDClient;
                keywords::Vector{String}=String[])
    
    @info "Updating CVE database..."
    
    for kw in keywords
        cves = search_cves(client, keyword=kw, results_per_page=100)
        
        for cve in cves
            db.vulnerabilities[cve.cve_id] = cve
        end
    end
    
    db.last_updated = now()
    save!(db)
    
    @info "Database updated" total=length(db.vulnerabilities)
end

"""
Search local database.
"""
function search(db::LocalCVEDatabase;
               cwe_id::Union{String, Nothing}=nothing,
               min_cvss::Float64=0.0)::Vector{NVDVulnerability}
    
    results = NVDVulnerability[]
    
    for (_, vuln) in db.vulnerabilities
        if vuln.cvss_v3_score < min_cvss
            continue
        end
        
        if !isnothing(cwe_id) && !(cwe_id in vuln.cwe_ids)
            continue
        end
        
        push!(results, vuln)
    end
    
    return results
end
