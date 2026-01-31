"""
Anomaly detection for discovering unknown vulnerability patterns.
Detects 0-days by identifying code that deviates from normal patterns.
"""

# ══════════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTOR
# ══════════════════════════════════════════════════════════════════════════════

"""
    AnomalyDetector

Isolation Forest-style anomaly detector for unknown vulnerabilities.
"""
mutable struct AnomalyDetector
    isolation_trees::Vector{IsolationTree}
    n_estimators::Int
    sample_size::Int
    contamination::Float64
    threshold::Float64
    feature_mins::Vector{Float64}
    feature_maxs::Vector{Float64}
    trained::Bool
    
    function AnomalyDetector(; n_estimators::Int=100, 
                             sample_size::Int=256,
                             contamination::Float64=0.1)
        new(
            IsolationTree[],
            n_estimators,
            sample_size,
            contamination,
            0.5,  # Default threshold
            Float64[],
            Float64[],
            false
        )
    end
end

# ══════════════════════════════════════════════════════════════════════════════
# ISOLATION TREE
# ══════════════════════════════════════════════════════════════════════════════

"""
Isolation tree node.
"""
abstract type IsolationNode end

"""
Internal split node.
"""
struct IsolationSplit <: IsolationNode
    feature_idx::Int
    split_value::Float64
    left::IsolationNode
    right::IsolationNode
end

"""
External leaf node.
"""
struct IsolationLeaf <: IsolationNode
    size::Int
    depth::Int
end

"""
Isolation tree.
"""
struct IsolationTree
    root::IsolationNode
    height_limit::Int
end

"""
Build isolation tree.
"""
function build_isolation_tree(X::Matrix{Float64}, sample_size::Int)::IsolationTree
    n = size(X, 2)
    
    # Subsample
    indices = randperm(n)[1:min(sample_size, n)]
    X_sample = X[:, indices]
    
    # Height limit based on sample size
    height_limit = ceil(Int, log2(sample_size))
    
    root = build_isolation_node(X_sample, 0, height_limit)
    
    return IsolationTree(root, height_limit)
end

"""
Recursively build isolation node.
"""
function build_isolation_node(X::Matrix{Float64}, depth::Int, 
                             height_limit::Int)::IsolationNode
    n = size(X, 2)
    n_features = size(X, 1)
    
    # Stop if height limit reached or node is pure
    if depth >= height_limit || n <= 1
        return IsolationLeaf(n, depth)
    end
    
    # Randomly select feature
    feature_idx = rand(1:n_features)
    
    # Get feature values
    feature_values = X[feature_idx, :]
    min_val = minimum(feature_values)
    max_val = maximum(feature_values)
    
    # No variation - make leaf
    if min_val == max_val
        return IsolationLeaf(n, depth)
    end
    
    # Random split value
    split_value = rand() * (max_val - min_val) + min_val
    
    # Split data
    left_mask = feature_values .<= split_value
    right_mask = .!left_mask
    
    X_left = X[:, left_mask]
    X_right = X[:, right_mask]
    
    # Empty splits - make leaf
    if size(X_left, 2) == 0 || size(X_right, 2) == 0
        return IsolationLeaf(n, depth)
    end
    
    # Recursively build children
    left = build_isolation_node(X_left, depth + 1, height_limit)
    right = build_isolation_node(X_right, depth + 1, height_limit)
    
    return IsolationSplit(feature_idx, split_value, left, right)
end

"""
Compute path length for a sample.
"""
function path_length(node::IsolationNode, x::Vector{Float64}, depth::Int=0)::Float64
    if node isa IsolationLeaf
        return depth + average_path_length(node.size)
    end
    
    # Split node
    if x[node.feature_idx] <= node.split_value
        return path_length(node.left, x, depth + 1)
    else
        return path_length(node.right, x, depth + 1)
    end
end

"""
Average path length for BST.
"""
function average_path_length(n::Int)::Float64
    if n <= 1
        return 0.0
    end
    
    # Euler-Mascheroni constant
    euler = 0.5772156649
    
    return 2.0 * (log(n - 1) + euler) - 2.0 * (n - 1) / n
end

# ══════════════════════════════════════════════════════════════════════════════
# TRAINING
# ══════════════════════════════════════════════════════════════════════════════

"""
    train!(detector::AnomalyDetector, X::Matrix)

Train the anomaly detector on normal code patterns.
"""
function train!(detector::AnomalyDetector, X::Matrix{Float64})
    n_samples = size(X, 2)
    n_features = size(X, 1)
    
    @info "Training anomaly detector" samples=n_samples features=n_features estimators=detector.n_estimators
    
    # Store feature ranges for normalization
    detector.feature_mins = vec(minimum(X, dims=2))
    detector.feature_maxs = vec(maximum(X, dims=2))
    
    # Build isolation trees
    detector.isolation_trees = IsolationTree[]
    
    for i in 1:detector.n_estimators
        tree = build_isolation_tree(X, detector.sample_size)
        push!(detector.isolation_trees, tree)
    end
    
    # Compute threshold from contamination
    scores = [anomaly_score(detector, X[:, i]) for i in 1:n_samples]
    sort!(scores, rev=true)
    
    threshold_idx = max(1, ceil(Int, detector.contamination * n_samples))
    detector.threshold = scores[threshold_idx]
    
    detector.trained = true
    @info "Anomaly detector training complete" threshold=detector.threshold
end

# ══════════════════════════════════════════════════════════════════════════════
# SCORING
# ══════════════════════════════════════════════════════════════════════════════

"""
    anomaly_score(detector::AnomalyDetector, x::Vector) -> Float64

Compute anomaly score for a sample (0 = normal, 1 = anomaly).
"""
function anomaly_score(detector::AnomalyDetector, x::Vector{Float64})::Float64
    if !detector.trained || isempty(detector.isolation_trees)
        return 0.0
    end
    
    # Normalize features
    x_norm = normalize_for_detection(x, detector.feature_mins, detector.feature_maxs)
    
    # Average path length across trees
    avg_path = 0.0
    
    for tree in detector.isolation_trees
        avg_path += path_length(tree.root, x_norm)
    end
    
    avg_path /= length(detector.isolation_trees)
    
    # Anomaly score: s(x) = 2^(-E[h(x)] / c(n))
    # where c(n) is average path length for n samples
    c_n = average_path_length(detector.sample_size)
    
    if c_n == 0
        return 0.0
    end
    
    score = 2.0^(-avg_path / c_n)
    
    return clamp(score, 0.0, 1.0)
end

"""
Normalize feature vector for detection.
"""
function normalize_for_detection(x::Vector{Float64}, mins::Vector{Float64}, 
                                maxs::Vector{Float64})::Vector{Float64}
    normalized = similar(x)
    
    for i in eachindex(x)
        range = maxs[i] - mins[i]
        if range > 0
            normalized[i] = (x[i] - mins[i]) / range
        else
            normalized[i] = 0.0
        end
    end
    
    return normalized
end

"""
    is_anomaly(detector::AnomalyDetector, x::Vector) -> Bool

Check if a sample is an anomaly.
"""
function is_anomaly(detector::AnomalyDetector, x::Vector{Float64})::Bool
    score = anomaly_score(detector, x)
    return score >= detector.threshold
end

"""
    detect_anomalies(detector::AnomalyDetector, X::Matrix) 
        -> Vector{Tuple{Int, Float64}}

Detect anomalies in a batch of samples.
Returns indices and scores of detected anomalies.
"""
function detect_anomalies(detector::AnomalyDetector, 
                         X::Matrix{Float64})::Vector{Tuple{Int, Float64}}
    
    anomalies = Tuple{Int, Float64}[]
    
    for i in 1:size(X, 2)
        score = anomaly_score(detector, X[:, i])
        if score >= detector.threshold
            push!(anomalies, (i, score))
        end
    end
    
    # Sort by score descending
    sort!(anomalies, by=x -> x[2], rev=true)
    
    return anomalies
end

# ══════════════════════════════════════════════════════════════════════════════
# ANOMALY ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

"""
    AnomalyAnalysis

Detailed analysis of a detected anomaly.
"""
struct AnomalyAnalysis
    score::Float64
    percentile::Float64
    contributing_features::Vector{Tuple{Int, Float64}}
    risk_assessment::String
    potential_vuln_types::Vector{VulnClass}
end

"""
    analyze_anomaly(detector::AnomalyDetector, x::Vector, 
                   reference_X::Matrix) -> AnomalyAnalysis

Perform detailed analysis of an anomaly.
"""
function analyze_anomaly(detector::AnomalyDetector, x::Vector{Float64},
                        reference_X::Matrix{Float64})::AnomalyAnalysis
    
    # Compute anomaly score
    score = anomaly_score(detector, x)
    
    # Compute percentile
    ref_scores = [anomaly_score(detector, reference_X[:, i]) 
                  for i in 1:size(reference_X, 2)]
    percentile = sum(score .> ref_scores) / length(ref_scores) * 100
    
    # Find contributing features by perturbation
    contributing_features = Tuple{Int, Float64}[]
    
    for f in eachindex(x)
        # Perturb feature to mean
        x_perturbed = copy(x)
        mean_val = mean(reference_X[f, :])
        x_perturbed[f] = mean_val
        
        # Measure impact
        score_perturbed = anomaly_score(detector, x_perturbed)
        impact = score - score_perturbed
        
        if impact > 0.01
            push!(contributing_features, (f, impact))
        end
    end
    
    # Sort by impact
    sort!(contributing_features, by=x -> x[2], rev=true)
    contributing_features = contributing_features[1:min(5, length(contributing_features))]
    
    # Risk assessment
    risk_assessment = if score >= 0.8
        "CRITICAL"
    elseif score >= 0.6
        "HIGH"
    elseif score >= 0.4
        "MEDIUM"
    else
        "LOW"
    end
    
    # Infer potential vulnerability types from features
    potential_vuln_types = infer_vuln_types(x, contributing_features)
    
    return AnomalyAnalysis(
        score,
        percentile,
        contributing_features,
        risk_assessment,
        potential_vuln_types
    )
end

"""
Infer potential vulnerability types from anomalous features.
"""
function infer_vuln_types(x::Vector{Float64}, 
                         contributing::Vector{Tuple{Int, Float64}})::Vector{VulnClass}
    
    types = Set{VulnClass}()
    
    for (feature_idx, _) in contributing
        # Feature index to vulnerability type mapping
        # Based on standard feature ordering
        if feature_idx in [5, 6, 12]  # input, output, taint
            push!(types, INJECTION)
            push!(types, XSS)
        end
        if feature_idx in [8, 14]  # memory, pointer
            push!(types, BUFFER_OVERFLOW)
            push!(types, USE_AFTER_FREE)
        end
        if feature_idx in [7]  # crypto
            push!(types, CRYPTO_WEAKNESS)
        end
        if feature_idx in [9]  # file
            push!(types, PATH_TRAVERSAL)
        end
        if feature_idx in [10]  # network
            push!(types, SSRF)
        end
        if feature_idx in [11]  # dangerous functions
            push!(types, CODE_EXECUTION)
            push!(types, DESERIALIZATION)
        end
    end
    
    return collect(types)
end

# ══════════════════════════════════════════════════════════════════════════════
# AUTO-ENCODER ANOMALY DETECTION
# ══════════════════════════════════════════════════════════════════════════════

"""
    AutoEncoderDetector

Neural network-based anomaly detector using reconstruction error.
"""
mutable struct AutoEncoderDetector
    encoder_weights::Vector{Matrix{Float64}}
    encoder_biases::Vector{Vector{Float64}}
    decoder_weights::Vector{Matrix{Float64}}
    decoder_biases::Vector{Vector{Float64}}
    threshold::Float64
    input_dim::Int
    hidden_dims::Vector{Int}
    trained::Bool
    
    function AutoEncoderDetector(; input_dim::Int=160, hidden_dims::Vector{Int}=[64, 32])
        # Initialize weights using Xavier/Glorot initialization
        encoder_weights = Matrix{Float64}[]
        encoder_biases = Vector{Float64}[]
        decoder_weights = Matrix{Float64}[]
        decoder_biases = Vector{Float64}[]
        
        # Encoder
        prev_dim = input_dim
        for hidden_dim in hidden_dims
            push!(encoder_weights, randn(hidden_dim, prev_dim) * sqrt(2.0 / prev_dim))
            push!(encoder_biases, zeros(hidden_dim))
            prev_dim = hidden_dim
        end
        
        # Decoder (mirror of encoder)
        for i in length(hidden_dims):-1:1
            next_dim = i > 1 ? hidden_dims[i-1] : input_dim
            prev_dim = hidden_dims[i]
            push!(decoder_weights, randn(next_dim, prev_dim) * sqrt(2.0 / prev_dim))
            push!(decoder_biases, zeros(next_dim))
        end
        
        new(
            encoder_weights,
            encoder_biases,
            decoder_weights,
            decoder_biases,
            0.1,  # Default threshold
            input_dim,
            hidden_dims,
            false
        )
    end
end

"""
ReLU activation.
"""
relu(x) = max(0, x)

"""
Forward pass through encoder.
"""
function encode(ae::AutoEncoderDetector, x::Vector{Float64})::Vector{Float64}
    h = x
    for (W, b) in zip(ae.encoder_weights, ae.encoder_biases)
        h = relu.(W * h .+ b)
    end
    return h
end

"""
Forward pass through decoder.
"""
function decode(ae::AutoEncoderDetector, z::Vector{Float64})::Vector{Float64}
    h = z
    for (i, (W, b)) in enumerate(zip(ae.decoder_weights, ae.decoder_biases))
        h = W * h .+ b
        if i < length(ae.decoder_weights)
            h = relu.(h)
        end
        # Last layer: no activation (linear reconstruction)
    end
    return h
end

"""
Reconstruction error.
"""
function reconstruction_error(ae::AutoEncoderDetector, x::Vector{Float64})::Float64
    z = encode(ae, x)
    x_reconstructed = decode(ae, z)
    return sum((x .- x_reconstructed).^2) / length(x)  # MSE
end

"""
Train autoencoder anomaly detector.
"""
function train!(ae::AutoEncoderDetector, X::Matrix{Float64};
               epochs::Int=50, learning_rate::Float64=0.001)
    
    n_samples = size(X, 2)
    @info "Training autoencoder" samples=n_samples epochs=epochs
    
    for epoch in 1:epochs
        total_loss = 0.0
        
        for i in 1:n_samples
            x = X[:, i]
            
            # Forward pass
            z = encode(ae, x)
            x_recon = decode(ae, z)
            
            # Compute gradients (simplified - gradient descent on weights)
            error = x .- x_recon
            loss = sum(error.^2)
            total_loss += loss
            
            # Backward pass (simplified gradient update)
            # Update decoder
            for j in length(ae.decoder_weights):-1:1
                grad = -2 * error / n_samples
                if j < length(ae.decoder_weights)
                    h = decode_partial(ae, z, j - 1)
                    ae.decoder_weights[j] .-= learning_rate * grad * h'
                else
                    ae.decoder_weights[j] .-= learning_rate * grad * z'
                end
                ae.decoder_biases[j] .-= learning_rate * grad
            end
        end
        
        avg_loss = total_loss / n_samples
        
        if epoch % 10 == 0
            @info "Epoch $epoch" loss=avg_loss
        end
    end
    
    # Compute threshold from training data
    errors = [reconstruction_error(ae, X[:, i]) for i in 1:n_samples]
    ae.threshold = quantile(errors, 0.95)
    
    ae.trained = true
end

"""
Partial decode for gradient computation.
"""
function decode_partial(ae::AutoEncoderDetector, z::Vector{Float64}, 
                       stop_layer::Int)::Vector{Float64}
    h = z
    for i in 1:stop_layer
        W, b = ae.decoder_weights[i], ae.decoder_biases[i]
        h = relu.(W * h .+ b)
    end
    return h
end

"""
Check if sample is anomaly using autoencoder.
"""
function is_anomaly(ae::AutoEncoderDetector, x::Vector{Float64})::Bool
    error = reconstruction_error(ae, x)
    return error > ae.threshold
end

# ══════════════════════════════════════════════════════════════════════════════
# SERIALIZATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Save anomaly detector to file.
"""
function save_detector(detector::AnomalyDetector, filepath::String)
    open(filepath, "w") do io
        serialize(io, detector)
    end
    @info "Anomaly detector saved" path=filepath
end

"""
Load anomaly detector from file.
"""
function load_detector(filepath::String)::AnomalyDetector
    return open(filepath, "r") do io
        deserialize(io)
    end
end
