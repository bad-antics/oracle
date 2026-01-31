"""
Vulnerability prediction ML model for Oracle.
"""

# ══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY PREDICTOR
# ══════════════════════════════════════════════════════════════════════════════

"""
    VulnerabilityPredictor

ML model for predicting vulnerabilities from code features.
"""
mutable struct VulnerabilityPredictor
    weights::Dict{VulnClass, Vector{Float64}}
    biases::Dict{VulnClass, Float64}
    embedder::CodeEmbedder
    thresholds::Dict{VulnClass, Float64}
    feature_means::Vector{Float64}
    feature_stds::Vector{Float64}
    trained::Bool
    version::String
    
    function VulnerabilityPredictor(; kwargs...)
        # Initialize weights for each vulnerability class
        weights = Dict{VulnClass, Vector{Float64}}()
        biases = Dict{VulnClass, Float64}()
        thresholds = Dict{VulnClass, Float64}()
        
        for vuln_class in instances(VulnClass)
            weights[vuln_class] = zeros(160)  # Feature dimension
            biases[vuln_class] = 0.0
            thresholds[vuln_class] = 0.5
        end
        
        new(
            weights,
            biases,
            CodeEmbedder(),
            thresholds,
            zeros(160),
            ones(160),
            false,
            string(ORACLE_VERSION)
        )
    end
end

# Global default predictor
const DEFAULT_PREDICTOR = Ref{VulnerabilityPredictor}()

"""
Load default predictor.
"""
function load_default_predictor()::VulnerabilityPredictor
    if !isassigned(DEFAULT_PREDICTOR)
        predictor = VulnerabilityPredictor()
        initialize_default_weights!(predictor)
        DEFAULT_PREDICTOR[] = predictor
    end
    return DEFAULT_PREDICTOR[]
end

"""
Initialize predictor with heuristic weights.
"""
function initialize_default_weights!(predictor::VulnerabilityPredictor)
    # Feature indices (matching CodeFeatures structure):
    # 0-3: Structural (complexity, nesting, loc, func_count)
    # 4-9: Security counts (inputs, sinks, crypto, memory, file, network)
    # 10-13: Pattern features (dangerous_funcs_count, taint_flows, unchecked, pointer)
    # 14-16: Statistical (entropy, diversity, comment_ratio)
    # 17-144: Embedding (128 dims)
    # 145-159: Reserved
    
    # Injection vulnerabilities
    predictor.weights[INJECTION] = zeros(160)
    predictor.weights[INJECTION][5] = 2.0   # input_sources
    predictor.weights[INJECTION][6] = 2.5   # output_sinks
    predictor.weights[INJECTION][11] = 1.5  # dangerous_functions
    predictor.weights[INJECTION][12] = 3.0  # taint_flows
    predictor.biases[INJECTION] = -2.0
    
    # Buffer overflow
    predictor.weights[BUFFER_OVERFLOW] = zeros(160)
    predictor.weights[BUFFER_OVERFLOW][8] = 3.0   # memory_operations
    predictor.weights[BUFFER_OVERFLOW][11] = 2.5  # dangerous_functions
    predictor.weights[BUFFER_OVERFLOW][14] = 2.0  # pointer_arithmetic
    predictor.biases[BUFFER_OVERFLOW] = -2.5
    
    # Use after free
    predictor.weights[USE_AFTER_FREE] = zeros(160)
    predictor.weights[USE_AFTER_FREE][8] = 3.5    # memory_operations
    predictor.weights[USE_AFTER_FREE][1] = 1.0    # cyclomatic_complexity
    predictor.weights[USE_AFTER_FREE][2] = 1.5    # nesting_depth
    predictor.biases[USE_AFTER_FREE] = -3.0
    
    # XSS
    predictor.weights[XSS] = zeros(160)
    predictor.weights[XSS][5] = 2.0    # input_sources
    predictor.weights[XSS][6] = 3.0    # output_sinks
    predictor.weights[XSS][12] = 2.5   # taint_flows
    predictor.biases[XSS] = -2.0
    
    # Code execution
    predictor.weights[CODE_EXECUTION] = zeros(160)
    predictor.weights[CODE_EXECUTION][5] = 2.5   # input_sources
    predictor.weights[CODE_EXECUTION][11] = 4.0  # dangerous_functions
    predictor.weights[CODE_EXECUTION][12] = 3.0  # taint_flows
    predictor.biases[CODE_EXECUTION] = -3.0
    
    # Deserialization
    predictor.weights[DESERIALIZATION] = zeros(160)
    predictor.weights[DESERIALIZATION][5] = 2.0   # input_sources
    predictor.weights[DESERIALIZATION][11] = 3.5  # dangerous_functions
    predictor.biases[DESERIALIZATION] = -2.5
    
    # Path traversal
    predictor.weights[PATH_TRAVERSAL] = zeros(160)
    predictor.weights[PATH_TRAVERSAL][5] = 2.0   # input_sources
    predictor.weights[PATH_TRAVERSAL][9] = 3.0   # file_operations
    predictor.weights[PATH_TRAVERSAL][12] = 2.0  # taint_flows
    predictor.biases[PATH_TRAVERSAL] = -2.0
    
    # SSRF
    predictor.weights[SSRF] = zeros(160)
    predictor.weights[SSRF][5] = 2.5    # input_sources
    predictor.weights[SSRF][10] = 3.0   # network_operations
    predictor.weights[SSRF][12] = 2.5   # taint_flows
    predictor.biases[SSRF] = -2.5
    
    # Authentication bypass
    predictor.weights[AUTHENTICATION_BYPASS] = zeros(160)
    predictor.weights[AUTHENTICATION_BYPASS][1] = 1.5   # complexity
    predictor.weights[AUTHENTICATION_BYPASS][13] = 2.0  # unchecked_returns
    predictor.biases[AUTHENTICATION_BYPASS] = -2.0
    
    # Crypto weakness
    predictor.weights[CRYPTO_WEAKNESS] = zeros(160)
    predictor.weights[CRYPTO_WEAKNESS][7] = 3.0   # crypto_operations
    predictor.weights[CRYPTO_WEAKNESS][11] = 2.0  # dangerous_functions
    predictor.biases[CRYPTO_WEAKNESS] = -1.5
    
    # Default for others
    for vuln_class in instances(VulnClass)
        if sum(abs.(predictor.weights[vuln_class])) == 0
            predictor.weights[vuln_class][1] = 0.5   # complexity
            predictor.weights[vuln_class][11] = 1.0  # dangerous_functions
            predictor.weights[vuln_class][12] = 1.5  # taint_flows
            predictor.biases[vuln_class] = -2.0
        end
    end
    
    predictor.trained = true
end

# ══════════════════════════════════════════════════════════════════════════════
# PREDICTION
# ══════════════════════════════════════════════════════════════════════════════

"""
    predict(predictor::VulnerabilityPredictor, features::CodeFeatures) 
        -> Vector{Tuple{VulnClass, Float64}}

Predict vulnerability classes from code features.
"""
function predict(predictor::VulnerabilityPredictor, 
                features::CodeFeatures)::Vector{Tuple{VulnClass, Float64}}
    
    # Convert features to vector
    feature_vec = features_to_vector(features)
    
    # Normalize features
    normalized = normalize_features(feature_vec, predictor.feature_means, 
                                   predictor.feature_stds)
    
    # Compute scores for each class
    predictions = Tuple{VulnClass, Float64}[]
    
    for vuln_class in instances(VulnClass)
        weights = predictor.weights[vuln_class]
        bias = predictor.biases[vuln_class]
        threshold = predictor.thresholds[vuln_class]
        
        # Linear combination
        score = dot(weights, normalized) + bias
        
        # Sigmoid activation
        prob = sigmoid(score)
        
        if prob >= threshold
            push!(predictions, (vuln_class, prob))
        end
    end
    
    # Sort by probability
    sort!(predictions, by=x -> x[2], rev=true)
    
    return predictions
end

"""
Convert CodeFeatures to a feature vector.
"""
function features_to_vector(features::CodeFeatures)::Vector{Float64}
    vec = zeros(Float64, 160)
    
    # Structural features (0-3)
    vec[1] = Float64(features.cyclomatic_complexity)
    vec[2] = Float64(features.nesting_depth)
    vec[3] = Float64(features.loc)
    vec[4] = Float64(features.function_count)
    
    # Security-relevant counts (4-9)
    vec[5] = Float64(features.input_sources)
    vec[6] = Float64(features.output_sinks)
    vec[7] = Float64(features.crypto_operations)
    vec[8] = Float64(features.memory_operations)
    vec[9] = Float64(features.file_operations)
    vec[10] = Float64(features.network_operations)
    
    # Pattern features (10-13)
    vec[11] = Float64(length(features.dangerous_functions))
    vec[12] = Float64(features.taint_flows)
    vec[13] = Float64(features.unchecked_returns)
    vec[14] = Float64(features.pointer_arithmetic)
    
    # Statistical features (14-16)
    vec[15] = features.entropy
    vec[16] = features.token_diversity
    vec[17] = features.comment_ratio
    
    # Embedding (17-144)
    for (i, val) in enumerate(features.embedding)
        if 17 + i <= 144
            vec[17 + i] = Float64(val)
        end
    end
    
    return vec
end

"""
Normalize features using mean and std.
"""
function normalize_features(features::Vector{Float64}, means::Vector{Float64},
                           stds::Vector{Float64})::Vector{Float64}
    normalized = similar(features)
    
    for i in eachindex(features)
        if stds[i] > 0
            normalized[i] = (features[i] - means[i]) / stds[i]
        else
            normalized[i] = features[i] - means[i]
        end
    end
    
    return normalized
end

"""
Sigmoid activation function.
"""
function sigmoid(x::Float64)::Float64
    return 1.0 / (1.0 + exp(-clamp(x, -500, 500)))
end

# ══════════════════════════════════════════════════════════════════════════════
# TRAINING
# ══════════════════════════════════════════════════════════════════════════════

"""
    train!(predictor::VulnerabilityPredictor, features::Matrix, labels::Vector)

Train the predictor on labeled data.
"""
function train!(predictor::VulnerabilityPredictor, 
               features::Matrix{Float64},
               labels::Vector{VulnClass};
               epochs::Int=100,
               learning_rate::Float64=0.01)
    
    n_samples = size(features, 2)
    n_features = size(features, 1)
    
    # Compute normalization parameters
    predictor.feature_means = vec(mean(features, dims=2))
    predictor.feature_stds = vec(std(features, dims=2))
    predictor.feature_stds[predictor.feature_stds .== 0] .= 1.0
    
    # Normalize features
    normalized = copy(features)
    for i in 1:n_samples
        normalized[:, i] = normalize_features(features[:, i], 
                                             predictor.feature_means,
                                             predictor.feature_stds)
    end
    
    # Convert labels to one-hot
    label_matrix = labels_to_onehot(labels)
    
    @info "Training predictor" samples=n_samples features=n_features epochs=epochs
    
    for epoch in 1:epochs
        total_loss = 0.0
        
        for i in 1:n_samples
            x = normalized[:, i]
            y = label_matrix[:, i]
            
            # Forward pass for each class
            for (j, vuln_class) in enumerate(instances(VulnClass))
                w = predictor.weights[vuln_class]
                b = predictor.biases[vuln_class]
                
                # Predict
                z = dot(w[1:n_features], x) + b
                pred = sigmoid(z)
                
                # Binary cross-entropy loss
                target = y[j]
                loss = -target * log(pred + 1e-10) - (1 - target) * log(1 - pred + 1e-10)
                total_loss += loss
                
                # Gradient descent update
                grad = (pred - target)
                predictor.weights[vuln_class][1:n_features] .-= learning_rate * grad .* x
                predictor.biases[vuln_class] -= learning_rate * grad
            end
        end
        
        avg_loss = total_loss / (n_samples * length(instances(VulnClass)))
        
        if epoch % 10 == 0
            @info "Epoch $epoch" loss=avg_loss
        end
    end
    
    predictor.trained = true
end

"""
Convert labels to one-hot matrix.
"""
function labels_to_onehot(labels::Vector{VulnClass})::Matrix{Float64}
    n = length(labels)
    n_classes = length(instances(VulnClass))
    
    onehot = zeros(Float64, n_classes, n)
    
    for (i, label) in enumerate(labels)
        onehot[Int(label), i] = 1.0
    end
    
    return onehot
end

"""
Extract training features from DataFrame.
"""
function extract_training_features(df::DataFrame)::Matrix{Float64}
    # Assume DataFrame has feature columns
    feature_cols = [col for col in names(df) if col != "vuln_class"]
    return Matrix{Float64}(df[:, feature_cols])'
end

# ══════════════════════════════════════════════════════════════════════════════
# EVALUATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Evaluate predictor accuracy.
"""
function evaluate(predictor::VulnerabilityPredictor,
                 features::Matrix{Float64},
                 labels::Vector{VulnClass})::Float64
    
    correct = 0
    total = length(labels)
    
    for i in 1:total
        feature_vec = features[:, i]
        
        # Create CodeFeatures from vector (simplified)
        code_features = vector_to_features(feature_vec)
        
        # Predict
        predictions = predict(predictor, code_features)
        
        if !isempty(predictions) && predictions[1][1] == labels[i]
            correct += 1
        end
    end
    
    return correct / total
end

"""
Convert feature vector back to CodeFeatures.
"""
function vector_to_features(vec::Vector{Float64})::CodeFeatures
    return CodeFeatures(
        Int(round(vec[1])),   # cyclomatic_complexity
        Int(round(vec[2])),   # nesting_depth
        Int(round(vec[3])),   # loc
        Int(round(vec[4])),   # function_count
        Int(round(vec[5])),   # input_sources
        Int(round(vec[6])),   # output_sinks
        Int(round(vec[7])),   # crypto_operations
        Int(round(vec[8])),   # memory_operations
        Int(round(vec[9])),   # file_operations
        Int(round(vec[10])),  # network_operations
        String[],             # dangerous_functions (empty)
        Int(round(vec[12])),  # taint_flows
        Int(round(vec[13])),  # unchecked_returns
        Int(round(vec[14])),  # pointer_arithmetic
        vec[15],              # entropy
        vec[16],              # token_diversity
        vec[17],              # comment_ratio
        Float32.(vec[18:145]) # embedding
    )
end

# ══════════════════════════════════════════════════════════════════════════════
# SERIALIZATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Save predictor to file.
"""
function save_predictor(predictor::VulnerabilityPredictor, filepath::String)
    open(filepath, "w") do io
        serialize(io, predictor)
    end
    @info "Predictor saved" path=filepath
end

"""
Load predictor from file.
"""
function load_predictor(filepath::String)::VulnerabilityPredictor
    return open(filepath, "r") do io
        deserialize(io)
    end
end
