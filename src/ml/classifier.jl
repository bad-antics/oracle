"""
Multi-class vulnerability classifier for Oracle.
Uses ensemble methods for accurate classification.
"""

# ══════════════════════════════════════════════════════════════════════════════
# PATTERN CLASSIFIER
# ══════════════════════════════════════════════════════════════════════════════

"""
    PatternClassifier

Ensemble classifier combining multiple weak classifiers.
"""
mutable struct PatternClassifier
    decision_trees::Vector{Dict{String, Any}}
    n_estimators::Int
    max_depth::Int
    classes::Vector{VulnClass}
    feature_importance::Dict{String, Float64}
    trained::Bool
    
    function PatternClassifier(; n_estimators::Int=10, max_depth::Int=5)
        new(
            Dict{String, Any}[],
            n_estimators,
            max_depth,
            collect(instances(VulnClass)),
            Dict{String, Float64}(),
            false
        )
    end
end

# ══════════════════════════════════════════════════════════════════════════════
# DECISION TREE IMPLEMENTATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Tree node for decision tree.
"""
struct TreeNode
    feature_idx::Int
    threshold::Float64
    left::Union{TreeNode, Int}  # Child or class index
    right::Union{TreeNode, Int}
    is_leaf::Bool
    class_idx::Int
    confidence::Float64
end

"""
Leaf node constructor.
"""
function leaf_node(class_idx::Int, confidence::Float64)
    TreeNode(0, 0.0, 0, 0, true, class_idx, confidence)
end

"""
Split node constructor.
"""
function split_node(feature_idx::Int, threshold::Float64, 
                   left::Union{TreeNode, Int}, right::Union{TreeNode, Int})
    TreeNode(feature_idx, threshold, left, right, false, 0, 0.0)
end

"""
Calculate Gini impurity.
"""
function gini_impurity(y::Vector{Int}, n_classes::Int)::Float64
    n = length(y)
    if n == 0
        return 0.0
    end
    
    counts = zeros(Int, n_classes)
    for label in y
        if 1 <= label <= n_classes
            counts[label] += 1
        end
    end
    
    impurity = 1.0
    for c in counts
        p = c / n
        impurity -= p^2
    end
    
    return impurity
end

"""
Find best split for a feature.
"""
function find_best_split(X::Matrix{Float64}, y::Vector{Int}, 
                        feature_idx::Int, n_classes::Int)::Tuple{Float64, Float64}
    
    n = length(y)
    feature_values = X[feature_idx, :]
    
    # Get unique values
    thresholds = sort(unique(feature_values))
    
    best_threshold = 0.0
    best_gain = -Inf
    
    parent_impurity = gini_impurity(y, n_classes)
    
    for threshold in thresholds
        left_mask = feature_values .<= threshold
        right_mask = .!left_mask
        
        left_y = y[left_mask]
        right_y = y[right_mask]
        
        if isempty(left_y) || isempty(right_y)
            continue
        end
        
        n_left = length(left_y)
        n_right = length(right_y)
        
        # Information gain
        left_impurity = gini_impurity(left_y, n_classes)
        right_impurity = gini_impurity(right_y, n_classes)
        
        weighted_impurity = (n_left * left_impurity + n_right * right_impurity) / n
        gain = parent_impurity - weighted_impurity
        
        if gain > best_gain
            best_gain = gain
            best_threshold = threshold
        end
    end
    
    return (best_threshold, best_gain)
end

"""
Build decision tree recursively.
"""
function build_tree(X::Matrix{Float64}, y::Vector{Int}, 
                   n_classes::Int, depth::Int, max_depth::Int)::TreeNode
    
    n = length(y)
    
    # Stopping conditions
    if depth >= max_depth || n < 2 || length(unique(y)) == 1
        # Return leaf
        counts = zeros(Int, n_classes)
        for label in y
            if 1 <= label <= n_classes
                counts[label] += 1
            end
        end
        best_class = argmax(counts)
        confidence = n > 0 ? counts[best_class] / n : 0.0
        return leaf_node(best_class, confidence)
    end
    
    # Find best feature and threshold
    n_features = size(X, 1)
    best_feature = 1
    best_threshold = 0.0
    best_gain = -Inf
    
    for f in 1:n_features
        threshold, gain = find_best_split(X, y, f, n_classes)
        if gain > best_gain
            best_gain = gain
            best_feature = f
            best_threshold = threshold
        end
    end
    
    # No improvement - make leaf
    if best_gain <= 0
        counts = zeros(Int, n_classes)
        for label in y
            if 1 <= label <= n_classes
                counts[label] += 1
            end
        end
        best_class = argmax(counts)
        confidence = n > 0 ? counts[best_class] / n : 0.0
        return leaf_node(best_class, confidence)
    end
    
    # Split data
    left_mask = X[best_feature, :] .<= best_threshold
    right_mask = .!left_mask
    
    left_X = X[:, left_mask]
    left_y = y[left_mask]
    right_X = X[:, right_mask]
    right_y = y[right_mask]
    
    # Recursively build children
    left_child = build_tree(left_X, left_y, n_classes, depth + 1, max_depth)
    right_child = build_tree(right_X, right_y, n_classes, depth + 1, max_depth)
    
    return split_node(best_feature, best_threshold, left_child, right_child)
end

"""
Predict with single tree.
"""
function tree_predict(tree::TreeNode, x::Vector{Float64})::Tuple{Int, Float64}
    node = tree
    
    while !node.is_leaf
        if x[node.feature_idx] <= node.threshold
            node = node.left
        else
            node = node.right
        end
    end
    
    return (node.class_idx, node.confidence)
end

# ══════════════════════════════════════════════════════════════════════════════
# CLASSIFIER TRAINING
# ══════════════════════════════════════════════════════════════════════════════

"""
    train!(classifier::PatternClassifier, X::Matrix, y::Vector)

Train the ensemble classifier.
"""
function train!(classifier::PatternClassifier, 
               X::Matrix{Float64}, y::Vector{VulnClass})
    
    n_samples = size(X, 2)
    n_features = size(X, 1)
    n_classes = length(classifier.classes)
    
    # Convert labels to integers
    y_int = [Int(label) for label in y]
    
    @info "Training classifier" samples=n_samples features=n_features estimators=classifier.n_estimators
    
    classifier.decision_trees = []
    feature_importance_counts = Dict{Int, Float64}()
    
    for i in 1:classifier.n_estimators
        # Bootstrap sampling
        indices = rand(1:n_samples, n_samples)
        X_boot = X[:, indices]
        y_boot = y_int[indices]
        
        # Feature subsampling (sqrt of features)
        n_selected = max(1, Int(ceil(sqrt(n_features))))
        selected_features = randperm(n_features)[1:n_selected]
        X_selected = X_boot[selected_features, :]
        
        # Build tree
        tree = build_tree(X_selected, y_boot, n_classes, 0, classifier.max_depth)
        
        # Store tree with feature mapping
        push!(classifier.decision_trees, Dict{String, Any}(
            "tree" => tree,
            "features" => selected_features
        ))
        
        # Track feature importance
        for f in selected_features
            feature_importance_counts[f] = get(feature_importance_counts, f, 0.0) + 1.0
        end
    end
    
    # Normalize feature importance
    total = sum(values(feature_importance_counts))
    feature_names = ["feature_$i" for i in 1:n_features]
    
    for (f, count) in feature_importance_counts
        if f <= length(feature_names)
            classifier.feature_importance[feature_names[f]] = count / total
        end
    end
    
    classifier.trained = true
    @info "Classifier training complete"
end

"""
    classify(classifier::PatternClassifier, features::Vector) -> VulnClass

Classify a single sample.
"""
function classify(classifier::PatternClassifier, 
                 features::Vector{Float64})::Tuple{VulnClass, Float64}
    
    if !classifier.trained || isempty(classifier.decision_trees)
        return (INJECTION, 0.0)  # Default
    end
    
    # Ensemble voting
    votes = Dict{Int, Float64}()
    
    for tree_info in classifier.decision_trees
        tree = tree_info["tree"]
        selected_features = tree_info["features"]
        
        # Extract selected features
        x_selected = features[selected_features]
        
        # Get prediction
        class_idx, confidence = tree_predict(tree, x_selected)
        votes[class_idx] = get(votes, class_idx, 0.0) + confidence
    end
    
    # Find majority vote
    best_class = 1
    best_score = 0.0
    
    for (class_idx, score) in votes
        if score > best_score
            best_score = score
            best_class = class_idx
        end
    end
    
    # Convert to VulnClass
    vuln_class = VulnClass(best_class)
    confidence = best_score / length(classifier.decision_trees)
    
    return (vuln_class, confidence)
end

"""
    classify_batch(classifier::PatternClassifier, X::Matrix) 
        -> Vector{Tuple{VulnClass, Float64}}

Classify multiple samples.
"""
function classify_batch(classifier::PatternClassifier, 
                       X::Matrix{Float64})::Vector{Tuple{VulnClass, Float64}}
    
    n_samples = size(X, 2)
    results = Vector{Tuple{VulnClass, Float64}}(undef, n_samples)
    
    Threads.@threads for i in 1:n_samples
        results[i] = classify(classifier, X[:, i])
    end
    
    return results
end

# ══════════════════════════════════════════════════════════════════════════════
# PROBABILITY DISTRIBUTION
# ══════════════════════════════════════════════════════════════════════════════

"""
    classify_proba(classifier::PatternClassifier, features::Vector) 
        -> Dict{VulnClass, Float64}

Get probability distribution over all classes.
"""
function classify_proba(classifier::PatternClassifier, 
                       features::Vector{Float64})::Dict{VulnClass, Float64}
    
    proba = Dict{VulnClass, Float64}()
    
    for vuln_class in classifier.classes
        proba[vuln_class] = 0.0
    end
    
    if !classifier.trained || isempty(classifier.decision_trees)
        return proba
    end
    
    # Collect votes
    votes = Dict{Int, Float64}()
    
    for tree_info in classifier.decision_trees
        tree = tree_info["tree"]
        selected_features = tree_info["features"]
        
        x_selected = features[selected_features]
        class_idx, confidence = tree_predict(tree, x_selected)
        
        votes[class_idx] = get(votes, class_idx, 0.0) + 1.0
    end
    
    # Normalize to probabilities
    total = sum(values(votes))
    
    if total > 0
        for (class_idx, count) in votes
            if 1 <= class_idx <= length(classifier.classes)
                proba[classifier.classes[class_idx]] = count / total
            end
        end
    end
    
    return proba
end

# ══════════════════════════════════════════════════════════════════════════════
# EVALUATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Evaluate classifier accuracy.
"""
function evaluate(classifier::PatternClassifier, 
                 X::Matrix{Float64}, y::Vector{VulnClass})::Dict{String, Float64}
    
    n_samples = length(y)
    correct = 0
    
    confusion = Dict{Tuple{VulnClass, VulnClass}, Int}()
    
    for i in 1:n_samples
        predicted, _ = classify(classifier, X[:, i])
        actual = y[i]
        
        if predicted == actual
            correct += 1
        end
        
        key = (actual, predicted)
        confusion[key] = get(confusion, key, 0) + 1
    end
    
    accuracy = correct / n_samples
    
    # Calculate per-class metrics
    per_class_precision = Float64[]
    per_class_recall = Float64[]
    
    for vuln_class in classifier.classes
        tp = get(confusion, (vuln_class, vuln_class), 0)
        
        # Predicted as this class
        fp = 0
        for other_class in classifier.classes
            if other_class != vuln_class
                fp += get(confusion, (other_class, vuln_class), 0)
            end
        end
        
        # Actual this class
        fn = 0
        for other_class in classifier.classes
            if other_class != vuln_class
                fn += get(confusion, (vuln_class, other_class), 0)
            end
        end
        
        precision = (tp + fp) > 0 ? tp / (tp + fp) : 0.0
        recall = (tp + fn) > 0 ? tp / (tp + fn) : 0.0
        
        push!(per_class_precision, precision)
        push!(per_class_recall, recall)
    end
    
    macro_precision = mean(per_class_precision)
    macro_recall = mean(per_class_recall)
    macro_f1 = 2 * macro_precision * macro_recall / (macro_precision + macro_recall + 1e-10)
    
    return Dict{String, Float64}(
        "accuracy" => accuracy,
        "macro_precision" => macro_precision,
        "macro_recall" => macro_recall,
        "macro_f1" => macro_f1
    )
end

# ══════════════════════════════════════════════════════════════════════════════
# SERIALIZATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Save classifier to file.
"""
function save_classifier(classifier::PatternClassifier, filepath::String)
    open(filepath, "w") do io
        serialize(io, classifier)
    end
    @info "Classifier saved" path=filepath
end

"""
Load classifier from file.
"""
function load_classifier(filepath::String)::PatternClassifier
    return open(filepath, "r") do io
        deserialize(io)
    end
end
