"""
Code embeddings for ML-based vulnerability prediction.
"""

# ══════════════════════════════════════════════════════════════════════════════
# CODE EMBEDDER
# ══════════════════════════════════════════════════════════════════════════════

"""
    CodeEmbedder

Generates dense vector representations of code for ML analysis.
"""
mutable struct CodeEmbedder
    vocab::Dict{String, Int}
    embedding_dim::Int
    max_seq_length::Int
    embeddings::Matrix{Float32}
    config::Dict{Symbol, Any}
    
    function CodeEmbedder(; embedding_dim::Int=128, max_seq_length::Int=512, kwargs...)
        vocab = build_default_vocab()
        embeddings = randn(Float32, embedding_dim, length(vocab)) .* 0.1f0
        new(vocab, embedding_dim, max_seq_length, embeddings, Dict{Symbol, Any}(kwargs))
    end
end

"""
Build default vocabulary from common code tokens.
"""
function build_default_vocab()::Dict{String, Int}
    vocab = Dict{String, Int}()
    idx = 1
    
    # Special tokens
    for token in ["<PAD>", "<UNK>", "<BOS>", "<EOS>"]
        vocab[token] = idx
        idx += 1
    end
    
    # Keywords (common across languages)
    keywords = [
        "if", "else", "elif", "for", "while", "do", "switch", "case",
        "return", "break", "continue", "try", "catch", "throw", "finally",
        "function", "def", "fn", "func", "class", "struct", "interface",
        "public", "private", "protected", "static", "const", "var", "let",
        "import", "export", "from", "require", "include", "using",
        "new", "delete", "this", "self", "super", "null", "nil", "None",
        "true", "false", "True", "False", "void", "int", "string", "bool",
        "async", "await", "yield", "lambda", "with", "as", "in", "is",
    ]
    
    for kw in keywords
        vocab[kw] = idx
        idx += 1
    end
    
    # Security-relevant tokens
    security_tokens = [
        "password", "secret", "key", "token", "auth", "login", "session",
        "user", "admin", "root", "sudo", "credential", "certificate",
        "encrypt", "decrypt", "hash", "sign", "verify", "salt", "iv",
        "sql", "query", "execute", "prepare", "cursor", "database",
        "eval", "exec", "system", "shell", "command", "process",
        "input", "output", "read", "write", "open", "close", "file",
        "request", "response", "http", "https", "url", "socket", "connect",
        "buffer", "memory", "malloc", "free", "pointer", "array",
        "sanitize", "escape", "encode", "decode", "validate", "filter",
        "injection", "xss", "csrf", "ssrf", "overflow", "traversal",
    ]
    
    for token in security_tokens
        vocab[token] = idx
        idx += 1
    end
    
    # Common operators and delimiters
    operators = [
        "+", "-", "*", "/", "%", "=", "==", "!=", "<", ">", "<=", ">=",
        "&&", "||", "!", "&", "|", "^", "~", "<<", ">>",
        "+=", "-=", "*=", "/=", "++", "--",
        ".", ",", ";", ":", "(", ")", "[", "]", "{", "}",
        "->", "=>", "::", "...",
    ]
    
    for op in operators
        vocab[op] = idx
        idx += 1
    end
    
    return vocab
end

"""
    embed(embedder::CodeEmbedder, code::String) -> Vector{Float32}

Generate embedding vector for code.
"""
function embed(embedder::CodeEmbedder, code::String; 
               language::Symbol=:auto)::Vector{Float32}
    
    # Tokenize
    tokens = tokenize_for_embedding(code, language)
    
    # Convert to indices
    indices = tokens_to_indices(tokens, embedder.vocab, embedder.max_seq_length)
    
    # Get embeddings
    token_embeddings = [embedder.embeddings[:, i] for i in indices]
    
    # Pool embeddings (mean pooling)
    if isempty(token_embeddings)
        return zeros(Float32, embedder.embedding_dim)
    end
    
    pooled = mean(token_embeddings)
    
    # Add positional features
    pos_features = compute_positional_features(tokens, embedder.embedding_dim ÷ 4)
    
    # Concatenate and normalize
    combined = vcat(pooled, pos_features)
    norm_val = sqrt(sum(combined .^ 2))
    if norm_val > 0
        combined ./= norm_val
    end
    
    return combined[1:embedder.embedding_dim]
end

"""
Tokenize code for embedding.
"""
function tokenize_for_embedding(code::String, language::Symbol)::Vector{String}
    tokens = String[]
    
    # Add BOS token
    push!(tokens, "<BOS>")
    
    # Simple tokenization (in production, use language-specific tokenizer)
    patterns = [
        r"[a-zA-Z_][a-zA-Z0-9_]*",     # Identifiers
        r"0[xX][0-9a-fA-F]+",           # Hex
        r"\d+\.?\d*",                    # Numbers
        r"\"[^\"]*\"",                   # Strings
        r"'[^']*'",                      # Char/strings
        r"[+\-*/%=<>!&|^~]+",           # Operators
        r"[\[\]{}();,.:]+",              # Delimiters
    ]
    
    remaining = code
    while !isempty(remaining) && length(tokens) < 1000
        # Skip whitespace
        m = match(r"^\s+", remaining)
        if !isnothing(m)
            remaining = remaining[length(m.match)+1:end]
            continue
        end
        
        # Try patterns
        matched = false
        for pattern in patterns
            m = match(Regex("^" * pattern.pattern), remaining)
            if !isnothing(m)
                # Normalize token
                token = lowercase(m.match)
                
                # Truncate long tokens
                if length(token) > 20
                    token = token[1:20]
                end
                
                push!(tokens, token)
                remaining = remaining[length(m.match)+1:end]
                matched = true
                break
            end
        end
        
        if !matched && !isempty(remaining)
            remaining = remaining[2:end]
        end
    end
    
    # Add EOS token
    push!(tokens, "<EOS>")
    
    return tokens
end

"""
Convert tokens to vocabulary indices.
"""
function tokens_to_indices(tokens::Vector{String}, vocab::Dict{String, Int},
                          max_length::Int)::Vector{Int}
    
    unk_idx = vocab["<UNK>"]
    pad_idx = vocab["<PAD>"]
    
    indices = Int[]
    
    for token in tokens[1:min(length(tokens), max_length)]
        idx = get(vocab, token, unk_idx)
        push!(indices, idx)
    end
    
    # Pad if needed
    while length(indices) < max_length
        push!(indices, pad_idx)
    end
    
    return indices[1:max_length]
end

"""
Compute positional features.
"""
function compute_positional_features(tokens::Vector{String}, dim::Int)::Vector{Float32}
    features = zeros(Float32, dim)
    
    n = length(tokens)
    n == 0 && return features
    
    # Position of security-related tokens
    security_words = Set(["password", "secret", "key", "token", "auth", 
                          "eval", "exec", "system", "query", "sql"])
    
    for (i, token) in enumerate(tokens)
        if lowercase(token) in security_words
            pos = Float32(i) / n
            idx = min(dim, Int(ceil(pos * dim)))
            features[idx] += 1.0f0
        end
    end
    
    # Normalize
    max_val = maximum(abs.(features))
    if max_val > 0
        features ./= max_val
    end
    
    return features
end

# ══════════════════════════════════════════════════════════════════════════════
# BATCH EMBEDDING
# ══════════════════════════════════════════════════════════════════════════════

"""
Embed multiple code samples.
"""
function embed_batch(embedder::CodeEmbedder, codes::Vector{String};
                    language::Symbol=:auto)::Matrix{Float32}
    
    n = length(codes)
    embeddings = Matrix{Float32}(undef, embedder.embedding_dim, n)
    
    for (i, code) in enumerate(codes)
        embeddings[:, i] = embed(embedder, code; language=language)
    end
    
    return embeddings
end

"""
Compute similarity between two code embeddings.
"""
function embedding_similarity(e1::Vector{Float32}, e2::Vector{Float32})::Float64
    # Cosine similarity
    dot_prod = sum(e1 .* e2)
    norm1 = sqrt(sum(e1 .^ 2))
    norm2 = sqrt(sum(e2 .^ 2))
    
    if norm1 > 0 && norm2 > 0
        return Float64(dot_prod / (norm1 * norm2))
    end
    
    return 0.0
end

"""
Find most similar code from a corpus.
"""
function find_similar(embedder::CodeEmbedder, query_code::String,
                     corpus::Vector{String}; top_k::Int=5)::Vector{Tuple{Int, Float64}}
    
    query_emb = embed(embedder, query_code)
    corpus_emb = embed_batch(embedder, corpus)
    
    similarities = Float64[]
    for i in 1:length(corpus)
        sim = embedding_similarity(query_emb, corpus_emb[:, i])
        push!(similarities, sim)
    end
    
    # Sort by similarity
    sorted_indices = sortperm(similarities, rev=true)
    
    return [(i, similarities[i]) for i in sorted_indices[1:min(top_k, length(sorted_indices))]]
end

# ══════════════════════════════════════════════════════════════════════════════
# EMBEDDING TRAINING (Simplified)
# ══════════════════════════════════════════════════════════════════════════════

"""
Update embeddings from training data (simplified contrastive learning).
"""
function train_embeddings!(embedder::CodeEmbedder, 
                          positive_pairs::Vector{Tuple{String, String}},
                          negative_pairs::Vector{Tuple{String, String}};
                          learning_rate::Float32=0.01f0,
                          epochs::Int=10)
    
    @info "Training embeddings" pairs=length(positive_pairs) epochs=epochs
    
    for epoch in 1:epochs
        total_loss = 0.0f0
        
        # Process positive pairs
        for (code1, code2) in positive_pairs
            e1 = embed(embedder, code1)
            e2 = embed(embedder, code2)
            
            # Contrastive loss: positive pairs should be similar
            sim = embedding_similarity(e1, e2)
            loss = max(0.0f0, 1.0f0 - Float32(sim))
            total_loss += loss
            
            # Simple gradient update (in production, use proper AD)
            if loss > 0
                update_embeddings_for_similarity!(embedder, code1, code2, learning_rate)
            end
        end
        
        # Process negative pairs
        for (code1, code2) in negative_pairs
            e1 = embed(embedder, code1)
            e2 = embed(embedder, code2)
            
            # Contrastive loss: negative pairs should be dissimilar
            sim = embedding_similarity(e1, e2)
            loss = max(0.0f0, Float32(sim) - 0.3f0)
            total_loss += loss
            
            if loss > 0
                update_embeddings_for_dissimilarity!(embedder, code1, code2, learning_rate)
            end
        end
        
        @info "Epoch $epoch" loss=total_loss
    end
end

"""
Update embeddings to increase similarity (simplified).
"""
function update_embeddings_for_similarity!(embedder::CodeEmbedder, 
                                          code1::String, code2::String,
                                          lr::Float32)
    tokens1 = tokenize_for_embedding(code1, :auto)
    tokens2 = tokenize_for_embedding(code2, :auto)
    
    # Move common token embeddings closer
    common = intersect(Set(tokens1), Set(tokens2))
    
    for token in common
        if haskey(embedder.vocab, token)
            idx = embedder.vocab[token]
            # Add small random perturbation toward mean
            embedder.embeddings[:, idx] .+= randn(Float32, embedder.embedding_dim) .* lr
        end
    end
end

"""
Update embeddings to decrease similarity (simplified).
"""
function update_embeddings_for_dissimilarity!(embedder::CodeEmbedder,
                                             code1::String, code2::String,
                                             lr::Float32)
    tokens1 = tokenize_for_embedding(code1, :auto)
    tokens2 = tokenize_for_embedding(code2, :auto)
    
    # Move different tokens further apart
    diff1 = setdiff(Set(tokens1), Set(tokens2))
    diff2 = setdiff(Set(tokens2), Set(tokens1))
    
    for token in diff1
        if haskey(embedder.vocab, token)
            idx = embedder.vocab[token]
            embedder.embeddings[:, idx] .+= randn(Float32, embedder.embedding_dim) .* lr
        end
    end
    
    for token in diff2
        if haskey(embedder.vocab, token)
            idx = embedder.vocab[token]
            embedder.embeddings[:, idx] .-= randn(Float32, embedder.embedding_dim) .* lr
        end
    end
end

# ══════════════════════════════════════════════════════════════════════════════
# SERIALIZATION
# ══════════════════════════════════════════════════════════════════════════════

"""
Save embedder to file.
"""
function save_embedder(embedder::CodeEmbedder, filepath::String)
    open(filepath, "w") do io
        serialize(io, (embedder.vocab, embedder.embedding_dim, 
                       embedder.max_seq_length, embedder.embeddings))
    end
end

"""
Load embedder from file.
"""
function load_embedder(filepath::String)::CodeEmbedder
    vocab, dim, max_len, embs = open(filepath, "r") do io
        deserialize(io)
    end
    
    embedder = CodeEmbedder(embedding_dim=dim, max_seq_length=max_len)
    embedder.vocab = vocab
    embedder.embeddings = embs
    
    return embedder
end
