# Oracle Installation

```julia
using Pkg
Pkg.add(url="https://github.com/bad-antics/oracle")
```

## From Source
```bash
git clone https://github.com/bad-antics/oracle
cd oracle
julia --project -e 'using Pkg; Pkg.instantiate()'
```

## Requirements
- Julia 1.9+
- Flux.jl (ML framework)
