pragma runar ^0.1.0;

/// @title NoCtorSol
/// @notice R-114: a `.runar.sol` contract with NO constructor.
///
/// Every other surface where a constructor is optional (the Go and Rust DSLs)
/// has the parser synthesise one from the declared properties, with `super()`
/// as its first statement — see CLAUDE.md, "Auto-generated constructors MUST
/// include super() as the first statement". Four tiers did that here and three
/// did not:
///
///   ts / go / zig / ruby   ACCEPT, script 00a0, constructor param [threshold]
///   rust                   parse error "Contract must have a constructor"
///   python / java          synthesised one WITHOUT super(), then rejected
///                          themselves: "constructor must call super() as its
///                          first statement"
///
/// Accept-or-reject divergence is a direct breach of the frontend-parity
/// invariant, and this shape is what the rejection corpus cannot catch: it is
/// a VALID contract, so it belongs in the acceptance corpus.
contract NoCtorSol is SmartContract {
    bigint immutable threshold;

    function verify(bigint x) public {
        require(x > threshold);
    }
}
