// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

/// @title IPropAMMRetail
/// @notice Optional extension a propAMM implements to price retail flow apart from the rest.
/// Advertised via ERC-165.
/// @dev A venue that has confirmed a swap is retail signs an attestation for it, and the swap
/// that carries the attestation fills at the propAMM's retail price. `IPropAMM.swap` and
/// `IPropAMM.quote` are untouched and keep the price everyone else gets.
///
/// The two quotes take no attestation: they say what an attested swap would get, so a router
/// can rank and split a retail order as it does any other, and a frontend can show the price.
/// Only `swapRetail`, where tokens move, checks one.
interface IPropAMMRetail {
    /// @notice What a venue signs to mark one swap as retail. EIP-712 typed data, under the
    /// domain `(name "PropAMM", version "1", chainId, verifyingContract)` of the instance the
    /// swap is for, so it is good on that instance and chain only.
    /// @param account An account that has to take part in the swap: its transaction's sender
    /// (`tx.origin`), the caller of `swapRetail`, or the swap's `recipient`. The user's own
    /// wallet for a swap the user sends; the venue's relayer for one the venue sends for them.
    /// It ties the attestation to someone, so a copy lifted from the mempool is of no use to
    /// anyone else. Never a contract anyone can call (a router, an aggregator): every swap made
    /// through one would pass as that account.
    /// @param tokenIn The token the swap sells.
    /// @param tokenOut The token the swap buys.
    /// @param maxAmountIn The most `tokenIn` the swap may sell. A maximum, not the amount: a
    /// router splitting an order across venues sends each of them part of it.
    /// @param expiry Unix timestamp after which the attestation is no longer valid.
    /// @param nonce Picked by the signer, and good once per signer: the swap that uses an
    /// attestation spends its nonce, whatever part of `maxAmountIn` it filled. Nonces need not
    /// be used in order.
    struct RetailAttestation {
        address account;
        address tokenIn;
        address tokenOut;
        uint256 maxAmountIn;
        uint256 expiry;
        uint256 nonce;
    }

    /// @notice Emitted once per retail swap, next to its `IPropAMM.Swapped`.
    /// @param signer The retail signer whose attestation the swap used.
    /// @param account The account the attestation named.
    /// @param nonce The nonce the swap spent.
    event RetailFill(address indexed signer, address indexed account, uint256 nonce);

    /// @notice `IPropAMM.quote` at the retail price: what `swapRetail` would deliver for
    /// `amountIn` under a valid attestation.
    /// @dev Reverts wherever `IPropAMM.quote` does.
    function quoteRetail(address tokenIn, address tokenOut, uint256 amountIn) external returns (uint256 amountOut);

    /// @notice `IPropAMMFillable.quoteFillable` at the retail price.
    function quoteFillableRetail(address tokenIn, address tokenOut, uint256 amountIn)
        external
        returns (uint256 fillableAmountIn, uint256 amountOut);

    /// @notice `IPropAMM.swap` at the retail price, for a swap that carries a retail signer's
    /// attestation. Push payment, like `swap`.
    /// @dev MUST revert, rather than fill at the price `swap` gives, when the attestation does
    /// not hold: signed by none of the instance's retail signers, expired, already used, for
    /// another pair or direction, for less than `amountIn`, or naming an account that takes no
    /// part in the swap. The caller ranked this venue on `quoteRetail`.
    /// @param attestation What the venue signed.
    /// @param signature The signer's 65-byte ECDSA signature over `attestation`.
    function swapRetail(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut,
        address recipient,
        uint256 deadline,
        RetailAttestation calldata attestation,
        bytes calldata signature
    ) external returns (uint256 amountOut);
}
