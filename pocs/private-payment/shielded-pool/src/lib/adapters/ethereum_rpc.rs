use alloy::{
    network::EthereumWallet,
    primitives::{
        Address,
        B256,
        Bytes,
        U256,
    },
    providers::{
        DynProvider,
        ProviderBuilder,
    },
    signers::local::PrivateKeySigner,
    sol,
};

use crate::{
    domain::proof::{
        DepositProof,
        TransferProof,
        WithdrawProof,
    },
    ports::on_chain::{
        AttestationData,
        OnChain,
        OnChainError,
        TxReceipt,
    },
};

// Generate contract bindings using Alloy's sol! macro
sol! {
    #[sol(rpc)]
    interface IShieldedPool {
        function commitmentRoot() external view returns (bytes32);
        function getCommitmentCount() external view returns (uint256);
        function nullifiers(bytes32 nullifier) external view returns (bool);
        function isKnownRoot(bytes32 root) external view returns (bool);
        function supportedTokens(address token) external view returns (bool);

        function deposit(
            bytes calldata proof,
            bytes32 commitment,
            address token,
            uint256 amount,
            address fundingAddress,
            bytes calldata encryptedNote
        ) external;

        function transfer(
            bytes calldata proof,
            bytes32[2] calldata inputNullifiers,
            bytes32[2] calldata outputCommitments,
            bytes32 root,
            bytes calldata encryptedNotes
        ) external;

        function withdraw(
            bytes calldata proof,
            bytes32 nullifier,
            address token,
            uint256 amount,
            address recipient,
            bytes32 root
        ) external;

        function addSupportedToken(address token) external;
    }

    #[sol(rpc)]
    interface IAttestationRegistry {
        function attestationRoot() external view returns (bytes32);
        function getAttestationCount() external view returns (uint256);
        // Note: getMerkleProof removed - clients maintain local trees using lean-imt
        function leafAtIndex(uint40 index) external view returns (bytes32);
        function authorizedAttesters(address attester) external view returns (bool);

        function addAttester(address attester) external;
        function addAttestation(bytes32 subjectPubkeyHash, uint64 expiresAt) external returns (bytes32);

        event AttestationAdded(
            bytes32 indexed leaf,
            bytes32 indexed subjectPubkeyHash,
            address indexed attester,
            uint64 issuedAt,
            uint64 expiresAt
        );
    }

    #[sol(rpc)]
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }

    #[sol(rpc)]
    interface IMockERC20 {
        function mint(address to, uint256 amount) external;
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }
}

/// Ethereum RPC adapter for interacting with shielded pool contracts.
pub struct EthereumRpc {
    provider: DynProvider,
    shielded_pool: Address,
    attestation_registry: Address,
    signer_address: Address,
}

impl EthereumRpc {
    /// Create a new EthereumRpc instance.
    ///
    /// # Arguments
    /// * `rpc_url` - The HTTP RPC endpoint URL
    /// * `private_key` - The private key for signing transactions
    /// * `shielded_pool` - The ShieldedPool contract address
    /// * `attestation_registry` - The AttestationRegistry contract address
    pub async fn new(
        rpc_url: &str,
        private_key: &str,
        shielded_pool: Address,
        attestation_registry: Address,
    ) -> Result<Self, OnChainError> {
        let signer: PrivateKeySigner = private_key.parse().map_err(|e| {
            OnChainError::SignerError(format!("Invalid private key: {}", e))
        })?;

        let signer_address = signer.address();
        let wallet = EthereumWallet::from(signer);
        let provider =
            DynProvider::new(ProviderBuilder::new().wallet(wallet).connect_http(
                rpc_url.parse().map_err(|e| {
                    OnChainError::RpcError(format!("Invalid RPC URL: {}", e))
                })?,
            ));

        Ok(Self {
            provider,
            shielded_pool,
            attestation_registry,
            signer_address,
        })
    }

    /// Get the signer's address.
    pub fn signer_address(&self) -> Address {
        self.signer_address
    }

    /// Get the ShieldedPool contract address.
    pub fn shielded_pool_address(&self) -> Address {
        self.shielded_pool
    }

    /// Get the AttestationRegistry contract address.
    pub fn attestation_registry_address(&self) -> Address {
        self.attestation_registry
    }

    /// Helper to convert alloy transaction receipt to our TxReceipt type.
    fn convert_receipt(receipt: &alloy::rpc::types::TransactionReceipt) -> TxReceipt {
        TxReceipt {
            tx_hash: receipt.transaction_hash,
            block_number: receipt.block_number.unwrap_or(0),
            gas_used: receipt.gas_used,
            success: receipt.status(),
        }
    }
}

impl OnChain for EthereumRpc {
    // ========== ShieldedPool Reads ==========

    async fn get_commitment_root(&self) -> Result<B256, OnChainError> {
        let pool = IShieldedPool::new(self.shielded_pool, &self.provider);
        let result = pool
            .commitmentRoot()
            .call()
            .await
            .map_err(|e| OnChainError::ContractError(e.to_string()))?;
        Ok(result.into())
    }

    async fn get_commitment_count(&self) -> Result<u64, OnChainError> {
        let pool = IShieldedPool::new(self.shielded_pool, &self.provider);
        let result = pool
            .getCommitmentCount()
            .call()
            .await
            .map_err(|e| OnChainError::ContractError(e.to_string()))?;
        Ok(result.try_into().unwrap_or(u64::MAX))
    }

    // Note: get_commitment_merkle_proof removed - clients maintain local trees using lean-imt

    async fn is_nullifier_spent(&self, nullifier: B256) -> Result<bool, OnChainError> {
        let pool = IShieldedPool::new(self.shielded_pool, &self.provider);
        let result = pool
            .nullifiers(nullifier)
            .call()
            .await
            .map_err(|e| OnChainError::ContractError(e.to_string()))?;
        Ok(result)
    }

    async fn is_known_root(&self, root: B256) -> Result<bool, OnChainError> {
        let pool = IShieldedPool::new(self.shielded_pool, &self.provider);
        let result = pool
            .isKnownRoot(root)
            .call()
            .await
            .map_err(|e| OnChainError::ContractError(e.to_string()))?;
        Ok(result)
    }

    async fn is_token_supported(&self, token: Address) -> Result<bool, OnChainError> {
        let pool = IShieldedPool::new(self.shielded_pool, &self.provider);
        let result = pool
            .supportedTokens(token)
            .call()
            .await
            .map_err(|e| OnChainError::ContractError(e.to_string()))?;
        Ok(result)
    }

    // ========== AttestationRegistry Reads ==========

    async fn get_attestation_root(&self) -> Result<B256, OnChainError> {
        let registry =
            IAttestationRegistry::new(self.attestation_registry, &self.provider);
        let result = registry
            .attestationRoot()
            .call()
            .await
            .map_err(|e| OnChainError::ContractError(e.to_string()))?;
        Ok(result.into())
    }

    async fn get_attestation_count(&self) -> Result<u64, OnChainError> {
        let registry =
            IAttestationRegistry::new(self.attestation_registry, &self.provider);
        let result = registry
            .getAttestationCount()
            .call()
            .await
            .map_err(|e| OnChainError::ContractError(e.to_string()))?;
        Ok(result.try_into().unwrap())
    }

    // Note: get_attestation_merkle_proof removed - clients maintain local trees using lean-imt

    async fn get_attestation_leaf(&self, index: u64) -> Result<B256, OnChainError> {
        let registry =
            IAttestationRegistry::new(self.attestation_registry, &self.provider);
        let result = registry
            .leafAtIndex(index.try_into().unwrap())
            .call()
            .await
            .map_err(|e| OnChainError::ContractError(e.to_string()))?;
        Ok(result)
    }

    async fn is_authorized_attester(
        &self,
        attester: Address,
    ) -> Result<bool, OnChainError> {
        let registry =
            IAttestationRegistry::new(self.attestation_registry, &self.provider);
        let result = registry
            .authorizedAttesters(attester)
            .call()
            .await
            .map_err(|e| OnChainError::ContractError(e.to_string()))?;
        Ok(result)
    }

    // ========== ShieldedPool Writes ==========

    async fn deposit(
        &self,
        proof: &DepositProof,
        commitment: B256,
        token: Address,
        amount: U256,
        funding_address: Address,
        encrypted_note: Bytes,
    ) -> Result<TxReceipt, OnChainError> {
        let pool = IShieldedPool::new(self.shielded_pool, &self.provider);

        let receipt = pool
            .deposit(
                proof.proof.clone(),
                commitment,
                token,
                amount,
                funding_address,
                encrypted_note,
            )
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;

        if !receipt.status() {
            return Err(OnChainError::TransactionReverted("Deposit reverted".into()));
        }

        Ok(Self::convert_receipt(&receipt))
    }

    async fn transfer(
        &self,
        proof: &TransferProof,
        nullifiers: [B256; 2],
        commitments: [B256; 2],
        root: B256,
        encrypted_notes: Bytes,
    ) -> Result<TxReceipt, OnChainError> {
        let pool = IShieldedPool::new(self.shielded_pool, &self.provider);

        let receipt = pool
            .transfer(
                proof.proof.clone(),
                nullifiers,
                commitments,
                root,
                encrypted_notes,
            )
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;

        if !receipt.status() {
            return Err(OnChainError::TransactionReverted(
                "Transfer reverted".into(),
            ));
        }

        Ok(Self::convert_receipt(&receipt))
    }

    async fn withdraw(
        &self,
        proof: &WithdrawProof,
        nullifier: B256,
        token: Address,
        amount: U256,
        recipient: Address,
        root: B256,
    ) -> Result<TxReceipt, OnChainError> {
        let pool = IShieldedPool::new(self.shielded_pool, &self.provider);

        let receipt = pool
            .withdraw(
                proof.proof.clone(),
                nullifier,
                token,
                amount,
                recipient,
                root,
            )
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;

        if !receipt.status() {
            return Err(OnChainError::TransactionReverted(
                "Withdraw reverted".into(),
            ));
        }

        Ok(Self::convert_receipt(&receipt))
    }

    // ========== Admin Operations ==========

    async fn add_attester(&self, attester: Address) -> Result<TxReceipt, OnChainError> {
        let registry =
            IAttestationRegistry::new(self.attestation_registry, &self.provider);

        let receipt = registry
            .addAttester(attester)
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;

        if !receipt.status() {
            return Err(OnChainError::TransactionReverted(
                "addAttester reverted".into(),
            ));
        }

        Ok(Self::convert_receipt(&receipt))
    }

    async fn add_attestation(
        &self,
        subject_pubkey_hash: B256,
        expires_at: u64,
    ) -> Result<(AttestationData, TxReceipt), OnChainError> {
        let registry =
            IAttestationRegistry::new(self.attestation_registry, &self.provider);

        // Get the current count before adding (this will be the new leaf's index)
        let index_before = self.get_attestation_count().await?;

        let receipt = registry
            .addAttestation(subject_pubkey_hash, expires_at)
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;

        if !receipt.status() {
            return Err(OnChainError::TransactionReverted(
                "addAttestation reverted".into(),
            ));
        }

        // Parse the AttestationAdded event to get all fields
        let event_data = receipt
            .inner
            .logs()
            .iter()
            .find_map(|log| {
                log.log_decode::<IAttestationRegistry::AttestationAdded>()
                    .ok()
                    .map(|event| {
                        let inner = event.inner;
                        AttestationData {
                            leaf: inner.leaf,
                            index: index_before,
                            attester: inner.attester,
                            issued_at: inner.issuedAt,
                            expires_at: inner.expiresAt,
                        }
                    })
            })
            .ok_or_else(|| {
                OnChainError::InvalidResponse("AttestationAdded event not found".into())
            })?;

        Ok((event_data, Self::convert_receipt(&receipt)))
    }

    async fn add_supported_token(
        &self,
        token: Address,
    ) -> Result<TxReceipt, OnChainError> {
        let pool = IShieldedPool::new(self.shielded_pool, &self.provider);

        let receipt = pool
            .addSupportedToken(token)
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;

        if !receipt.status() {
            return Err(OnChainError::TransactionReverted(
                "addSupportedToken reverted".into(),
            ));
        }

        Ok(Self::convert_receipt(&receipt))
    }

    // ========== ERC20 Operations ==========

    async fn approve_token(
        &self,
        token: Address,
        amount: U256,
    ) -> Result<TxReceipt, OnChainError> {
        let erc20 = IERC20::new(token, &self.provider);

        let receipt = erc20
            .approve(self.shielded_pool, amount)
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;

        if !receipt.status() {
            return Err(OnChainError::TransactionReverted("approve reverted".into()));
        }

        Ok(Self::convert_receipt(&receipt))
    }

    async fn get_token_balance(
        &self,
        token: Address,
        account: Address,
    ) -> Result<U256, OnChainError> {
        let erc20 = IERC20::new(token, &self.provider);
        let result = erc20
            .balanceOf(account)
            .call()
            .await
            .map_err(|e| OnChainError::ContractError(e.to_string()))?;
        Ok(result)
    }

    async fn mint_mock_token(
        &self,
        token: Address,
        to: Address,
        amount: U256,
    ) -> Result<TxReceipt, OnChainError> {
        let mock_token = IMockERC20::new(token, &self.provider);

        let receipt = mock_token
            .mint(to, amount)
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;

        if !receipt.status() {
            return Err(OnChainError::TransactionReverted("mint reverted".into()));
        }

        Ok(Self::convert_receipt(&receipt))
    }
}
