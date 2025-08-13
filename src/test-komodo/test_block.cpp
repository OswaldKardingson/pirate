#include "primitives/block.h"
#include "testutils.h"
#include "komodo_extern_globals.h"
#include "consensus/validation.h"
#include "consensus/upgrades.h"
#include "coincontrol.h"
#include "miner.h"

#include <thread>
#include <gtest/gtest.h>

// Forward declaration
bool CalcPoW(CBlock *pblock);

// NB! first generateBlock call changes IsInitialBlockDownload() to false globally (!), affects other tests

TEST(test_block, header_size_is_expected) {
    // Header with an empty Equihash solution.
    CBlockHeader header;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << header;

    auto stream_size = CBlockHeader::HEADER_SIZE + 1;
    // ss.size is +1 due to data stream header of 1 byte
    EXPECT_EQ(ss.size(), stream_size);
}

TEST(test_block, TestStopAt)
{
    TestChain chain;
    auto notary = std::make_shared<TestWallet>(chain.getNotaryKey(), "notary");
    std::shared_ptr<CBlock> lastBlock = chain.generateBlock(notary); // genesis block
    ASSERT_GT( chain.GetIndex()->nHeight, 0 );
    lastBlock = chain.generateBlock(notary); // now we should be above 1
    ASSERT_GT( chain.GetIndex()->nHeight, 1);
    CBlock block;
    CValidationState state;
    KOMODO_STOPAT = 1;
    EXPECT_FALSE( chain.ConnectBlock(block, state, chain.GetIndex(), false, true) );
    KOMODO_STOPAT = 0; // to not stop other tests
}

TEST(test_block, TestConnectWithoutChecks)
{
    TestChain chain;
    auto notary = std::make_shared<TestWallet>(chain.getNotaryKey(), "notary");
    auto alice = std::make_shared<TestWallet>("alice");
    std::shared_ptr<CBlock> lastBlock = chain.generateBlock(notary); // genesis block
    ASSERT_GT( chain.GetIndex()->nHeight, 0 );
    // Add some transaction to a block
    int32_t newHeight = chain.GetIndex()->nHeight + 1;
    TransactionInProcess fundAlice = notary->CreateSpendTransaction(alice, 100000);
    // construct the block
    CBlock block;
    // first a coinbase tx
    auto consensusParams = Params().GetConsensus();
    CMutableTransaction txNew = CreateNewContextualCMutableTransaction(consensusParams, newHeight);
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vin[0].scriptSig = (CScript() << newHeight << CScriptNum(1)) + COINBASE_FLAGS;
    txNew.vout.resize(1);
    txNew.vout[0].nValue = GetBlockSubsidy(newHeight,consensusParams);
    txNew.nExpiryHeight = 0;
    block.vtx.push_back(CTransaction(txNew));
    // then the actual tx
    block.vtx.push_back(fundAlice.transaction);
    CValidationState state;
    // create a new CBlockIndex to forward to ConnectBlock
    auto index = chain.GetIndex();
    CBlockIndex newIndex;
    newIndex.pprev = index;
    EXPECT_TRUE( chain.ConnectBlock(block, state, &newIndex, true, false) );
    if (!state.IsValid() )
        FAIL() << state.GetRejectReason();
}

TEST(test_block, TestSpendInSameBlock)
{
    //setConsoleDebugging(true);
    TestChain chain;
    chainName = assetchain("TST"); // use not KMD to ensure komodo_hardfork_active() is true for tx nLockTime to be handled: both tx nLocktime and nBlockTime are set to the MTP
    auto notary = std::make_shared<TestWallet>(chain.getNotaryKey(), "notary");
    notary->SetBroadcastTransactions(true);
    auto alice = std::make_shared<TestWallet>("alice");
    alice->SetBroadcastTransactions(true);
    auto bob = std::make_shared<TestWallet>("bob");
    auto miner = std::make_shared<TestWallet>("miner");
    SelectParams(CBaseChainParams::REGTEST);
    
    std::shared_ptr<CBlock> lastBlock = chain.generateBlock(notary); // genesis block
    
    // Mine enough blocks to fully mature the coinbase output
    int maturity = Params().CoinbaseMaturity();
    for (int i = 1; i <= maturity + 5; ++i) {  // +5 extra for safety
        chain.generateBlock(miner);
    }
    
    ASSERT_GT( chain.GetIndex()->nHeight, 0 );
    
    // Capture exact balance before transaction
    CAmount notaryBalanceBefore = notary->GetBalance();
    
    // delay just a second to help with locktime
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    // Start to build a block
    int32_t newHeight = chain.GetIndex()->nHeight + 1;
    
    // Create funding transaction but don't commit to mempool
    TransactionInProcess fundAlice = notary->CreateSpendTransaction(alice, 100000, 5000, true);
    // Compute expected notary balance precisely: value sent to others + fee
    CAmount sentToOthers = fundAlice.transaction.GetValueOut() - notary->GetChange(fundAlice.transaction);
    CAmount txFee = fundAlice.transaction.GetDebit(ISMINE_SPENDABLE) - fundAlice.transaction.GetValueOut();
    CAmount txCost = sentToOthers + txFee;
    CAmount expectedNotaryBalance = notaryBalanceBefore - txCost;
    
    // now have Alice move some funds to Bob in the same block
    CCoinControl useThisTransaction;
    COutPoint tx(fundAlice.transaction.GetHash(), 1);
    useThisTransaction.Select(tx);
    TransactionInProcess aliceToBob = alice->CreateSpendTransaction(bob, 50000, 5000, useThisTransaction);
    
    // Create block with both transactions
    CBlock block;
    auto consensusParams = Params().GetConsensus();
    CMutableTransaction txNew = CreateNewContextualCMutableTransaction(consensusParams, newHeight);
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vin[0].scriptSig = (CScript() << newHeight << CScriptNum(1)) + COINBASE_FLAGS;
    txNew.vout.resize(1);
    txNew.vout[0].nValue = GetBlockSubsidy(newHeight, consensusParams);
    txNew.nExpiryHeight = 0;
    block.vtx.push_back(CTransaction(txNew));
    block.vtx.push_back(fundAlice.transaction);
    block.vtx.push_back(aliceToBob.transaction);
    
    // Ensure time and work are valid
    chain.IncrementChainTime();
    // Complete the block construction
    block.nBits = GetNextWorkRequired(chain.GetIndex(), &block, consensusParams);
    block.nTime = GetTime();
    block.hashPrevBlock = chain.GetIndex()->GetBlockHash();
    block.hashMerkleRoot = block.BuildMerkleTree();
    
    // Add proof-of-work
    EXPECT_TRUE(CalcPoW(&block));
    
    // Process the block
    CValidationState state;
    EXPECT_TRUE(ProcessNewBlock(false, newHeight, state, nullptr, &block, false, nullptr));
    if (!state.IsValid())
        FAIL() << state.GetRejectReason();
    
    lastBlock = std::make_shared<CBlock>(block);
    EXPECT_TRUE(lastBlock != nullptr);
    
    // Generate one more block to ensure everything is confirmed
    chain.generateBlock(miner);
    
    // Verify exact balances
    EXPECT_EQ(bob->GetBalance(), CAmount(50000));
    EXPECT_EQ(notary->GetBalance(), expectedNotaryBalance);
    EXPECT_EQ(alice->GetBalance(), CAmount(45000));
}

// Note: long delays during this test occur in reservekey.GetReservedKey(vchPubKey) call 
TEST(test_block, TestDoubleSpendInSameBlock)
{
    TestChain chain;
    chainName = assetchain("TST"); // use non-KMD chain to avoid KMD-specific interest/donation and miner fee effects
    auto notary = std::make_shared<TestWallet>(chain.getNotaryKey(), "notary");
    notary->SetBroadcastTransactions(true);
    auto alice = std::make_shared<TestWallet>("alice");
    alice->SetBroadcastTransactions(true);
    auto bob = std::make_shared<TestWallet>("bob");
    auto charlie = std::make_shared<TestWallet>("charlie");
    SelectParams(CBaseChainParams::REGTEST);
    
    std::shared_ptr<CBlock> lastBlock = chain.generateBlock(notary); // genesis block
    
    // Mine enough blocks to fully mature the coinbase output
    int maturity = Params().CoinbaseMaturity();
    for (int i = 1; i <= maturity + 5; ++i) {  // +5 extra for safety
        chain.generateBlock(notary);
    }
    
    CAmount notaryBalanceBefore = notary->GetBalance();
    ASSERT_GT( chain.GetIndex()->nHeight, 0 );
    
    // Start to build a block
    int32_t newHeight = chain.GetIndex()->nHeight + 1;
    TransactionInProcess fundAlice = notary->CreateSpendTransaction(alice, 100000, 5000, true);
    // Compute expected notary balance precisely: value sent to others + fee
    CAmount sentToOthers = fundAlice.transaction.GetValueOut() - notary->GetChange(fundAlice.transaction);
    CAmount txFee = fundAlice.transaction.GetDebit(ISMINE_SPENDABLE) - fundAlice.transaction.GetValueOut();
    CAmount txCost = sentToOthers + txFee;
    CAmount expectedNotaryBalance = notaryBalanceBefore - txCost;
    
    // Create and mine block with funding transaction
    CBlock block;
    auto consensusParams = Params().GetConsensus();
    CMutableTransaction txNew = CreateNewContextualCMutableTransaction(consensusParams, newHeight);
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vin[0].scriptSig = (CScript() << newHeight << CScriptNum(1)) + COINBASE_FLAGS;
    txNew.vout.resize(1);
    txNew.vout[0].nValue = GetBlockSubsidy(newHeight, consensusParams);
    txNew.nExpiryHeight = 0;
    
    block.vtx.push_back(CTransaction(txNew));
    block.vtx.push_back(fundAlice.transaction);
    
    // Ensure time and work are valid
    chain.IncrementChainTime();
    // Complete the block construction
    block.nBits = GetNextWorkRequired(chain.GetIndex(), &block, consensusParams);
    block.nTime = GetTime();
    block.hashPrevBlock = chain.GetIndex()->GetBlockHash();
    block.hashMerkleRoot = block.BuildMerkleTree();
    
    // Add proof-of-work
    EXPECT_TRUE(CalcPoW(&block));
    
    // Process the block
    CValidationState state;
    EXPECT_TRUE(ProcessNewBlock(false, newHeight, state, nullptr, &block, false, nullptr));
    if (!state.IsValid())
        FAIL() << state.GetRejectReason();
    
    lastBlock = std::make_shared<CBlock>(block);
    EXPECT_TRUE(lastBlock != nullptr);
    
    // now have Alice move some funds to Bob in the same block
    {
        CCoinControl useThisTransaction;
        COutPoint tx(fundAlice.transaction.GetHash(), 1);
        useThisTransaction.Select(tx);
        TransactionInProcess aliceToBob = alice->CreateSpendTransaction(bob, 10000, 5000, useThisTransaction);
        CValidationState state;
        EXPECT_TRUE(alice->CommitTransaction(aliceToBob.transaction, aliceToBob.reserveKey, state));
    }
    
    // alice attempts to double spend the vout and send something to charlie
    {
        CCoinControl useThisTransaction;
        COutPoint tx(fundAlice.transaction.GetHash(), 1);
        useThisTransaction.Select(tx);
        TransactionInProcess aliceToCharlie = alice->CreateSpendTransaction(charlie, 10000, 5000, useThisTransaction);
        CValidationState state;
        EXPECT_FALSE(alice->CommitTransaction(aliceToCharlie.transaction, aliceToCharlie.reserveKey, state));
        EXPECT_EQ(state.GetRejectReason(), "mempool conflict");
    }
    
    // Verify exact balances after all transactions
    chain.generateBlock(notary); // Confirm transactions
    
    EXPECT_EQ(bob->GetBalance(), CAmount(10000));
    EXPECT_EQ(charlie->GetBalance(), CAmount(0));
    EXPECT_EQ(alice->GetBalance(), CAmount(85000));//
    EXPECT_EQ(notary->GetBalance(), expectedNotaryBalance);
}

TEST(test_block, TestProcessBlock)
{
    TestChain chain;
    EXPECT_EQ(chain.GetIndex()->nHeight, 0);
    auto notary = std::make_shared<TestWallet>(chain.getNotaryKey(), "notary");
    auto alice = std::make_shared<TestWallet>("alice");
    auto bob = std::make_shared<TestWallet>("bob");
    auto charlie = std::make_shared<TestWallet>("charlie");
    std::shared_ptr<CBlock> lastBlock = chain.generateBlock(notary); // gives notary everything
    EXPECT_EQ(chain.GetIndex()->nHeight, 1);
    chain.IncrementChainTime();
    // add a transaction to the mempool
    TransactionInProcess fundAlice = notary->CreateSpendTransaction(alice, 100000);
    EXPECT_TRUE( chain.acceptTx(fundAlice.transaction).IsValid() );
    // construct the block
    CBlock block;
    int32_t newHeight = chain.GetIndex()->nHeight + 1;
    CValidationState state;
    // no transactions
    EXPECT_FALSE( ProcessNewBlock(false, newHeight, state, nullptr, &block, false, nullptr) );
    EXPECT_EQ(state.GetRejectReason(), "bad-blk-length");
    EXPECT_EQ(chain.GetIndex()->nHeight, 1);
    // add first a coinbase tx
    auto consensusParams = Params().GetConsensus();
    CMutableTransaction txNew = CreateNewContextualCMutableTransaction(consensusParams, newHeight);
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vin[0].scriptSig = (CScript() << newHeight << CScriptNum(1)) + COINBASE_FLAGS;
    txNew.vout.resize(1);
    txNew.vout[0].nValue = GetBlockSubsidy(newHeight,consensusParams);
    txNew.nExpiryHeight = 0;
    block.vtx.push_back(CTransaction(txNew));
    // no PoW, no merkle root should fail on merkle error
    EXPECT_FALSE( ProcessNewBlock(false, newHeight, state, nullptr, &block, false, nullptr) );
    EXPECT_EQ(state.GetRejectReason(), "bad-txnmrklroot");
    // Verify transaction is still in mempool
    EXPECT_EQ(mempool.size(), 1);
    // finish constructing the block
    block.nBits = GetNextWorkRequired( chain.GetIndex(), &block, Params().GetConsensus());
    block.nTime = GetTime();
    block.hashPrevBlock = lastBlock->GetHash();
    block.hashMerkleRoot = block.BuildMerkleTree();
    // Add the PoW
    EXPECT_TRUE(CalcPoW(&block));
    state = CValidationState();
    EXPECT_TRUE( ProcessNewBlock(false, newHeight, state, nullptr, &block, false, nullptr) );
    if (!state.IsValid())
        FAIL() << state.GetRejectReason();
    // Verify transaction is still in mempool
    EXPECT_EQ(mempool.size(), 1);
}

TEST(test_block, TestProcessBadBlock)
{
    TestChain chain;
    auto notary = std::make_shared<TestWallet>(chain.getNotaryKey(), "notary");
    auto alice = std::make_shared<TestWallet>("alice");
    auto bob = std::make_shared<TestWallet>("bob");
    auto charlie = std::make_shared<TestWallet>("charlie");
    std::shared_ptr<CBlock> lastBlock = chain.generateBlock(notary); // genesis block
    // add a transaction to the mempool
    TransactionInProcess fundAlice = notary->CreateSpendTransaction(alice, 100000);
    EXPECT_TRUE( chain.acceptTx(fundAlice.transaction).IsValid() );
    // construct the block
    CBlock block;
    int32_t newHeight = chain.GetIndex()->nHeight + 1;
    CValidationState state;
    // no transactions
    EXPECT_FALSE( ProcessNewBlock(false, newHeight, state, nullptr, &block, false, nullptr) );
    EXPECT_EQ(state.GetRejectReason(), "bad-blk-length");
    // add first a coinbase tx
    auto consensusParams = Params().GetConsensus();
    CMutableTransaction txNew = CreateNewContextualCMutableTransaction(consensusParams, newHeight);
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vin[0].scriptSig = (CScript() << newHeight << CScriptNum(1)) + COINBASE_FLAGS;
    txNew.vout.resize(1);
    txNew.vout[0].nValue = GetBlockSubsidy(newHeight,consensusParams);
    txNew.nExpiryHeight = 0;
    block.vtx.push_back(CTransaction(txNew));
    // Add no PoW, should fail on merkle error
    EXPECT_FALSE( ProcessNewBlock(false, newHeight, state, nullptr, &block, false, nullptr) );
    EXPECT_EQ(state.GetRejectReason(), "bad-txnmrklroot");
    // Verify transaction is still in mempool
    EXPECT_EQ(mempool.size(), 1);
}