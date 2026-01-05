/**
 * Double Ratchet Unit Tests
 * Tests for HKDF, KDF, Ratchet initialization, and message encryption/decryption
 */

// ===== TEST UTILITIES =====

function arrayToHex(arr) {
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToArray(hex) {
    const result = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        result[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return result;
}

async function runTests() {
    console.log('🧪 Starting Double Ratchet Unit Tests...\n');
    
    let passed = 0;
    let failed = 0;
    
    // Test 1: HKDF Extract
    try {
        console.log('Test 1: HKDF Extract & Expand');
        const salt = new TextEncoder().encode('test-salt');
        const ikm = new TextEncoder().encode('input-key-material');
        const info = new TextEncoder().encode('test-info');
        
        const prk = await hkdfExtract(salt, ikm);
        console.log('  ✓ PRK generated:', arrayToHex(prk).substring(0, 16) + '...');
        
        const expanded = await hkdfExpand(prk, info, 64);
        console.log('  ✓ Expanded to 64 bytes:', arrayToHex(expanded).substring(0, 16) + '...');
        
        if (expanded.length === 64) {
            console.log('  ✅ PASS: HKDF works correctly\n');
            passed++;
        } else {
            console.log('  ❌ FAIL: Wrong expanded length\n');
            failed++;
        }
    } catch (err) {
        console.log('  ❌ FAIL:', err.message, '\n');
        failed++;
    }
    
    // Test 2: KDF_RK (Root Key Derivation)
    try {
        console.log('Test 2: KDF_RK');
        const rootKey = window.crypto.getRandomValues(new Uint8Array(32));
        const dhSecret = window.crypto.getRandomValues(new Uint8Array(32));
        
        const result = await kdfRK(rootKey, dhSecret);
        console.log('  ✓ New Root Key:', arrayToHex(result.rootKey).substring(0, 16) + '...');
        console.log('  ✓ Init Chain Key:', arrayToHex(result.chainKey).substring(0, 16) + '...');
        
        if (result.rootKey.length === 32 && result.chainKey.length === 32) {
            console.log('  ✅ PASS: KDF_RK generates correct size keys\n');
            passed++;
        } else {
            console.log('  ❌ FAIL: Wrong key sizes\n');
            failed++;
        }
    } catch (err) {
        console.log('  ❌ FAIL:', err.message, '\n');
        failed++;
    }
    
    // Test 3: KDF_CK (Chain Key Derivation)
    try {
        console.log('Test 3: KDF_CK');
        const chainKey = window.crypto.getRandomValues(new Uint8Array(32));
        
        const result1 = await kdfCK(chainKey);
        console.log('  ✓ Round 1 - New ChainKey:', arrayToHex(result1.newCK).substring(0, 16) + '...');
        console.log('  ✓ Round 1 - MessageKey:', arrayToHex(result1.messageKey).substring(0, 16) + '...');
        
        const result2 = await kdfCK(result1.newCK);
        console.log('  ✓ Round 2 - New ChainKey:', arrayToHex(result2.newCK).substring(0, 16) + '...');
        console.log('  ✓ Round 2 - MessageKey:', arrayToHex(result2.messageKey).substring(0, 16) + '...');
        
        // Verify they're different
        if (arrayToHex(result1.messageKey) !== arrayToHex(result2.messageKey)) {
            console.log('  ✅ PASS: KDF_CK generates unique keys per iteration\n');
            passed++;
        } else {
            console.log('  ❌ FAIL: Same key generated twice\n');
            failed++;
        }
    } catch (err) {
        console.log('  ❌ FAIL:', err.message, '\n');
        failed++;
    }
    
    // Test 4: Double Ratchet Initialization (Initiator)
    try {
        console.log('Test 4: Double Ratchet Initialization (Initiator)');
        doubleRatchetState.clear(); // Reset state
        
        const sharedSecret = window.crypto.getRandomValues(new Uint8Array(32));
        const odId = 'test-peer-1';
        
        const dhPubKey = await initializeDoubleRatchet(odId, sharedSecret, true);
        console.log('  ✓ DH Public Key:', dhPubKey.substring(0, 20) + '...');
        
        const state = doubleRatchetState.get(odId);
        if (state && state.rootKey && state.sendChain.active && !state.recvChain.active) {
            console.log('  ✓ Send chain active, Recv chain inactive (correct for initiator)');
            console.log('  ✅ PASS: Initiator ratchet initialized correctly\n');
            passed++;
        } else {
            console.log('  ❌ FAIL: Incorrect state\n');
            failed++;
        }
    } catch (err) {
        console.log('  ❌ FAIL:', err.message, '\n');
        failed++;
    }
    
    // Test 5: Double Ratchet Initialization (Non-Initiator)
    try {
        console.log('Test 5: Double Ratchet Initialization (Non-Initiator)');
        doubleRatchetState.clear();
        
        const sharedSecret = window.crypto.getRandomValues(new Uint8Array(32));
        const odId = 'test-peer-2';
        
        const dhPubKey = await initializeDoubleRatchet(odId, sharedSecret, false);
        
        const state = doubleRatchetState.get(odId);
        if (state && state.rootKey && !state.sendChain.active && state.recvChain.active) {
            console.log('  ✓ Send chain inactive, Recv chain active (correct for non-initiator)');
            console.log('  ✅ PASS: Non-initiator ratchet initialized correctly\n');
            passed++;
        } else {
            console.log('  ❌ FAIL: Incorrect state\n');
            failed++;
        }
    } catch (err) {
        console.log('  ❌ FAIL:', err.message, '\n');
        failed++;
    }
    
    // Test 6: Ratchet Handshake Completion
    try {
        console.log('Test 6: Ratchet Handshake Completion');
        doubleRatchetState.clear();
        
        // Initialize both peers
        const secret = window.crypto.getRandomValues(new Uint8Array(32));
        const aliceId = 'alice';
        const bobId = 'bob';
        
        const aliceDhKey = await initializeDoubleRatchet(aliceId, secret, true);
        const bobDhKey = await initializeDoubleRatchet(bobId, secret, false);
        
        // Complete handshake
        await completeDoubleRatchetHandshake(aliceId, bobDhKey);
        await completeDoubleRatchetHandshake(bobId, aliceDhKey);
        
        const aliceState = doubleRatchetState.get(aliceId);
        const bobState = doubleRatchetState.get(bobId);
        
        if (aliceState.sendChain.active && aliceState.recvChain.active &&
            bobState.sendChain.active && bobState.recvChain.active) {
            console.log('  ✓ Both peers have send and recv chains active');
            console.log('  ✅ PASS: Handshake completed successfully\n');
            passed++;
        } else {
            console.log('  ❌ FAIL: Not all chains activated\n');
            failed++;
        }
    } catch (err) {
        console.log('  ❌ FAIL:', err.message, '\n');
        failed++;
    }
    
    // Test 7: Send and Receive Message (In-Order)
    try {
        console.log('Test 7: Send and Receive Message (In-Order)');
        doubleRatchetState.clear();
        
        const secret = window.crypto.getRandomValues(new Uint8Array(32));
        const aliceId = 'alice';
        const bobId = 'bob';
        
        // Initialize and handshake
        const aliceDhKey = await initializeDoubleRatchet(aliceId, secret, true);
        const bobDhKey = await initializeDoubleRatchet(bobId, secret, false);
        await completeDoubleRatchetHandshake(aliceId, bobDhKey);
        await completeDoubleRatchetHandshake(bobId, aliceDhKey);
        
        // Alice sends a message
        const plaintext = new TextEncoder().encode('Hello, Bob!');
        const encrypted = await sendMessageWithDoubleRatchet(aliceId, plaintext);
        console.log('  ✓ Message encrypted by Alice');
        
        // Bob receives the message
        const decrypted = await receiveMessageWithDoubleRatchet(
            bobId,
            encrypted.data,
            encrypted.dhPublicKey
        );
        
        const decryptedText = new TextDecoder().decode(decrypted);
        console.log('  ✓ Message decrypted by Bob:', decryptedText);
        
        if (decryptedText === 'Hello, Bob!') {
            console.log('  ✅ PASS: Message encrypted and decrypted correctly\n');
            passed++;
        } else {
            console.log('  ❌ FAIL: Decrypted text does not match\n');
            failed++;
        }
    } catch (err) {
        console.log('  ❌ FAIL:', err.message, '\n');
        failed++;
    }
    
    // Test 8: Multiple Messages (Chain Advancement)
    try {
        console.log('Test 8: Multiple Messages (Chain Advancement)');
        doubleRatchetState.clear();
        
        const secret = window.crypto.getRandomValues(new Uint8Array(32));
        const aliceId = 'alice';
        const bobId = 'bob';
        
        const aliceDhKey = await initializeDoubleRatchet(aliceId, secret, true);
        const bobDhKey = await initializeDoubleRatchet(bobId, secret, false);
        await completeDoubleRatchetHandshake(aliceId, bobDhKey);
        await completeDoubleRatchetHandshake(bobId, aliceDhKey);
        
        // Alice sends 5 messages
        const messages = ['Hello', 'World', 'Test', '123', '!'];
        const encrypted = [];
        
        for (const msg of messages) {
            const enc = await sendMessageWithDoubleRatchet(
                aliceId,
                new TextEncoder().encode(msg)
            );
            encrypted.push(enc);
        }
        console.log('  ✓ Alice sent 5 messages');
        
        // Bob receives and decrypts all
        const decrypted = [];
        for (const enc of encrypted) {
            const dec = await receiveMessageWithDoubleRatchet(
                bobId,
                enc.data,
                enc.dhPublicKey
            );
            decrypted.push(new TextDecoder().decode(dec));
        }
        
        console.log('  ✓ Bob received and decrypted:', decrypted.join(' '));
        
        if (decrypted.join(' ') === messages.join(' ')) {
            console.log('  ✅ PASS: All messages correctly encrypted/decrypted\n');
            passed++;
        } else {
            console.log('  ❌ FAIL: Message mismatch\n');
            failed++;
        }
    } catch (err) {
        console.log('  ❌ FAIL:', err.message, '\n');
        failed++;
    }
    
    // Test 9: Zeroize
    try {
        console.log('Test 9: Zeroize Double Ratchet');
        const odId = 'test-zeroize';
        const secret = window.crypto.getRandomValues(new Uint8Array(32));
        
        await initializeDoubleRatchet(odId, secret, true);
        console.log('  ✓ Ratchet initialized');
        
        const beforeZeroize = doubleRatchetState.has(odId);
        zeroizeDoubleRatchet(odId);
        const afterZeroize = doubleRatchetState.has(odId);
        
        if (beforeZeroize && !afterZeroize) {
            console.log('  ✓ Ratchet state deleted');
            console.log('  ✅ PASS: Zeroize successful\n');
            passed++;
        } else {
            console.log('  ❌ FAIL: Ratchet not deleted\n');
            failed++;
        }
    } catch (err) {
        console.log('  ❌ FAIL:', err.message, '\n');
        failed++;
    }
    
    // Results
    console.log('\n' + '='.repeat(50));
    console.log(`📊 Test Results: ${passed} PASSED, ${failed} FAILED`);
    console.log('='.repeat(50) + '\n');
    
    if (failed === 0) {
        console.log('✅ All tests passed!');
        return true;
    } else {
        console.log(`❌ ${failed} test(s) failed`);
        return false;
    }
}

// Run tests if in browser console
if (typeof window !== 'undefined' && window.crypto) {
    // Tests can be run manually via: runTests()
    console.log('📝 Double Ratchet tests loaded. Run: runTests()');
}
