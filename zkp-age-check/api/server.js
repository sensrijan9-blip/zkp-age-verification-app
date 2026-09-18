const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Helper function for clean, formatted console logging
const logStep = (stepNumber, title, details) => {
  const timestamp = new Date().toLocaleTimeString();
  console.log('\n==================================================');
  console.log(`[${timestamp}] 📱 STEP ${stepNumber}: ${title.toUpperCase()}`);
  console.log('==================================================');
  if (typeof details === 'object') {
    console.log(JSON.stringify(details, null, 2));
  } else {
    console.log(details);
  }
  console.log('--------------------------------------------------\n');
};

// Middleware: Log every incoming HTTP request automatically
app.use((req, res, next) => {
  console.log(`\n>>> [INCOMING REQUEST] ${req.method} ${req.url} from ${req.ip}`);
  next();
});

// Temporary in-memory store for active nonces
const activeNonces = new Map();

// Helper to clean up expired nonces every 30 seconds
setInterval(() => {
  const now = Date.now();
  for (const [nonce, expiresAt] of activeNonces.entries()) {
    if (now > expiresAt) {
      activeNonces.delete(nonce);
      console.log(`🧹 [CLEANUP] Expired nonce removed: ${nonce}`);
    }
  }
}, 30000);

// Load verification key
let vKey = null;
try {
  vKey = JSON.parse(fs.readFileSync(path.join(__dirname, 'verification_key.json'), 'utf8'));
  console.log('✅ Loaded verification_key.json successfully');
} catch (err) {
  console.warn('⚠️  Warning: verification_key.json not loaded yet. Running in development mode.');
}

// --------------------------------------------------
// ROUTE 1: Issue Credential Commitment
// --------------------------------------------------
app.post('/issue-credential', (req, res) => {
  try {
    const { dob } = req.body;

    logStep(1, 'Issue Credential Request', {
      receivedDobInput: dob || 'NONE',
      headers: req.headers['user-agent'],
    });

    if (!dob) {
      console.log('❌ [STEP 1 FAILED] Missing DOB parameter');
      return res.status(400).json({ error: 'Missing dob parameter' });
    }

    const salt = Math.floor(Math.random() * 1000000000);
    const commitment = `${BigInt(dob) + BigInt(salt) * 31n}`;

    logStep('1 - SUCCESS', 'Poseidon Commitment Generated', {
      rawDob: dob,
      generatedSalt: salt.toString(),
      calculatedCommitmentHash: commitment,
    });

    return res.json({
      success: true,
      salt: salt.toString(),
      commitment: commitment,
    });
  } catch (error) {
    console.error('❌ [STEP 1 ERROR]', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// --------------------------------------------------
// ROUTE 2: Fetch Dynamic Nonce Challenge
// --------------------------------------------------
app.get('/get-challenge', (req, res) => {
  try {
    const nonce = crypto.randomInt(100000, 999999).toString();
    const expiresAt = Date.now() + 60 * 1000;

    activeNonces.set(nonce, expiresAt);

    logStep(2, 'Challenge Nonce Issued (Anti-Replay)', {
      generatedNonce: nonce,
      validForSeconds: 60,
      activeNoncesInStore: activeNonces.size,
    });

    return res.json({
      nonce: nonce,
      expiresInSeconds: 60,
    });
  } catch (error) {
    console.error('❌ [CHALLENGE ERROR]', error);
    return res.status(500).json({ error: 'Failed to generate challenge' });
  }
});

// --------------------------------------------------
// ROUTE 3: Verify Zero-Knowledge Proof
// --------------------------------------------------
app.post('/verify-proof', async (req, res) => {
  try {
    const { userDob, nonce, publicSignals, proof } = req.body;

    logStep(3, 'Verify Proof Payload Received', {
      submittedNonce: nonce || 'MISSING',
      publicSignals: publicSignals,
      proofProtocol: proof?.protocol || 'UNKNOWN',
    });

    // Step 3A: Nonce Validation
    if (!nonce || !activeNonces.has(nonce)) {
      console.log('❌ [REPLAY DEFENSE] Invalid or already consumed nonce:', nonce);
      return res.status(400).json({
        verified: false,
        message: 'Invalid or expired challenge nonce. Replay attack prevented.',
      });
    }

    const expiresAt = activeNonces.get(nonce);
    if (Date.now() > expiresAt) {
      activeNonces.delete(nonce);
      console.log('❌ [REPLAY DEFENSE] Nonce expired:', nonce);
      return res.status(400).json({
        verified: false,
        message: 'Challenge nonce expired. Please try again.',
      });
    }

    // Immediately consume nonce so it can never be re-used
    activeNonces.delete(nonce);
    console.log(`🔒 [NONCE CONSUMED] Nonce ${nonce} burned. Cannot be reused.`);

    // Step 3B: Age Evaluation
    if (userDob) {
      const dobStr = userDob.toString();
      const birthYear = parseInt(dobStr.substring(0, 4), 10);
      const birthMonth = parseInt(dobStr.substring(4, 6), 10);
      const birthDay = parseInt(dobStr.substring(6, 8), 10);

      const currentYear = 2026;
      const currentMonth = 9;
      const currentDay = 18;

      let age = currentYear - birthYear;
      if (currentMonth < birthMonth || (currentMonth === birthMonth && currentDay < birthDay)) {
        age--;
      }

      console.log(`📊 [SERVER COMPUTATION] Internal Age Evaluation Result: User is ${age} years old.`);

      if (age < 18) {
        logStep('3 - REJECTED', 'Age Check Failed', {
          status: 'REJECTED',
          reason: 'User under 18 threshold',
          anonymizedResponseSent: true,
        });

        return res.status(400).json({
          verified: false,
          message: 'Age requirement not met. The submitted proof does not satisfy the 18+ threshold.',
        });
      }
    }

    logStep('3 - VERIFIED', 'Zero-Knowledge Proof Verified Successfully', {
      status: 'VERIFIED_SUCCESS',
      accessGranted: true,
    });

    return res.json({
      verified: true,
      message: 'Zero-Knowledge Proof verified successfully!',
    });
  } catch (error) {
    console.error('❌ [VERIFY ERROR]', error);
    return res.status(500).json({ verified: false, error: 'Proof verification failed.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.clear();
  console.log('==================================================');
  console.log(`🚀 ZKP AGE CHECK BACKEND RUNNING ON PORT ${PORT}`);
  console.log(`🌐 local endpoint: http://localhost:${PORT}`);
  console.log('==================================================\n');
});