/**
 * BACKEND TOKEN VALIDATOR - Admin System
 * 
 * Server-side database tracking for TRUE one-time checkout tokens.
 * Prevents ANY reuse of checkout URLs, even within the 5-minute window.
 * 
 * Tech Stack: Node.js + Express + MongoDB
 */

// Load environment variables first
require('dotenv').config();

const express = require('express');
const { MongoClient, ServerApiVersion } = require('mongodb');
const crypto = require('crypto');
const cors = require('cors');

const app = express();

// ============================================
// CORS CONFIGURATION
// ============================================

// For development: Allow all origins
if (process.env.NODE_ENV === 'development') {
  app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
  }));
  console.log('🌐 CORS: Allowing all origins (development mode)');
}
// For production: Allow specific Shopify store
else {
  const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',') 
    : ['*']; // Fallback to allow all if not configured
  
  app.use(cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl)
      if (!origin) return callback(null, true);
      
      // Allow all origins if wildcard is set
      if (allowedOrigins.includes('*')) return callback(null, true);
      
      // Check if origin is in allowed list
      if (allowedOrigins.some(allowed => origin.includes(allowed))) {
        return callback(null, true);
      }
      
      console.warn(`⚠️ CORS blocked request from: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
  }));
  
  console.log('🌐 CORS: Configured for origins:', allowedOrigins);
}

app.use(express.json());

// ============================================
// REQUEST LOGGING (for debugging)
// ============================================

app.use((req, res, next) => {
  console.log(`📥 ${req.method} ${req.path}`);
  next();
});

// ============================================
// DATABASE CONFIGURATION
// ============================================

const MONGO_USERNAME = process.env.MONGO_USERNAME || 'eduardferneysuarezavella_db_user';
const MONGO_PASSWORD = process.env.MONGO_PASSWORD || 'vhDysowvcLqIGAwh';
const MONGO_CLUSTER = process.env.MONGO_CLUSTER || 'cluster0.wbhlzwe.mongodb.net';
const MONGO_DB_NAME = process.env.MONGO_DB_NAME || 'shopify_tokens';

const MONGO_URI = `mongodb+srv://${MONGO_USERNAME}:${MONGO_PASSWORD}@${MONGO_CLUSTER}/?retryWrites=true&w=majority&appName=${MONGO_DB_NAME}&ssl=true`;

const mongoClient = new MongoClient(MONGO_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  tls: true,
  tlsAllowInvalidCertificates: false,
  tlsAllowInvalidHostnames: false,
  connectTimeoutMS: 30000,
  socketTimeoutMS: 30000,
  serverSelectionTimeoutMS: 30000,
  maxPoolSize: 10,
  minPoolSize: 2,
});

let db;
let sessionsCollection;
let attemptsCollection;
let logsCollection;

// ============================================
// DATABASE SCHEMA & INITIALIZATION
// ============================================

async function initDatabase() {
  try {
    // Connect to MongoDB
    await mongoClient.connect();
    console.log('✅ Connected to MongoDB Atlas');
    
    // Get database and collections
    db = mongoClient.db(MONGO_DB_NAME);
    sessionsCollection = db.collection('checkout_sessions');
    attemptsCollection = db.collection('checkout_attempts');
    logsCollection = db.collection('validation_logs');
    
    // Create indexes for performance
    await sessionsCollection.createIndex({ session_token: 1 }, { unique: true });
    await sessionsCollection.createIndex({ expires_at: 1 });
    await sessionsCollection.createIndex({ is_used: 1 });
    
    await attemptsCollection.createIndex({ attempt_id: 1 }, { unique: true });
    await attemptsCollection.createIndex({ session_token: 1 });
    await attemptsCollection.createIndex({ expires_at: 1 });
    await attemptsCollection.createIndex({ is_used: 1 });
    
    await logsCollection.createIndex({ attempt_id: 1 });
    await logsCollection.createIndex({ validation_result: 1 });
    await logsCollection.createIndex({ created_at: -1 });
    
    console.log('✅ Database indexes created');
    
    // Test connection
    await db.command({ ping: 1 });
    console.log('✅ Database ready');
    
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    process.exit(1);
  }
}

// ============================================
// HELPER FUNCTIONS
// ============================================

/**
 * Clean up expired tokens (run periodically)
 */
async function cleanupExpiredTokens() {
  try {
    const now = new Date();
    
    const attemptsResult = await attemptsCollection.deleteMany({
      expires_at: { $lt: now }
    });
    
    const sessionsResult = await sessionsCollection.deleteMany({
      expires_at: { $lt: now }
    });
    
    const total = attemptsResult.deletedCount + sessionsResult.deletedCount;
    console.log(`🧹 Cleaned up ${attemptsResult.deletedCount} expired attempts and ${sessionsResult.deletedCount} expired sessions`);
    return total;
  } catch (error) {
    console.error('Cleanup error:', error);
    throw error;
  }
}

/**
 * Parse timestamp from token
 */
function parseTimestamp(token, delimiter = '_') {
  const parts = token.split(delimiter);
  if (parts.length < 2) return null;
  const timestamp = parseInt(parts[0], 10);
  return isNaN(timestamp) ? null : timestamp;
}

/**
 * Validate token format and expiry
 */
function validateTokenFormat(token, delimiter = '_', maxAge = 5 * 60 * 1000) {
  const timestamp = parseTimestamp(token, delimiter);
  if (!timestamp) {
    return { valid: false, error: 'Invalid token format' };
  }
  
  const age = Date.now() - timestamp;
  
  if (age > maxAge) {
    return { valid: false, error: 'Token expired' };
  }
  
  if (age < 0) {
    return { valid: false, error: 'Token from future (tampered)' };
  }
  
  return { valid: true, timestamp };
}

// ============================================
// API ENDPOINTS
// ============================================

/**
 * GET /api/health
 * Health check endpoint
 */
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    status: 'healthy',
    database: {
      connected: !!mongoClient && !!db,
      collections: {
        sessions: !!sessionsCollection,
        attempts: !!attemptsCollection,
        logs: !!logsCollection
      }
    },
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /api/session/register
 * Register a new session token
 */
app.post('/api/session/register', async (req, res) => {
  try {
    console.log('🔍 Session registration request:', { body: req.body });
    
    let { session_token, ip_address, user_agent } = req.body;
    
    // Extract IP from request if not provided
    if (!ip_address) {
      ip_address = req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
                   || req.headers['x-real-ip']
                   || req.connection.remoteAddress 
                   || req.socket.remoteAddress
                   || 'unknown';
    }
    
    if (!session_token) {
      console.log('❌ Missing session_token');
      return res.status(400).json({ 
        success: false, 
        error: 'session_token is required' 
      });
    }
    
    // Check if database is initialized
    if (!sessionsCollection) {
      console.error('❌ Database not initialized! sessionsCollection is null');
      return res.status(503).json({ 
        success: false, 
        error: 'Database not ready' 
      });
    }
    
    console.log('🔍 Validating token format...');
    // Validate token format (basic check only, no expiration)
    const validation = validateTokenFormat(session_token, '_', 24 * 60 * 60 * 1000); // 24 hours for better UX
    console.log('🔍 Validation result:', validation);
    
    if (!validation.valid) {
      console.log('❌ Token validation failed:', validation.error);
      return res.status(400).json({ 
        success: false, 
        error: validation.error 
      });
    }
    
    // Calculate expiry (24 hours from token creation for better customer experience)
    const expiresAt = new Date(validation.timestamp + (24 * 60 * 60 * 1000));
    console.log('🔍 Expiry date:', expiresAt);
    
    // Insert or update session
    const sessionDoc = {
      session_token,
      expires_at: expiresAt,
      is_used: false,
      used_at: null,
      ip_address,
      user_agent
    };
    
    console.log('🔍 Attempting MongoDB updateOne...');
    const result = await sessionsCollection.updateOne(
      { session_token },
      { 
        $set: sessionDoc,
        $setOnInsert: { created_at: new Date() }  // Only set created_at on first insert
      },
      { upsert: true }
    );
    console.log('🔍 MongoDB result:', { 
      matchedCount: result.matchedCount, 
      modifiedCount: result.modifiedCount, 
      upsertedCount: result.upsertedCount 
    });
    
    console.log(`✅ Session registered: ${session_token.substring(0, 20)}...`);
    
    res.json({
      success: true,
      session: {
        token: session_token,
        expires_at: expiresAt
      }
    });
    
  } catch (error) {
    console.error('❌ Session registration error:', error.message);
    console.error('❌ Error name:', error.name);
    console.error('❌ Error code:', error.code);
    console.error('❌ Stack:', error.stack);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/attempt/register
 * Register a new checkout attempt ID
 */
app.post('/api/attempt/register', async (req, res) => {
  try {
    let { 
      attempt_id, 
      session_token, 
      checkout_url, 
      ip_address, 
      user_agent 
    } = req.body;
    
    // Extract IP from request if not provided
    if (!ip_address) {
      ip_address = req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
                   || req.headers['x-real-ip']
                   || req.connection.remoteAddress 
                   || req.socket.remoteAddress
                   || 'unknown';
    }
    
    if (!attempt_id || !session_token) {
      return res.status(400).json({ 
        success: false, 
        error: 'attempt_id and session_token are required' 
      });
    }
    
    // Validate attempt ID format
    const attemptValidation = validateTokenFormat(attempt_id, '-', 5 * 60 * 1000);
    if (!attemptValidation.valid) {
      return res.status(400).json({ 
        success: false, 
        error: attemptValidation.error 
      });
    }
    
    // Verify session exists and is valid
    const session = await sessionsCollection.findOne({ session_token });
    
    if (!session) {
      return res.status(404).json({ 
        success: false, 
        error: 'Session not found' 
      });
    }
    
    if (new Date() > new Date(session.expires_at)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Session expired' 
      });
    }
    
    // Calculate expiry (5 minutes from attempt creation)
    const expiresAt = new Date(attemptValidation.timestamp + (5 * 60 * 1000));
    
    // Check if attempt already exists
    const existingAttempt = await attemptsCollection.findOne({ attempt_id });
    if (existingAttempt) {
      return res.status(409).json({ 
        success: false, 
        error: 'Attempt ID already exists' 
      });
    }
    
    // Insert attempt
    const attemptDoc = {
      attempt_id,
      session_token,
      created_at: new Date(),
      expires_at: expiresAt,
      is_used: false,
      used_at: null,
      checkout_url,
      order_id: null,
      ip_address,
      user_agent
    };
    
    const result = await attemptsCollection.insertOne(attemptDoc);
    
    res.json({
      success: true,
      attempt: {
        attempt_id,
        expires_at: expiresAt
      }
    });
    
  } catch (error) {
    console.error('Attempt registration error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

/**
 * POST /api/shopify/validate
 * [DEPRECATED - NOT CURRENTLY USED]
 * 
 * Originally intended for Shopify Functions, but Shopify Functions 
 * do not have access to fetch() API for making HTTP requests.
 * 
 * Current implementation uses Checkout UI Extension instead,
 * which calls /api/validate endpoint.
 * 
 * Keeping this endpoint for future use if Shopify adds network 
 * capabilities to Functions.
 */
app.post('/api/shopify/validate', async (req, res) => {
  try {
    let { session_token, attempt_id, buyer_journey_step } = req.body;
    console.log('🔍 Shopify validation request:', { session_token: session_token?.substring(0, 20), attempt_id: attempt_id?.substring(0, 20), buyer_journey_step });
    // Extract IP from request if not provided
    if (!req.body.ip_address) {
      const ip_address = req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
                   || req.headers['x-real-ip']
                   || req.connection.remoteAddress 
                   || req.socket.remoteAddress
                   || 'shopify-function';
      req.body.ip_address = ip_address;
    }
    
    console.log(`🔍 Shopify validation request:`, { session_token: session_token?.substring(0, 20), attempt_id: attempt_id?.substring(0, 20), buyer_journey_step });
    
    if (!attempt_id || !session_token) {
      await logValidation(attempt_id, session_token, 'invalid', 'Missing parameters', req.body.ip_address, 'Shopify-Function');
      return res.status(400).json({ 
        valid: false, 
        error: 'session_token and attempt_id are required' 
      });
    }
    
    // Check attempt exists and session matches
    const attempt = await attemptsCollection.findOne({ 
      attempt_id, 
      session_token 
    });
    
    if (!attempt) {
      await logValidation(attempt_id, session_token, 'invalid', 'Attempt not found or session mismatch', req.body.ip_address, 'Shopify-Function');
      return res.status(404).json({ 
        valid: false, 
        error: 'Invalid checkout session. Please return to cart and try again.' 
      });
    }
    
    // Check if already used (ONE-TIME enforcement)
    if (attempt.is_used) {
      await logValidation(attempt_id, session_token, 'already_used', 
        `Attempt already used at ${attempt.used_at}`, req.body.ip_address, 'Shopify-Function');
      console.error(`❌ Attempt already used at ${attempt.used_at}`);
      return res.status(409).json({ 
        valid: false, 
        error: 'This checkout URL has already been used. Please return to cart and start over.',
        used_at: attempt.used_at
      });
    }
    
    // Check expiry
    if (new Date() > new Date(attempt.expires_at)) {
      await logValidation(attempt_id, session_token, 'expired', 
        'Attempt expired', req.body.ip_address, 'Shopify-Function');
      console.error(`❌ Attempt expired at ${attempt.expires_at}`);
      return res.status(400).json({ 
        valid: false, 
        error: 'Checkout attempt has expired. Please return to cart and try again.' 
      });
    }
    
    // Mark as used (atomic operation to prevent race conditions)
    const now = new Date();
    const updateResult = await attemptsCollection.updateOne(
      { attempt_id, is_used: false },
      { 
        $set: { 
          is_used: true, 
          used_at: now 
        } 
      }
    );
    
    // If no documents were modified, it means another request already used it
    if (updateResult.modifiedCount === 0) {
      await logValidation(attempt_id, session_token, 'already_used', 
        'Attempt was just used by another request (race condition)', req.body.ip_address, 'Shopify-Function');
      console.error(`❌ Race condition: attempt already used by another request`);
      return res.status(409).json({ 
        valid: false, 
        error: 'This checkout URL has already been used.'
      });
    }
    
    // Mark session as used
    await sessionsCollection.updateOne(
      { session_token },
      { 
        $set: { 
          is_used: true, 
          used_at: now 
        } 
      }
    );
    
    await logValidation(attempt_id, session_token, 'success', null, req.body.ip_address, 'Shopify-Function');
    console.log(`✅ Shopify validation passed - marked as USED`);
    
    res.json({
      valid: true,
      message: 'Validation successful',
      attempt_id: attempt_id
    });
    
  } catch (error) {
    console.error('❌ Shopify validation error:', error.message);
    await logValidation(req.body.attempt_id, req.body.session_token, 'error', 
      error.message, req.body.ip_address, 'Shopify-Function');
    res.status(500).json({ 
      valid: false, 
      error: 'Internal server error' 
    });
  }
});

/**
 * POST /api/validate
 * PAIR VALIDATION - Implements checkout_storage_id verification
 * Validates: (session_token, checkout_storage_id)
 * 
 * Flow:
 * 1. Theme registers at cart: (session_token) with checkout_storage_id = null
 * 2. Extension sends at checkout: (session_token, checkout_storage_id)
 * 3. Backend validates:
 *    - If both match → ALLOW (same browser, refresh)
 *    - If session matches, storage_id is null in DB → ALLOW + UPDATE (first legitimate checkout)
 *    - If session matches, storage_id differs → BLOCK (copied URL, different browser)
 *    - If no match → BLOCK (invalid)
 */
app.post('/api/validate', async (req, res) => {
  try {
    let { 
      session_token,
      checkout_storage_id, // Browser-specific storage ID from extension
      source, // 'checkout_ui_extension' or 'theme'
      ip_address, 
      user_agent 
    } = req.body;
    
    // Extract IP from request if not provided
    if (!ip_address) {
      ip_address = req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
                   || req.headers['x-real-ip']
                   || req.connection.remoteAddress 
                   || req.socket.remoteAddress
                   || 'unknown';
    }
    
    // Set user agent based on source if not provided
    if (!user_agent) {
      user_agent = source || req.headers['user-agent'] || 'unknown';
    }
    
    console.log(`🔍 VALIDATION REQUEST from: ${source || 'unknown'}`);
    console.log(`   Session Token: ${session_token?.substring(0, 20)}...`);
    console.log(`   Checkout Storage ID: ${checkout_storage_id?.substring(0, 20) || 'NULL'}...`);
    console.log(`   IP Address: ${ip_address}`);
    
    // Validate required parameters
    if (!session_token) {
      console.error('❌ Missing required parameter: session_token');
      await logValidation(null, null, 'invalid', 'Missing session_token', ip_address, user_agent);
      return res.status(400).json({ 
        success: false, 
        error: 'session_token is required' 
      });
    }
    
    // If request is from theme (no checkout_storage_id), use simple validation
    if (!checkout_storage_id || source === 'theme') {
      console.log('⚠️ Theme validation (no checkout_storage_id) - using simple validation');
      
      // Find the session
      const dbRecord = await sessionsCollection.findOne({ 
        session_token
      });
      
      if (!dbRecord) {
        console.error('🚨 INVALID: No matching session_token');
        await logValidation(null, session_token, 'not_found', 
          'No matching session', ip_address, user_agent);
        return res.status(404).json({ 
          success: false,
          valid: false,
          error: 'Checkout session not found. Please return to cart and try again.' 
        });
      }
      
      // Theme validation - just check if exists and not expired
      if (dbRecord.expires_at && new Date() > new Date(dbRecord.expires_at)) {
        console.error('⏰ EXPIRED: Checkout session expired');
        await logValidation(null, session_token, 'expired', 
          'Session expired', ip_address, user_agent);
        return res.status(400).json({ 
          success: false,
          valid: false,
          error: 'Checkout session has expired. Please return to cart and try again.' 
        });
      }
      
      console.log('✅ Theme validation PASSED');
      await logValidation(null, session_token, 'success', 
        'Theme validation successful', ip_address, user_agent);
      
      return res.status(200).json({ 
        success: true,
        valid: true,
        message: 'Checkout validated successfully (theme)',
        theme_validation: true
      });
    }
    
    // ===== PAIR VALIDATION (Extension with checkout_storage_id) =====
    console.log('🔒 PAIR VALIDATION MODE - checkout_storage_id provided');
    
    // ===== PAIR VALIDATION LOGIC =====
    // Find the record with matching session_token
    const dbRecord = await sessionsCollection.findOne({ 
      session_token
    });
    
    if (!dbRecord) {
      // No matching session_token in DB → BLOCK
      console.error('🚨 INVALID: No matching session_token in database');
      await logValidation(null, session_token, 'not_found', 
        'No matching session', ip_address, user_agent);
      return res.status(404).json({ 
        success: false,
        valid: false,
        error: 'Checkout session not found. Please return to cart and try again.' 
      });
    }
    
    // Check if session has expired
    if (dbRecord.expires_at && new Date() > new Date(dbRecord.expires_at)) {
      console.error('⏰ EXPIRED: Checkout session expired');
      await logValidation(null, session_token, 'expired', 
        'Session expired', ip_address, user_agent);
      return res.status(400).json({ 
        success: false,
        valid: false,
        error: 'Checkout session has expired. Please return to cart and try again.' 
      });
    }
    
    console.log(`📋 DB Record found: checkout_storage_id = ${dbRecord.checkout_storage_id || 'NULL'}`);
    
    // Now check checkout_storage_id
    if (!dbRecord.checkout_storage_id || dbRecord.checkout_storage_id === '') {
      // Case B: session_token matches, but checkout_storage_id is NULL in DB
      // This is the FIRST legitimate checkout → ALLOW + UPDATE
      console.log('✅ FIRST CHECKOUT: checkout_storage_id is NULL in DB → Storing new checkout_storage_id');
      
      const updateResult = await sessionsCollection.updateOne(
        { session_token, checkout_storage_id: { $in: [null, ''] } },
        { 
          $set: { 
            checkout_storage_id: checkout_storage_id,
            first_checkout_at: new Date(),
            last_validated_at: new Date()
          } 
        }
      );
      
      if (updateResult.modifiedCount === 0) {
        // Race condition: another request just updated it
        console.error('⚠️ RACE CONDITION: checkout_storage_id was just set by another request');
        // Re-fetch and compare
        const updatedRecord = await sessionsCollection.findOne({ session_token });
        if (updatedRecord.checkout_storage_id === checkout_storage_id) {
          console.log('✅ Same checkout_storage_id - allowing');
        } else {
          console.error('🚨 Different checkout_storage_id - blocking');
          await logValidation(null, session_token, 'storage_mismatch', 
            'Different checkout_storage_id (copied URL)', ip_address, user_agent);
          return res.status(403).json({ 
            success: false,
            valid: false,
            error: 'This checkout URL cannot be used from a different browser or device. Please return to cart and checkout again.' 
          });
        }
      }
      
      await logValidation(null, session_token, 'success', 
        'First checkout - storage_id stored', ip_address, user_agent);
      
      console.log('✅ VALIDATION PASSED - First legitimate checkout');
      return res.status(200).json({ 
        success: true,
        valid: true,
        message: 'Checkout validated successfully (first checkout)',
        first_checkout: true
      });
      
    } else if (dbRecord.checkout_storage_id === checkout_storage_id) {
      // Case A: Both match → ALLOW (same browser, refresh or revisit)
      console.log('✅ BOTH MATCH: Same browser refresh/revisit');
      
      // Update last validated time
      await sessionsCollection.updateOne(
        { session_token },
        { 
          $set: { 
            last_validated_at: new Date()
          } 
        }
      );
      
      await logValidation(null, session_token, 'success', 
        'Same browser validation', ip_address, user_agent);
      
      console.log('✅ VALIDATION PASSED - Same browser');
      return res.status(200).json({ 
        success: true,
        valid: true,
        message: 'Checkout validated successfully (same browser)',
        same_browser: true
      });
      
    } else {
      // Case C: session_token matches, but checkout_storage_id is DIFFERENT
      // This is a COPIED URL from different browser → BLOCK
      console.error('🚨 COPIED URL DETECTED!');
      console.error(`   Expected checkout_storage_id: ${dbRecord.checkout_storage_id.substring(0, 20)}...`);
      console.error(`   Provided checkout_storage_id: ${checkout_storage_id.substring(0, 20)}...`);
      console.error(`   This checkout URL was copied to a different browser!`);
      
      await logValidation(null, session_token, 'storage_mismatch', 
        'FRAUD: Different checkout_storage_id (copied URL to different browser)', 
        ip_address, user_agent);
      
      return res.status(403).json({ 
        success: false,
        valid: false,
        error: 'This checkout URL cannot be used from a different browser or device. Please return to cart and checkout again.',
        reason: 'copied_url_detected'
      });
    }
    
  } catch (error) {
    console.error('Validation error:', error);
    await logValidation(null, req.body.session_token, 'error', 
      error.message, req.body.ip_address, req.body.user_agent);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

/**
 * GET /api/admin/stats
 * Get validation statistics
 */
app.get('/api/admin/stats', async (req, res) => {
  try {
    const yesterday = new Date(Date.now() - (24 * 60 * 60 * 1000));
    
    // Aggregate validation stats from last 24 hours
    const statsAggregation = await logsCollection.aggregate([
      { $match: { created_at: { $gte: yesterday } } },
      {
        $group: {
          _id: '$validation_result',
          count: { $sum: 1 }
        }
      }
    ]).toArray();
    
    const statsMap = {
      successful_validations: 0,
      reuse_attempts: 0,
      expired_attempts: 0,
      invalid_attempts: 0,
      fraud_attempts: 0, // Session mismatch = copied checkout URL
      total_validations: 0
    };
    
    statsAggregation.forEach(stat => {
      statsMap.total_validations += stat.count;
      if (stat._id === 'success') statsMap.successful_validations = stat.count;
      if (stat._id === 'already_used') statsMap.reuse_attempts = stat.count;
      if (stat._id === 'expired') statsMap.expired_attempts = stat.count;
      if (stat._id === 'invalid') statsMap.invalid_attempts = stat.count;
      if (stat._id === 'session_mismatch') statsMap.fraud_attempts = stat.count;
    });
    
    const now = new Date();
    const activeSessions = await sessionsCollection.countDocuments({
      expires_at: { $gt: now },
      is_used: false
    });
    
    const activeAttempts = await attemptsCollection.countDocuments({
      expires_at: { $gt: now },
      is_used: false
    });
    
    res.json({
      success: true,
      stats: {
        last_24_hours: statsMap,
        active_sessions: activeSessions,
        active_attempts: activeAttempts
      }
    });
    
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

/**
 * GET /api/admin/attempts
 * View recent attempts (admin)
 */
app.get('/api/admin/attempts', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    
    const attempts = await attemptsCollection
      .find({}, {
        projection: {
          _id: 0,
          attempt_id: 1,
          session_token: 1,
          created_at: 1,
          expires_at: 1,
          is_used: 1,
          used_at: 1,
          ip_address: 1,
          order_id: 1
        }
      })
      .sort({ created_at: -1 })
      .skip(offset)
      .limit(limit)
      .toArray();
    
    const total = await attemptsCollection.countDocuments();
    
    res.json({
      success: true,
      attempts,
      pagination: {
        limit,
        offset,
        total
      }
    });
    
  } catch (error) {
    console.error('Attempts query error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

/**
 * GET /api/admin/logs
 * View validation logs (admin)
 */
app.get('/api/admin/logs', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const result_filter = req.query.result; // success, expired, already_used, invalid
    
    const filter = {};
    if (result_filter) {
      filter.validation_result = result_filter;
    }
    
    const logs = await logsCollection
      .find(filter, { projection: { _id: 0 } })
      .sort({ created_at: -1 })
      .limit(limit)
      .toArray();
    
    res.json({
      success: true,
      logs
    });
    
  } catch (error) {
    console.error('Logs query error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

/**
 * POST /api/admin/cleanup
 * Manually trigger cleanup
 */
app.post('/api/admin/cleanup', async (req, res) => {
  try {
    const cleaned = await cleanupExpiredTokens();
    res.json({
      success: true,
      message: `Cleaned up ${cleaned} expired records`
    });
  } catch (error) {
    console.error('Manual cleanup error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

// ============================================
// AUDIT LOGGING
// ============================================

async function logValidation(attemptId, sessionToken, result, errorMessage, ipAddress, userAgent) {
  try {
    await logsCollection.insertOne({
      attempt_id: attemptId,
      session_token: sessionToken,
      validation_result: result,
      error_message: errorMessage,
      ip_address: ipAddress,
      user_agent: userAgent,
      created_at: new Date()
    });
  } catch (error) {
    console.error('Logging error:', error);
  }
}

// ============================================
// STATIC FILES (Admin Dashboard)
// ============================================

const path = require('path');
const fs = require('fs');

// Serve admin dashboard
app.get('/', (req, res) => {
  const dashboardPath = path.join(__dirname, 'admin-dashboard.html');
  if (fs.existsSync(dashboardPath)) {
    res.sendFile(dashboardPath);
  } else {
    res.json({
      success: true,
      message: 'Token Validator API',
      endpoints: {
        stats: '/api/admin/stats',
        logs: '/api/admin/logs',
        attempts: '/api/admin/attempts',
        dashboard: '/admin-dashboard.html (file not found)'
      }
    });
  }
});

app.get('/admin-dashboard.html', (req, res) => {
  const dashboardPath = path.join(__dirname, 'admin-dashboard.html');
  if (fs.existsSync(dashboardPath)) {
    res.sendFile(dashboardPath);
  } else {
    res.status(404).send('Admin dashboard not found');
  }
});

// ============================================
// ERROR HANDLING & 404
// ============================================

// 404 handler - must be after all routes
app.use((req, res) => {
  console.warn(`⚠️ 404 Not Found: ${req.method} ${req.path}`);
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    path: req.path,
    method: req.method,
    availableEndpoints: {
      session: 'POST /api/session/register',
      attempt: 'POST /api/attempt/register',
      validate: 'POST /api/validate',
      stats: 'GET /api/admin/stats',
      attempts: 'GET /api/admin/attempts',
      logs: 'GET /api/admin/logs',
      cleanup: 'POST /api/admin/cleanup',
      dashboard: 'GET /'
    }
  });
});

// ============================================
// SERVER STARTUP
// ============================================

const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    // Initialize database first
    await initDatabase();
    console.log('✅ Database initialized');
    
    // Start cleanup scheduler (after DB is ready)
    setInterval(async () => {
      await cleanupExpiredTokens();
    }, 5 * 60 * 1000);
    console.log('✅ Cleanup scheduler started');
    
    // Start server
    app.listen(PORT, () => {
      console.log('\n' + '='.repeat(50));
      console.log(`✅ Token Validator API running on port ${PORT}`);
      console.log('='.repeat(50));
      console.log(`📊 Admin Dashboard: https://fraud-check-app.onrender.com:${PORT}/`);
      console.log(`📈 Admin Stats API: https://fraud-check-app.onrender.com:${PORT}/api/admin/stats`);
      console.log(`📝 Admin Logs API: https://fraud-check-app.onrender.com:${PORT}/api/admin/logs`);
      console.log('\n🔗 Available Endpoints:');
      console.log('   POST /api/session/register');
      console.log('   POST /api/attempt/register');
      console.log('   POST /api/validate');
      console.log('   GET  /api/admin/stats');
      console.log('   GET  /api/admin/attempts');
      console.log('   GET  /api/admin/logs');
      console.log('   POST /api/admin/cleanup');
      console.log('='.repeat(50) + '\n');
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

module.exports = { app, mongoClient, db, cleanupExpiredTokens };

