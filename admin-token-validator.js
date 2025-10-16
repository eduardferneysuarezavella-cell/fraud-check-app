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
    logsCollection = db.collection('validation_logs');
    
    // Create indexes for performance
    await sessionsCollection.createIndex({ session_token: 1 }, { unique: true });
    await sessionsCollection.createIndex({ expires_at: 1 });
    await sessionsCollection.createIndex({ checkout_storage_id: 1 });
    
    await logsCollection.createIndex({ session_token: 1 });
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
    
    const sessionsResult = await sessionsCollection.deleteMany({
      expires_at: { $lt: now }
    });
    
    console.log(`🧹 Cleaned up ${sessionsResult.deletedCount} expired sessions`);
    return sessionsResult.deletedCount;
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
      await logValidation(null, 'invalid', 'Missing session_token', ip_address, user_agent);
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
        await logValidation(session_token, 'not_found', 
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
        await logValidation(session_token, 'expired', 
          'Session expired', ip_address, user_agent);
        return res.status(400).json({ 
          success: false,
          valid: false,
          error: 'Checkout session has expired. Please return to cart and try again.' 
        });
      }
      
      console.log('✅ Theme validation PASSED');
      await logValidation(session_token, 'success', 
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
      await logValidation(session_token, 'not_found', 
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
      await logValidation(session_token, 'expired', 
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
          await logValidation(session_token, 'storage_mismatch', 
            'Different checkout_storage_id (copied URL)', ip_address, user_agent);
          return res.status(403).json({ 
            success: false,
            valid: false,
            error: 'This checkout URL cannot be used from a different browser or device. Please return to cart and checkout again.' 
          });
        }
      }
      
      await logValidation(session_token, 'success', 
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
      
      await logValidation(session_token, 'success', 
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
      
      await logValidation(session_token, 'storage_mismatch', 
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
      expires_at: { $gt: now }
    });
    
    res.json({
      success: true,
      stats: {
        last_24_hours: statsMap,
        active_sessions: activeSessions
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

async function logValidation(sessionToken, result, errorMessage, ipAddress, userAgent) {
  try {
    await logsCollection.insertOne({
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
      validate: 'POST /api/validate',
      stats: 'GET /api/admin/stats',
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
      console.log('   POST /api/validate');
      console.log('   GET  /api/admin/stats');
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

