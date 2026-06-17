const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const crypto = require('crypto');
const Ajv = require('ajv'); // Import the Advanced Validation Engine
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET = "super_secret_omni_cloud_key_2026"; // keep this in a hidden .env file
const addFormats = require("ajv-formats");
const app = express();
app.use(express.json());
app.use(cors());

// Initialize the validator compiler
const ajv = new Ajv({ allErrors: true }); 
addFormats(ajv);
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: '_iot_db',
  password: 'astro-cod3x',
  port: 5432,
});

// 1. THE ADVANCED VALIDATION BLUEPRINT
// This forces the server to ONLY accept specific, predictable IoT variables
const iotPayloadSchema = {
  type: "object",
  properties: {
    device_id: { type: "string" },
    token: { type: "string" },
    temperature: { type: "number", minimum: -40, maximum: 150 }, // Strict ranges
    humidity: { type: "number", minimum: 0, maximum: 100 },
    latitude: { type: "number" },
    longitude: { type: "number" }
  },
  // These fields MUST be present in every single transmission packet
  required: ["device_id", "token"], 
  // THE ADVANCED GUARD: If a user sends ANY field not listed above, REJECT IT instantly.
  additionalProperties: false 
};

// Compile the schema in memory for lightning-fast execution speed
const validatePayload = ajv.compile(iotPayloadSchema);

const userSignupSchema = {
  type: "object",
  properties: {
    username: { 
      type: "string", 
      minLength: 3, 
      maxLength: 30
    },
    email: { 
      type: "string", 
      format: "email" 
    },
    password: { 
      type: "string", 
      minLength: 6 
    }
  },
  required: ["username", "email", "password"],
  additionalProperties: false
};

const validateSignup = ajv.compile(userSignupSchema);



//--------------------------------------------------------------
// INGESTION GATEWAY
app.post('/api/v1/data', async (req, res) => {
  
  // Phase 1: Fire the Validation Blueprint Guard
  const isValid = validatePayload(req.body);
  
  if (!isValid) {
    console.log(`[REJECTED] Malformed payload attempt:`, validatePayload.errors);
    return res.status(400).json({ 
      error: "Bad Request: Schema violation.", 
      details: validatePayload.errors.map(e => `${e.instancePath.slice(1)} ${e.message}`) 
    });
  }

  // Phase 2: If it passes validation, proceed with your existing logic safely
  const { device_id, token, ...payload } = req.body;
  const calculatedHash = crypto.createHash('sha256').update(token).digest('hex');

  try {
    const deviceVerify = await pool.query(
      'SELECT is_active FROM devices WHERE device_id = $1 AND api_token_hash = $2',
      [device_id, calculatedHash]
    );

    if (deviceVerify.rows.length === 0 || !deviceVerify.rows[0].is_active) {
      return res.status(401).json({ error: "Authentication Failed: Node unauthorized." });
    }

    // Phase 3: Fast Relational Batch Inserter
    const insertQuery = `
      INSERT INTO iot_data_stream (device_id, metric_name, numeric_value, text_value, boolean_value)
      VALUES ($1, $2, $3, $4, $5)
    `;

    for (const [metricName, value] of Object.entries(payload)) {
      let numericVal = null, textVal = null, booleanVal = null;
      if (typeof value === 'number') numericVal = value;
      else if (typeof value === 'boolean') booleanVal = value;
      else textVal = String(value);

      await pool.query(insertQuery, [device_id, metricName, numericVal, textVal, booleanVal]);
    }

    res.status(200).json({ status: "Success", metrics_logged: Object.keys(payload).length });

  } catch (err) {
    console.error("Database Error:", err.message);
    res.status(500).send("Server Error");
  }
});

const PORT = 3000;
// 1. AUTHENTICATION MIDDLEWARE GATEKEEPER
// This function sits in front of routes and blocks unauthorized browsers
const authenticateToken = (req, res, next) => {
    // Grab the token from the HTTP Authorization header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN_STRING"

    if (!token) return res.status(401).json({ error: "Access Denied: Missing session token." });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Session expired or invalid token." });
        req.user = user; // Inject the verified user data into the request object
        next(); // Pass control to the actual route handler below
    });
};
//------------------------------


app.post('/api/v1/auth/signup', async (req, res) => {
    // Fire the validator compiler instantly
    const isValid = validateSignup(req.body);
    if (!isValid) {
        return res.status(400).json({ 
            error: "Registration failed: Invalid input criteria.", 
            details: validateSignup.errors.map(e => `${e.instancePath.slice(1)} ${e.message}`) 
        });
    }

    const { username, email, password } = req.body;
    try {
        const salt = await bcrypt.genSalt(10);
        const securedPassword = await bcrypt.hash(password, salt);

        const newUser = await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING user_id, username',
            [username, email, securedPassword]
        );
        res.status(201).json({ message: "Registration successful!", user: newUser.rows[0] });
    } catch (err) {
        res.status(400).json({ error: "Username or Email address already taken." });
    }
});

// 2. USER LOGIN ENDPOINT
app.post('/api/v1/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const userQuery = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userQuery.rows.length === 0) return res.status(400).json({ error: "Invalid profile credentials." });

        const user = userQuery.rows[0];
        
        // Cryptographically compare the text password to the database bcrypt hash
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(400).json({ error: "Invalid profile credentials." });

        // Sign a session secure token that expires in 2 hours
        const sessionToken = jwt.sign({ user_id: user.user_id }, JWT_SECRET, { expiresIn: '2h' });

        res.json({ message: "Login approved.", sessionToken, username: user.username });
    } catch (err) {
        res.status(500).send("Login gateway component failure.");
    }
});

// ADD THIS ROUTE FOR YOUR DASHBOARD TO READ FROM THE DB
app.get('/api/v1/data/:device_id', authenticateToken, async (req, res) => {
  try {
    const requestedDevice = req.params.device_id;
    const verifiedUserId = req.user.user_id; // Pulled safely from the encrypted JWT token

    // VERIFICATION CHECK: Does this verified user actually own this device?
    const ownershipCheck = await pool.query(
        'SELECT 1 FROM devices WHERE device_id = $1 AND user_id = $2',
        [requestedDevice, verifiedUserId]
    );

    if (ownershipCheck.rows.length === 0) {
        return res.status(403).json({ error: "Access Forbidden: You do not own this hardware asset." });
    }

    // If ownership passes, fetch the latest metrics exactly like before
    const queryStr = `
      SELECT DISTINCT ON (metric_name) metric_name, numeric_value, text_value, boolean_value, timestamp
      FROM iot_data_stream
      WHERE device_id = $1
      ORDER BY metric_name, timestamp DESC;
    `;
    const result = await pool.query(queryStr, [requestedDevice]);
    
    if (result.rows.length === 0) {
      return res.json({ device_id: requestedDevice, metrics: {} });
    }

    const structuredPayload = {};
    let latestTimestamp = result.rows[0].timestamp;

    result.rows.forEach(row => {
        if (row.numeric_value !== null) structuredPayload[row.metric_name] = Number(row.numeric_value);
        else if (row.boolean_value !== null) structuredPayload[row.metric_name] = row.boolean_value;
        else structuredPayload[row.text_value] = row.text_value;
    });

    res.json({ device_id: requestedDevice, timestamp: latestTimestamp, metrics: structuredPayload });

  } catch (err) {
    console.error("Dashboard secure fetch error:", err.message);
    res.status(500).json({ error: "Internal Secure Read Transaction failure." });
  }
});
//---------------------
//------Devices-related
// 1. ENDPOINT: PROVISION A NEW HARDWARE NODE
app.post('/api/v1/devices', authenticateToken, async (req, res) => {
    const { device_id, device_name } = req.body;
    const verifiedUserId = req.user.user_id;

    if (!device_id || !device_name) {
        return res.status(400).json({ error: "Device ID and Name are required." });
    }

    // Clean up the device ID string to match standard safe URL formats
    const cleanDeviceId = device_id.trim().toUpperCase().replace(/\s+/g, '_');

    try {
        // Generate a random, high-entropy plaintext secret key for the hardware client
        const rawSecretToken = "omni_live_sk_" + crypto.randomBytes(16).toString('hex');
        
        // Hash it immediately using our SHA-256 protocol before writing to the database disk
        const tokenHash = crypto.createHash('sha256').update(rawSecretToken).digest('hex');

        await pool.query(
            'INSERT INTO devices (device_id, user_id, api_token_hash, device_name) VALUES ($1, $2, $3, $4)',
            [cleanDeviceId, verifiedUserId, tokenHash, device_name]
        );

        // Crucial: Return the raw plaintext secret token ONCE so the user can copy it into their microcontroller
        res.status(201).json({
            message: "Node registered successfully.",
            device_id: cleanDeviceId,
            device_name,
            plaintext_secret_token: rawSecretToken
        });

    } catch (err) {
        res.status(400).json({ error: "Device ID already exists in the global cloud namespace." });
    }
});

// 2. ENDPOINT: FETCH ALL RECOGNIZED HARDWARE NODES OWNED BY THIS USER
app.get('/api/v1/devices', authenticateToken, async (req, res) => {
    try {
        const userDevices = await pool.query(
            'SELECT device_id, device_name, is_active, created_at FROM devices WHERE user_id = $1 ORDER BY created_at DESC',
            [req.user.user_id]
        );
        res.json(userDevices.rows);
    } catch (err) {
        res.status(500).json({ error: "Failed to compile user node collection index." });
    }
});

//-------------------------------



app.listen(PORT, () => console.log(`🚀 Advanced Core running locally on port ${PORT}`));